"""
PhishGuard — ML Training Pipeline
==================================
Trains a phishing URL classifier and exports to ONNX for browser inference.

Author: Akshay | https://akshay.fruvvi.com
GitHub: https://github.com/Akshay-core

Why RandomForest?
- Handles mixed feature types naturally (boolean + float)
- Resistant to overfitting on limited data
- Fast inference (critical for ONNX export)
- Interpretable via feature importance
- Baseline: ~95-97% accuracy on PhishTank data

Run from ml/ directory:
  python training/train.py

Run from training/ directory:
  python train.py

Output: ml/exports/phishguard.onnx
"""

import logging
import argparse
import sys
from pathlib import Path

# ── Make features.py importable regardless of working directory ───────────────
_TRAINING_DIR = Path(__file__).resolve().parent
if str(_TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(_TRAINING_DIR))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

from features import extract, FEATURE_NAMES, NUM_FEATURES

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("PhishGuard.train")

# ─── Default paths (relative to THIS file, not working directory) ─────────────
_ML_DIR = _TRAINING_DIR.parent
DEFAULT_DATASETS = _ML_DIR / "datasets"
DEFAULT_EXPORTS  = _ML_DIR / "exports"


# ─── Data Loading ─────────────────────────────────────────────────────────────

def load_dataset(datasets_dir: Path) -> pd.DataFrame:
    """
    Load phishing + legitimate URLs from CSVs.
    Expected: CSV with 'url' column. Label inferred from filename prefix.
      phishing_*.csv  → label = 1
      legit_*.csv     → label = 0
    """
    frames = []

    for path in sorted(datasets_dir.glob("phishing_*.csv")):
        try:
            df = pd.read_csv(path, usecols=lambda c: c.lower() in {"url", "label"})
            df.columns = df.columns.str.lower()
            df["label"] = 1
            frames.append(df[["url", "label"]])
            log.info(f"Loaded {len(df):,} phishing URLs from {path.name}")
        except Exception as e:
            log.warning(f"Skipping {path.name}: {e}")

    for path in sorted(datasets_dir.glob("legit_*.csv")):
        try:
            df = pd.read_csv(path, usecols=lambda c: c.lower() in {"url", "label"})
            df.columns = df.columns.str.lower()
            df["label"] = 0
            frames.append(df[["url", "label"]])
            log.info(f"Loaded {len(df):,} legitimate URLs from {path.name}")
        except Exception as e:
            log.warning(f"Skipping {path.name}: {e}")

    if not frames:
        raise FileNotFoundError(
            f"No CSV files found in: {datasets_dir.resolve()}\n"
            "  Run first: python training/download_datasets.py\n"
            "  Or place CSVs named 'phishing_*.csv' and 'legit_*.csv' in that directory."
        )

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.dropna(subset=["url"])
    combined = combined.drop_duplicates(subset=["url"])
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined[combined["url"].str.startswith(("http://", "https://", "www."))]

    phish_count = int(combined["label"].sum())
    legit_count = int((combined["label"] == 0).sum())
    log.info(f"Dataset: {len(combined):,} URLs ({phish_count:,} phishing, {legit_count:,} legitimate)")
    return combined


# ─── Feature Extraction ───────────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame):
    """Extract features for all URLs. Uses shared features.py module."""
    log.info(f"Extracting features for {len(df):,} URLs...")
    feature_rows = []
    errors = 0

    for url in df["url"]:
        try:
            feature_rows.append(extract(str(url)).to_list())
        except Exception:
            # Fallback to zeros rather than crashing the whole run
            feature_rows.append([0.0] * NUM_FEATURES)
            errors += 1

    if errors:
        log.warning(f"Feature extraction errors: {errors} URLs used zero-vector fallback")

    X = np.array(feature_rows, dtype=np.float32)
    y = df["label"].values.astype(np.int64)
    log.info(f"Feature matrix: {X.shape} | Labels: {y.shape}")
    return X, y


# ─── Training ─────────────────────────────────────────────────────────────────

def train(datasets_dir: Path, exports_dir: Path) -> None:
    """Full training pipeline: load → features → train → evaluate → export."""
    log.info("Starting PhishGuard ML training pipeline")
    log.info(f"  Datasets : {datasets_dir.resolve()}")
    log.info(f"  Exports  : {exports_dir.resolve()}")

    # 1. Load data
    df = load_dataset(datasets_dir)

    # 2. Extract features using shared features.py (same as TypeScript extractor)
    X, y = build_feature_matrix(df)

    # Guard: need at least 2 samples per class for stratified split
    unique, counts = np.unique(y, return_counts=True)
    for cls, cnt in zip(unique, counts):
        if cnt < 4:
            raise ValueError(
                f"Class {cls} has only {cnt} sample(s). Need at least 4. "
                "Add more data or run download_datasets.py first."
            )

    # 3. Train/test split — stratified to maintain class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )
    log.info(f"Train: {len(y_train):,} | Test: {len(y_test):,}")

    # 4. Train RandomForestClassifier
    log.info("Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # 5. Evaluate on held-out test set
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    log.info("\n" + classification_report(
        y_test, y_pred, target_names=["Legitimate", "Phishing"]
    ))

    auc = roc_auc_score(y_test, y_proba)
    log.info(f"ROC-AUC: {auc:.4f}")

    # Cross-validation (skip if dataset too small)
    if len(y) >= 20:
        cv_scores = cross_val_score(model, X, y, cv=min(5, len(y) // 4), scoring="roc_auc")
        log.info(f"CV AUC : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Feature importances
    importance_pairs = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    log.info("\nTop feature importances:")
    for name, imp in importance_pairs[:8]:
        bar = "█" * max(1, int(imp * 40))
        log.info(f"  {name:22s} {imp:.4f}  {bar}")

    # 6. Export to ONNX
    log.info("\nExporting to ONNX...")
    initial_type = [("features", FloatTensorType([None, NUM_FEATURES]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        options={type(model): {"zipmap": False}},
        target_opset=17,
    )

    exports_dir.mkdir(parents=True, exist_ok=True)
    output_path = exports_dir / "phishguard.onnx"
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = output_path.stat().st_size / 1024
    log.info(f"Model saved: {output_path.resolve()} ({size_kb:.1f} KB)")
    log.info("\n✓ Training complete.")
    log.info("  Next: bash scripts/copy-model.sh --validate")


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PhishGuard ML Training Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python training/train.py\n"
            "  python training/train.py --datasets ./datasets --exports ./exports\n"
        )
    )
    parser.add_argument(
        "--datasets", type=Path, default=DEFAULT_DATASETS,
        help=f"Directory containing phishing_*.csv and legit_*.csv (default: {DEFAULT_DATASETS})"
    )
    parser.add_argument(
        "--exports", type=Path, default=DEFAULT_EXPORTS,
        help=f"Directory to save phishguard.onnx (default: {DEFAULT_EXPORTS})"
    )
    args = parser.parse_args()
    train(args.datasets, args.exports)