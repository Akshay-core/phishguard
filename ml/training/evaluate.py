"""
PhishGuard — Model Evaluation Script
======================================
Loads a trained ONNX model and generates a comprehensive evaluation report:
accuracy, precision, recall, F1, ROC-AUC, confusion matrix, ROC curve.

Run from ml/ directory:
  python training/evaluate.py
  python training/evaluate.py --model exports/phishguard.onnx

Author: Akshay | https://akshay.fruvvi.com
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Tuple

# ── Make features.py importable regardless of working directory ───────────────
_TRAINING_DIR = Path(__file__).resolve().parent
if str(_TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(_TRAINING_DIR))

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — safe for all environments
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve,
    classification_report,
)
from sklearn.model_selection import train_test_split

from features import extract, NUM_FEATURES

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("PhishGuard.eval")

# Default paths relative to this file
_ML_DIR          = _TRAINING_DIR.parent
DEFAULT_MODEL    = _ML_DIR / "exports" / "phishguard.onnx"
DEFAULT_DATASETS = _ML_DIR / "datasets"
DEFAULT_OUTPUT   = _ML_DIR / "exports" / "eval"


# ─── ONNX inference ───────────────────────────────────────────────────────────

def load_onnx_model(model_path: Path):
    """Load ONNX model. Raises FileNotFoundError if path doesn't exist."""
    try:
        import onnxruntime as ort
    except ImportError:
        raise ImportError(
            "onnxruntime not installed.\n"
            "  Run: pip install onnxruntime"
        )

    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found: {model_path.resolve()}\n"
            "  Run training first: python training/train.py"
        )

    session = ort.InferenceSession(
        str(model_path),
        providers=["CPUExecutionProvider"],
    )
    size_kb = model_path.stat().st_size / 1024
    log.info(f"Model loaded: {model_path.resolve()} ({size_kb:.1f} KB)")
    return session


def predict_onnx(session, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Run ONNX inference. Returns (labels, phish_probabilities)."""
    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: X.astype(np.float32)})
    # outputs[0] = int64 labels, outputs[1] = float32 [[p_safe, p_phish], ...]
    labels = outputs[0].flatten().astype(np.int64)
    proba  = outputs[1][:, 1].astype(np.float64)  # phishing probability
    return labels, proba


# ─── Dataset loading ──────────────────────────────────────────────────────────

def load_test_data(datasets_dir: Path) -> Tuple[np.ndarray, np.ndarray]:
    """Load datasets and return stratified 20% test split."""
    frames = []

    for path in sorted(datasets_dir.glob("phishing_*.csv")):
        try:
            df = pd.read_csv(path)
            df.columns = df.columns.str.lower()
            if "url" not in df.columns:
                continue
            df["label"] = 1
            frames.append(df[["url", "label"]])
        except Exception as e:
            log.warning(f"Skipping {path.name}: {e}")

    for path in sorted(datasets_dir.glob("legit_*.csv")):
        try:
            df = pd.read_csv(path)
            df.columns = df.columns.str.lower()
            if "url" not in df.columns:
                continue
            df["label"] = 0
            frames.append(df[["url", "label"]])
        except Exception as e:
            log.warning(f"Skipping {path.name}: {e}")

    if not frames:
        raise FileNotFoundError(
            f"No CSVs found in {datasets_dir.resolve()}\n"
            "  Run: python training/download_datasets.py"
        )

    combined = pd.concat(frames, ignore_index=True).dropna(subset=["url"])
    combined = combined.drop_duplicates(subset=["url"])

    X = np.array(
        [extract(str(u)).to_list() for u in combined["url"]],
        dtype=np.float32,
    )
    y = combined["label"].values.astype(np.int64)

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    log.info(
        f"Test set: {len(y_test):,} samples "
        f"({int(y_test.sum()):,} phishing, {int((y_test == 0).sum()):,} legit)"
    )
    return X_test, y_test


# ─── Evaluation + plots ───────────────────────────────────────────────────────

def evaluate(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    output_dir: Path,
) -> dict:
    """Compute metrics, save plots, return metrics dict."""
    metrics = {
        "accuracy":  round(float(accuracy_score(y_true, y_pred)),  4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)),    4),
        "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)),        4),
        "roc_auc":   round(float(roc_auc_score(y_true, y_proba)),  4),
    }

    log.info("\n── Evaluation Results ──────────────────────────────")
    for k, v in metrics.items():
        log.info(f"  {k:12s}: {v:.4f}")

    log.info("\n" + classification_report(
        y_true, y_pred, target_names=["Legitimate", "Phishing"], zero_division=0
    ))

    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Plots ─────────────────────────────────────────────────
    try:
        plt.style.use("dark_background")
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle("PhishGuard Model Evaluation", fontsize=14, fontweight="bold")

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Pred Safe", "Pred Phish"],
            yticklabels=["Actual Safe", "Actual Phish"],
            ax=axes[0],
        )
        axes[0].set_title("Confusion Matrix")

        # ROC curve
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        axes[1].plot(fpr, tpr, color="#6366f1", lw=2,
                     label=f"ROC (AUC = {metrics['roc_auc']:.4f})")
        axes[1].plot([0, 1], [0, 1], "k--", lw=1)
        axes[1].set_xlabel("False Positive Rate")
        axes[1].set_ylabel("True Positive Rate")
        axes[1].set_title("ROC Curve")
        axes[1].legend(loc="lower right")
        axes[1].grid(alpha=0.3)

        plt.tight_layout()
        plot_path = output_dir / "evaluation.png"
        plt.savefig(plot_path, dpi=150, bbox_inches="tight")
        plt.close()
        log.info(f"Plot saved: {plot_path.resolve()}")

    except Exception as e:
        log.warning(f"Plot generation failed (non-fatal): {e}")

    # Save JSON metrics
    metrics_path = output_dir / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    log.info(f"Metrics saved: {metrics_path.resolve()}")

    return metrics


# ─── Entrypoint ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PhishGuard — Model Evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python training/evaluate.py\n"
            "  python training/evaluate.py --model exports/phishguard.onnx\n"
        )
    )
    parser.add_argument(
        "--model",    type=Path, default=DEFAULT_MODEL,
        help=f"Path to ONNX model (default: {DEFAULT_MODEL})"
    )
    parser.add_argument(
        "--datasets", type=Path, default=DEFAULT_DATASETS,
        help=f"Dataset directory (default: {DEFAULT_DATASETS})"
    )
    parser.add_argument(
        "--output",   type=Path, default=DEFAULT_OUTPUT,
        help=f"Output directory for plots/metrics (default: {DEFAULT_OUTPUT})"
    )
    args = parser.parse_args()

    X_test, y_test = load_test_data(args.datasets)
    session = load_onnx_model(args.model)
    y_pred, y_proba = predict_onnx(session, X_test)
    evaluate(y_test, y_pred, y_proba, args.output)
    log.info("\n✓ Evaluation complete.")


if __name__ == "__main__":
    main()