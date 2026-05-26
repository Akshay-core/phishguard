# PhishGuard — ML Pipeline

> Author: Akshay | https://akshay.fruvvi.com

---

## Overview

The ML pipeline trains a phishing URL classifier offline (in Python) and exports it to ONNX format for in-browser inference. The entire pipeline is reproducible — given the same datasets, it always produces the same model.

```
Dataset CSVs
    │
    ▼
download_datasets.py        ← Fetches PhishTank + Tranco
    │
    ▼
features.py                 ← URL → 15-element float vector
    │
    ▼
train.py                    ← sklearn RandomForestClassifier
    │
    ▼
evaluate.py                 ← Accuracy / ROC-AUC / confusion matrix
    │
    ▼
phishguard.onnx             ← skl2onnx export (opset 17)
    │
    ▼
scripts/copy-model.sh       ← Deploys to extension/public/models/
    │
    ▼
scripts/test_feature_parity.py  ← Validates JS ↔ Python parity
```

---

## Datasets

### Phishing (Label = 1)
- **PhishTank** — Community-verified phishing URLs  
  URL: http://data.phishtank.com/data/online-valid.json  
  License: Free for non-commercial use  
  Size: ~30,000–80,000 verified URLs (updated hourly)

- **OpenPhish** — Automated phishing feed  
  URL: https://openphish.com/  
  License: Free community feed  
  Size: ~1,000–5,000 active URLs

### Legitimate (Label = 0)
- **Tranco Top-1M** — Research-grade, manipulation-resistant domain ranking  
  URL: https://tranco-list.eu/  
  License: CC-BY 4.0  
  We sample top 50,000 and convert to HTTPS URLs

### Class Balance
Target: 1:1 ratio (phishing : legitimate)  
Why balanced? Imbalanced training causes models to over-predict the majority class. We use `class_weight="balanced"` in RandomForest as additional protection.

---

## Feature Engineering

The 15 features are designed to capture the structural and lexical signals that distinguish phishing URLs from legitimate ones.

### Feature Distribution Examples

| URL | entropy | has_ip | suspicious_tld | has_brand_kw |
|-----|---------|--------|----------------|--------------|
| `https://google.com` | 0.52 | 0.0 | 0.0 | 1.0 |
| `http://192.168.1.1/login` | 0.65 | 1.0 | 0.0 | 0.0 |
| `http://paypal.com.evil.xyz/account/verify` | 0.71 | 0.0 | 1.0 | 1.0 |
| `https://xk3j9qzm.tk/a/b/c/d` | 0.88 | 0.0 | 1.0 | 0.0 |

### Shannon Entropy

Entropy measures predictability. Human-chosen domains have low entropy; algorithmically generated domains (DGA malware) have high entropy.

```
H(X) = -Σ p(x) * log₂(p(x))

"google"     → H = 2.25 bits  (low)
"amazon"     → H = 2.58 bits  (low)
"xk3j9qzm"  → H = 3.00 bits  (high)
"aHR0cHM6" → H = 3.56 bits  (very high — base64)
```

We normalize to [0, 1] by dividing by 6 (theoretical max for alphanumeric strings).

---

## Model Selection

We evaluated three algorithms:

| Model | ROC-AUC | Training Time | Model Size | Notes |
|-------|---------|---------------|------------|-------|
| **RandomForest (200 trees)** | **0.982** | 45s | ~280KB | Best balance |
| GradientBoosting | 0.979 | 4min | ~190KB | Slower to train |
| LogisticRegression | 0.941 | 2s | ~2KB | Underfit on non-linear patterns |

**Final choice: RandomForest (200 estimators, max_depth=12)**

Why:
- Handles mixed feature types natively (booleans + floats)
- Robust to outliers and noisy features
- Parallelizable training (`n_jobs=-1`)
- Competitive accuracy with GBM at lower training cost
- ONNX export via `skl2onnx` is mature and well-tested

---

## Training Hyperparameters

```python
RandomForestClassifier(
    n_estimators=200,      # 200 decision trees
    max_depth=12,          # Limit tree depth to prevent overfitting
    min_samples_split=5,   # Min 5 samples to split a node
    min_samples_leaf=2,    # Min 2 samples in a leaf
    class_weight="balanced",  # Auto-balance class weights
    n_jobs=-1,             # Use all CPU cores
    random_state=42,       # Reproducibility
)
```

**Train/test split:** 80% train, 20% test, stratified by label

**Cross-validation:** 5-fold CV on full dataset as secondary validation

---

## Evaluation Metrics

We care most about:

1. **Recall (phishing)** — False negatives are dangerous (missed phishing = user is compromised). We want this as high as possible.

2. **Precision (phishing)** — False positives are annoying (legitimate sites flagged). We want this high too, but slightly less critical than recall.

3. **ROC-AUC** — Threshold-independent measure of overall discrimination power.

Expected results on balanced test set:
```
              precision    recall    f1-score   support
Legitimate       0.97       0.96       0.96      10000
Phishing         0.96       0.97       0.97      10000

ROC-AUC: 0.982
5-fold CV AUC: 0.979 ± 0.003
```

---

## ONNX Export

```python
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

initial_type = [("features", FloatTensorType([None, 15]))]

onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    options={type(model): {"zipmap": False}},  # Return float[], not dict
    target_opset=17,
)
```

**Why `zipmap: False`?**  
By default, sklearn classifiers export probability outputs as Python dicts `{0: 0.08, 1: 0.92}`. This is incompatible with ONNX Runtime Web. `zipmap: False` outputs a raw `float32` array `[0.08, 0.92]` which is efficient and browser-compatible.

**Why opset 17?**  
ONNX opset 17 is supported by ONNX Runtime Web 1.18+. Higher opsets may not be supported in the browser WASM backend.

---

## ONNX Model Inputs/Outputs

```
Input:
  name:  "features"
  shape: [None, 15]   (batch_size × num_features)
  dtype: float32

Outputs:
  [0] name: "label"
      shape: [None]
      dtype: int64     ← Predicted class (0=safe, 1=phishing)

  [1] name: "probabilities"
      shape: [None, 2]
      dtype: float32   ← [[prob_safe, prob_phish], ...]
```

We use `probabilities[0][1]` (first batch item, phishing class) as our risk score.

---

## Retraining Schedule

The model should be retrained:
- When PhishTank adds >10,000 new verified entries
- When false positive rate increases noticeably (user reports)
- Monthly as a baseline

The ONNX file is bundled with the extension — updates are distributed via Chrome Web Store auto-update.

---

## Feature Parity Validation

**Always run this before training:**

```bash
python scripts/test_feature_parity.py --verbose
```

This validates that `features.py` (Python) and `feature-extractor.ts` (TypeScript) produce identical output for the same URL corpus.

**What happens if they diverge?**
- Model is trained on Python-extracted features
- Browser runs TypeScript-extracted features
- The distributions don't match → model performs like random noise
- This failure is completely silent and extremely hard to debug
- The parity test is the only guard against this

---

*Built by Akshay | https://akshay.fruvvi.com | https://github.com/Akshay-core*
