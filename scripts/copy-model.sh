#!/usr/bin/env bash
##############################################################
# PhishGuard — Copy ONNX Model to Extension
#
# Run this after training to deploy the model into the extension.
# Usage:
#   bash scripts/copy-model.sh
#   bash scripts/copy-model.sh --validate   # also runs ONNX sanity check
#
# Author: Akshay | https://akshay.fruvvi.com
##############################################################

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${REPO_ROOT}/ml/exports/phishguard.onnx"
DEST_DIR="${REPO_ROOT}/extension/public/models"
DEST="${DEST_DIR}/phishguard.onnx"

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No color

info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

echo ""
echo "  PhishGuard — Model Deployment"
echo "  ──────────────────────────────"
echo ""

# ── Check source exists ───────────────────────────────────────
if [[ ! -f "${SOURCE}" ]]; then
  error "Model not found at: ${SOURCE}\n\n  Run training first:\n    cd ml && python training/train.py"
fi

SOURCE_SIZE=$(du -sh "${SOURCE}" | cut -f1)
info "Source: ${SOURCE} (${SOURCE_SIZE})"

# ── Create destination directory ──────────────────────────────
mkdir -p "${DEST_DIR}"

# ── Backup existing model if present ─────────────────────────
if [[ -f "${DEST}" ]]; then
  BACKUP="${DEST}.backup-$(date +%Y%m%d-%H%M%S)"
  cp "${DEST}" "${BACKUP}"
  warn "Existing model backed up to: ${BACKUP}"
fi

# ── Copy model ────────────────────────────────────────────────
cp "${SOURCE}" "${DEST}"
success "Model copied to: ${DEST}"

# ── Optional validation ───────────────────────────────────────
if [[ "${1:-}" == "--validate" ]]; then
  info "Validating ONNX model..."

  # Check onnxruntime is available
  if ! python3 -c "import onnxruntime" 2>/dev/null; then
    warn "onnxruntime not installed — skipping validation"
    warn "Install with: pip install onnxruntime"
  else
    python3 - <<'PYEOF'
import sys
import numpy as np
import onnxruntime as ort

model_path = sys.argv[1] if len(sys.argv) > 1 else "extension/public/models/phishguard.onnx"

try:
    session = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])

    # Check inputs/outputs
    inputs  = session.get_inputs()
    outputs = session.get_outputs()
    assert len(inputs)  == 1, f"Expected 1 input, got {len(inputs)}"
    assert len(outputs) == 2, f"Expected 2 outputs (label + probabilities), got {len(outputs)}"
    assert inputs[0].shape[1] == 15, f"Expected 15 features, got {inputs[0].shape[1]}"

    # Run a test inference
    test_features = np.random.rand(1, 15).astype(np.float32)
    result = session.run(None, {inputs[0].name: test_features})
    proba = result[1][0]
    assert 0.0 <= proba[0] <= 1.0, "Invalid probability output"
    assert 0.0 <= proba[1] <= 1.0, "Invalid probability output"
    assert abs(proba[0] + proba[1] - 1.0) < 1e-4, "Probabilities don't sum to 1"

    print(f"  ✓ Model valid — inputs: {inputs[0].shape}, test inference: {proba[1]:.4f} phish prob")
    sys.exit(0)

except AssertionError as e:
    print(f"  ✗ Validation failed: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"  ✗ Error: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

    if [[ $? -eq 0 ]]; then
      success "ONNX model validation passed"
    else
      error "ONNX model validation failed — check the model export"
    fi
  fi
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "  ✓ Model deployed successfully"
echo "  ─────────────────────────────────────────────────────"
echo "  Next steps:"
echo "    1. cd extension && npm run build"
echo "    2. Load dist/ in chrome://extensions"
echo ""
