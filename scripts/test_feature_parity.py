#!/usr/bin/env python3
"""
PhishGuard — Feature Parity Test
==================================
Validates that Python (features.py) and TypeScript (feature-extractor.ts)
produce identical feature vectors for the same URLs.

Run from anywhere in the project:
  python scripts/test_feature_parity.py
  python scripts/test_feature_parity.py --verbose

Author: Akshay | https://akshay.fruvvi.com
"""

import sys
import argparse
import textwrap
from pathlib import Path

# ── Robust path resolution — works from any working directory ──────────────────
_SCRIPT_DIR  = Path(__file__).resolve().parent
_PROJECT_DIR = _SCRIPT_DIR.parent
_TRAINING_DIR = _PROJECT_DIR / "ml" / "training"

if str(_TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(_TRAINING_DIR))

try:
    from features import extract, URLFeatureVector
except ImportError as e:
    print(f"\n[ERROR] Cannot import features.py: {e}")
    print(f"  Expected location: {_TRAINING_DIR / 'features.py'}")
    sys.exit(1)

EPSILON = 1e-4  # Maximum allowable floating point deviation per feature

# ─── Test corpus ──────────────────────────────────────────────────────────────
# Each entry: (url, description, dict of feature_name → expected_value)
# Expected values match the TypeScript feature-extractor.ts output.
# Update these whenever either extractor changes.

TEST_CASES = [
    (
        "https://www.google.com/search?q=hello",
        "Safe HTTPS URL — baseline legitimate",
        {
            "no_https":       0.0,
            "has_ip":         0.0,
            "suspicious_tld": 0.0,
            "has_login_kw":   0.0,
            "has_brand_kw":   1.0,   # "google" in brand list
            "has_redirect":   0.0,
            "has_port":       0.0,
        },
    ),
    (
        "http://192.168.1.1/login/verify",
        "IP-based URL + login keywords",
        {
            "no_https":    1.0,
            "has_ip":      1.0,
            "has_login_kw": 1.0,
            "has_port":    0.0,
        },
    ),
    (
        "http://paypa1-secure-login.xyz/account/verify?redirect=http://evil.com",
        "Full phishing — brand spoof + suspicious TLD + redirect param",
        {
            "no_https":       1.0,
            "suspicious_tld": 1.0,
            "has_login_kw":   1.0,
            "has_redirect":   1.0,
            "has_ip":         0.0,
        },
    ),
    (
        "https://secure.paypal.com",
        "Legitimate PayPal — brand keyword in safe context",
        {
            "no_https":       0.0,
            "suspicious_tld": 0.0,
            "has_brand_kw":   1.0,
            "has_ip":         0.0,
            "has_port":       0.0,
        },
    ),
    (
        "http://microsoft-account.pw:8080/signin",
        "Port + suspicious TLD + brand spoof + login keyword",
        {
            "no_https":       1.0,
            "suspicious_tld": 1.0,
            "has_brand_kw":   1.0,
            "has_login_kw":   1.0,
            "has_port":       1.0,
        },
    ),
    (
        "https://apple.com.account-suspended.tk/id/signin",
        "Subdomain spoofing — apple.com as subdomain of .tk",
        {
            "no_https":       0.0,
            "suspicious_tld": 1.0,
            "has_brand_kw":   1.0,
            "has_login_kw":   1.0,
        },
    ),
    (
        "https://github.com/torvalds/linux",
        "Clean developer URL — should score very low",
        {
            "no_https":       0.0,
            "has_ip":         0.0,
            "suspicious_tld": 0.0,
            "has_login_kw":   0.0,
            "has_redirect":   0.0,
            "has_port":       0.0,
        },
    ),
    (
        "http://xk3j9qzm2p.gq/a/b/c?next=http://evil.com",
        "DGA domain + suspicious TLD + redirect param",
        {
            "no_https":       1.0,
            "suspicious_tld": 1.0,
            "has_redirect":   1.0,
            "has_ip":         0.0,
        },
    ),
]

# ─── Feature name → URLFeatureVector attribute map ────────────────────────────

def get_feature_value(vec: URLFeatureVector, name: str) -> float:
    return float(getattr(vec, name))


# ─── Test runner ──────────────────────────────────────────────────────────────

def run_tests(verbose: bool = False) -> bool:
    passed = 0
    failed = 0
    total_checks = 0

    print("\n  PhishGuard — Feature Parity Test Suite")
    print("  " + "─" * 52)

    for url, description, expected in TEST_CASES:
        try:
            vec: URLFeatureVector = extract(url)
        except Exception as e:
            failed += 1
            print(f"\n  ✗ ERROR  {description}")
            print(f"    Exception during extract(): {e}")
            continue

        case_errors = []
        for feat_name, expected_val in expected.items():
            try:
                actual_val = get_feature_value(vec, feat_name)
            except AttributeError:
                case_errors.append(f"    {feat_name}: attribute not found on URLFeatureVector")
                continue

            if abs(actual_val - float(expected_val)) > EPSILON:
                case_errors.append(
                    f"    {feat_name:22s} expected={expected_val:.4f}  got={actual_val:.6f}  "
                    f"diff={abs(actual_val - expected_val):.6f}"
                )

        total_checks += len(expected)

        if case_errors:
            failed += 1
            print(f"\n  ✗ FAIL   {description}")
            print(f"    URL: {url[:72]}")
            for err in case_errors:
                print(err)
        else:
            passed += 1
            if verbose:
                print(f"  ✓ PASS   {description}")

    # ── Summary ───────────────────────────────────────────────
    total = passed + failed
    print(f"\n  {'─' * 52}")
    print(f"  Tests:  {passed}/{total} passed  |  Checks: {total_checks}")

    if failed == 0:
        print(
            "\n  ✓ All parity tests passed.\n"
            "    Python feature-extractor matches TypeScript expectations.\n"
            "    Safe to train.\n"
        )
        return True
    else:
        print(textwrap.dedent(f"""
  ✗ {failed} test(s) FAILED — PARITY VIOLATION DETECTED
  ─────────────────────────────────────────────────────────────
  The Python extractor produced different values than expected.

  This means the model will be trained on different feature
  distributions than it receives during browser inference.

  Fix steps:
    1. Compare features.py and feature-extractor.ts side by side
    2. Fix the divergence (keep both in sync)
    3. Re-run this test until all pass
    4. Then run: python training/train.py
        """))
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard Feature Parity Tests")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show result for every test case, not just failures")
    args = parser.parse_args()

    success = run_tests(verbose=args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()