# PhishGuard

PhishGuard is a local-first, privacy-focused phishing detection browser extension.
It runs URL feature extraction and ONNX inference in the browser, with optional
threat-intelligence checks through a self-hosted backend.

## What It Does Now

- Scans HTTP/HTTPS URLs locally in the browser extension.
- Extracts URL risk features such as HTTPS state, IP hosts, suspicious TLDs,
  redirect parameters, entropy, path depth, brand keywords, and unusual ports.
- Runs an ONNX phishing model through WebAssembly.
- Applies contextual rules so one weak signal does not automatically become
  "high risk".
- Uses local trusted-domain intelligence for sites such as Google, GitHub,
  Microsoft, Apple, PayPal, Cloudflare, and others.
- Understands trusted subdomains, so `mail.google.com` is treated differently
  from `google.login-security.example`.
- Provides a local investigation API for redirect tracing, DNS/TLS inspection,
  HTML/JavaScript behavior heuristics, IOC extraction, favicon hashing,
  timeline generation, threat graph generation, and multi-signal scoring.

## Accuracy Fixes Added

- User-entered domains without a scheme are normalized as HTTPS instead of being
  treated as malformed and maximally suspicious.
- Trusted registrable domains cap weak model false positives unless dangerous
  signals are also present.
- Brand detection now separates real brand-owned domains from impersonation.
- GitHub, GitLab, iCloud, Office365, and Cloudflare are included in brand
  spoofing detection.
- TypeScript and Python feature extraction remain aligned for model training.

## Free Local-First Roadmap

1. Add a local SQLite reputation cache for scan history, feed hits, and domain
   reputation evolution.
2. Add downloadable feeds from URLHaus, PhishTank, and OpenPhish so checks can
   work offline after sync.
3. Add DNS and TLS analysis: certificate issuer, SAN mismatch, expiry, CAA, MX,
   NS, and ASN signals.
4. Add WHOIS/domain-age lookup in the backend and feed that into the existing
   `domainAge` feature.
5. Add Playwright deep scan mode for redirects, forced downloads, fake login
   flows, notification abuse, and suspicious JavaScript behavior.
6. Add YARA rules for phishing kits and malicious JavaScript patterns.
7. Add screenshot/OCR brand impersonation checks with Tesseract, OpenCV, and
   perceptual hashing.

For the full security-research roadmap, see
[docs/advanced-roadmap.md](docs/advanced-roadmap.md). It includes redirect
chain tracing, ASN reputation, passive DNS, JavaScript deobfuscation, sandbox
behavior monitoring, OCR, logo detection, threat graphs, IOC extraction, local
LLM explanations, DNS sinkhole mode, and malware payload inspection.

## Development

```bash
cd extension
npm install
npm run build
```

Run the local backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Run a full local URL investigation:

```bash
curl "http://127.0.0.1:8000/api/v1/investigate/url?url=https://example.com"
```

Feature parity check:

```bash
python scripts/test_feature_parity.py
```

On Windows terminals that do not use UTF-8 by default:

```powershell
$env:PYTHONIOENCODING='utf-8'; python scripts\test_feature_parity.py
```
