# PhishGuard — Architecture

> Author: Akshay | https://akshay.fruvvi.com  
> GitHub: https://github.com/Akshay-core

---

## System Overview

PhishGuard is a **local-first browser extension** for real-time phishing URL detection. The primary design goal is **zero cloud dependency for detection** — the ML model runs entirely in the browser via WebAssembly.

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser Extension (TypeScript + React)                          │
│                                                                   │
│  ┌──────────────┐   URL change    ┌────────────────────────────┐ │
│  │   Browser    │ ──────────────▶ │  Background Service Worker │ │
│  │   (Chrome)   │                 │                            │ │
│  └──────────────┘                 │  1. Extract 15 features    │ │
│                                   │  2. Run ONNX inference     │ │
│  ┌──────────────┐   Scan result   │  3. Apply hard rules       │ │
│  │  Popup UI    │ ◀────────────── │  4. Store result           │ │
│  │  (React)     │                 └────────────────────────────┘ │
│  └──────────────┘                           │                     │
│                                             │ ONNX Runtime Web    │
│  ┌──────────────┐                           │ (WebAssembly)       │
│  │  Content     │   Warning banner          ▼                     │
│  │  Script      │ ◀──────────────  phishguard.onnx (~150KB)      │
│  └──────────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Optional  │ Threat Intel
                    (user      │ hostname only
                    opt-in)   ▼
               ┌─────────────────────────┐
               │  PhishGuard API         │
               │  (FastAPI + Python)     │
               │                         │
               │  URLHaus ──────────────▶│
               │  PhishTank ────────────▶│──▶ ThreatResult
               └─────────────────────────┘
```

---

## Component Deep-Dive

### 1. Background Service Worker

**File:** `extension/src/background/index.ts`

The service worker is the extension's brain. In Manifest V3, service workers are event-driven and short-lived — they are spun up on events and terminated when idle.

**Key design decisions:**
- All persistent state lives in `chrome.storage.session` (not module-level variables), because service workers are terminated and restarted
- Model initialization happens on startup to reduce first-scan latency
- URL filtering prevents wasting inference on `chrome://` or `about:` pages
- Tab-scoped scan state allows multiple tabs to have independent scan results

**Event flow:**
```
chrome.tabs.onUpdated (status: "complete")
  → isScannableURL() guard
  → getSettings() → check enableAutoScan
  → setScanState(tabId, { status: "scanning" })
  → scanURL(url)                          ← feature extraction + ONNX
  → setScanState(tabId, { status: "done", result })
  → chrome.action.setBadgeText()
  → showThreatNotification() if high/critical
```

### 2. Feature Extractor

**Files:** `extension/src/lib/feature-extractor.ts` + `ml/training/features.py`

The feature extractor is the **most critical component** for accuracy. It transforms a raw URL string into a 15-element float vector that the model understands.

**CRITICAL CONTRACT:** The TypeScript and Python implementations must produce identical output for the same input. Any divergence means the model is evaluated on distributions it was never trained on.

**Feature design rationale:**

| # | Feature | Why it matters |
|---|---------|---------------|
| 1 | URL length | Phishing URLs are often long to bury the real domain |
| 2 | Domain length | Legitimate domains are short and memorable |
| 3 | Subdomain count | `login.account.paypal.fake.com` — depth obscures real domain |
| 4 | IP address | `http://192.168.1.1/login` — bypasses domain reputation systems |
| 5 | HTTPS absent | Credential pages without TLS = red flag |
| 6 | Special chars | `@`, `%2F` tricks used to spoof URL appearance |
| 7 | Digit ratio | `paypa1`, `g00gle` — numeric character substitution |
| 8 | Shannon entropy | DGA domains have high randomness: `x3kj9qz.com` |
| 9 | Path depth | `/account/login/verify/update/confirm` — suspicious nesting |
| 10 | Login keywords | `signin`, `verify`, `credential` in URL — social engineering |
| 11 | Brand keywords | `paypal` in `paypal.evil.com` — brand spoofing |
| 12 | Suspicious TLD | `.xyz`, `.tk`, `.pw` — low-cost, frequently abused |
| 13 | Redirect param | `?redirect=http://evil.com` — open redirect chains |
| 14 | Domain age | Newly registered domains are high-risk (proxied via backend) |
| 15 | Non-standard port | `:8080` — avoids network filters |

**Normalization:** All values are mapped to [0, 1] before inference. This is critical for tree-based models and mandatory for neural networks.

### 3. ONNX Runtime Web

**File:** `extension/src/lib/onnx-runner.ts`

ONNX Runtime Web executes the trained model as WebAssembly in the browser tab's JavaScript context.

**Performance characteristics:**
- Model load time: ~50–150ms (one-time, amortized across all scans)
- Inference time: ~2–5ms per URL
- Model size: ~150–300KB (RandomForest with 200 trees)
- Memory footprint: ~5–10MB during inference

**Why WebAssembly?**
- Near-native performance (5–10x faster than equivalent JS)
- Sandboxed execution — cannot access the file system or network
- Same binary runs on all platforms (Windows, Mac, Linux, ARM)

**Singleton pattern:** The session is initialized once and reused. Creating a new session for each URL would be ~10x slower.

### 4. Risk Score Engine

**File:** `extension/src/lib/risk-engine.ts`

Combines probabilistic output (model) with deterministic rules (hard rules) into a final threat level.

**Why hybrid?**
- Pure ML: Can miss obvious patterns if they're underrepresented in training data
- Pure rules: Brittle, high maintenance, low recall
- Hybrid: Rules catch certain obvious cases; ML handles the rest

**Hard rule examples:**
- IP + no HTTPS + login keyword → always `critical`
- Suspicious TLD + brand keyword → elevate by 1 level

**Threshold tuning:** The 5 thresholds (safe/low/medium/high/critical) are intentionally conservative to minimize false positives on legitimate sites. A legitimate site incorrectly flagged is more damaging to user trust than a phishing site that slips through.

### 5. Content Script

**File:** `extension/src/content/index.ts`

Runs in page context. Handles:
- SPA navigation detection (intercepts `history.pushState`)
- Warning banner injection (Shadow DOM isolated — page CSS cannot override it)
- Password field highlighting on high-risk pages

**Shadow DOM isolation rationale:** A regular `<div>` injected into the page can be hidden by page CSS (`display: none`, `z-index: -1`, `opacity: 0`). A Shadow DOM host is immune to external stylesheet rules.

---

## Data Flow: Complete Scan Lifecycle

```
User navigates to http://paypa1-login.xyz/account

1. chrome.tabs.onUpdated fires (status: "complete")
   └─ background/index.ts

2. isScannableURL() → true (starts with http://)

3. setScanState(tabId, { status: "scanning" })
   └─ chrome.storage.session

4. extractFeatures("http://paypa1-login.xyz/account")
   └─ Returns URLFeatures {
       hasHTTPS: false,       → no_https = 1.0
       tldSuspicious: true,   → suspicious_tld = 1.0
       entropyScore: 4.1,     → entropy = 0.68
       hasLoginKeyword: false,
       ...
     }

5. featuresToArray(features) → Float32Array[15]

6. ONNX session.run({ features: tensor })
   └─ Returns { probabilities: [[0.08, 0.92]] }
   └─ phishProbability = 0.92

7. probabilityToLevel(0.92) → "critical"

8. applyHardRules(features, "critical")
   └─ Already "critical" → no override needed

9. getTriggeredIndicators(features)
   └─ Returns [
       { id: "no_https",       label: "No HTTPS encryption",       severity: "warning" },
       { id: "suspicious_tld", label: "Suspicious TLD (.xyz)",      severity: "danger"  },
       { id: "high_entropy",   label: "High URL randomness",        severity: "warning" },
     ]

10. ThreatScore = {
      level: "critical",
      probability: 0.92,
      confidence: 92,
      indicators: [...],
      scanDurationMs: 3
    }

11. setScanState(tabId, { status: "done", result: ThreatScore })

12. chrome.action.setBadgeText({ text: "✕", color: "#991b1b" })

13. chrome.notifications.create({ title: "⚠ Phishing Detected" })

14. chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", payload: result })
    └─ content/index.ts injects warning banner
    └─ Password fields get red outline

15. User clicks extension icon → Popup opens
    → useScan() hook fetches from chrome.storage.session
    → ScanResult renders with ThreatMeter animated to 92%
    → IndicatorList shows 3 expandable indicators
```

---

## Storage Architecture

| Store | Area | TTL | Contents |
|-------|------|-----|----------|
| Scan results | `chrome.storage.session` | Browser session | Per-tab `ScanState` objects |
| User settings | `chrome.storage.sync` | Persistent | `PhishGuardSettings` |
| Threat intel cache | Extension memory | 10min | Hostname → `ThreatIntelResult` |
| Backend cache | Python dict | 1hr | Hostname → `ThreatResult` |

---

## Security Threat Model

**What PhishGuard protects against:**
- URL-based phishing (spoofed domains, homoglyphs)
- DGA (Domain Generation Algorithm) malware domains
- Open-redirect chains
- Brand impersonation via subdomain
- Newly registered malicious domains (via threat intel feed)

**What it does NOT protect against:**
- Compromised legitimate sites (legitimate domain, malicious content)
- Phishing via email attachments (PDF, DOCX)
- Screen-sharing attacks
- Adversarial ML attacks against the ONNX model

**Extension security:**
- No `eval()` or dynamic code execution
- Content Security Policy enforced
- `wasm-unsafe-eval` is required for ONNX Runtime Web — this is a Chrome requirement for WASM, not arbitrary eval
- Model is bundled — no remote code loaded at runtime
- Permissions are minimal: `tabs`, `storage`, `notifications`, `activeTab`

---

## Scalability Considerations

**Current:** Single-user browser extension, no backend required

**If adding backend at scale:**
- Replace in-memory Python dict cache with Redis (TTL-based eviction)
- Add PostgreSQL for storing community threat reports
- Use a job queue (Celery/ARQ) for async PhishTank sync
- Rate limiting per extension ID, not just IP
- Horizontal scaling: FastAPI is stateless, scale with Kubernetes or Railway

**ML model updates:**
- Bundle new ONNX model in extension update
- Alternative: fetch model from CDN on first install, cache in IndexedDB
- Version the model: `phishguard-v2.onnx` — allows A/B testing

---

*Built by Akshay | https://akshay.fruvvi.com | https://github.com/Akshay-core*
