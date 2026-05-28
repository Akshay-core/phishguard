# Advanced Security Platform Roadmap

This roadmap collects high-impact features that can turn PhishGuard from a URL
checker into a local security research platform. The priority is free,
open-source, privacy-first tooling that can run locally.

## Network And Internet Layer

### 1. Live Redirect Chain Tracing

Status: first local implementation exists in `backend/app/services/investigation.py`.

Trace every server, meta, and JavaScript redirect:

```text
site -> shortener -> fake captcha -> phishing page
```

Detection goals:

- Hidden redirects
- JavaScript redirects
- Meta refresh redirects
- Cloaking behavior

Suggested stack: Playwright, request interception, response headers, DOM event
hooks.

### 2. ASN And Hosting Reputation

Analyze the resolved IP owner and hosting provider.

Useful signals:

- Suspicious VPS providers
- Known abuse-heavy ASNs
- Bulletproof hosting indicators
- Repeated malicious domains on the same ASN

Suggested stack: `ipwhois`, MaxMind GeoLite2 ASN database, local ASN reputation
tables.

### 3. Passive DNS History

Track historical domain-to-IP and IP-to-domain relationships.

Useful signals:

- Many unrelated domains sharing one IP
- IP reuse by phishing kits
- Domains moving quickly between IPs

Suggested stack: local passive DNS cache, SecurityTrails optional API, SQLite.

### 4. DNS Record Anomaly Detection

Status: first local DNS/IP resolution and fast-flux heuristic implemented.

Analyze DNS records beyond basic A/AAAA lookups.

Useful signals:

- Strange MX records
- Suspicious TXT records
- Fast-flux DNS
- Rapidly rotating IPs
- Very low TTL values

Suggested stack: `dnspython`, local DNS history store.

### 5. Browser Fingerprinting Detection

Status: static JavaScript fingerprinting references are detected. Runtime API
hooking requires the optional Playwright sandbox.

Detect pages that try to identify bots, sandboxes, or victims.

Monitor:

- Canvas fingerprinting
- WebGL probing
- Audio fingerprinting
- Navigator and screen leaks
- Timezone and locale probing

Suggested stack: Playwright init scripts that hook browser APIs.

## Malware Analysis Layer

### 6. JavaScript Deobfuscation Engine

Status: first local heuristic implementation detects `eval()`, `atob()`, large
Base64 blobs, runtime API references, and suspicious script patterns.

Detect and unpack suspicious JavaScript.

Useful signals:

- Packed scripts
- `eval()` chains
- `atob()` payloads
- String-array obfuscation
- Hidden URLs
- Crypto payloads

Suggested stack: `jsbeautifier`, Esprima/Acorn AST parsing, YARA.

### 7. DOM Mutation Monitoring

Watch the page after load for delayed phishing behavior.

Useful signals:

- Late login form injection
- Hidden field creation
- Iframe insertion
- Script-injected overlays

Suggested stack: `MutationObserver` injected through Playwright.

### 8. WebSocket Abuse Detection

Status: static WebSocket references are detected. Runtime network capture is a
future Playwright/proxy feature.

Track hidden live command channels.

Useful signals:

- Unexpected WebSocket endpoints
- Long-lived hidden connections
- Suspicious binary messages
- Connections to unrelated domains

Suggested stack: hook `WebSocket`, browser devtools protocol network events.

### 9. Download Payload Inspection

Analyze files pushed by suspicious pages.

Targets:

- EXE
- APK
- ZIP
- JavaScript
- Office documents
- Macro-enabled files

Suggested stack: hash calculation, entropy checks, YARA, `pefile`,
`python-magic`.

### 10. Macro Malware Detection

Inspect Office documents for embedded scripts.

Useful signals:

- VBA macros
- Auto-open behavior
- Powershell launch commands
- Embedded URLs

Suggested stack: `oletools`, YARA.

## Visual And Human Impersonation

### 11. Logo Detection

Detect brand logos on domains that do not belong to the brand.

Example:

```text
Microsoft logo + non-microsoft.com domain = strong phishing signal
```

Suggested stack: OpenCV, perceptual hashing, template matching.

### 12. Fake Login Page Detection

Status: first implementation detects password fields, forms, brand mentions,
and brand/domain mismatches.

Analyze credential forms and cloned login flows.

Useful signals:

- Password fields
- Fake OAuth prompts
- Copied brand styling
- Seed phrase fields
- Hidden credential exfiltration endpoints

### 13. OCR And Semantic Analysis

Extract text from screenshots and score scam language.

Useful phrases:

- "verify account"
- "account suspended"
- "wallet expired"
- "security alert"
- "press Win+R"

Suggested stack: Tesseract OCR, lightweight NLP classifier.

### 14. Visual Similarity Engine

Compare screenshots against trusted site baselines.

Example:

```text
fake-github-login.example looks 95 percent like GitHub login
```

Suggested stack: perceptual hashing, OpenCV, SSIM.

## Advanced URL Analysis

### 15. Homograph Attack Detection

Status: first local implementation detects punycode and mixed Unicode scripts.

Detect lookalike Unicode domains.

Example:

```text
gοοgle.com
```

The visible characters look like Google, but the `o` characters can be from
another alphabet.

Suggested stack: punycode decoding, Unicode script checks, confusable character
mapping.

### 16. URL Intent Classification

Classify what a URL is trying to be.

Classes:

- Login portal
- Banking page
- Crypto wallet page
- Tech support scam
- Giveaway scam
- Fake update page

Suggested stack: local ML or small local LLM.

### 17. Typosquatting Intelligence

Status: first local implementation uses Levenshtein distance against protected
brand domains.

Detect domains close to protected brands.

Examples:

- `paypaI.com`
- `micros0ft-login.example`
- `githb.com`

Suggested stack: Levenshtein distance, keyboard-neighbor distance, homoglyph
normalization.

## Behavioral Analysis

### 18. User Interaction Trap Detection

Detect pages that attempt to trap users.

Useful signals:

- Disabled back button
- Infinite popups
- Fullscreen lock
- Forced clicks
- Fake browser alerts

### 19. Clipboard Hijacking Detection

Status: static clipboard API references are detected. Runtime clipboard write
monitoring requires the optional browser sandbox.

Detect scripts that read or overwrite clipboard contents.

Important for crypto scams where wallet addresses are replaced silently.

### 20. Crypto Wallet Scam Detection

Status: first local implementation detects seed phrase, wallet connect, airdrop,
and wallet address indicators.

Detect modern web3 phishing.

Useful signals:

- Fake wallet connect flows
- Drainer scripts
- Fake airdrops
- Seed phrase forms
- Suspicious contract approval prompts

### 21. Browser Notification Abuse

Status: first local implementation detects notification permission references
and notification scam wording.

Detect deceptive push-notification prompts and fake allow screens.

## Threat Intelligence

### 22. Local Threat Graph Database

Status: first SQLite history and per-report graph generation implemented.

Build relationships between infrastructure objects:

```text
domain <-> IP <-> ASN <-> certificate <-> favicon <-> phishing kit
```

Suggested stack: SQLite first, Neo4j later for advanced graph exploration.

### 23. Campaign Clustering

Group related phishing pages into campaigns.

Useful shared signals:

- Favicon hash
- JavaScript hash
- HTML structure
- Hosting ASN
- Certificate fields
- Redirect pattern

### 24. IOC Extraction

Status: first local implementation extracts URLs, domains, IPs, emails, and
crypto wallet addresses.

Automatically extract indicators of compromise.

Targets:

- URLs
- Domains
- IPs
- File hashes
- Emails
- Wallet addresses

### 25. MITRE ATT&CK Mapping

Map observed behavior to MITRE ATT&CK techniques for professional reports.

## AI And ML Features

### 26. AI Risk Explanation

Generate clear explanations:

```text
Detected fake Microsoft branding, obfuscated JavaScript, a credential form,
and a redirect chain ending on a newly observed domain.
```

### 27. Local LLM Security Analyst

Run an offline assistant for summarizing investigations and generating reports.

Suggested stack: Ollama, llama.cpp, Mistral-family local models.

### 28. AI HTML Understanding

Use local models to classify page intent, scam psychology, brand impersonation,
and suspicious form behavior.

## Browser-Level Features

### 29. Browser Extension Protection

Continue improving realtime browser protection:

- Scan current tab
- Warn before password entry
- Highlight suspicious URLs
- Show local explanations

### 30. DNS Sinkhole Mode

Block known malicious domains locally by resolving them to `127.0.0.1`.

### 31. Local Proxy Interceptor

Add a local proxy for request and response inspection, similar to a tiny
defensive Burp Suite.

### 32. Packet Capture Analysis

Analyze outbound traffic for command-and-control or exfiltration patterns.

Suggested stack: Scapy, tshark.

## Malware Sandbox Features

### 33. Disposable Browser Containers

Launch isolated Chromium sessions with temporary profiles for safe analysis.

### 34. Screenshot Timeline Recording

Record a visual timeline:

```text
page load -> redirect -> fake captcha -> phishing form
```

### 35. Runtime API Hooking

Hook dangerous runtime APIs:

- `fetch()`
- `XMLHttpRequest`
- `WebSocket`
- `localStorage`
- Cookie access
- Clipboard access

## Scoring System Ideas

### 36. Confidence Score

Status: implemented in the local investigation report.

Display both risk and confidence:

```text
Risk: 87/100
Confidence: 94%
```

### 37. Multi-Engine Consensus

Status: first implementation combines domain, DNS, TLS, redirect, HTML,
JavaScript, behavior, IOC, favicon, and history signals.

Combine multiple local engines:

- Heuristics
- ML model
- YARA
- Browser behavior engine
- Visual engine
- Threat intel

### 38. Adaptive Scoring

Track false positives and tune weights over time.

## UI Features

### 39. Threat Timeline

Status: first event timeline is generated by the local investigation API.

Show event order:

```text
Domain created -> SSL issued -> redirected -> credential form injected
```

### 40. Attack Graph Visualization

Status: graph data is generated by the API. A visual UI can render the returned
nodes and edges.

Visualize infrastructure:

```text
domain -> IP -> ASN -> certificate -> phishing cluster
```

### 41. Heatmap Risk UI

Split risk into categories:

- Domain risk
- Network risk
- JavaScript risk
- Visual risk
- Behavior risk
- Threat intelligence risk

### 42. One-Click Full Investigation

User enters a URL and PhishGuard automatically runs:

- Screenshot
- Redirect chain
- DNS
- WHOIS
- TLS
- JavaScript scan
- OCR
- Sandbox behavior
- Threat-intel lookup
- IOC extraction

### 43. Offline Intelligence Mode

Download local datasets:

- Phishing feeds
- YARA rules
- ASN reputation
- Favicon hashes
- Brand assets

Then keep scanning without remote lookups.

### 44. Memory And Historical Reputation

Status: first local SQLite scan history implemented.

Track how domains and infrastructure change over time.

Example:

```text
Domain was clean for 2 months, then started serving credential forms.
```

### 45. Fake CAPTCHA Scam Detection

Detect modern fake verification flows.

Useful signals:

- "Press Win+R"
- Clipboard write instructions
- Fake Cloudflare screens
- Hidden script copying commands

### 46. AI Voice Scam Site Detection

Detect tech-support and call-center scam pages.

Useful signals:

- Fake support numbers
- Browser lock screens
- "Your computer is infected" wording
- Audio prompts

### 47. QR Code Scanner

Extract QR codes from pages and analyze the target URLs.

Suggested stack: OpenCV, `pyzbar`.

### 48. Mobile APK Analysis

If a site pushes APK files, inspect:

- Permissions
- Package name
- Signing certificate
- Embedded URLs
- Suspicious services

Suggested stack: Androguard.

### 49. Hidden Iframe Mapping

Status: first local HTML parser detects iframe count and hidden iframe patterns.

Map the full iframe tree and identify hidden or cross-origin frames.

### 50. Favicon Hash Intelligence

Status: first implementation fetches and hashes favicons with SHA-256.

Hash favicons and cluster related phishing kits.

This is a strong OSINT signal because many phishing campaigns reuse the same
favicon across domains.

## Suggested Build Order

1. Redirect chain tracing
2. DNS/TLS/ASN analyzer
3. Local SQLite threat graph
4. Playwright disposable browser sandbox
5. JavaScript deobfuscation and YARA scanning
6. Screenshot OCR and fake-login detection
7. IOC extraction and report generation
8. Attack graph and timeline UI
