/**
 * PhishGuard — Content Script
 *
 * Runs in the context of every web page (all_frames: false).
 * Responsibilities:
 *  1. Detect form submissions that might be credential harvesting
 *  2. Inject a subtle warning banner for high/critical threats
 *  3. Monitor dynamic URL changes (SPAs that use history.pushState)
 *
 * Security notes:
 * - Never reads form field values (privacy-preserving)
 * - Only inspects form presence + input types
 * - Banner is injected with isolated styles (Shadow DOM)
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { ChromeMessage, ThreatScore, ThreatLevel } from "../types";

// Track whether we've already shown a warning on this page
let warningShown = false;
let lastURL = location.href;

// ─── Listen for messages from background ─────────────────────

chrome.runtime.onMessage.addListener((message: ChromeMessage) => {
  if (message.type === "SCAN_RESULT") {
    const payload = message.payload as { result: ThreatScore };
    handleScanResult(payload.result);
  }
});

// ─── SPA navigation detection ─────────────────────────────────
// Intercept history.pushState to detect URL changes in React/Vue/Next apps

const originalPushState = history.pushState.bind(history);
history.pushState = (...args) => {
  originalPushState(...args);
  if (location.href !== lastURL) {
    lastURL = location.href;
    warningShown = false;
    removeBanner();
    notifyBackgroundOfNavigation();
  }
};

window.addEventListener("popstate", () => {
  if (location.href !== lastURL) {
    lastURL = location.href;
    warningShown = false;
    removeBanner();
    notifyBackgroundOfNavigation();
  }
});

function notifyBackgroundOfNavigation() {
  chrome.runtime.sendMessage<ChromeMessage>({
    type: "SCAN_URL",
    payload: { url: location.href },
  }).catch(() => {
    // Background may not be ready yet — ignore
  });
}

// ─── Threat Response ──────────────────────────────────────────

function handleScanResult(result: ThreatScore) {
  if (result.level === "high" || result.level === "critical") {
    if (!warningShown) {
      warningShown = true;
      injectWarningBanner(result);
      highlightPasswordFields();
    }
  }
}

// ─── Warning Banner (Shadow DOM isolated) ────────────────────

function injectWarningBanner(result: ThreatScore) {
  if (document.getElementById("phishguard-banner-host")) return;

  const host = document.createElement("div");
  host.id = "phishguard-banner-host";
  host.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 2147483647;
    pointer-events: auto;
  `;

  // Shadow DOM prevents page styles from leaking into our banner
  const shadow = host.attachShadow({ mode: "closed" });

  const isCritical = result.level === "critical";
  const bgColor = isCritical ? "#7f1d1d" : "#7c2d12";
  const borderColor = isCritical ? "#dc2626" : "#ea580c";
  const label = isCritical ? "⚠ Phishing Detected" : "⚠ High Risk Site";

  shadow.innerHTML = `
    <style>
      :host { display: block; }
      .banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 16px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        font-size: 13px;
        background: ${bgColor};
        border-bottom: 2px solid ${borderColor};
        color: #fef2f2;
        line-height: 1.4;
      }
      .left { display: flex; align-items: center; gap: 10px; }
      .icon { font-size: 18px; flex-shrink: 0; }
      .title { font-weight: 600; font-size: 13px; }
      .desc  { font-size: 11px; opacity: 0.8; margin-top: 1px; }
      .dismiss {
        flex-shrink: 0;
        background: rgba(255,255,255,0.12);
        border: 1px solid rgba(255,255,255,0.20);
        color: #fef2f2;
        border-radius: 5px;
        padding: 4px 10px;
        font-size: 11px;
        cursor: pointer;
        font-family: inherit;
      }
      .dismiss:hover { background: rgba(255,255,255,0.20); }
    </style>
    <div class="banner" role="alert" aria-live="assertive">
      <div class="left">
        <span class="icon" aria-hidden="true">🛡</span>
        <div>
          <div class="title">PhishGuard: ${label}</div>
          <div class="desc">Do not enter passwords or personal information · ${result.confidence}% phishing probability</div>
        </div>
      </div>
      <button class="dismiss" id="dismiss">Dismiss</button>
    </div>
  `;

  shadow.getElementById("dismiss")?.addEventListener("click", () => {
    host.remove();
  });

  document.documentElement.insertBefore(host, document.documentElement.firstChild);

  // Shift page content down to avoid overlap
  document.documentElement.style.marginTop = "46px";
}

function removeBanner() {
  const host = document.getElementById("phishguard-banner-host");
  if (host) {
    host.remove();
    document.documentElement.style.marginTop = "";
  }
}

// ─── Password Field Highlighting ─────────────────────────────

function highlightPasswordFields() {
  const passwordInputs = document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]'
  );

  passwordInputs.forEach((input) => {
    input.style.outline = "2px solid #dc2626";
    input.style.outlineOffset = "2px";
    input.setAttribute("data-phishguard-warned", "true");

    // Add warning tooltip on focus
    input.addEventListener("focus", () => {
      input.title = "⚠ PhishGuard: This page may be a phishing site. Do not enter your password.";
    }, { once: true });
  });
}
