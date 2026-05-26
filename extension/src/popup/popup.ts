/**
 * PhishGuard — Popup Entry Point (vanilla TypeScript)
 * 
 * Handles the popup UI without React dependency.
 * Communicates with background service worker via Chrome messaging.
 * 
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { ScanState, ChromeMessage, ThreatLevel } from "../types";

// ─── Threat display config ────────────────────────────────────────────────────

const THREAT_META: Record<ThreatLevel, { label: string; color: string; desc: string }> = {
  safe:     { label: "Safe",              color: "#22c55e", desc: "No phishing indicators detected." },
  low:      { label: "Low Risk",          color: "#eab308", desc: "Minor suspicious signals. Proceed with caution." },
  medium:   { label: "Suspicious",        color: "#f97316", desc: "Multiple phishing indicators detected." },
  high:     { label: "High Risk",         color: "#ef4444", desc: "Strong phishing signals. Do not enter credentials." },
  critical: { label: "Phishing Detected", color: "#dc2626", desc: "Matches known phishing patterns. Leave immediately." },
};

// ─── DOM helpers ──────────────────────────────────────────────────────────────

function $(id: string): HTMLElement | null {
  return document.getElementById(id);
}

// ─── State ────────────────────────────────────────────────────────────────────

let currentURL: string | null = null;
let pollInterval: ReturnType<typeof setInterval> | null = null;

// ─── Chrome messaging ─────────────────────────────────────────────────────────

function sendMessage<T>(message: ChromeMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response: T) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

// ─── Render functions ─────────────────────────────────────────────────────────

function showScanning(): void {
  const content = $("content");
  if (!content) return;
  content.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;gap:16px;padding:32px 20px;">
      <div id="pulse" style="
        width:48px;height:48px;border-radius:50%;
        border:2px solid #6366f1;
        animation:pulse 1.2s ease-in-out infinite;
      "></div>
      <div style="text-align:center;">
        <p style="color:#f0f2f5;font-size:13px;font-weight:500;margin:0;">Analyzing URL</p>
        <p style="color:#4d5566;font-size:11px;margin:4px 0 0;">Running local ML inference…</p>
      </div>
    </div>
  `;
}

function showIdle(): void {
  const content = $("content");
  if (!content) return;
  content.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;text-align:center;gap:12px;padding:32px 24px;">
      <div style="font-size:36px;">🛡</div>
      <div>
        <p style="color:#f0f2f5;font-size:14px;font-weight:600;margin:0;">Ready to protect you</p>
        <p style="color:#8892a4;font-size:12px;margin:8px 0 0;line-height:1.5;">
          Navigate to a page and PhishGuard<br>will automatically scan it.
        </p>
      </div>
      <button id="manualScanBtn" style="
        margin-top:4px;padding:8px 20px;
        background:#6366f1;color:#fff;border:none;
        border-radius:7px;font-size:12px;font-weight:500;
        cursor:pointer;
      ">Scan current page</button>
    </div>
  `;
  $("manualScanBtn")?.addEventListener("click", triggerScan);
}

function showError(message: string): void {
  const content = $("content");
  if (!content) return;
  content.innerHTML = `
    <div style="margin:0 16px;padding:16px;border-radius:12px;
      background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.20);">
      <p style="color:#f87171;font-size:13px;font-weight:600;margin:0 0 6px;">Scan failed</p>
      <p style="color:#8892a4;font-size:11px;margin:0 0 10px;">${message}</p>
      <button id="retryBtn" style="
        padding:5px 14px;background:rgba(239,68,68,0.15);
        color:#f87171;border:1px solid rgba(239,68,68,0.25);
        border-radius:6px;font-size:11px;cursor:pointer;
      ">Try again</button>
    </div>
  `;
  $("retryBtn")?.addEventListener("click", triggerScan);
}

function showResult(state: ScanState): void {
  if (!state.result) return;
  const result = state.result;
  const meta   = THREAT_META[result.level];
  const content = $("content");
  if (!content) content;

  // Arc math
  const R    = 38;
  const CIRC = 2 * Math.PI * R;
  const offset = CIRC * (1 - Math.min(result.probability, 1));

  // Indicators HTML
  const indicatorsHTML = result.indicators.length > 0 ? `
    <div style="margin:12px 16px 0;">
      <p style="font-size:10px;font-weight:600;text-transform:uppercase;
        letter-spacing:0.09em;color:#4d5566;margin:0 0 8px;">
        Threat Indicators (${result.indicators.length})
      </p>
      ${result.indicators.map(ind => {
        const dotColor = ind.severity === "danger" ? "#ef4444"
                       : ind.severity === "warning" ? "#f97316" : "#3b82f6";
        return `
          <div class="indicator" data-desc="${encodeURIComponent(ind.description)}"
            style="display:flex;align-items:flex-start;gap:8px;
              background:#161923;border:1px solid rgba(255,255,255,0.07);
              border-radius:7px;padding:8px 10px;margin-bottom:4px;cursor:pointer;">
            <span style="width:6px;height:6px;border-radius:50%;
              background:${dotColor};margin-top:4px;flex-shrink:0;display:block;"></span>
            <div>
              <div style="font-size:12px;font-weight:500;color:#f0f2f5;">${ind.label}</div>
              <div class="ind-desc" style="display:none;font-size:11px;color:#8892a4;
                margin-top:4px;line-height:1.5;">${ind.description}</div>
            </div>
          </div>
        `;
      }).join("")}
    </div>
  ` : "";

  const criticalBanner = result.level === "critical" ? `
    <div style="margin-top:12px;display:flex;align-items:center;gap:8px;
      padding:8px 12px;border-radius:8px;
      background:rgba(220,38,38,0.12);border:1px solid rgba(220,38,38,0.30);">
      <span style="font-size:14px;">⚠</span>
      <span style="font-size:11px;font-weight:500;color:#fca5a5;">
        Do not enter any personal information on this page.
      </span>
    </div>
  ` : "";

  (content as HTMLElement).innerHTML = `
    <div style="margin:0 16px;background:#161923;border:1px solid ${
      result.level !== "safe" ? meta.color + "55" : "rgba(255,255,255,0.07)"
    };border-radius:12px;padding:20px;
    background:${result.level !== "safe"
      ? `linear-gradient(135deg,#161923 0%,${meta.color}15 100%)`
      : "#161923"};">

      <!-- Arc meter -->
      <div style="display:flex;justify-content:center;margin-bottom:16px;">
        <div style="position:relative;display:flex;align-items:center;justify-content:center;">
          <svg width="96" height="96" viewBox="0 0 96 96"
            style="transform:rotate(-90deg);">
            <circle cx="48" cy="48" r="${R}"
              fill="none" stroke="#1d2130" stroke-width="6" stroke-linecap="round"/>
            <circle id="meterArc" cx="48" cy="48" r="${R}"
              fill="none" stroke="${meta.color}" stroke-width="6" stroke-linecap="round"
              stroke-dasharray="${CIRC}"
              stroke-dashoffset="${CIRC}"
              style="transition:stroke-dashoffset 0.9s cubic-bezier(0.34,1.56,0.64,1);"/>
          </svg>
          <div style="position:absolute;text-align:center;">
            <div style="font-size:24px;font-weight:700;color:${meta.color};
              letter-spacing:-0.04em;line-height:1;">${result.confidence}</div>
            <div style="font-size:10px;color:#4d5566;text-transform:uppercase;
              letter-spacing:0.08em;margin-top:2px;">risk %</div>
          </div>
        </div>
      </div>

      <!-- Badge -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <div style="display:flex;align-items:center;gap:7px;">
          <span style="width:7px;height:7px;border-radius:50%;
            background:${meta.color};box-shadow:0 0 6px ${meta.color};
            display:inline-block;"></span>
          <span style="font-size:13px;font-weight:600;color:${meta.color};">${meta.label}</span>
        </div>
        <span style="font-size:10px;color:#4d5566;">${result.scanDurationMs}ms · local</span>
      </div>

      <p style="font-size:12px;color:#8892a4;margin:0;line-height:1.55;">${meta.desc}</p>
      ${criticalBanner}
    </div>
    ${indicatorsHTML}
  `;

  // Animate arc after DOM paint
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const arc = document.getElementById("meterArc");
      if (arc) arc.setAttribute("stroke-dashoffset", String(offset));
    });
  });

  // Indicator expand/collapse
  document.querySelectorAll<HTMLElement>(".indicator").forEach(el => {
    el.addEventListener("click", () => {
      const desc = el.querySelector<HTMLElement>(".ind-desc");
      if (desc) {
        desc.style.display = desc.style.display === "block" ? "none" : "block";
      }
    });
  });
}

// ─── Scan logic ───────────────────────────────────────────────────────────────

async function triggerScan(): Promise<void> {
  if (!currentURL) return;
  stopPolling();
  showScanning();
  try {
    await sendMessage<void>({ type: "SCAN_URL", payload: { url: currentURL } });
    startPolling();
  } catch (err) {
    showError(err instanceof Error ? err.message : "Scan failed");
  }
}

function startPolling(): void {
  stopPolling();
  pollInterval = setInterval(async () => {
    try {
      const state = await sendMessage<ScanState | null>({ type: "GET_CURRENT_SCAN" });
      if (state && state.status !== "scanning") {
        stopPolling();
        if (state.status === "done" && state.result) {
          showResult(state);
        } else if (state.status === "error") {
          showError(state.error ?? "Unknown error");
        }
      }
    } catch {
      stopPolling();
    }
  }, 250);
}

function stopPolling(): void {
  if (pollInterval !== null) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

// ─── URL bar ──────────────────────────────────────────────────────────────────

function updateURLBar(url: string): void {
  const urlEl   = $("urlText") as HTMLElement;
  const protoEl = $("urlProto") as HTMLElement;
  if (!urlEl || !protoEl) return;

  try {
    const parsed = new URL(url);
    urlEl.textContent   = parsed.hostname;
    protoEl.textContent = parsed.protocol === "https:" ? "HTTPS" : "HTTP";
    protoEl.style.background = parsed.protocol === "https:"
      ? "rgba(34,197,94,0.12)" : "rgba(239,68,68,0.12)";
    protoEl.style.color = parsed.protocol === "https:" ? "#4ade80" : "#f87171";
  } catch {
    urlEl.textContent = url.slice(0, 40);
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init(): Promise<void> {
  // Get current tab
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab  = tabs[0];
  if (tab?.url) {
    currentURL = tab.url;
    updateURLBar(tab.url);
  }

  // Check for existing scan result
  try {
    const state = await sendMessage<ScanState | null>({ type: "GET_CURRENT_SCAN" });
    if (state?.status === "done" && state.result) {
      showResult(state);
    } else if (state?.status === "scanning") {
      showScanning();
      startPolling();
    } else {
      showIdle();
    }
  } catch {
    showIdle();
  }
}

// ─── Event listeners ──────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  init().catch(console.error);

  $("scanBtn")?.addEventListener("click", triggerScan);
  $("refreshBtn")?.addEventListener("click", triggerScan);
  $("settingsBtn")?.addEventListener("click", () => chrome.runtime.openOptionsPage());
});