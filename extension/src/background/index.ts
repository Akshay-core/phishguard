/**
 * PhishGuard — Background Service Worker
 *
 * Runs persistently in the background.
 * Listens for tab URL changes, triggers scans, stores results.
 *
 * Manifest V3 constraint: service workers are short-lived.
 * All state must be in chrome.storage, not module-level variables.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { initModel } from "../lib/onnx-runner";
import { scanURL } from "../lib/risk-engine";
import { ChromeMessage, ScanState, DEFAULT_SETTINGS } from "../types";

// Pre-initialize the model on service worker startup to reduce first-scan latency
initModel().catch((err) => console.error("[PhishGuard] Model init failed:", err));

// ─── Tab Navigation Listener ─────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only scan on fully committed navigations — ignore partial loads
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !isScannableURL(tab.url)) return;

  const settings = await getSettings();
  if (!settings.enableAutoScan) return;

  await performScan(tabId, tab.url);
});

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (message: ChromeMessage, sender, sendResponse) => {
    handleMessage(message, sendResponse);
    return true; // Keep the message channel open for async response
  }
);

async function handleMessage(
  message: ChromeMessage,
  sendResponse: (response: unknown) => void
) {
  switch (message.type) {
    case "SCAN_URL": {
      const { url } = message.payload as { url: string };
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tabId = tabs[0]?.id;
      if (!tabId) return;
      await performScan(tabId, url);
      sendResponse({ success: true });
      break;
    }

    case "GET_CURRENT_SCAN": {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tabId = tabs[0]?.id;
      if (!tabId) { sendResponse(null); return; }
      const state = await getScanState(tabId);
      sendResponse(state);
      break;
    }

    case "CLEAR_SCAN": {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tabId = tabs[0]?.id;
      if (tabId) await clearScanState(tabId);
      sendResponse({ success: true });
      break;
    }
  }
}

// ─── Scan Pipeline ────────────────────────────────────────────────────────────

async function performScan(tabId: number, url: string): Promise<void> {
  // Set scanning state
  await setScanState(tabId, {
    status: "scanning",
    url,
    result: null,
    error: null,
    timestamp: Date.now(),
  });

  // Update badge to indicate scanning
  await chrome.action.setBadgeText({ text: "…", tabId });
  await chrome.action.setBadgeBackgroundColor({ color: "#6B7280", tabId });

  try {
    const result = await scanURL(url);

    await setScanState(tabId, {
      status: "done",
      url,
      result,
      error: null,
      timestamp: Date.now(),
    });

    // Update badge based on threat level
    const badgeConfig = getBadgeConfig(result.level);
    await chrome.action.setBadgeText({ text: badgeConfig.text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: badgeConfig.color, tabId });

    // Show browser notification for high/critical threats
    if (result.level === "high" || result.level === "critical") {
      await showThreatNotification(url, result.level);
    }
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : "Unknown error";
    await setScanState(tabId, {
      status: "error",
      url,
      result: null,
      error: errorMessage,
      timestamp: Date.now(),
    });

    await chrome.action.setBadgeText({ text: "!", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#6B7280", tabId });

    console.error("[PhishGuard] Scan failed:", errorMessage);
  }
}

// ─── Storage Helpers ──────────────────────────────────────────────────────────

const SCAN_KEY = (tabId: number) => `scan:${tabId}`;

async function getScanState(tabId: number): Promise<ScanState | null> {
  const result = await chrome.storage.session.get(SCAN_KEY(tabId));
  return result[SCAN_KEY(tabId)] ?? null;
}

async function setScanState(tabId: number, state: ScanState): Promise<void> {
  await chrome.storage.session.set({ [SCAN_KEY(tabId)]: state });
}

async function clearScanState(tabId: number): Promise<void> {
  await chrome.storage.session.remove(SCAN_KEY(tabId));
}

async function getSettings() {
  const result = await chrome.storage.sync.get("settings");
  return { ...DEFAULT_SETTINGS, ...(result.settings ?? {}) };
}

// ─── Badge Config ─────────────────────────────────────────────────────────────

function getBadgeConfig(level: string) {
  switch (level) {
    case "safe":     return { text: "✓",  color: "#16a34a" };
    case "low":      return { text: "!",  color: "#ca8a04" };
    case "medium":   return { text: "!",  color: "#ea580c" };
    case "high":     return { text: "✕",  color: "#dc2626" };
    case "critical": return { text: "✕",  color: "#991b1b" };
    default:         return { text: "?",  color: "#6b7280" };
  }
}

// ─── Notifications ────────────────────────────────────────────────────────────

async function showThreatNotification(url: string, level: string): Promise<void> {
  const domain = new URL(url).hostname;
  await chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon-48.png"),
    title: `⚠ PhishGuard: ${level === "critical" ? "Phishing Detected" : "High Risk Site"}`,
    message: `${domain} has suspicious phishing characteristics. Do not enter passwords.`,
    priority: 2,
  });
}

// ─── URL Filter ───────────────────────────────────────────────────────────────

/**
 * Only scan HTTP/HTTPS pages. Skip chrome://, about:, extension pages, etc.
 */
function isScannableURL(url: string): boolean {
  return url.startsWith("http://") || url.startsWith("https://");
}
