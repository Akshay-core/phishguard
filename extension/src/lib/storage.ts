/**
 * PhishGuard — Typed Chrome Storage Wrapper
 *
 * Why abstract chrome.storage?
 * - chrome.storage API is stringly-typed (any keys, any values)
 * - Direct usage scatters storage concerns across the codebase
 * - This wrapper enforces types, centralizes keys, and handles errors
 * - Makes unit testing trivial (mock this module, not chrome.storage)
 *
 * Two storage areas are used:
 * - chrome.storage.session  → scan results (cleared on browser close)
 * - chrome.storage.sync     → user settings (persisted, synced across devices)
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { PhishGuardSettings, ScanState, DEFAULT_SETTINGS } from "../types";

// ─── Storage key registry ─────────────────────────────────────────────────────
// All keys live here — no magic strings scattered in the codebase

const KEYS = {
  settings:    "phishguard:settings",
  scanPrefix:  "phishguard:scan:",
} as const;

function scanKey(tabId: number): string {
  return `${KEYS.scanPrefix}${tabId}`;
}

// ─── Settings (sync storage) ─────────────────────────────────────────────────

export async function getSettings(): Promise<PhishGuardSettings> {
  try {
    const result = await chrome.storage.sync.get(KEYS.settings);
    const stored = result[KEYS.settings] as Partial<PhishGuardSettings> | undefined;
    // Merge with defaults so new settings fields always have a value
    return { ...DEFAULT_SETTINGS, ...stored };
  } catch (err) {
    console.warn("[PhishGuard] Failed to load settings, using defaults:", err);
    return DEFAULT_SETTINGS;
  }
}

export async function saveSettings(
  settings: Partial<PhishGuardSettings>
): Promise<void> {
  try {
    const current = await getSettings();
    await chrome.storage.sync.set({
      [KEYS.settings]: { ...current, ...settings },
    });
  } catch (err) {
    console.error("[PhishGuard] Failed to save settings:", err);
    throw err;
  }
}

// ─── Scan state (session storage) ────────────────────────────────────────────

export async function getScanState(tabId: number): Promise<ScanState | null> {
  try {
    const result = await chrome.storage.session.get(scanKey(tabId));
    return (result[scanKey(tabId)] as ScanState) ?? null;
  } catch {
    return null;
  }
}

export async function setScanState(tabId: number, state: ScanState): Promise<void> {
  try {
    await chrome.storage.session.set({ [scanKey(tabId)]: state });
  } catch (err) {
    console.error(`[PhishGuard] Failed to set scan state for tab ${tabId}:`, err);
    throw err;
  }
}

export async function clearScanState(tabId: number): Promise<void> {
  try {
    await chrome.storage.session.remove(scanKey(tabId));
  } catch {
    // Non-critical — ignore errors on cleanup
  }
}

/**
 * Clean up scan states for tabs that no longer exist.
 * Call periodically to prevent session storage from growing indefinitely.
 */
export async function pruneOrphanedScans(): Promise<void> {
  try {
    const [allStorage, allTabs] = await Promise.all([
      chrome.storage.session.get(null),
      chrome.tabs.query({}),
    ]);

    const activeTabIds = new Set(allTabs.map((t) => t.id).filter(Boolean));
    const keysToRemove: string[] = [];

    for (const key of Object.keys(allStorage)) {
      if (key.startsWith(KEYS.scanPrefix)) {
        const tabId = parseInt(key.replace(KEYS.scanPrefix, ""), 10);
        if (!activeTabIds.has(tabId)) {
          keysToRemove.push(key);
        }
      }
    }

    if (keysToRemove.length > 0) {
      await chrome.storage.session.remove(keysToRemove);
    }
  } catch {
    // Non-critical
  }
}
