/**
 * PhishGuard — useScan Hook
 *
 * Manages the complete scan lifecycle for the popup.
 * Abstracts Chrome extension messaging, polling, and state updates.
 *
 * Why a custom hook instead of plain state?
 * - Encapsulates all Chrome API interactions in one place
 * - Makes PopupApp purely declarative
 * - Easy to unit-test in isolation
 * - Handles race conditions (stale poll after rapid navigation)
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { ScanState, ChromeMessage } from "../../types";

type UseScanReturn = {
  scanState: ScanState | null;
  currentURL: string | null;
  triggerScan: () => Promise<void>;
  isScanning: boolean;
};

/**
 * Send a message to the background service worker.
 * Type-safe wrapper around chrome.runtime.sendMessage.
 */
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

export function useScan(): UseScanReturn {
  const [scanState, setScanState] = useState<ScanState | null>(null);
  const [currentURL, setCurrentURL] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback(() => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const state = await sendMessage<ScanState | null>({
          type: "GET_CURRENT_SCAN",
        });
        if (state) {
          setScanState(state);
          if (state.status !== "scanning") {
            stopPolling();
          }
        }
      } catch {
        stopPolling();
      }
    }, 250);
  }, [stopPolling]);

  // On mount: get current tab URL and any existing scan result
  useEffect(() => {
    let cancelled = false;

    async function init() {
      try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];
        if (!tab?.url || cancelled) return;

        setCurrentURL(tab.url);

        const existingState = await sendMessage<ScanState | null>({
          type: "GET_CURRENT_SCAN",
        });

        if (cancelled) return;

        if (existingState) {
          setScanState(existingState);
          // If a scan is in progress (background started it on navigation),
          // start polling to catch the result
          if (existingState.status === "scanning") {
            startPolling();
          }
        }
      } catch (err) {
        console.error("[PhishGuard] Init failed:", err);
      }
    }

    void init();
    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [startPolling, stopPolling]);

  const triggerScan = useCallback(async () => {
    if (!currentURL) return;

    // Optimistic UI update
    setScanState({
      status: "scanning",
      url: currentURL,
      result: null,
      error: null,
      timestamp: Date.now(),
    });

    try {
      await sendMessage({ type: "SCAN_URL", payload: { url: currentURL } });
      startPolling();
    } catch (err) {
      setScanState({
        status: "error",
        url: currentURL,
        result: null,
        error: err instanceof Error ? err.message : "Scan failed",
        timestamp: Date.now(),
      });
    }
  }, [currentURL, startPolling]);

  const isScanning = scanState?.status === "scanning";

  return { scanState, currentURL, triggerScan, isScanning };
}
