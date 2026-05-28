/**
 * PhishGuard — Offscreen ML Runtime
 *
 * Owns ONNX Runtime Web inference in an extension page context. Chrome MV3
 * service workers cannot use the dynamic import() path required by ORT WASM.
 */

import { scanURL } from "../lib/risk-engine";
import { ChromeMessage, ThreatScore } from "../types";

interface OffscreenScanResponse {
  ok: boolean;
  result?: ThreatScore;
  error?: string;
}

chrome.runtime.onMessage.addListener(
  (
    message: ChromeMessage<{ url: string }>,
    _sender,
    sendResponse: (response: OffscreenScanResponse) => void
  ) => {
    if (message.type !== "OFFSCREEN_SCAN_URL") return false;

    const url = message.payload?.url;
    if (!url) {
      sendResponse({ ok: false, error: "No URL provided for scan." });
      return false;
    }

    scanURL(url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => {
        const error = err instanceof Error ? err.message : "Scan failed";
        sendResponse({ ok: false, error });
      });

    return true;
  }
);
