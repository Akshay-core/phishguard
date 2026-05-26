/**
 * PhishGuard — PopupApp Root Component
 *
 * Orchestrates the popup UI. Handles four states:
 *  1. idle    — no scan yet, prompt user
 *  2. scanning — inference in progress
 *  3. done    — show result + indicators
 *  4. error   — graceful error state
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { useScan } from "./hooks/useScan";
import { ScanResult } from "./components/ScanResult";
import { IndicatorList } from "./components/IndicatorList";
import { truncateURL, getDisplayDomain } from "../utils/url-parser";

export function PopupApp() {
  const { scanState, currentURL, triggerScan, isScanning } = useScan();

  const openOptions = () => chrome.runtime.openOptionsPage();
  const rescan = () => { void triggerScan(); };

  const displayURL = currentURL ? truncateURL(currentURL) : "No URL detected";
  const domain     = currentURL ? getDisplayDomain(currentURL) : "";

  return (
    <div
      className="flex flex-col"
      style={{ width: 360, minHeight: 480, background: "#0d0f14" }}
    >
      {/* ── Header ─────────────────────────────────────────────── */}
      <header
        className="flex items-center justify-between px-4 py-3.5"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}
      >
        <div className="flex items-center gap-2">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center text-sm shrink-0"
            style={{ background: "linear-gradient(135deg, #6366f1 0%, #818cf8 100%)" }}
            aria-hidden="true"
          >
            🛡
          </div>
          <span className="text-[14px] font-semibold tracking-tight" style={{ color: "#f0f2f5" }}>
            Phish<span style={{ color: "#6366f1" }}>Guard</span>
          </span>
        </div>

        <div className="flex items-center gap-1">
          {/* Rescan button — only show when scan exists */}
          {scanState?.status === "done" && (
            <button
              onClick={rescan}
              disabled={isScanning}
              className="w-7 h-7 rounded-lg flex items-center justify-center text-sm transition-all duration-150 disabled:opacity-40"
              style={{
                background: "transparent",
                border: "none",
                color: "#4d5566",
                cursor: "pointer",
                fontSize: 16,
              }}
              title="Rescan this page"
              aria-label="Rescan"
            >
              ↻
            </button>
          )}
          <button
            onClick={openOptions}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-sm transition-all duration-150"
            style={{
              background: "transparent",
              border: "none",
              color: "#4d5566",
              cursor: "pointer",
              fontSize: 15,
            }}
            title="Settings"
            aria-label="Open settings"
          >
            ⚙
          </button>
        </div>
      </header>

      {/* ── URL Bar ────────────────────────────────────────────── */}
      <div className="mx-4 mt-3 mb-0">
        <div
          className="flex items-center gap-2 rounded-lg px-3 py-2"
          style={{
            background: "#161923",
            border: "1px solid rgba(255,255,255,0.07)",
          }}
        >
          {/* Protocol indicator */}
          <span
            className="text-[10px] font-mono shrink-0 rounded px-1 py-0.5"
            style={{
              background: currentURL?.startsWith("https://")
                ? "rgba(34,197,94,0.12)"
                : "rgba(239,68,68,0.12)",
              color: currentURL?.startsWith("https://") ? "#4ade80" : "#f87171",
            }}
          >
            {currentURL?.startsWith("https://") ? "HTTPS" : "HTTP"}
          </span>

          <span
            className="flex-1 text-[11.5px] font-mono truncate"
            style={{ color: "#8892a4" }}
            title={currentURL ?? ""}
          >
            {domain || displayURL}
          </span>

          <button
            onClick={rescan}
            disabled={isScanning}
            className="shrink-0 rounded px-2.5 py-1 text-[11px] font-medium transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed"
            style={{
              background: isScanning ? "rgba(99,102,241,0.4)" : "#6366f1",
              color: "#fff",
              border: "none",
              cursor: isScanning ? "not-allowed" : "pointer",
            }}
          >
            {isScanning ? "Scanning…" : "Scan"}
          </button>
        </div>
      </div>

      {/* ── Main Content ───────────────────────────────────────── */}
      <div className="flex-1 flex flex-col py-3 overflow-y-auto">
        {scanState?.status === "scanning" && <ScanningState />}

        {scanState?.status === "done" && scanState.result && (
          <>
            <ScanResult result={scanState.result} />
            <div className="mt-3">
              <IndicatorList indicators={scanState.result.indicators} />
            </div>
          </>
        )}

        {scanState?.status === "error" && (
          <ErrorState message={scanState.error ?? "Unknown error"} onRetry={rescan} />
        )}

        {(!scanState || scanState.status === "idle") && (
          <IdleState onScan={rescan} />
        )}
      </div>

      {/* ── Footer ─────────────────────────────────────────────── */}
      <footer
        className="flex items-center justify-between px-4 py-2.5"
        style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
      >
        <div
          className="flex items-center gap-1.5 rounded px-2 py-1 text-[10px]"
          style={{
            background: "rgba(34,197,94,0.08)",
            border: "1px solid rgba(34,197,94,0.14)",
            color: "#4ade80",
          }}
        >
          <span aria-hidden="true">🔒</span>
          <span>Local · No tracking</span>
        </div>

        <a
          href="https://akshay.fruvvi.com"
          target="_blank"
          rel="noreferrer"
          className="text-[10px] transition-colors duration-150"
          style={{ color: "#4d5566", textDecoration: "none" }}
          onMouseEnter={(e) => ((e.target as HTMLAnchorElement).style.color = "#6366f1")}
          onMouseLeave={(e) => ((e.target as HTMLAnchorElement).style.color = "#4d5566")}
        >
          by Akshay
        </a>
      </footer>
    </div>
  );
}

// ── Sub-state components ──────────────────────────────────────

function ScanningState() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-10 animate-fade-in">
      {/* Concentric pulse rings */}
      <div className="relative flex items-center justify-center" style={{ width: 64, height: 64 }}>
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className="absolute rounded-full"
            style={{
              width: 24 + i * 18,
              height: 24 + i * 18,
              border: "1px solid rgba(99,102,241,0.4)",
              animation: `pulse ${1.2 + i * 0.3}s cubic-bezier(0.4,0,0.6,1) infinite`,
              animationDelay: `${i * 0.15}s`,
              opacity: 1 - i * 0.25,
            }}
            aria-hidden="true"
          />
        ))}
        <span style={{ fontSize: 18 }}>🛡</span>
      </div>
      <div className="text-center">
        <p className="text-[13px] font-medium" style={{ color: "#f0f2f5" }}>
          Analyzing URL
        </p>
        <p className="text-[11px] mt-0.5" style={{ color: "#4d5566" }}>
          Running local ML inference…
        </p>
      </div>
    </div>
  );
}

function IdleState({ onScan }: { onScan: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center text-center gap-3 py-10 px-6 animate-fade-in">
      <div className="text-4xl" aria-hidden="true">🛡</div>
      <div>
        <p className="text-[14px] font-semibold" style={{ color: "#f0f2f5" }}>
          Ready to protect you
        </p>
        <p className="text-[12px] mt-1 leading-relaxed" style={{ color: "#8892a4" }}>
          Navigate to a page and PhishGuard will automatically scan it, or click Scan to analyze the current URL.
        </p>
      </div>
      <button
        onClick={onScan}
        className="mt-1 px-5 py-2 rounded-lg text-[12px] font-medium transition-opacity duration-150 hover:opacity-85"
        style={{ background: "#6366f1", color: "#fff", border: "none", cursor: "pointer" }}
      >
        Scan current page
      </button>
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="mx-4 rounded-xl p-5 animate-fade-in" style={{
      background: "rgba(239,68,68,0.06)",
      border: "1px solid rgba(239,68,68,0.20)",
    }}>
      <p className="text-[13px] font-semibold mb-1" style={{ color: "#f87171" }}>
        Scan failed
      </p>
      <p className="text-[11px] mb-3" style={{ color: "#8892a4" }}>
        {message}
      </p>
      <button
        onClick={onRetry}
        className="text-[11px] px-3 py-1.5 rounded-lg transition-opacity hover:opacity-80"
        style={{ background: "rgba(239,68,68,0.15)", color: "#f87171", border: "1px solid rgba(239,68,68,0.25)", cursor: "pointer" }}
      >
        Try again
      </button>
    </div>
  );
}
