/**
 * PhishGuard — Options Page
 *
 * Full settings management with persistent storage.
 * Settings are synced across devices via chrome.storage.sync.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { PhishGuardSettings, DEFAULT_SETTINGS, ThreatLevel } from "../types";
import { DeveloperCard } from "../popup/components/DeveloperCard";
import "../popup/styles.css";

// ─── Settings hook ─────────────────────────────────────────────

function useSettings() {
  const [settings, setSettings] = useState<PhishGuardSettings>(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    chrome.storage.sync.get("settings", (result) => {
      if (result["settings"]) {
        setSettings({ ...DEFAULT_SETTINGS, ...result["settings"] as PhishGuardSettings });
      }
    });
  }, []);

  const updateSetting = <K extends keyof PhishGuardSettings>(
    key: K,
    value: PhishGuardSettings[K]
  ) => {
    setSettings((prev) => {
      const updated = { ...prev, [key]: value };
      chrome.storage.sync.set({ settings: updated });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      return updated;
    });
  };

  return { settings, updateSetting, saved };
}

// ─── Components ────────────────────────────────────────────────

function Toggle({
  checked,
  onChange,
  id,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  id: string;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      id={id}
      onClick={() => onChange(!checked)}
      className="relative inline-flex items-center rounded-full transition-colors duration-200 focus-visible:outline-none"
      style={{
        width: 36,
        height: 20,
        background: checked ? "#6366f1" : "#1d2130",
        border: `1px solid ${checked ? "#6366f1" : "rgba(255,255,255,0.12)"}`,
        cursor: "pointer",
        flexShrink: 0,
      }}
    >
      <span
        className="rounded-full transition-transform duration-200"
        style={{
          width: 14,
          height: 14,
          background: "#fff",
          transform: `translateX(${checked ? 16 : 2}px)`,
          display: "block",
        }}
        aria-hidden="true"
      />
    </button>
  );
}

function SettingRow({
  title,
  description,
  id,
  checked,
  onChange,
  badge,
}: {
  title: string;
  description: string;
  id: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  badge?: string;
}) {
  return (
    <div
      className="flex items-start justify-between gap-4 py-4"
      style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}
    >
      <div className="flex-1">
        <div className="flex items-center gap-2 mb-0.5">
          <label
            htmlFor={id}
            className="text-[13px] font-medium cursor-pointer"
            style={{ color: "#f0f2f5" }}
          >
            {title}
          </label>
          {badge && (
            <span
              className="text-[9px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded"
              style={{
                background: "rgba(99,102,241,0.15)",
                color: "#818cf8",
                border: "1px solid rgba(99,102,241,0.25)",
              }}
            >
              {badge}
            </span>
          )}
        </div>
        <p className="text-[11px] leading-relaxed" style={{ color: "#4d5566" }}>
          {description}
        </p>
      </div>
      <Toggle id={id} checked={checked} onChange={onChange} />
    </div>
  );
}

const THREAT_LEVELS: Array<{ value: ThreatLevel; label: string }> = [
  { value: "low",    label: "Low — alert on any suspicion" },
  { value: "medium", label: "Medium — recommended" },
  { value: "high",   label: "High — only severe threats" },
];

// ─── Main Options Component ────────────────────────────────────

function OptionsApp() {
  const { settings, updateSetting, saved } = useSettings();

  return (
    <div
      className="min-h-screen p-6"
      style={{ background: "#0d0f14", color: "#f0f2f5", maxWidth: 560, margin: "0 auto" }}
    >
      {/* Header */}
      <header className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center text-xl shrink-0"
            style={{ background: "linear-gradient(135deg, #6366f1 0%, #818cf8 100%)" }}
          >
            🛡
          </div>
          <div>
            <h1 className="text-[18px] font-semibold tracking-tight" style={{ color: "#f0f2f5" }}>
              Phish<span style={{ color: "#6366f1" }}>Guard</span> Settings
            </h1>
            <p className="text-[11px]" style={{ color: "#4d5566" }}>
              Privacy-first phishing detection
            </p>
          </div>
        </div>

        {saved && (
          <span
            className="text-[11px] px-3 py-1 rounded-full animate-fade-in"
            style={{
              background: "rgba(34,197,94,0.12)",
              color: "#4ade80",
              border: "1px solid rgba(34,197,94,0.20)",
            }}
          >
            ✓ Saved
          </span>
        )}
      </header>

      {/* Detection */}
      <section className="mb-8">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.09em] mb-1" style={{ color: "#4d5566" }}>
          Detection
        </h2>
        <div
          className="rounded-xl px-4"
          style={{ background: "#161923", border: "1px solid rgba(255,255,255,0.07)" }}
        >
          <SettingRow
            id="enableAutoScan"
            title="Auto-scan on navigation"
            description="Automatically scan every URL you visit. Recommended."
            checked={settings.enableAutoScan}
            onChange={(v) => updateSetting("enableAutoScan", v)}
          />
          <SettingRow
            id="enableThreatIntel"
            title="Threat intelligence feed"
            description="Check URLs against URLHaus and PhishTank databases. Sends only the hostname — never the full URL."
            checked={settings.enableThreatIntel}
            onChange={(v) => updateSetting("enableThreatIntel", v)}
            badge="Network"
          />
        </div>
      </section>

      {/* Alert threshold */}
      <section className="mb-8">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.09em] mb-1" style={{ color: "#4d5566" }}>
          Alert Threshold
        </h2>
        <div
          className="rounded-xl p-4"
          style={{ background: "#161923", border: "1px solid rgba(255,255,255,0.07)" }}
        >
          <p className="text-[12px] mb-3" style={{ color: "#8892a4" }}>
            Minimum threat level required to show warnings and notifications.
          </p>
          <div className="flex flex-col gap-2">
            {THREAT_LEVELS.map(({ value, label }) => (
              <button
                key={value}
                onClick={() => updateSetting("threatThreshold", value)}
                className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-all duration-150"
                style={{
                  background: settings.threatThreshold === value
                    ? "rgba(99,102,241,0.12)"
                    : "rgba(255,255,255,0.03)",
                  border: `1px solid ${settings.threatThreshold === value
                    ? "rgba(99,102,241,0.35)"
                    : "rgba(255,255,255,0.06)"}`,
                  cursor: "pointer",
                }}
              >
                <span
                  className="w-3.5 h-3.5 rounded-full shrink-0 flex items-center justify-center"
                  style={{
                    background: settings.threatThreshold === value ? "#6366f1" : "transparent",
                    border: `1.5px solid ${settings.threatThreshold === value ? "#6366f1" : "rgba(255,255,255,0.2)"}`,
                  }}
                  aria-hidden="true"
                >
                  {settings.threatThreshold === value && (
                    <span style={{ width: 5, height: 5, borderRadius: "50%", background: "#fff", display: "block" }} />
                  )}
                </span>
                <span className="text-[12px]" style={{ color: settings.threatThreshold === value ? "#f0f2f5" : "#8892a4" }}>
                  {label}
                </span>
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Notifications */}
      <section className="mb-8">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.09em] mb-1" style={{ color: "#4d5566" }}>
          Notifications
        </h2>
        <div
          className="rounded-xl px-4"
          style={{ background: "#161923", border: "1px solid rgba(255,255,255,0.07)" }}
        >
          <SettingRow
            id="showSafeNotifications"
            title="Safe site confirmations"
            description="Show a notification when PhishGuard confirms a site is safe."
            checked={settings.showSafeNotifications}
            onChange={(v) => updateSetting("showSafeNotifications", v)}
          />
        </div>
      </section>

      {/* Privacy */}
      <section className="mb-8">
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.09em] mb-1" style={{ color: "#4d5566" }}>
          Privacy
        </h2>
        <div
          className="rounded-xl p-4"
          style={{ background: "#161923", border: "1px solid rgba(255,255,255,0.07)" }}
        >
          <div className="flex flex-col gap-2">
            {[
              { icon: "🔒", text: "ML model runs entirely in your browser via WebAssembly" },
              { icon: "🚫", text: "URLs are never sent to any server (unless threat intel is enabled)" },
              { icon: "🗑",  text: "Scan history is stored in session storage — cleared when browser closes" },
              { icon: "📊", text: "No analytics collected without explicit opt-in" },
            ].map(({ icon, text }) => (
              <div key={text} className="flex items-start gap-2.5">
                <span className="text-sm shrink-0" aria-hidden="true">{icon}</span>
                <span className="text-[12px] leading-relaxed" style={{ color: "#8892a4" }}>{text}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Developer */}
      <section>
        <h2 className="text-[11px] font-semibold uppercase tracking-[0.09em] mb-1" style={{ color: "#4d5566" }}>
          Developer
        </h2>
        <DeveloperCard />
        <p className="text-[10px] text-center mt-3" style={{ color: "#2d3142" }}>
          PhishGuard v1.0.0 · MIT License · Built with ♥ by Akshay
        </p>
      </section>
    </div>
  );
}

// Mount
const container = document.getElementById("root");
if (!container) throw new Error("Root not found");
createRoot(container).render(
  <React.StrictMode>
    <OptionsApp />
  </React.StrictMode>
);
