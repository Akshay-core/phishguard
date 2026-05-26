/**
 * PhishGuard — ScanResult Component
 *
 * Displays the primary scan result: threat meter, level badge,
 * description, and scan metadata.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { ThreatScore, ThreatLevel } from "../../types";
import { ThreatMeter } from "./ThreatMeter";

interface ScanResultProps {
  result: ThreatScore;
}

const THREAT_META: Record<ThreatLevel, {
  label: string;
  description: string;
  color: string;
  bgGlow: string;
  borderColor: string;
}> = {
  safe: {
    label: "Safe",
    description: "No phishing indicators detected. This URL appears legitimate.",
    color: "#22c55e",
    bgGlow: "rgba(34,197,94,0.06)",
    borderColor: "rgba(34,197,94,0.25)",
  },
  low: {
    label: "Low Risk",
    description: "Minor suspicious signals detected. Proceed with caution.",
    color: "#eab308",
    bgGlow: "rgba(234,179,8,0.06)",
    borderColor: "rgba(234,179,8,0.25)",
  },
  medium: {
    label: "Suspicious",
    description: "Multiple phishing indicators detected. Verify this site before entering any data.",
    color: "#f97316",
    bgGlow: "rgba(249,115,22,0.08)",
    borderColor: "rgba(249,115,22,0.30)",
  },
  high: {
    label: "High Risk",
    description: "Strong phishing signals. Do not enter passwords or personal information.",
    color: "#ef4444",
    bgGlow: "rgba(239,68,68,0.10)",
    borderColor: "rgba(239,68,68,0.35)",
  },
  critical: {
    label: "Phishing Detected",
    description: "This URL matches known phishing patterns with high confidence. Leave immediately.",
    color: "#dc2626",
    bgGlow: "rgba(220,38,38,0.14)",
    borderColor: "rgba(220,38,38,0.45)",
  },
};

export function ScanResult({ result }: ScanResultProps) {
  const meta = THREAT_META[result.level];
  const isThreating = result.level !== "safe";

  return (
    <div
      className="mx-4 rounded-xl p-5 transition-all duration-300"
      style={{
        background: isThreating
          ? `linear-gradient(135deg, #161923 0%, ${meta.bgGlow} 100%)`
          : "#161923",
        border: `1px solid ${isThreating ? meta.borderColor : "rgba(255,255,255,0.07)"}`,
      }}
    >
      {/* Threat Meter */}
      <div className="flex justify-center mb-4">
        <ThreatMeter
          probability={result.probability}
          level={result.level}
          size={96}
          strokeWidth={6}
        />
      </div>

      {/* Level badge + scan time */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{
              background: meta.color,
              boxShadow: `0 0 6px ${meta.color}`,
            }}
            aria-hidden="true"
          />
          <span
            className="text-[13px] font-semibold"
            style={{ color: meta.color }}
          >
            {meta.label}
          </span>
        </div>

        <span className="text-[10px]" style={{ color: "#4d5566" }}>
          {result.scanDurationMs}ms · local inference
        </span>
      </div>

      {/* Description */}
      <p className="text-[12px] leading-relaxed" style={{ color: "#8892a4" }}>
        {meta.description}
      </p>

      {/* Critical warning banner */}
      {result.level === "critical" && (
        <div
          className="mt-3 flex items-center gap-2 rounded-lg px-3 py-2"
          style={{
            background: "rgba(220,38,38,0.12)",
            border: "1px solid rgba(220,38,38,0.30)",
          }}
        >
          <span className="text-sm shrink-0" aria-hidden="true">⚠</span>
          <span className="text-[11px] font-medium" style={{ color: "#fca5a5" }}>
            Do not enter any personal information on this page.
          </span>
        </div>
      )}
    </div>
  );
}
