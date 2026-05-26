/**
 * PhishGuard — IndicatorList Component
 *
 * Renders the list of triggered threat indicators with expandable
 * detail explanations. Each indicator can be clicked to toggle
 * its description — provides the "explainable AI" feature.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { useState } from "react";
import { ThreatIndicator } from "../../types";

interface IndicatorListProps {
  indicators: ThreatIndicator[];
}

const SEVERITY_COLORS = {
  info:    { dot: "#3b82f6", bg: "rgba(59,130,246,0.08)",  border: "rgba(59,130,246,0.18)" },
  warning: { dot: "#f97316", bg: "rgba(249,115,22,0.08)",  border: "rgba(249,115,22,0.18)" },
  danger:  { dot: "#ef4444", bg: "rgba(239,68,68,0.08)",   border: "rgba(239,68,68,0.20)" },
} as const;

export function IndicatorList({ indicators }: IndicatorListProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (indicators.length === 0) return null;

  const toggle = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="px-4 pb-4">
      <p
        className="text-[10px] font-semibold uppercase tracking-[0.09em] mb-2"
        style={{ color: "#4d5566" }}
      >
        Threat Indicators ({indicators.length})
      </p>

      <div className="flex flex-col gap-1.5">
        {indicators.map((indicator) => {
          const isExpanded = expandedId === indicator.id;
          const colors = SEVERITY_COLORS[indicator.severity];

          return (
            <button
              key={indicator.id}
              onClick={() => toggle(indicator.id)}
              className="w-full text-left rounded-lg px-3 py-2.5 transition-all duration-150"
              style={{
                background: isExpanded ? colors.bg : "rgba(22,25,35,1)",
                border: `1px solid ${isExpanded ? colors.border : "rgba(255,255,255,0.07)"}`,
              }}
              aria-expanded={isExpanded}
            >
              <div className="flex items-center gap-2">
                {/* Severity dot */}
                <span
                  className="shrink-0 rounded-full"
                  style={{
                    width: 6,
                    height: 6,
                    marginTop: 1,
                    background: colors.dot,
                    boxShadow: isExpanded ? `0 0 6px ${colors.dot}` : "none",
                    transition: "box-shadow 0.15s",
                  }}
                  aria-hidden="true"
                />

                {/* Label */}
                <span
                  className="flex-1 text-[12px] font-medium leading-tight"
                  style={{ color: isExpanded ? "#f0f2f5" : "#c4cad6" }}
                >
                  {indicator.label}
                </span>

                {/* Expand chevron */}
                <span
                  className="text-[10px] transition-transform duration-200"
                  style={{
                    color: "#4d5566",
                    transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)",
                    display: "inline-block",
                  }}
                  aria-hidden="true"
                >
                  ▾
                </span>
              </div>

              {/* Expandable explanation */}
              {isExpanded && (
                <p
                  className="mt-2 text-[11px] leading-relaxed animate-fade-in"
                  style={{ color: "#8892a4", paddingLeft: 14 }}
                >
                  {indicator.description}
                </p>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
