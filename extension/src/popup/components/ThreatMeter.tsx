/**
 * PhishGuard — ThreatMeter Component
 *
 * Animated circular arc meter showing threat probability.
 * The arc fills clockwise from 0% (safe) to 100% (critical).
 *
 * Engineering notes:
 * - Uses SVG stroke-dashoffset animation (GPU-accelerated, no layout thrash)
 * - Animates on mount and on value change via CSS transition
 * - Color transitions match the threat level palette
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { useEffect, useRef } from "react";
import { ThreatLevel } from "../../types";

interface ThreatMeterProps {
  probability: number;    // 0–1
  level: ThreatLevel;
  size?: number;          // SVG dimensions (square)
  strokeWidth?: number;
}

const THREAT_COLORS: Record<ThreatLevel, string> = {
  safe:     "#22c55e",
  low:      "#eab308",
  medium:   "#f97316",
  high:     "#ef4444",
  critical: "#dc2626",
};

const THREAT_LABELS: Record<ThreatLevel, string> = {
  safe:     "Safe",
  low:      "Low Risk",
  medium:   "Suspicious",
  high:     "High Risk",
  critical: "Phishing",
};

export function ThreatMeter({
  probability,
  level,
  size = 100,
  strokeWidth = 6,
}: ThreatMeterProps) {
  const arcRef = useRef<SVGCircleElement>(null);
  const center = size / 2;
  const radius = center - strokeWidth * 1.5;
  const circumference = 2 * Math.PI * radius;
  const color = THREAT_COLORS[level];
  const displayPercent = Math.round(probability * 100);

  useEffect(() => {
    const arc = arcRef.current;
    if (!arc) return;

    // Start from empty (full dashoffset) then animate to target
    arc.style.strokeDashoffset = String(circumference);

    // Trigger reflow to ensure start state is applied before transition
    void arc.getBoundingClientRect();

    // Schedule fill animation on next frame
    requestAnimationFrame(() => {
      const targetOffset = circumference * (1 - Math.min(probability, 1));
      arc.style.transition = "stroke-dashoffset 0.9s cubic-bezier(0.34, 1.56, 0.64, 1), stroke 0.3s ease";
      arc.style.strokeDashoffset = String(targetOffset);
    });
  }, [probability, circumference]);

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        style={{ transform: "rotate(-90deg)" }}
        aria-hidden="true"
      >
        {/* Background track */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="#1d2130"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        {/* Animated fill arc */}
        <circle
          ref={arcRef}
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference}
        />
      </svg>

      {/* Center content */}
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span
          className="font-bold leading-none tabular-nums"
          style={{ fontSize: size * 0.26, color }}
        >
          {displayPercent}
        </span>
        <span
          className="uppercase tracking-widest"
          style={{ fontSize: size * 0.095, color: "#4d5566", marginTop: 2 }}
        >
          {displayPercent === 100 ? THREAT_LABELS[level] : "risk %"}
        </span>
      </div>
    </div>
  );
}
