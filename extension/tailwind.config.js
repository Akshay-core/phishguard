/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{ts,tsx}", "./public/**/*.html"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // PhishGuard brand
        brand: {
          50:  "#eef2ff",
          100: "#e0e7ff",
          400: "#818cf8",
          500: "#6366f1",
          600: "#4f46e5",
          700: "#4338ca",
        },
        // Threat palette — consistent across extension
        threat: {
          safe:     "#22c55e",
          low:      "#eab308",
          medium:   "#f97316",
          high:     "#ef4444",
          critical: "#dc2626",
        },
        // Dark surface system
        surface: {
          bg:      "#0d0f14",
          DEFAULT: "#161923",
          hover:   "#1d2130",
          active:  "#242738",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["Menlo", "Consolas", "monospace"],
      },
      borderRadius: {
        sm: "5px",
        DEFAULT: "7px",
        md: "8px",
        lg: "12px",
        xl: "16px",
      },
      animation: {
        "pulse-slow": "pulse 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in":    "fadeIn 0.2s ease-out",
        "slide-up":   "slideUp 0.25s cubic-bezier(0.34, 1.56, 0.64, 1)",
      },
      keyframes: {
        fadeIn: {
          "0%":   { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%":   { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
