/**
 * PhishGuard — Extension Logger
 *
 * Structured logging with:
 * - Consistent [PhishGuard][module] prefix for easy DevTools filtering
 * - Log level gating (no debug noise in production builds)
 * - Timing helpers for performance measurement
 * - Zero-cost in production (tree-shaken by Vite)
 *
 * Usage:
 *   import { createLogger } from '../lib/logger';
 *   const log = createLogger('FeatureExtractor');
 *   log.debug('Extracting features for:', url);
 *   log.info('Scan complete in %dms', duration);
 *   log.warn('Model not ready, retrying...');
 *   log.error('ONNX inference failed:', err);
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info:  1,
  warn:  2,
  error: 3,
};

// In production builds, Vite replaces process.env.NODE_ENV
// Set minimum level to 'info' in production (strips debug logs at build time)
const MIN_LEVEL: LogLevel =
  typeof process !== "undefined" && process.env?.NODE_ENV === "production"
    ? "info"
    : "debug";

export interface Logger {
  debug: (...args: unknown[]) => void;
  info:  (...args: unknown[]) => void;
  warn:  (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  time:  (label: string) => () => number;  // Returns a function that stops timing and returns ms
}

/**
 * Create a namespaced logger for a module.
 * @param module - Module name shown in log prefix
 */
export function createLogger(module: string): Logger {
  const prefix = `[PhishGuard][${module}]`;

  function shouldLog(level: LogLevel): boolean {
    return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[MIN_LEVEL];
  }

  return {
    debug: (...args) => {
      if (shouldLog("debug")) console.debug(prefix, ...args);
    },
    info: (...args) => {
      if (shouldLog("info")) console.info(prefix, ...args);
    },
    warn: (...args) => {
      if (shouldLog("warn")) console.warn(prefix, ...args);
    },
    error: (...args) => {
      if (shouldLog("error")) console.error(prefix, ...args);
    },
    time: (label: string) => {
      const start = performance.now();
      return () => {
        const duration = Math.round(performance.now() - start);
        if (shouldLog("debug")) {
          console.debug(`${prefix} ⏱ ${label}: ${duration}ms`);
        }
        return duration;
      };
    },
  };
}

// Convenience: root logger (no module prefix)
export const log = createLogger("Core");
