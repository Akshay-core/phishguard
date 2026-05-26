/**
 * PhishGuard — useSettings Hook
 *
 * Loads and saves extension settings from chrome.storage.sync.
 * Used by both PopupApp and the Options page.
 *
 * Sync storage means settings are shared across all the user's
 * Chrome instances signed into the same account — correct behavior.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { useState, useEffect, useCallback } from "react";
import { PhishGuardSettings, DEFAULT_SETTINGS } from "../../types";
import { getSettings, saveSettings } from "../../lib/storage";

interface UseSettingsReturn {
  settings: PhishGuardSettings;
  isLoading: boolean;
  updateSetting: <K extends keyof PhishGuardSettings>(
    key: K,
    value: PhishGuardSettings[K]
  ) => Promise<void>;
}

export function useSettings(): UseSettingsReturn {
  const [settings, setSettings] = useState<PhishGuardSettings>(DEFAULT_SETTINGS);
  const [isLoading, setIsLoading] = useState(true);

  // Load settings on mount
  useEffect(() => {
    let cancelled = false;

    getSettings().then((loaded) => {
      if (!cancelled) {
        setSettings(loaded);
        setIsLoading(false);
      }
    });

    // Listen for settings changes from other extension pages (e.g. options → popup)
    const listener = (changes: Record<string, chrome.storage.StorageChange>) => {
      if (changes["phishguard:settings"] && !cancelled) {
        const newValue = changes["phishguard:settings"].newValue as Partial<PhishGuardSettings>;
        if (newValue) {
          setSettings((prev) => ({ ...prev, ...newValue }));
        }
      }
    };

    chrome.storage.onChanged.addListener(listener);
    return () => {
      cancelled = true;
      chrome.storage.onChanged.removeListener(listener);
    };
  }, []);

  const updateSetting = useCallback(async <K extends keyof PhishGuardSettings>(
    key: K,
    value: PhishGuardSettings[K]
  ) => {
    // Optimistic update — update UI immediately, persist in background
    setSettings((prev) => ({ ...prev, [key]: value }));
    await saveSettings({ [key]: value });
  }, []);

  return { settings, isLoading, updateSetting };
}
