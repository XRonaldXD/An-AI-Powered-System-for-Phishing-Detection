/**
 * Background service worker.
 *
 * Responsibilities:
 *  - One-time setup on install (default settings in storage).
 *  - Central messaging hub between content scripts and the popup:
 *      - Content scripts report how many suspicious links they found on a
 *        page; we surface that count as a badge on the toolbar icon.
 *      - The popup asks for the last scan result of the active tab so it can
 *        show a summary before the user manually analyzes anything.
 *  - Manual URL analysis requests from the popup are also handled here so
 *    that all scoring goes through a single code path.
 */

importScripts("lib/risk-engine.js");

const DEFAULT_SETTINGS = {
  warnOnHighRisk: true,
  highlightSuspiciousLinks: true,
};

/** In-memory cache of the latest per-tab scan summary: tabId -> summary. */
const tabScanResults = new Map();

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get("settings", (data) => {
    if (!data.settings) {
      chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
    }
  });
  console.log("Phishing Link Guard installed.");
});

function setBadgeForTab(tabId, suspiciousCount) {
  if (typeof tabId !== "number") return;

  const text = suspiciousCount > 0 ? String(suspiciousCount) : "";
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return undefined;

  switch (message.type) {
    case "ANALYZE_URL": {
      const result = self.PhishingRiskEngine.analyzeUrl(message.url);
      sendResponse(result);
      return true;
    }

    case "PAGE_SCAN_RESULT": {
      const tabId = sender.tab && sender.tab.id;
      if (typeof tabId === "number") {
        tabScanResults.set(tabId, {
          pageUrl: message.pageUrl,
          totalLinks: message.totalLinks,
          suspiciousLinks: message.suspiciousLinks,
          updatedAt: Date.now(),
        });
        setBadgeForTab(tabId, message.suspiciousLinks);
      }
      return undefined;
    }

    case "GET_TAB_SCAN_RESULT": {
      const tabId = message.tabId;
      sendResponse(tabScanResults.get(tabId) || null);
      return true;
    }

    default:
      return undefined;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScanResults.delete(tabId);
});
