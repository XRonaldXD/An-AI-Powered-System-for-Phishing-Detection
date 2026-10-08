/**
 * Background service worker.
 *
 * Responsibilities:
 *  - One-time setup on install (default settings in storage).
 *  - Central messaging hub between content scripts and the popup:
 *      - Content scripts report how many suspicious links they found on a
 *        page; we surface that as a colored badge (blue = none, yellow = medium,
 *        red = high risk) on the toolbar icon.
 *      - The popup asks for the last scan result of the active tab so it can
 *        show a summary before the user manually analyzes anything.
 *  - Manual URL analysis requests from the popup are also handled here so
 *    that all scoring goes through a single code path.
 *  - Keeps a bounded local history of URL analyses and page scan summaries,
 *    and applies the user's sensitivity and allowlist/denylist (chrome.storage.local).
 *    Nothing is ever sent off-device.
 */

importScripts("lib/risk-engine.js", "lib/ml-model.js", "lib/scoring-adapter.js");

const DEFAULT_SETTINGS = self.PhishingScoringAdapter.DEFAULT_SETTINGS;

const MAX_HISTORY_ENTRIES = 50;

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

// Serialize history writes so concurrent messages do not overwrite each other.
let historyQueue = Promise.resolve();

/**
 * Add an entry to the history (newest first), capped at MAX_HISTORY_ENTRIES.
 * Page scans replace the previous entry for the same page so rescans of a
 * dynamic page do not flood the log.
 */
function addHistoryEntry(entry) {
  historyQueue = historyQueue
    .then(async () => {
      const data = await chrome.storage.local.get("history");
      let history = Array.isArray(data.history) ? data.history : [];
      if (entry.type === "page") {
        history = history.filter((e) => !(e.type === "page" && e.url === entry.url));
      }
      history.unshift({ ...entry, timestamp: Date.now() });
      await chrome.storage.local.set({ history: history.slice(0, MAX_HISTORY_ENTRIES) });
    })
    .catch((err) => console.error("Failed to save history", err));
  return historyQueue;
}

const BADGE_STYLES = {
  low: { text: "OK", color: "#2563eb" }, // blue: no suspicious links
  medium: { color: "#eab308" }, // yellow
  high: { color: "#dc2626" }, // red
};

/** Derive a page risk level from the number of suspicious links. */
function getRiskLevel(suspiciousCount) {
  if (suspiciousCount >= 3) return "high";
  if (suspiciousCount > 0) return "medium";
  return "low";
}

function setBadgeForTab(tabId, suspiciousCount, riskLevel) {
  if (typeof tabId !== "number") return;

  const style = BADGE_STYLES[riskLevel] || BADGE_STYLES.low;
  const text = style.text || String(suspiciousCount);
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return undefined;

  switch (message.type) {
    case "ANALYZE_URL": {
      const adapter = self.PhishingScoringAdapter;
      adapter
        .loadSettings()
        .then((settings) => adapter.analyze(message.url, settings))
        .then((result) => {
          if (result.url) {
            addHistoryEntry({
              type: "url",
              url: result.url,
              label: result.label,
              score: result.score,
            });
          }
          sendResponse(result);
        })
        .catch(() => sendResponse(adapter.analyzeLocal(message.url)));
      return true;
    }

    case "PAGE_SCAN_RESULT": {
      const tabId = sender.tab && sender.tab.id;
      if (typeof tabId === "number") {
        const suspiciousLinks = Number(message.suspiciousLinks) || 0;
        const riskLevel = getRiskLevel(suspiciousLinks);
        tabScanResults.set(tabId, {
          pageUrl: message.pageUrl,
          totalLinks: message.totalLinks,
          suspiciousLinks,
          riskLevel,
          updatedAt: Date.now(),
        });
        setBadgeForTab(tabId, suspiciousLinks, riskLevel);
        if (typeof message.pageUrl === "string") {
          addHistoryEntry({
            type: "page",
            url: message.pageUrl,
            label: riskLevel === "high" ? "High risk" : riskLevel === "medium" ? "Medium risk" : "Low risk",
            totalLinks: Number(message.totalLinks) || 0,
            suspiciousLinks,
          });
        }
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
