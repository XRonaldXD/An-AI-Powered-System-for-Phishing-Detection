/**
 * Content script: scans links on the current page and highlights/warns
 * about ones that look suspicious. Relies on `PhishingRiskEngine` from
 * lib/risk-engine.js, which is loaded before this file (see manifest.json).
 */

(function () {
  const { analyzeUrl, RISK_THRESHOLDS } = self.PhishingRiskEngine;

  const HIGHLIGHT_OUTLINE = "2px solid #dc2626";
  const HIGHLIGHT_BACKGROUND = "rgba(220, 38, 38, 0.08)";

  function warnBeforeNavigating(event, result) {
    const proceed = window.confirm(
      "Warning: this link looks suspicious.\n\n" +
        `Risk: ${result.score}/100 (${result.label})\n` +
        "Reasons:\n" +
        result.reasons.map((reason) => `- ${reason}`).join("\n") +
        "\n\nDo you still want to continue?"
    );
    if (!proceed) {
      event.preventDefault();
      event.stopPropagation();
    }
  }

  function highlightLink(link, result) {
    link.style.outline = HIGHLIGHT_OUTLINE;
    link.style.backgroundColor = HIGHLIGHT_BACKGROUND;
    link.title = `⚠ Suspicious link (${result.label}, score ${result.score}/100)`;
    link.dataset.phishingGuardWarned = "true";

    link.addEventListener("click", (event) => warnBeforeNavigating(event, result));
  }

  function scanLinks() {
    const links = Array.from(document.querySelectorAll("a[href]"));
    let suspiciousCount = 0;

    for (const link of links) {
      if (link.dataset.phishingGuardWarned) continue;

      let href = link.href;
      // Skip non-http(s) links such as mailto:, tel:, javascript:, or bare anchors.
      if (!/^https?:\/\//i.test(href)) continue;

      const result = analyzeUrl(href);
      if (result.score >= RISK_THRESHOLDS.HIGH) {
        highlightLink(link, result);
        suspiciousCount += 1;
      }
    }

    chrome.runtime.sendMessage({
      type: "PAGE_SCAN_RESULT",
      pageUrl: window.location.href,
      totalLinks: links.length,
      suspiciousLinks: suspiciousCount,
    });
  }

  function scheduleScan() {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", scanLinks, { once: true });
    } else {
      scanLinks();
    }
  }

  scheduleScan();

  // Re-scan when the page content changes significantly (e.g. SPA navigation
  // or dynamically injected links), without spamming on every tiny mutation.
  let rescanTimeout = null;
  const observer = new MutationObserver(() => {
    if (rescanTimeout) return;
    rescanTimeout = setTimeout(() => {
      rescanTimeout = null;
      scanLinks();
    }, 1000);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
