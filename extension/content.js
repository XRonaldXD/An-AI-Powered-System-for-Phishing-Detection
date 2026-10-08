/**
 * Content script: scans links on the current page and highlights/warns
 * about ones that look suspicious. Relies on `PhishingRiskEngine` from
 * lib/risk-engine.js, which is loaded before this file (see manifest.json).
 *
 * Everything happens locally: links are scored in the page and only a small
 * summary (counts) is sent to the extension's own background worker.
 */

(function () {
  const adapter = self.PhishingScoringAdapter;

  const FLAG_ATTR = "data-phishing-guard-risk";
  const STYLE_ID = "phishing-guard-style";

  /** link element -> analysis result for links currently flagged. */
  const flagged = new WeakMap();
  let settings = adapter.normalizeSettings({});
  let lastSent = null;

  // Badge/outline are pure CSS (attribute-driven) so the page DOM is not modified.
  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      a[${FLAG_ATTR}] {
        outline: 2px solid #dc2626 !important;
        outline-offset: 1px;
        background-color: rgba(220, 38, 38, 0.1) !important;
        border-radius: 3px;
      }
      a[${FLAG_ATTR}]::after {
        content: "⚠ Risky link";
        display: inline-block;
        margin-left: 6px;
        padding: 0 5px;
        background: #dc2626;
        color: #fff;
        font: 700 10px/16px -apple-system, "Segoe UI", Arial, sans-serif;
        border-radius: 999px;
        vertical-align: middle;
        white-space: nowrap;
      }`;
    (document.head || document.documentElement).appendChild(style);
  }

  function buildTooltip(result) {
    const top = result.signals
      .slice()
      .sort((a, b) => b.points - a.points)
      .slice(0, 3)
      .map((s) => `• ${s.title}`);
    return `⚠ ${result.label} (${result.score}/100)\n${result.summary}` + (top.length ? `\n${top.join("\n")}` : "");
  }

  function el(tag, props, children) {
    const node = document.createElement(tag);
    Object.assign(node, props || {});
    for (const child of children || []) node.append(child);
    return node;
  }

  /** Overlay-style warning. Resolves true if the user chooses to continue. */
  function showWarningOverlay(result) {
    return new Promise((resolve) => {
      const host = el("div");
      host.style.cssText = "all: initial; position: fixed; inset: 0; z-index: 2147483647;";
      const root = host.attachShadow({ mode: "closed" });

      const style = el("style", {
        textContent: `
          .backdrop { position: fixed; inset: 0; background: rgba(17, 24, 39, 0.65); display: flex;
            align-items: center; justify-content: center; font-family: -apple-system, "Segoe UI", Arial, sans-serif; }
          .card { background: #fff; color: #1f2937; width: min(440px, 92vw); max-height: 85vh; overflow: auto;
            border-radius: 12px; border-top: 6px solid #dc2626; padding: 20px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
          h2 { margin: 0 0 6px; font-size: 18px; color: #991b1b; }
          .score { font-size: 13px; color: #6b7280; margin: 0 0 10px; }
          .url { font-size: 12px; word-break: break-all; background: #f3f4f6; padding: 6px 8px; border-radius: 6px; }
          ul { padding-left: 18px; margin: 10px 0; font-size: 13px; }
          li { margin-bottom: 6px; } li span { display: block; color: #6b7280; font-size: 12px; }
          .actions { display: flex; gap: 8px; margin-top: 14px; }
          button { flex: 1; padding: 10px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; border: 1px solid #d1d5db; background: #fff; }
          button.safe { background: #2563eb; color: #fff; border-color: #2563eb; }`,
      });

      const list = el("ul", {}, result.signals.map((signal) =>
        el("li", {}, [el("strong", { textContent: `${signal.title} (+${signal.points})` }), el("span", { textContent: signal.explanation })])
      ));
      const stay = el("button", { className: "safe", textContent: "Go back to safety" });
      const proceed = el("button", { textContent: "Continue anyway" });

      const card = el("div", { className: "card", role: "alertdialog" }, [
        el("h2", { textContent: "⚠ This link looks dangerous" }),
        el("p", { className: "score", textContent: `${result.label} · ${result.score}/100 · ${result.summary}` }),
        el("div", { className: "url", textContent: result.url }),
        list,
        el("div", { className: "actions" }, [stay, proceed]),
      ]);
      root.append(style, el("div", { className: "backdrop" }, [card]));

      const finish = (value) => {
        document.removeEventListener("keydown", onKey, true);
        host.remove();
        resolve(value);
      };
      const onKey = (event) => {
        if (event.key === "Escape") finish(false);
      };
      stay.addEventListener("click", () => finish(false));
      proceed.addEventListener("click", () => finish(true));
      document.addEventListener("keydown", onKey, true);
      document.documentElement.appendChild(host);
      stay.focus();
    });
  }

  // One delegated handler; flagged links are looked up so rescans stay cheap.
  document.addEventListener(
    "click",
    (event) => {
      const link = event.target instanceof Element ? event.target.closest(`a[${FLAG_ATTR}]`) : null;
      const result = link && flagged.get(link);
      if (!result) return;

      event.preventDefault();
      event.stopPropagation();
      showWarningOverlay(result).then((proceed) => {
        if (!proceed) return;
        if (link.target && link.target !== "_self") {
          window.open(link.href, link.target, "noopener,noreferrer");
        } else {
          window.location.href = link.href;
        }
      });
    },
    true
  );

  function flagLink(link, result) {
    flagged.set(link, result);
    link.setAttribute(FLAG_ATTR, "true");
    link.title = buildTooltip(result);
  }

  function unflagLink(link) {
    flagged.delete(link);
    link.removeAttribute(FLAG_ATTR);
    link.removeAttribute("title");
  }

  function scanLinks() {
    const links = Array.from(document.querySelectorAll("a[href]"));
    let suspiciousCount = 0;

    for (const link of links) {
      // Skip non-http(s) links such as mailto:, tel:, javascript:, or bare anchors.
      if (!/^https?:\/\//i.test(link.href)) continue;

      // Bulk scanning stays local; external providers are used for manual checks.
      const result = adapter.analyzeLocal(link.href, settings);
      if (result.label === "High risk") {
        if (!flagged.has(link) || flagged.get(link).url !== result.url) flagLink(link, result);
        suspiciousCount += 1;
      } else if (flagged.has(link)) {
        unflagLink(link);
      }
    }

    if (suspiciousCount > 0) injectStyle();

    // Only report when something changed to avoid noisy history entries.
    const signature = `${window.location.href}:${links.length}:${suspiciousCount}`;
    if (signature === lastSent) return;
    lastSent = signature;
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

  adapter.loadSettings().then((loaded) => {
    settings = loaded;
    scheduleScan();
  });

  // Re-apply warnings immediately when the user edits their settings or lists.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !(changes.allowlist || changes.denylist || changes.settings)) return;
    adapter.loadSettings().then((loaded) => {
      settings = loaded;
      // Force a fresh flag evaluation with the new settings.
      document.querySelectorAll(`a[${FLAG_ATTR}]`).forEach(unflagLink);
      scanLinks();
    });
  });

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
