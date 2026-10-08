/**
 * Shared URL risk-scoring engine.
 *
 * This module is intentionally rule-based and dependency-free so it can run
 * unmodified in the popup, the content script, and the background service
 * worker. Keeping the scoring logic in one place also makes it easy to swap
 * in (or blend with) a machine-learning model or remote API later on:
 * replace/extend `analyzeUrl` while keeping the same `{ score, label, reasons, ... }`
 * return shape and every caller keeps working.
 */

const RISK_THRESHOLDS = Object.freeze({
  HIGH: 70,
  MEDIUM: 35,
});

/** Threshold presets for the user-selectable sensitivity (risk bias) setting. */
const SENSITIVITY_PRESETS = Object.freeze({
  low: Object.freeze({ HIGH: 80, MEDIUM: 45 }),
  balanced: RISK_THRESHOLDS,
  high: Object.freeze({ HIGH: 55, MEDIUM: 25 }),
});

/** Thresholds for a sensitivity level; unknown values fall back to "balanced". */
function getThresholds(sensitivity) {
  return SENSITIVITY_PRESETS[sensitivity] || SENSITIVITY_PRESETS.balanced;
}

const SUSPICIOUS_KEYWORDS = Object.freeze([
  "login",
  "verify",
  "secure",
  "update",
  "bank",
  "account",
  "password",
  "wallet",
  "confirm",
  "signin",
]);

const KNOWN_URL_SHORTENERS = Object.freeze([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "ow.ly",
  "goo.gl",
  "cutt.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "rb.gy",
]);

/**
 * Determine a human-readable risk label from a numeric score.
 * @param {number} score
 * @param {"low"|"balanced"|"high"} [sensitivity] Optional risk bias (default "balanced").
 * @returns {"Low risk"|"Medium risk"|"High risk"}
 */
function scoreToLabel(score, sensitivity) {
  const thresholds = getThresholds(sensitivity);
  if (score >= thresholds.HIGH) return "High risk";
  if (score >= thresholds.MEDIUM) return "Medium risk";
  return "Low risk";
}

/**
 * Normalize user input (a URL or bare domain) into a lowercase hostname.
 * Returns null if no usable hostname can be extracted.
 * @param {string} input
 * @returns {string|null}
 */
function normalizeDomain(input) {
  const trimmed = (input || "").trim();
  if (!trimmed) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    return url.hostname.toLowerCase().replace(/\.$/, "") || null;
  } catch {
    return null;
  }
}

/** True if `hostname` equals `domain` or is a subdomain of it. */
function hostMatchesDomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

/** Estimated confidence (%) in the label: lower near a threshold boundary. */
function estimateConfidence(score, sensitivity) {
  const thresholds = getThresholds(sensitivity);
  const distance = Math.min(Math.abs(score - thresholds.MEDIUM), Math.abs(score - thresholds.HIGH));
  return Math.round(Math.min(95, 55 + distance));
}

function severityForPoints(points) {
  if (points >= 20) return "high";
  if (points >= 10) return "medium";
  return "low";
}

/**
 * Analyze a URL (string) and return a phishing risk assessment.
 * @param {string} input Raw URL text, e.g. pasted by the user or read from a link on the page.
 * @param {{allowlist?: string[], denylist?: string[], sensitivity?: string}} [options] User-managed domain lists.
 *   Denylisted domains are always High risk; allowlisted domains are suppressed to score 0.
 * @returns {{score: number, label: string, reasons: string[], url: string|null,
 *   signals: {id: string, title: string, points: number, severity: string, explanation: string}[],
 *   confidence: number, summary: string, listStatus: "allowlist"|"denylist"|null}}
 */
function analyzeUrl(input, options) {
  const trimmed = (input || "").trim();
  const allowlist = (options && options.allowlist) || [];
  const denylist = (options && options.denylist) || [];
  const sensitivity = options && options.sensitivity;

  let url;
  try {
    // Allow bare domains like "example.com" by defaulting to https://.
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
  } catch {
    return {
      score: 100,
      label: "Invalid URL",
      reasons: ["This does not look like a valid URL."],
      url: null,
      signals: [],
      confidence: 0,
      summary: "This text could not be read as a web address.",
      listStatus: null,
    };
  }

  let score = 0;
  const signals = [];
  const addSignal = (id, title, points, explanation, severity) => {
    score += points;
    signals.push({
      id,
      title,
      points,
      severity: severity || severityForPoints(points),
      explanation,
    });
  };

  const hostname = url.hostname.toLowerCase();
  const href = url.href.toLowerCase();

  // User-managed lists take priority over heuristics. Denylist wins over allowlist.
  if (denylist.some((d) => hostMatchesDomain(hostname, d))) {
    return buildResult(url, 100, [
      {
        id: "denylist",
        title: "On your blocked list",
        points: 100,
        severity: "high",
        explanation: "You added this domain to your denylist, so it is always treated as high risk.",
      },
    ], "denylist", sensitivity);
  }
  if (allowlist.some((d) => hostMatchesDomain(hostname, d))) {
    return buildResult(url, 0, [
      {
        id: "allowlist",
        title: "On your trusted list",
        points: 0,
        severity: "low",
        explanation: "You added this domain to your allowlist, so warnings are suppressed for it.",
      },
    ], "allowlist", sensitivity);
  }

  // IP address instead of domain name.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    addSignal("ip-address", "IP address instead of a name", 30,
      "Real websites almost always use a name like example.com. Raw numbers are often used to hide who runs a site.");
  }

  // Too many subdomains.
  const subdomainCount = Math.max(0, hostname.split(".").length - 2);
  if (subdomainCount >= 3) {
    addSignal("many-subdomains", "Many subdomains", 15,
      "Long chains like login.bank.example.evil.com can make a fake site look like a real one.");
  }

  // Suspicious keywords anywhere in the URL.
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((word) => href.includes(word));
  if (matchedKeywords.length) {
    addSignal("keywords", `Suspicious words: ${matchedKeywords.join(", ")}`,
      Math.min(24, matchedKeywords.length * 8),
      "Scammers often use words like these to pressure you into entering passwords or payment details.");
  }

  // Very long URL.
  if (href.length > 120) {
    addSignal("long-url", "Very long address", 10,
      "Extremely long links can bury the real destination where you will not notice it.");
  }

  // Encoded characters, which can be used to hide the real destination.
  if (/%[0-9a-f]{2}/i.test(href)) {
    addSignal("encoded-chars", "Encoded characters", 8,
      "Percent-escaped characters (like %2F) can disguise what the link really says.");
  }

  // Punycode / internationalized domain names, often used for lookalike domains.
  if (hostname.includes("xn--")) {
    addSignal("punycode", "Lookalike (punycode) domain", 25,
      "This domain uses special characters that can imitate a well-known site, e.g. a Cyrillic 'а' that looks like a Latin 'a'.");
  }

  // "@" symbol in the URL can be used to obscure the real destination.
  if (href.includes("@")) {
    addSignal("at-symbol", 'Contains an "@" symbol', 20,
      "Everything before an @ in a link is ignored by the browser, so it can be used to make a link look trustworthy.");
  }

  // Known URL shorteners hide the final destination.
  if (KNOWN_URL_SHORTENERS.some((domain) => hostMatchesDomain(hostname, domain))) {
    addSignal("shortener", "URL shortener", 20,
      "Shortened links hide where they lead, so you cannot tell if the destination is safe before clicking.");
  }

  // Many hyphens in the domain (common in typosquatting/lookalike domains).
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    addSignal("hyphens", "Many hyphens in the domain", 6,
      "Fake domains often chain words with hyphens, like secure-login-my-bank.com.");
  }

  // Not using HTTPS.
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    addSignal("protocol", `Uncommon protocol ("${url.protocol.replace(":", "")}")`, 5,
      "Normal websites use http or https. Other link types can behave in unexpected ways.");
  } else if (url.protocol === "http:") {
    addSignal("no-https", "Not secure (no HTTPS)", 10,
      "The connection is not encrypted, so anything you type could be seen by others.");
  }

  return buildResult(url, score, signals, null, sensitivity);
}

function buildResult(url, rawScore, signals, listStatus, sensitivity) {
  const score = Math.min(100, Math.max(0, rawScore));
  const label = scoreToLabel(score, sensitivity);

  let reasons;
  let summary;
  if (listStatus) {
    reasons = signals.map((s) => s.explanation);
    summary = listStatus === "denylist"
      ? "This domain is on your blocked list, so it is treated as high risk."
      : "This domain is on your trusted list, so warnings are turned off for it.";
  } else if (signals.length === 0) {
    reasons = ["No common phishing indicators were detected."];
    summary = "We did not find any common warning signs in this link. Stay careful anyway.";
  } else {
    reasons = signals.map((s) => `${s.title}: ${s.explanation}`);
    const top = signals.slice().sort((a, b) => b.points - a.points)[0];
    summary =
      `${label === "Low risk" ? "Minor" : "Main"} concern: ${top.title.toLowerCase()}. ` +
      `${signals.length} warning sign${signals.length === 1 ? "" : "s"} found.`;
  }

  return {
    score,
    label,
    reasons,
    url: url.href,
    signals,
    confidence: listStatus ? 100 : estimateConfidence(score, sensitivity),
    summary,
    listStatus,
  };
}

// Expose to whichever environment loads this script: browser globals
// (content scripts, popup, classic service worker via importScripts) and
// CommonJS/Node (useful for quick local testing).
const api = {
  analyzeUrl,
  scoreToLabel,
  normalizeDomain,
  hostMatchesDomain,
  getThresholds,
  RISK_THRESHOLDS,
  SENSITIVITY_PRESETS,
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}
if (typeof globalThis !== "undefined") {
  globalThis.PhishingRiskEngine = api;
}
