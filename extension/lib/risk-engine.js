/**
 * Shared URL risk-scoring engine.
 *
 * This module is intentionally rule-based and dependency-free so it can run
 * unmodified in the popup, the content script, and the background service
 * worker. Keeping the scoring logic in one place also makes it easy to swap
 * in (or blend with) a machine-learning model or remote API later on:
 * replace/extend `analyzeUrl` while keeping the same `{ score, label, reasons }`
 * return shape and every caller keeps working.
 */

const RISK_THRESHOLDS = Object.freeze({
  HIGH: 70,
  MEDIUM: 35,
});

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
 * @returns {"Low risk"|"Medium risk"|"High risk"}
 */
function scoreToLabel(score) {
  if (score >= RISK_THRESHOLDS.HIGH) return "High risk";
  if (score >= RISK_THRESHOLDS.MEDIUM) return "Medium risk";
  return "Low risk";
}

/**
 * Analyze a URL (string) and return a phishing risk assessment.
 * @param {string} input Raw URL text, e.g. pasted by the user or read from a link on the page.
 * @returns {{score: number, label: string, reasons: string[], url: string|null}}
 */
function analyzeUrl(input) {
  const trimmed = (input || "").trim();

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
    };
  }

  let score = 0;
  const reasons = [];

  const hostname = url.hostname.toLowerCase();
  const href = url.href.toLowerCase();

  // IP address instead of domain name.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    reasons.push("Uses an IP address instead of a domain name.");
  }

  // Too many subdomains.
  const subdomainCount = Math.max(0, hostname.split(".").length - 2);
  if (subdomainCount >= 3) {
    score += 15;
    reasons.push("Contains an unusually large number of subdomains.");
  }

  // Suspicious keywords anywhere in the URL.
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((word) => href.includes(word));
  if (matchedKeywords.length) {
    score += Math.min(24, matchedKeywords.length * 8);
    reasons.push(`Contains suspicious keyword(s): ${matchedKeywords.join(", ")}.`);
  }

  // Very long URL.
  if (href.length > 120) {
    score += 10;
    reasons.push("URL is unusually long.");
  }

  // Encoded characters, which can be used to hide the real destination.
  if (/%[0-9a-f]{2}/i.test(href)) {
    score += 8;
    reasons.push("Contains encoded (percent-escaped) characters.");
  }

  // Punycode / internationalized domain names, often used for lookalike domains.
  if (hostname.includes("xn--")) {
    score += 25;
    reasons.push("Uses punycode, which can hide lookalike domains.");
  }

  // "@" symbol in the URL can be used to obscure the real destination.
  if (href.includes("@")) {
    score += 20;
    reasons.push('Contains an "@" symbol, which can hide the real destination.');
  }

  // Known URL shorteners hide the final destination.
  if (KNOWN_URL_SHORTENERS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) {
    score += 20;
    reasons.push("Uses a known URL shortener, which hides the real destination.");
  }

  // Many hyphens in the domain (common in typosquatting/lookalike domains).
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 6;
    reasons.push("Domain name has an unusually large number of hyphens.");
  }

  // Not using HTTPS.
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    score += 5;
    reasons.push(`Uses an uncommon protocol ("${url.protocol.replace(":", "")}").`);
  } else if (url.protocol === "http:") {
    score += 10;
    reasons.push("Does not use a secure (HTTPS) connection.");
  }

  score = Math.min(100, Math.max(0, score));

  if (reasons.length === 0) {
    reasons.push("No common phishing indicators were detected.");
  }

  return {
    score,
    label: scoreToLabel(score),
    reasons,
    url: url.href,
  };
}

// Expose to whichever environment loads this script: browser globals
// (content scripts, popup, classic service worker via importScripts) and
// CommonJS/Node (useful for quick local testing).
const api = { analyzeUrl, scoreToLabel, RISK_THRESHOLDS };

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}
if (typeof globalThis !== "undefined") {
  globalThis.PhishingRiskEngine = api;
}
