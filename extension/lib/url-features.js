/**
 * URL cleaning + feature extraction for the local phishing-URL model.
 * Dependency-free so it can be reused by the training script, tests and the
 * extension's trained-model runtime. Keep this file identical to its copy
 * (ml/url-features.js <-> extension/lib/url-features.js); a test enforces it.
 */
(function (root) {
  const SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "bank", "account", "password", "wallet", "confirm", "signin"];
  const SHORTENERS = ["bit.ly", "t.co", "tinyurl.com", "ow.ly", "goo.gl", "cutt.ly", "is.gd", "buff.ly", "rebrand.ly", "rb.gy"];

  const FEATURE_NAMES = [
    "url_length", "hostname_length", "num_subdomains", "num_hyphens", "num_digits",
    "has_ip", "has_punycode", "has_at_symbol", "has_https", "has_shortener",
    "has_suspicious_keyword", "has_encoded_chars", "path_length", "query_length",
  ];

  /** Trim, add `https://` when no scheme is present, and parse. Returns a URL or null. */
  function parseUrl(input) {
    if (typeof input !== "string") return null;
    const text = input.trim();
    if (!text || /\s/.test(text)) return null;
    try {
      const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
      if (url.protocol !== "http:" && url.protocol !== "https:") return null;
      return url.hostname ? url : null;
    } catch {
      return null;
    }
  }

  /** Canonical form used for de-duplication; null when the URL is invalid. */
  function normalizeUrl(input) {
    const url = parseUrl(input);
    return url ? url.href : null;
  }

  /** Returns an array of numbers ordered as FEATURE_NAMES, or null for invalid URLs. */
  function extractFeatures(input) {
    const url = parseUrl(input);
    if (!url) return null;
    const hostname = url.hostname.toLowerCase();
    const href = url.href.toLowerCase();
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith("[");
    const count = (s, re) => (s.match(re) || []).length;
    return [
      href.length,
      hostname.length,
      isIp ? 0 : Math.max(0, hostname.split(".").length - 2),
      count(hostname, /-/g),
      count(href, /\d/g),
      isIp ? 1 : 0,
      hostname.includes("xn--") ? 1 : 0,
      /@/.test(input) || href.includes("@") || url.username ? 1 : 0,
      url.protocol === "https:" ? 1 : 0,
      SHORTENERS.some((d) => hostname === d || hostname.endsWith(`.${d}`)) ? 1 : 0,
      SUSPICIOUS_WORDS.some((w) => href.includes(w)) ? 1 : 0,
      /%[0-9a-f]{2}/i.test(href) ? 1 : 0,
      url.pathname.length,
      url.search.length,
    ];
  }

  const api = { FEATURE_NAMES, SUSPICIOUS_WORDS, SHORTENERS, parseUrl, normalizeUrl, extractFeatures };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.UrlFeatures = api;
})(typeof self !== "undefined" ? self : globalThis);
