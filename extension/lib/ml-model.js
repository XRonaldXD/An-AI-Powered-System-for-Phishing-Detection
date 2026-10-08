/**
 * Local on-device ML scorer (no network, no endpoint).
 *
 * A compact logistic-regression classifier over URL-derived features. The
 * weights are bundled below, so inference is a deterministic dot product plus a
 * sigmoid that runs inside the extension. It is intentionally separate from the
 * rule engine (`risk-engine.js`) and never calls it.
 */
(function () {
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "rb.gy"];
  const SUSPICIOUS_TLDS = ["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "support", "work", "loan", "icu", "rest"];
  const KEYWORDS = ["login", "signin", "verify", "account", "update", "secure", "bank", "banking", "password", "confirm", "wallet", "suspend", "paypal", "apple", "microsoft", "amazon", "netflix", "support"];

  const BIAS = -4.2;

  /** feature -> { weight, title, explanation } (explanation used when the feature fires). */
  const MODEL = Object.freeze({
    isIpHost: { weight: 4.5, title: "IP address host", explanation: "The link uses a raw IP address instead of a domain name." },
    hasAtSymbol: { weight: 4.5, title: "'@' in URL", explanation: "An '@' can hide the real destination of the link." },
    hasPunycode: { weight: 2.5, title: "Punycode domain", explanation: "The domain uses punycode, which can imitate trusted brands." },
    isShortener: { weight: 3.0, title: "URL shortener", explanation: "The real destination is hidden behind a link shortener." },
    suspiciousTld: { weight: 2.0, title: "Suspicious TLD", explanation: "The top-level domain is frequently abused for phishing." },
    notHttps: { weight: 0.8, title: "Not HTTPS", explanation: "The connection is not encrypted." },
    keywordCount: { weight: 0.9, title: "Phishing keywords", explanation: "The URL contains words common in phishing lures." },
    hostKeyword: { weight: 1.2, title: "Keywords in domain", explanation: "A lure keyword appears in the domain name itself." },
    subdomainCount: { weight: 0.8, title: "Many subdomains", explanation: "Deeply nested subdomains are often used to mimic real sites." },
    hostHyphens: { weight: 0.7, title: "Hyphens in domain", explanation: "Multiple hyphens in the domain are common in lookalike sites." },
    hostDigitRatio: { weight: 3.0, title: "Digits in domain", explanation: "The domain contains an unusually high share of digits." },
    longUrl: { weight: 1.4, title: "Long URL", explanation: "Very long URLs can hide the real destination." },
    hostEntropy: { weight: 1.0, title: "Random-looking domain", explanation: "The domain name looks randomly generated." },
    nonStandardPort: { weight: 1.2, title: "Unusual port", explanation: "The link uses a non-standard port." },
    deepPath: { weight: 0.4, title: "Deep path", explanation: "The path is unusually deep." },
  });

  function parseUrl(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) return null;
    try {
      return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    } catch {
      return null;
    }
  }

  function entropy(text) {
    if (!text) return 0;
    const counts = {};
    for (const ch of text) counts[ch] = (counts[ch] || 0) + 1;
    return -Object.values(counts).reduce((sum, c) => sum + (c / text.length) * Math.log2(c / text.length), 0);
  }

  const clamp01 = (n) => Math.min(1, Math.max(0, n));

  /** Extract numeric URL features (each roughly in 0..1). Returns null for unparseable input. */
  function extractFeatures(input) {
    const url = parseUrl(input);
    if (!url) return null;
    const host = url.hostname.toLowerCase();
    const href = url.href.toLowerCase();
    const labels = host.split(".");
    const tld = labels[labels.length - 1];
    const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
    const registrable = labels.slice(-2).join(".");
    const hostLetters = host.replace(/\./g, "");
    const digits = (hostLetters.match(/\d/g) || []).length;
    const keywordCount = KEYWORDS.filter((k) => href.includes(k)).length;
    const hostName = labels.slice(0, -1).join(".");
    return {
      isIpHost: isIpHost ? 1 : 0,
      hasAtSymbol: url.username || url.password || /@/.test(url.pathname) ? 1 : 0,
      hasPunycode: labels.some((l) => l.startsWith("xn--")) ? 1 : 0,
      isShortener: SHORTENERS.includes(registrable) ? 1 : 0,
      suspiciousTld: !isIpHost && SUSPICIOUS_TLDS.includes(tld) ? 1 : 0,
      notHttps: url.protocol === "https:" ? 0 : 1,
      keywordCount: clamp01(keywordCount / 3),
      hostKeyword: KEYWORDS.some((k) => hostName.includes(k)) ? 1 : 0,
      subdomainCount: isIpHost ? 0 : clamp01(Math.max(0, labels.length - 2) / 4),
      hostHyphens: clamp01(((host.match(/-/g) || []).length) / 3),
      hostDigitRatio: isIpHost ? 0 : clamp01(digits / Math.max(1, hostLetters.length) / 0.4),
      longUrl: clamp01((href.length - 40) / 100),
      hostEntropy: isIpHost ? 0 : clamp01((entropy(hostLetters) - 3.2) / 1.3),
      nonStandardPort: url.port && !["80", "443"].includes(url.port) ? 1 : 0,
      deepPath: clamp01((url.pathname.split("/").filter(Boolean).length - 2) / 4),
    };
  }

  /**
   * Run inference.
   * @returns {{ probability: number, score: number, url: string, contributions: object[] } | null}
   */
  function predict(input) {
    const features = extractFeatures(input);
    if (!features) return null;
    let logit = BIAS;
    const contributions = [];
    for (const [name, spec] of Object.entries(MODEL)) {
      const value = features[name] || 0;
      const contribution = spec.weight * value;
      logit += contribution;
      if (value > 0) contributions.push({ name, value, contribution, title: spec.title, explanation: spec.explanation });
    }
    contributions.sort((a, b) => b.contribution - a.contribution);
    const probability = 1 / (1 + Math.exp(-logit));
    return {
      probability,
      score: Math.min(100, Math.max(0, Math.round(probability * 100))),
      url: parseUrl(input).href,
      contributions,
    };
  }

  const api = { predict, extractFeatures, MODEL, BIAS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof globalThis !== "undefined") globalThis.PhishingMlModel = api;
})();
