/**
 * Scoring adapter: the single interface popup, content script and background
 * worker use to score URLs.
 *
 *  - `analyzeLocal(url, settings)` is synchronous and uses only the rule-based
 *    engine (used for scanning many page links cheaply).
 *  - `analyze(url, settings)` is async. If an external model / threat-intel
 *    provider is enabled and configured it is queried and blended with the
 *    rule-based result; on any failure (network, timeout, bad response, missing
 *    config) it silently falls back to the rule-based result.
 *
 * The provider is a generic HTTPS JSON endpoint configured in the options
 * page (no credentials are bundled). It receives `POST {"url": "..."}` and
 * should reply `{"score": 0-100}` or `{"probability": 0-1}`, with optional
 * `"reasons": string[]`. The result shape stays
 * `{ score, label, reasons, url, ... }`.
 */
(function () {
  const engine =
    (typeof globalThis !== "undefined" && globalThis.PhishingRiskEngine) ||
    (typeof require === "function" ? require("./risk-engine.js") : null);

  const DEFAULT_SETTINGS = Object.freeze({
    warnOnHighRisk: true,
    highlightSuspiciousLinks: true,
    sensitivity: "balanced",
    provider: Object.freeze({
      enabled: false,
      name: "Threat intelligence",
      endpoint: "", // e.g. "https://your-model-host.example/score"
      apiKey: "", // optional; sent in the Authorization header
      timeoutMs: 4000,
    }),
  });

  /** Merge stored settings + lists into one normalized object. */
  function normalizeSettings(data) {
    const stored = (data && data.settings) || {};
    return {
      ...DEFAULT_SETTINGS,
      ...stored,
      sensitivity: engine.SENSITIVITY_PRESETS[stored.sensitivity] ? stored.sensitivity : "balanced",
      provider: { ...DEFAULT_SETTINGS.provider, ...(stored.provider || {}) },
      allowlist: Array.isArray(data && data.allowlist) ? data.allowlist : [],
      denylist: Array.isArray(data && data.denylist) ? data.denylist : [],
    };
  }

  /** Load the user's settings and lists from chrome.storage.local. */
  async function loadSettings() {
    const data = await chrome.storage.local.get(["settings", "allowlist", "denylist"]);
    return normalizeSettings(data);
  }

  function engineOptions(settings) {
    const s = settings || {};
    return { allowlist: s.allowlist, denylist: s.denylist, sensitivity: s.sensitivity };
  }

  function analyzeLocal(url, settings) {
    return engine.analyzeUrl(url, engineOptions(settings));
  }

  function providerConfigured(provider) {
    return !!(provider && provider.enabled && /^https:\/\//i.test(provider.endpoint || ""));
  }

  /** Turn a provider response into { score, reasons } or null if unusable. */
  function parseProviderResponse(body) {
    if (!body || typeof body !== "object") return null;
    let score = Number(body.score);
    if (body.score === undefined || Number.isNaN(score)) {
      score = Number(body.probability) * 100;
    }
    if (body.score === undefined && body.probability === undefined) return null;
    if (!Number.isFinite(score)) return null;
    const reasons = Array.isArray(body.reasons) ? body.reasons.filter((r) => typeof r === "string") : [];
    return { score: Math.min(100, Math.max(0, Math.round(score))), reasons };
  }

  async function queryProvider(url, provider, fetchImpl) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Number(provider.timeoutMs) || 4000);
    try {
      const headers = { "Content-Type": "application/json" };
      if (provider.apiKey) headers.Authorization = "Bearer " + provider.apiKey;
      const response = await fetchImpl(provider.endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
      if (!response.ok) return null;
      return parseProviderResponse(await response.json());
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Score a URL, using the external provider when available.
   * @param {string} input
   * @param {object} [settings] Result of `loadSettings()`.
   * @param {{fetch?: Function}} [deps] Injectable fetch (for tests).
   */
  async function analyze(input, settings, deps) {
    const local = analyzeLocal(input, settings);
    const provider = settings && settings.provider;
    // Invalid URLs and allow/deny-listed domains are decided locally.
    if (!local.url || local.listStatus || !providerConfigured(provider)) return local;

    const fetchImpl = (deps && deps.fetch) || (typeof fetch === "function" ? fetch : null);
    if (!fetchImpl) return local;

    let remote = null;
    try {
      remote = await queryProvider(local.url, provider, fetchImpl);
    } catch {
      remote = null;
    }
    if (!remote) return local;

    const name = provider.name || "Threat intelligence";
    const score = Math.max(local.score, remote.score);
    const label = engine.scoreToLabel(score, settings.sensitivity);
    const reasons = remote.reasons.length
      ? remote.reasons.map((r) => `[${name}] ${r}`)
      : [`[${name}] Risk score ${remote.score}/100.`];
    const signals = local.signals.concat({
      id: "provider",
      title: `${name} verdict`,
      points: remote.score,
      severity: remote.score >= 70 ? "high" : remote.score >= 35 ? "medium" : "low",
      explanation: remote.reasons[0] || `${name} rated this link ${remote.score}/100.`,
    });
    const baseReasons = local.signals.length ? local.reasons : [];
    return {
      ...local,
      score,
      label,
      reasons: baseReasons.concat(reasons),
      signals,
      confidence: Math.max(local.confidence, 80),
      provider: name,
    };
  }

  const api = { analyze, analyzeLocal, loadSettings, normalizeSettings, parseProviderResponse, DEFAULT_SETTINGS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof globalThis !== "undefined") globalThis.PhishingScoringAdapter = api;
})();
