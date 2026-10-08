/**
 * Scoring adapter: the single interface popup, content script and background
 * worker use to score URLs.
 *
 *  - `analyzeLocal(url, settings)` is synchronous and uses only the rule-based
 *    engine (used for scanning many page links cheaply).
 *  - `analyze(url, settings)` is async and respects `settings.scoringMode`:
 *    "rules" (default) or "ml" (the bundled on-device model in `ml-model.js`).
 *    If the model is unavailable or throws, the rule-based result is returned.
 *
 * Everything runs locally: no endpoint, no network calls. Invalid URLs and
 * allow/deny-listed domains are always decided by the rules engine. The result
 * shape stays `{ score, label, reasons, signals, confidence, summary, url, listStatus }`
 * plus `scoringMode` (the mode actually used).
 */
(function () {
  const engine =
    (typeof globalThis !== "undefined" && globalThis.PhishingRiskEngine) ||
    (typeof require === "function" ? require("./risk-engine.js") : null);
  const defaultModel =
    (typeof globalThis !== "undefined" && globalThis.PhishingMlModel) ||
    (typeof require === "function" ? (() => { try { return require("./ml-model.js"); } catch { return null; } })() : null);

  /** "rules" = rule engine (default), "ml" = bundled local model. */
  const SCORING_MODES = Object.freeze(["rules", "ml"]);

  const DEFAULT_SETTINGS = Object.freeze({
    scoringMode: "rules",
    warnOnHighRisk: true,
    highlightSuspiciousLinks: true,
    sensitivity: "balanced",
  });

  /** Merge stored settings + lists into one normalized object. */
  function normalizeSettings(data) {
    const stored = (data && data.settings) || {};
    const { provider, ...rest } = stored; // drop legacy endpoint settings
    return {
      ...DEFAULT_SETTINGS,
      ...rest,
      scoringMode: SCORING_MODES.includes(stored.scoringMode) ? stored.scoringMode : "rules",
      sensitivity: engine.SENSITIVITY_PRESETS[stored.sensitivity] ? stored.sensitivity : "balanced",
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
    return { ...engine.analyzeUrl(url, engineOptions(settings)), scoringMode: "rules" };
  }

  /** Build an analysis result from a model prediction. */
  function buildMlResult(prediction, local, settings) {
    const score = prediction.score;
    const label = engine.scoreToLabel(score, settings && settings.sensitivity);
    const signals = prediction.contributions.slice(0, 6).map((c) => ({
      id: `ml-${c.name}`,
      title: c.title,
      points: Math.max(1, Math.round(c.contribution * 10)),
      severity: c.contribution >= 2 ? "high" : c.contribution >= 1 ? "medium" : "low",
      explanation: c.explanation,
    }));
    const reasons = signals.length
      ? signals.map((s) => `${s.title}: ${s.explanation}`)
      : ["The local model found no common phishing indicators."];
    const top = signals[0];
    const summary = top
      ? `Local ML estimates a ${score}/100 phishing risk. Main factor: ${top.title.toLowerCase()}.`
      : `Local ML estimates a ${score}/100 phishing risk.`;
    return {
      score,
      label,
      reasons,
      url: local.url,
      signals,
      confidence: Math.round(Math.max(prediction.probability, 1 - prediction.probability) * 100),
      summary,
      listStatus: null,
      scoringMode: "ml",
    };
  }

  /**
   * Score a URL according to the selected mode.
   * @param {string} input
   * @param {object} [settings] Result of `loadSettings()`.
   * @param {{model?: {predict: Function}}} [deps] Injectable model (for tests).
   */
  async function analyze(input, settings, deps) {
    const local = analyzeLocal(input, settings);
    const mode = (settings && settings.scoringMode) || "rules";
    if (mode !== "ml" || !local.url || local.listStatus) return local;

    try {
      const model = (deps && "model" in deps ? deps.model : defaultModel);
      const prediction = model && model.predict(local.url);
      if (!prediction || !Number.isFinite(prediction.score) || !Array.isArray(prediction.contributions)) return local;
      return buildMlResult(prediction, local, settings);
    } catch {
      return local;
    }
  }

  const api = { analyze, analyzeLocal, loadSettings, normalizeSettings, DEFAULT_SETTINGS, SCORING_MODES };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof globalThis !== "undefined") globalThis.PhishingScoringAdapter = api;
})();
