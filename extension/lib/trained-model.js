/**
 * Runtime for the trained model artifact produced by `ml/train-model.js`
 * (`phishing-model.json`, packaged for the extension as `trained-model-data.js`).
 *
 * P(legit) = sigmoid(bias + sum(weights[i] * (x[i] - mean[i]) / std[i])), with
 * features from `url-features.js`. The risk score is P(phishing) * 100.
 * Fully local: no network. When no valid artifact is installed, `predict`
 * returns null so the scoring adapter can fall back.
 */
(function () {
  const urlFeatures =
    (typeof globalThis !== "undefined" && globalThis.UrlFeatures) ||
    (typeof require === "function" ? (() => { try { return require("./url-features.js"); } catch { return null; } })() : null);
  const defaultArtifact =
    (typeof globalThis !== "undefined" && globalThis.PhishingTrainedModelData) ||
    (typeof require === "function" ? (() => { try { return require("./trained-model-data.js"); } catch { return null; } })() : null);

  const FEATURE_INFO = {
    url_length: ["Long URL", "The URL is longer than typical legitimate links."],
    hostname_length: ["Long domain", "The domain name is unusually long."],
    num_subdomains: ["Many subdomains", "Deeply nested subdomains are often used to mimic real sites."],
    num_hyphens: ["Hyphens in domain", "Hyphens in the domain are common in lookalike sites."],
    num_digits: ["Many digits", "The URL contains an unusual number of digits."],
    has_ip: ["IP address host", "The link uses a raw IP address instead of a domain name."],
    has_punycode: ["Punycode domain", "The domain uses punycode, which can imitate trusted brands."],
    has_at_symbol: ["'@' in URL", "An '@' can hide the real destination of the link."],
    has_https: ["Not HTTPS", "The connection is not encrypted."],
    has_shortener: ["URL shortener", "The real destination is hidden behind a link shortener."],
    has_suspicious_keyword: ["Phishing keywords", "The URL contains words common in phishing lures."],
    has_encoded_chars: ["Encoded characters", "Percent-encoded characters can obscure the real address."],
    path_length: ["Long path", "The path is unusually long."],
    query_length: ["Long query string", "The query string is unusually long."],
  };

  const isNumArray = (a, n) => Array.isArray(a) && a.length === n && a.every((v) => typeof v === "number" && Number.isFinite(v));

  /** True when the artifact is a usable logistic-regression model for the bundled feature extractor. */
  function isValidArtifact(a) {
    if (!a || typeof a !== "object" || !urlFeatures) return false;
    const names = urlFeatures.FEATURE_NAMES;
    const n = names.length;
    return (
      Array.isArray(a.featureNames) &&
      a.featureNames.length === n &&
      a.featureNames.every((name, i) => name === names[i]) &&
      isNumArray(a.weights, n) &&
      typeof a.bias === "number" && Number.isFinite(a.bias) &&
      (a.phishingThreshold === undefined ||
        (typeof a.phishingThreshold === "number" && a.phishingThreshold > 0 && a.phishingThreshold < 1)) &&
      !!a.scaler && isNumArray(a.scaler.mean, n) && isNumArray(a.scaler.std, n) &&
      a.scaler.std.every((s) => s > 0)
    );
  }

  /** Build a predictor around an artifact (injectable for tests). */
  function createModel(artifact) {
    const valid = isValidArtifact(artifact);

    function predict(input) {
      if (!valid) return null;
      const features = urlFeatures.extractFeatures(input);
      if (!features) return null;
      let logit = artifact.bias;
      const contributions = [];
      artifact.featureNames.forEach((name, i) => {
        const z = (features[i] - artifact.scaler.mean[i]) / artifact.scaler.std[i];
        logit += artifact.weights[i] * z;
        const toward = -artifact.weights[i] * z; // positive pushes towards phishing
        if (toward > 0) {
          const [title, explanation] = FEATURE_INFO[name] || [name, "This feature raised the phishing estimate."];
          contributions.push({ name, value: features[i], contribution: toward, title, explanation });
        }
      });
      contributions.sort((a, b) => b.contribution - a.contribution);
      const threshold = Number.isFinite(artifact.phishingThreshold) ? artifact.phishingThreshold : 0.5;
      const thresholdLogit = Math.log(threshold / (1 - threshold));
      const probability = 1 / (1 + Math.exp(logit - thresholdLogit));
      return {
        probability,
        score: Math.min(100, Math.max(0, Math.round(probability * 100))),
        url: urlFeatures.normalizeUrl(input),
        contributions,
      };
    }

    return {
      predict,
      isAvailable: () => valid,
      info: () => (valid ? { trainedAt: artifact.trainedAt || null, metrics: artifact.metrics || null } : null),
    };
  }

  const api = { ...createModel(defaultArtifact), createModel, isValidArtifact };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof globalThis !== "undefined") globalThis.PhishingTrainedModel = api;
})();
