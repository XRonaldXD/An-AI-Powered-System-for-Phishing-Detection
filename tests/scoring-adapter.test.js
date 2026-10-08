const test = require("node:test");
const assert = require("node:assert/strict");
const adapter = require("../extension/lib/scoring-adapter.js");
const engine = require("../extension/lib/risk-engine.js");
const mlModel = require("../extension/lib/ml-model.js");

const settings = (scoringMode, extra) =>
  adapter.normalizeSettings({ settings: { sensitivity: "balanced", scoringMode }, ...extra });

test("rules mode is unchanged and is the default", async () => {
  for (const s of [settings("rules"), adapter.normalizeSettings({})]) {
    const r = await adapter.analyze("http://example.com", s);
    const expected = engine.analyzeUrl("http://example.com", { sensitivity: "balanced" });
    assert.equal(r.score, expected.score);
    assert.deepEqual(r.reasons, expected.reasons);
    assert.equal(r.scoringMode, "rules");
  }
  assert.equal(adapter.normalizeSettings({}).scoringMode, "rules");
});

test("local ML mode produces a compatible score without any network", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("network must not be used"); };
  try {
    const r = await adapter.analyze("http://secure-paypal-login-verify.xyz/account/update", settings("ml"));
    assert.equal(r.scoringMode, "ml");
    assert.ok(r.score >= 70 && r.score <= 100);
    assert.equal(r.label, "High risk");
    for (const key of ["reasons", "signals", "confidence", "summary", "url", "listStatus"]) assert.ok(key in r, key);
    assert.ok(r.reasons.length > 0 && r.signals.length > 0);
    const clean = await adapter.analyze("https://example.com", settings("ml"));
    assert.equal(clean.label, "Low risk");
    assert.ok(clean.score < r.score);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("mode switching changes the result source for the same URL", async () => {
  const url = "https://192.168.0.1/login";
  const rules = await adapter.analyze(url, settings("rules"));
  const ml = await adapter.analyze(url, settings("ml"));
  assert.equal(rules.scoringMode, "rules");
  assert.equal(ml.scoringMode, "ml");
  assert.equal(adapter.normalizeSettings({ settings: { scoringMode: "bogus" } }).scoringMode, "rules");
});

test("falls back to rules if the model throws, is missing, or returns junk", async () => {
  const expected = engine.analyzeUrl("http://example.com", { sensitivity: "balanced" });
  const s = settings("ml");
  const throwing = { predict() { throw new Error("boom"); } };
  for (const model of [throwing, null, { predict: () => null }, { predict: () => ({ score: NaN, contributions: [] }) }]) {
    const r = await adapter.analyze("http://example.com", s, { model });
    assert.equal(r.score, expected.score);
    assert.equal(r.scoringMode, "rules");
  }
});

test("invalid URLs and listed domains are decided by rules in ML mode", async () => {
  assert.equal((await adapter.analyze("not a url", settings("ml"))).label, "Invalid URL");
  const allowed = await adapter.analyze("https://example.com", settings("ml", { allowlist: ["example.com"] }));
  assert.equal(allowed.score, 0);
  assert.equal(allowed.listStatus, "allowlist");
  const denied = await adapter.analyze("https://example.com", settings("ml", { denylist: ["example.com"] }));
  assert.equal(denied.listStatus, "denylist");
});

test("analyzeLocal always uses rules, even in ML mode", () => {
  assert.equal(adapter.analyzeLocal("http://example.com", settings("ml")).scoringMode, "rules");
});

test("ml model: feature extraction and bounded predictions", () => {
  assert.equal(mlModel.extractFeatures("not a url with spaces%%"), null);
  assert.equal(mlModel.extractFeatures("https://192.168.0.1/").isIpHost, 1);
  assert.equal(mlModel.predict(""), null);
  const p = mlModel.predict("https://bit.ly/x");
  assert.ok(p.score >= 0 && p.score <= 100 && p.probability > 0 && p.probability < 1);
});

const trainedModel = require("../extension/lib/trained-model.js");
const urlFeatures = require("../extension/lib/url-features.js");
const t = require("../ml/train-model.js");

function sampleArtifact() {
  const names = urlFeatures.FEATURE_NAMES;
  const weights = names.map((n) => (n === "has_https" ? 1.5 : n === "has_suspicious_keyword" ? -2 : n === "has_ip" ? -3 : 0));
  return {
    featureNames: names,
    weights,
    bias: 0,
    scaler: { mean: names.map(() => 0), std: names.map(() => 1) },
  };
}

test("trained mode uses the trained model artifact", async () => {
  const model = trainedModel.createModel(sampleArtifact());
  assert.ok(model.isAvailable());
  const r = await adapter.analyze("http://192.168.0.1/login", settings("trained"), { trainedModel: model });
  assert.equal(r.scoringMode, "trained");
  assert.ok(r.score > 50);
  assert.ok(r.signals.length > 0 && r.signals[0].id.startsWith("trained-"));
  const safe = await adapter.analyze("https://example.com", settings("trained"), { trainedModel: model });
  assert.ok(safe.score < r.score);
});

test("trained mode falls back to bundled ML, then rules", async () => {
  const url = "http://secure-paypal-login-verify.xyz/account";
  const bad = [null, { predict() { throw new Error("boom"); } }, trainedModel.createModel(null), trainedModel.createModel({ bogus: 1 })];
  for (const m of bad) {
    const r = await adapter.analyze(url, settings("trained"), { trainedModel: m });
    assert.equal(r.scoringMode, "ml");
    assert.equal(r.requestedMode, "trained");
  }
  const r = await adapter.analyze("http://example.com", settings("trained"), { trainedModel: null, model: null });
  assert.equal(r.scoringMode, "rules");
  assert.equal(r.requestedMode, "trained");
  assert.equal((await adapter.analyze("not a url", settings("trained"))).label, "Invalid URL");
});

test("no trained model is installed by default and no network is used", async () => {
  assert.equal(adapter.isTrainedModelAvailable(), false);
  const r = await adapter.analyze("http://example.com", settings("trained"));
  assert.equal(r.scoringMode, "ml");
});

test("installed artifact script matches training output and shared feature code", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  assert.equal(
    fs.readFileSync(path.join(__dirname, "../extension/lib/url-features.js"), "utf8"),
    fs.readFileSync(path.join(__dirname, "../ml/url-features.js"), "utf8"),
  );
  const script = t.toExtensionScript(sampleArtifact());
  const mod = { exports: null };
  new Function("module", script)(mod);
  delete globalThis.PhishingTrainedModelData;
  assert.ok(trainedModel.isValidArtifact(mod.exports));
});
