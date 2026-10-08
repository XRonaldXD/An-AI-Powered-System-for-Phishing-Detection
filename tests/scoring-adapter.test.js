const test = require("node:test");
const assert = require("node:assert/strict");
const adapter = require("../extension/lib/scoring-adapter.js");

const settings = (provider) =>
  adapter.normalizeSettings({ settings: { sensitivity: "balanced", provider } });
const okFetch = (body) => async () => ({ ok: true, json: async () => body });

test("without provider, behaves like the rule engine", async () => {
  const r = await adapter.analyze("http://example.com", settings({}));
  assert.equal(r.score, 10);
  assert.equal(r.provider, undefined);
});

test("provider verdict raises score and adds prefixed reasons", async () => {
  const s = settings({ enabled: true, endpoint: "https://api.example/score", name: "TI" });
  const r = await adapter.analyze("https://example.com", s, { fetch: okFetch({ score: 90, reasons: ["Known phishing"] }) });
  assert.equal(r.score, 90);
  assert.equal(r.label, "High risk");
  assert.ok(r.reasons.includes("[TI] Known phishing"));
  assert.equal(r.url, "https://example.com/");
});

test("probability responses are scaled", async () => {
  const s = settings({ enabled: true, endpoint: "https://api.example/score" });
  const r = await adapter.analyze("https://example.com", s, { fetch: okFetch({ probability: 0.5 }) });
  assert.equal(r.score, 50);
});

test("falls back to rules on failure or bad response", async () => {
  const s = settings({ enabled: true, endpoint: "https://api.example/score" });
  const failing = async () => { throw new Error("offline"); };
  assert.equal((await adapter.analyze("http://example.com", s, { fetch: failing })).score, 10);
  assert.equal((await adapter.analyze("http://example.com", s, { fetch: okFetch({ nope: 1 }) })).score, 10);
  assert.equal((await adapter.analyze("http://example.com", s, { fetch: async () => ({ ok: false }) })).score, 10);
});

test("non-https endpoint is ignored; allowlisted domains skip provider", async () => {
  let called = false;
  const fetch = async () => { called = true; return { ok: true, json: async () => ({ score: 99 }) }; };
  await adapter.analyze("https://example.com", settings({ enabled: true, endpoint: "http://x" }), { fetch });
  const s = adapter.normalizeSettings({ allowlist: ["example.com"], settings: { provider: { enabled: true, endpoint: "https://api.example/score" } } });
  const r = await adapter.analyze("https://example.com", s, { fetch });
  assert.equal(called, false);
  assert.equal(r.score, 0);
});
