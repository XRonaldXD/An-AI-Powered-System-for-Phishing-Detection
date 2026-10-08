const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl } = require("../extension/lib/risk-engine.js");

const ids = (r) => r.signals.map((s) => s.id);

test("return shape is preserved", () => {
  const r = analyzeUrl("https://example.com");
  for (const key of ["score", "label", "reasons", "url"]) assert.ok(key in r);
  assert.equal(r.url, "https://example.com/");
});

test("clean https URL is low risk", () => {
  const r = analyzeUrl("https://example.com/about");
  assert.equal(r.score, 0);
  assert.equal(r.label, "Low risk");
  assert.deepEqual(r.reasons, ["No common phishing indicators were detected."]);
});

test("invalid URL", () => {
  const r = analyzeUrl("http://");
  assert.equal(r.label, "Invalid URL");
  assert.equal(r.url, null);
});

test("IP-based URL", () => {
  const r = analyzeUrl("https://192.168.0.1/");
  assert.deepEqual(ids(r), ["ip-address"]);
  assert.equal(r.score, 30);
  assert.match(r.reasons[0], /IP address/);
});

test("punycode / IDN domain", () => {
  const r = analyzeUrl("https://xn--pple-43d.com");
  assert.ok(ids(r).includes("punycode"));
  assert.equal(r.score, 31); // punycode (25) + hyphens (6)
  assert.equal(analyzeUrl("https://аpple.com").signals[0].id, "punycode");
});

test("URL shortener", () => {
  const r = analyzeUrl("https://bit.ly/abc");
  assert.deepEqual(ids(r), ["shortener"]);
  assert.equal(r.score, 20);
});

test("long and encoded URLs", () => {
  const r = analyzeUrl("https://example.com/" + "a".repeat(130));
  assert.deepEqual(ids(r), ["long-url"]);
  const e = analyzeUrl("https://example.com/%2Fpath");
  assert.deepEqual(ids(e), ["encoded-chars"]);
  assert.equal(e.score, 8);
});

test("suspicious keywords", () => {
  const r = analyzeUrl("https://example.com/login/verify");
  assert.deepEqual(ids(r), ["keywords"]);
  assert.equal(r.score, 16);
  assert.match(r.reasons[0], /login, verify/);
});

test("missing HTTPS", () => {
  const r = analyzeUrl("http://example.com");
  assert.deepEqual(ids(r), ["no-https"]);
  assert.equal(r.score, 10);
});

test("@ symbol trickery", () => {
  const r = analyzeUrl("https://paypal.com@evil.example/");
  assert.ok(ids(r).includes("at-symbol"));
  assert.equal(r.score, 20);
});

test("combined indicators reach High risk", () => {
  const r = analyzeUrl("http://192.168.0.1/login/verify/account@x");
  assert.equal(r.label, "High risk");
  assert.ok(r.score >= 70);
  assert.equal(r.score, Math.min(100, r.score));
});

test("allowlist and denylist", () => {
  const allow = analyzeUrl("http://login.bank.example.com", { allowlist: ["example.com"] });
  assert.equal(allow.score, 0);
  assert.equal(allow.listStatus, "allowlist");
  const deny = analyzeUrl("https://example.com", { allowlist: ["example.com"], denylist: ["example.com"] });
  assert.equal(deny.label, "High risk");
  assert.equal(deny.listStatus, "denylist");
});

test("sensitivity shifts labels", () => {
  const url = "http://example.com/login/verify"; // 26 points
  assert.equal(analyzeUrl(url, { sensitivity: "low" }).label, "Low risk");
  assert.equal(analyzeUrl(url).label, "Low risk");
  assert.equal(analyzeUrl(url, { sensitivity: "high" }).label, "Medium risk");
  const mid = "https://192.168.0.1/login"; // 38 points
  assert.equal(analyzeUrl(mid).label, "Medium risk");
  assert.equal(analyzeUrl(mid, { sensitivity: "low" }).label, "Low risk");
  assert.equal(analyzeUrl(mid, { sensitivity: "bogus" }).label, "Medium risk");
});

test("whole-word keyword matching avoids false positives", () => {
  assert.deepEqual(ids(analyzeUrl("https://accounts.google.com/")), []);
  assert.deepEqual(ids(analyzeUrl("https://example.com/bankruptcy")), []);
  assert.deepEqual(ids(analyzeUrl("https://example.com/secure-login")), ["keywords"]);
});

test("suspicious TLD, IPv6, public suffix and @handle paths", () => {
  assert.ok(ids(analyzeUrl("https://example.xyz")).includes("suspicious-tld"));
  assert.ok(ids(analyzeUrl("https://[2001:db8::1]/")).includes("ip-address"));
  assert.deepEqual(ids(analyzeUrl("https://www.bbc.co.uk/")), []);
  assert.ok(ids(analyzeUrl("https://a.b.c.example.co.uk/")).includes("many-subdomains"));
  assert.deepEqual(ids(analyzeUrl("https://example.com/@user")), []);
});
