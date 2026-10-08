const test = require("node:test");
const assert = require("node:assert/strict");
const f = require("../ml/url-features.js");
const t = require("../ml/train-model.js");

const feat = (u) => Object.fromEntries(f.FEATURE_NAMES.map((n, i) => [n, f.extractFeatures(u)[i]]));

test("normalizeUrl prefixes https and rejects malformed input", () => {
  assert.equal(f.normalizeUrl("example.com/a"), "https://example.com/a");
  for (const bad of ["", "   ", null, "http://", "ht tp://x", "ftp://example.com", "http://exa mple.com"]) {
    assert.equal(f.normalizeUrl(bad), null);
  }
  assert.equal(f.extractFeatures(""), null);
});

test("extractFeatures detects phishing signals", () => {
  const p = feat("http://192.168.0.1/login?x=1%20");
  assert.equal(p.has_ip, 1);
  assert.equal(p.has_https, 0);
  assert.equal(p.has_suspicious_keyword, 1);
  assert.equal(p.has_encoded_chars, 1);
  assert.equal(p.query_length, "?x=1%20".length);
  assert.equal(feat("https://xn--pple-43d.com").has_punycode, 1);
  assert.equal(feat("https://paypal.com@evil.example/").has_at_symbol, 1);
  assert.equal(feat("bit.ly/abc").has_shortener, 1);
  const q = feat("https://a.b-c.example.com/x/y");
  assert.equal(q.num_subdomains, 2);
  assert.equal(q.num_hyphens, 1);
  assert.equal(q.path_length, 4);
  assert.equal(q.has_https, 1);
  assert.equal(q.has_ip, 0);
});

test("buildDataset skips bad rows and duplicates", () => {
  const csv = 'url,status\nexample.com,1\nhttps://example.com/,1\n"a.com/x,y",0\n,0\nhttp://,0\nfoo.com,2\nbad.com,0\n';
  const { X, y, stats } = t.buildDataset(csv);
  assert.equal(X.length, 3);
  assert.deepEqual(y, [1, 0, 0]);
  assert.equal(stats.duplicates, 1);
  assert.equal(stats.skippedInvalidUrl, 2);
  assert.equal(stats.skippedInvalidLabel, 1);
  assert.throws(() => t.buildDataset("a,b\n1,2"));
});

test("stratified split, training and evaluation work end to end", () => {
  const rows = ["url,status"];
  for (let i = 0; i < 200; i++) {
    rows.push(`https://site${i}.com/about,1`);
    rows.push(`http://secure-login-verify${i}.example.tk/account/update?id=${i}%20,0`);
  }
  const { X, y } = t.buildDataset(rows.join("\n"));
  const { train, test: te } = t.stratifiedSplit(y);
  const share = (idx) => idx.filter((i) => y[i] === 1).length / idx.length;
  assert.ok(Math.abs(share(train) - 0.5) < 0.01 && Math.abs(share(te) - 0.5) < 0.01);
  const scaler = t.fitScaler(train.map((i) => X[i]));
  const Xs = train.map((i) => X[i].map((v, j) => (v - scaler.mean[j]) / scaler.std[j]));
  const m = { ...t.trainLogReg(Xs, train.map((i) => y[i]), { epochs: 10 }), scaler };
  const metrics = t.evaluate(te.map((i) => y[i]), te.map((i) => t.predictProbLegit(m, X[i])));
  assert.ok(metrics.accuracy > 0.95);
  const c = metrics.confusionMatrix;
  assert.equal(c.truePhishing + c.falsePhishing + c.trueLegit + c.falseLegit, te.length);
});

test("stratified split handles large datasets without exceeding argument limits", () => {
  const y = Array.from({ length: 200_000 }, (_, i) => i % 2);
  const { train, test: te } = t.stratifiedSplit(y);

  assert.equal(train.length + te.length, y.length);
  assert.equal(te.length, 40_000);
  assert.equal(train.length, 160_000);
  assert.equal(te.filter((i) => y[i] === 0).length, 20_000);
  assert.equal(te.filter((i) => y[i] === 1).length, 20_000);
});
