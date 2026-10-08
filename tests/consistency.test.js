const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");

test("extension/lib/url-features.js is identical to ml/url-features.js", () => {
  assert.equal(read("extension/lib/url-features.js"), read("ml/url-features.js"));
});

test("shortener and keyword lists agree across scoring modules", () => {
  const features = require("../extension/lib/url-features.js");
  const engineSrc = read("extension/lib/risk-engine.js");
  const mlSrc = read("extension/lib/ml-model.js");
  for (const d of features.SHORTENERS) {
    assert.ok(engineSrc.includes(`"${d}"`), `risk-engine missing shortener ${d}`);
    assert.ok(mlSrc.includes(`"${d}"`), `ml-model missing shortener ${d}`);
  }
  for (const w of features.SUSPICIOUS_WORDS) {
    assert.ok(engineSrc.includes(`"${w}"`), `risk-engine missing keyword ${w}`);
    assert.ok(mlSrc.includes(`"${w}"`), `ml-model missing keyword ${w}`);
  }
});

test("manifest requests only needed permissions", () => {
  const m = JSON.parse(read("extension/manifest.json"));
  assert.deepEqual(m.permissions, ["storage"]);
  assert.equal(m.host_permissions, undefined);
});
