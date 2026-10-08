#!/usr/bin/env node
/**
 * Train a logistic-regression phishing-URL classifier.
 *
 * Usage: node ml/train-model.js [path/to/new_data_urls.csv] [--out ml/model] [--epochs 30]
 *
 * Input CSV columns: `url`, `status` (1 = legit, 0 = phishing).
 * Outputs (in --out, default ml/model/):
 *   phishing-model.json  weights, bias, feature means/stds (browser-friendly)
 *   metrics.json         accuracy / precision / recall / F1 / confusion matrix
 * "Positive" in the metrics means phishing.
 */
const fs = require("node:fs");
const path = require("node:path");
const { FEATURE_NAMES, normalizeUrl, extractFeatures } = require("./url-features.js");

/** Minimal RFC-4180 CSV parser (quoted fields, escaped quotes, CRLF). */
function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.length > 1 || row[0] !== "") rows.push(row);
  return rows;
}

/** Clean rows into { X, y, stats }. Skips malformed/empty rows and duplicate URLs. */
function buildDataset(csvText) {
  const rows = parseCsv(csvText.replace(/^\uFEFF/, ""));
  const stats = { total: 0, used: 0, skippedInvalidUrl: 0, skippedInvalidLabel: 0, duplicates: 0, conflicting: 0 };
  if (!rows.length) return { X: [], y: [], stats };
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const ui = header.indexOf("url"), si = header.indexOf("status");
  if (ui < 0 || si < 0) throw new Error("CSV must have `url` and `status` columns");
  const seen = new Map();
  const X = [], y = [];
  for (const r of rows.slice(1)) {
    stats.total++;
    const label = String(r[si] ?? "").trim();
    if (!["0", "1", "0.0", "1.0"].includes(label)) { stats.skippedInvalidLabel++; continue; }
    const key = normalizeUrl(r[ui] ?? "");
    const feats = key && extractFeatures(key);
    if (!feats) { stats.skippedInvalidUrl++; continue; }
    const lab = Number(label);
    if (seen.has(key)) {
      stats.duplicates++;
      if (y[seen.get(key)] !== lab) stats.conflicting++;
      continue;
    }
    seen.set(key, X.length);
    X.push(feats);
    y.push(lab);
  }
  stats.used = X.length;
  return { X, y, stats };
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle(arr, rnd) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** Stratified split: each class is split by the same ratio. Returns index arrays. */
function stratifiedSplit(y, testRatio = 0.2, seed = 42) {
  const rnd = mulberry32(seed);
  const train = [], test = [];
  for (const cls of [0, 1]) {
    const idx = shuffle(y.map((v, i) => (v === cls ? i : -1)).filter((i) => i >= 0), rnd);
    const nTest = Math.round(idx.length * testRatio);
    for (let i = 0; i < nTest; i++) test.push(idx[i]);
    for (let i = nTest; i < idx.length; i++) train.push(idx[i]);
  }
  return { train: shuffle(train, rnd), test: shuffle(test, rnd) };
}

/** Log-scale count-like features is left to the model; we only standardize. */
function fitScaler(X) {
  const n = X.length, d = FEATURE_NAMES.length;
  const mean = new Array(d).fill(0), std = new Array(d).fill(0);
  for (const r of X) for (let j = 0; j < d; j++) mean[j] += r[j] / n;
  for (const r of X) for (let j = 0; j < d; j++) std[j] += (r[j] - mean[j]) ** 2 / n;
  for (let j = 0; j < d; j++) std[j] = Math.sqrt(std[j]) || 1;
  return { mean, std };
}

const sigmoid = (z) => 1 / (1 + Math.exp(-z));
const scale = (row, s) => row.map((v, j) => (v - s.mean[j]) / s.std[j]);

/** Mini-batch gradient descent with L2 regularisation. */
function trainLogReg(Xs, y, { epochs = 30, lr = 0.1, l2 = 1e-4, batch = 256, seed = 7 } = {}) {
  const d = Xs[0].length;
  const w = new Array(d).fill(0);
  let b = 0;
  const rnd = mulberry32(seed);
  const order = Xs.map((_, i) => i);
  for (let e = 0; e < epochs; e++) {
    shuffle(order, rnd);
    const step = lr / (1 + e * 0.1);
    for (let s = 0; s < order.length; s += batch) {
      const end = Math.min(s + batch, order.length);
      const gw = new Array(d).fill(0);
      let gb = 0;
      for (let k = s; k < end; k++) {
        const i = order[k], x = Xs[i];
        let z = b;
        for (let j = 0; j < d; j++) z += w[j] * x[j];
        const err = sigmoid(z) - y[i];
        for (let j = 0; j < d; j++) gw[j] += err * x[j];
        gb += err;
      }
      const m = end - s;
      for (let j = 0; j < d; j++) w[j] -= step * (gw[j] / m + l2 * w[j]);
      b -= step * (gb / m);
    }
  }
  return { weights: w, bias: b };
}

/** Metrics treat phishing (status 0) as the positive class. */
function evaluate(yTrue, probLegit, threshold = 0.5) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  yTrue.forEach((t, i) => {
    const predPhish = probLegit[i] < threshold;
    const isPhish = t === 0;
    if (predPhish && isPhish) tp++;
    else if (predPhish) fp++;
    else if (isPhish) fn++;
    else tn++;
  });
  const div = (a, c) => (c ? a / c : 0);
  const precision = div(tp, tp + fp), recall = div(tp, tp + fn);
  return {
    positiveClass: "phishing",
    accuracy: div(tp + tn, tp + fp + tn + fn),
    precision,
    recall,
    f1: div(2 * precision * recall, precision + recall),
    confusionMatrix: { truePhishing: tp, falsePhishing: fp, trueLegit: tn, falseLegit: fn },
    samples: yTrue.length,
  };
}

function predictProbLegit(model, features) {
  const x = scale(features, model.scaler);
  let z = model.bias;
  for (let j = 0; j < x.length; j++) z += model.weights[j] * x[j];
  return sigmoid(z);
}

function run(argv) {
  const args = { csv: "new_data_urls.csv", out: path.join(__dirname, "model"), epochs: 30 };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") args.out = argv[++i];
    else if (argv[i] === "--epochs") args.epochs = Number(argv[++i]);
    else args.csv = argv[i];
  }
  if (!fs.existsSync(args.csv)) {
    console.error(`Dataset not found: ${args.csv}\nUsage: node ml/train-model.js <new_data_urls.csv>`);
    process.exit(1);
  }
  const { X, y, stats } = buildDataset(fs.readFileSync(args.csv, "utf8"));
  console.log("Data cleaning:", JSON.stringify(stats));
  if (new Set(y).size < 2) { console.error("Need both classes to train."); process.exit(1); }

  const { train, test } = stratifiedSplit(y);
  const scaler = fitScaler(train.map((i) => X[i]));
  const Xtr = train.map((i) => scale(X[i], scaler));
  const { weights, bias } = trainLogReg(Xtr, train.map((i) => y[i]), { epochs: args.epochs });
  const model = { weights, bias, scaler };

  const metrics = evaluate(test.map((i) => y[i]), test.map((i) => predictProbLegit(model, X[i])));
  console.log(`Train: ${train.length}  Test: ${test.length}`);
  console.log(`Accuracy:  ${metrics.accuracy.toFixed(4)}`);
  console.log(`Precision: ${metrics.precision.toFixed(4)} (phishing)`);
  console.log(`Recall:    ${metrics.recall.toFixed(4)} (phishing)`);
  console.log(`F1:        ${metrics.f1.toFixed(4)}`);
  console.log("Confusion matrix:", JSON.stringify(metrics.confusionMatrix));

  fs.mkdirSync(args.out, { recursive: true });
  const artifact = {
    version: 1,
    modelType: "logistic_regression",
    description: "P(legit) = sigmoid(bias + sum(weights[i] * (x[i] - mean[i]) / std[i])); status 1 = legit, 0 = phishing.",
    trainedAt: new Date().toISOString(),
    featureNames: FEATURE_NAMES,
    scaler: scaler,
    weights,
    bias,
    metrics,
    dataStats: stats,
  };
  fs.writeFileSync(path.join(args.out, "phishing-model.json"), JSON.stringify(artifact, null, 2));
  fs.writeFileSync(path.join(args.out, "metrics.json"), JSON.stringify({ metrics, dataStats: stats }, null, 2));
  console.log(`Wrote ${path.join(args.out, "phishing-model.json")} and metrics.json`);
}

module.exports = { parseCsv, buildDataset, stratifiedSplit, fitScaler, trainLogReg, evaluate, predictProbLegit };
if (require.main === module) run(process.argv.slice(2));
