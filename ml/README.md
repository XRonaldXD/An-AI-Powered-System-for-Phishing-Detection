# Local ML training pipeline

Trains a lightweight logistic-regression phishing-URL classifier. No dependencies beyond Node.js. The rules engine in `extension/` is not touched.

## Run

```sh
node ml/train-model.js path/to/new_data_urls.csv        # optional: --out <dir> --epochs 30
```

Input CSV: columns `url` and `status` (`1` = legit, `0` = phishing).

Cleaning: URLs without a scheme get `https://`; empty/malformed URLs, non-http(s) URLs and rows with invalid labels are skipped; duplicate URLs (after normalisation) are dropped (first occurrence wins). Counts are printed. Data is split 80/20, stratified by class.

## Output (`ml/model/`, git-ignored)

- `phishing-model.json` – feature names, scaler (`mean`/`std`), `weights`, `bias`, metrics. Inference: `P(legit) = sigmoid(bias + Σ weights[i]·(x[i]−mean[i])/std[i])`, with `x` from `extractFeatures()` in `url-features.js` (UMD, usable in the extension).
- `metrics.json` – accuracy, precision, recall, F1 and confusion matrix (phishing is the positive class).

Tests: `npm test`.
