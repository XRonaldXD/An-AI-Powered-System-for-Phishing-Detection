# Local ML training pipeline

Trains a lightweight logistic-regression phishing-URL classifier. No dependencies beyond Node.js. The rules engine in `extension/` is not touched.

## Run

```sh
node ml/train-model.js path/to/new_data_urls.csv        # optional: --out <dir> --epochs 30
```

Input CSV: columns `url` and `status` (`1` = legit, `0` = phishing).

Cleaning: URLs without a scheme get `https://`; empty/malformed URLs, non-http(s) URLs and rows with invalid labels are skipped; duplicate URLs (after normalisation) are dropped (first occurrence wins). Counts are printed. By default, the trainer compares 10, 30, and 60 epochs on a stratified training/validation split, selects the phishing decision threshold by validation accuracy (breaking ties with F1), retrains on the combined training and validation data, and reports final metrics on an untouched stratified test split. Pass `--epochs N` to evaluate a single epoch count instead of comparing candidates. The threshold is a `P(legit)` cutoff: values below it are classified as phishing, so raising it increases phishing recall at the cost of more false positives.

## Output (`ml/model/`, git-ignored)

- `phishing-model.json` – feature names, scaler (`mean`/`std`), `weights`, `bias`, selected `phishingThreshold`, baseline and threshold-adjusted test metrics. The installed model applies the validation-selected threshold as an intercept calibration so a phishing score of 50 corresponds to the selected operating point. Features come from `extractFeatures()` in `url-features.js` (UMD, usable in the extension).
- `metrics.json` – accuracy, precision, recall, F1 and confusion matrix (phishing is the positive class).

Tests: `npm test`.

## Use it in the extension

`node ml/train-model.js <csv> --install` also writes `extension/lib/trained-model-data.js` (the artifact as a script). Reload the extension and select **Trained model** under Settings → Scoring mode. `extension/lib/url-features.js` must stay identical to `ml/url-features.js`.
