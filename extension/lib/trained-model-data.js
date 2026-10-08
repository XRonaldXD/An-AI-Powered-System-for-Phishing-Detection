/**
 * Placeholder for the trained model artifact. No model is installed by default.
 * Generate the real file with:
 *   node ml/train-model.js path/to/new_data_urls.csv --install
 * which overwrites this file with the contents of `phishing-model.json`.
 */
(function () {
  const artifact = null;
  if (typeof module !== "undefined") module.exports = artifact;
  if (typeof globalThis !== "undefined") globalThis.PhishingTrainedModelData = artifact;
})();
