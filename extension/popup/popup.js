const input = document.getElementById("urlInput");
const button = document.getElementById("analyzeBtn");
const result = document.getElementById("result");
const resultLabel = document.getElementById("resultLabel");
const resultScore = document.getElementById("resultScore");
const pageSummary = document.getElementById("pageSummary");
const pageSummaryText = document.getElementById("pageSummaryText");

function labelToClass(label) {
  if (label === "High risk") return "high";
  if (label === "Medium risk") return "medium";
  if (label === "Invalid URL") return "invalid";
  return "low";
}

const resultSummary = document.getElementById("resultSummary");
const indicators = document.getElementById("indicators");
const meterFill = document.getElementById("meterFill");
const resultConfidence = document.getElementById("resultConfidence");
const resultMode = document.getElementById("resultMode");
const resultSignals = document.getElementById("resultSignals");
const listActions = document.getElementById("listActions");
const domainInput = document.getElementById("domainInput");
const allowList = document.getElementById("allowList");
const denyList = document.getElementById("denyList");
const historyList = document.getElementById("historyList");
const trustBtn = document.getElementById("trustBtn");
const blockBtn = document.getElementById("blockBtn");
const trustDomainBtn = document.getElementById("trustDomainBtn");
const blockDomainBtn = document.getElementById("blockDomainBtn");
const domainError = document.getElementById("domainError");
const openOptions = document.getElementById("openOptions");

let currentDomain = null;

function getModeLabel(analysis) {
  if (analysis.listStatus) return analysis.listStatus === "allowlist" ? "Trusted list" : "Blocked list";
  if (analysis.scoringMode === "ml") return "Local ML";
  if (analysis.scoringMode === "trained") return "Trained model";
  return "Rules-based";
}

function showResult(analysis) {
  const invalid = analysis.label === "Invalid URL";
  result.classList.remove("hidden", "low", "medium", "high", "invalid");
  result.classList.add(labelToClass(analysis.label));

  resultLabel.textContent = analysis.label;
  resultScore.textContent = invalid ? "" : `${analysis.score}/100`;
  resultSummary.textContent = analysis.summary || analysis.reasons.join(" ");

  indicators.hidden = invalid;
  listActions.hidden = invalid;
  currentDomain = invalid ? null : self.PhishingRiskEngine.normalizeDomain(analysis.url);

  meterFill.style.width = `${analysis.score}%`;
  const modeLabel = getModeLabel(analysis);
  resultConfidence.textContent = `Confidence: ${analysis.confidence}%${analysis.listStatus ? " (from your list)" : analysis.scoringMode === "ml" ? " (local ML estimate)" : analysis.scoringMode === "trained" ? " (trained model estimate)" : " (rule-based estimate)"}`;
  resultMode.innerHTML = `Mode: <span class="mode-badge ${analysis.listStatus ? "trained" : analysis.scoringMode || "rules"}">${modeLabel}</span>`;

  resultSignals.innerHTML = "";
  const signals = analysis.signals || [];
  if (!signals.length && !invalid) {
    const li = document.createElement("li");
    li.textContent = analysis.reasons[0];
    resultSignals.appendChild(li);
  }
  for (const signal of signals) {
    const li = document.createElement("li");
    const title = document.createElement("div");
    title.className = "signal-title";
    const name = document.createElement("span");
    name.textContent = signal.title;
    const points = document.createElement("span");
    points.className = "signal-points";
    points.textContent = `${signal.severity} · +${signal.points}`;
    title.append(name, points);
    const text = document.createElement("span");
    text.className = "signal-text";
    text.textContent = signal.explanation;
    li.append(title, text);
    resultSignals.appendChild(li);
  }
}

function analyze(value) {
  chrome.runtime.sendMessage({ type: "ANALYZE_URL", url: value }, (analysis) => {
    if (chrome.runtime.lastError || !analysis) {
      self.PhishingScoringAdapter.loadSettings()
        .then((settings) => self.PhishingScoringAdapter.analyze(value, settings))
        .catch(() => self.PhishingScoringAdapter.analyzeLocal(value))
        .then((fallback) => {
          showResult(fallback);
          loadHistory();
        });
      return;
    }
    showResult(analysis);
    loadHistory();
  });
}

button.addEventListener("click", () => {
  const value = input.value.trim();
  if (!value) {
    input.focus();
    return;
  }
  analyze(value);
});

trustBtn.addEventListener("click", () => {
  if (currentDomain) addCurrentDomain("allowlist");
});

blockBtn.addEventListener("click", () => {
  if (currentDomain) addCurrentDomain("denylist");
});

trustDomainBtn.addEventListener("click", async () => {
  await addFromInput("allowlist");
});

blockDomainBtn.addEventListener("click", async () => {
  await addFromInput("denylist");
});

openOptions.addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});
