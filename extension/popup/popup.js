const input = document.getElementById("urlInput");
const button = document.getElementById("analyzeBtn");
const result = document.getElementById("result");
const resultLabel = document.getElementById("resultLabel");
const resultScore = document.getElementById("resultScore");
const resultReasons = document.getElementById("resultReasons");
const pageSummary = document.getElementById("pageSummary");
const pageSummaryText = document.getElementById("pageSummaryText");

function labelToClass(label) {
  if (label === "High risk") return "high";
  if (label === "Medium risk") return "medium";
  if (label === "Invalid URL") return "invalid";
  return "low";
}

function showResult(analysis) {
  result.classList.remove("hidden", "low", "medium", "high", "invalid");
  result.classList.add(labelToClass(analysis.label));

  resultLabel.textContent = analysis.label;
  resultScore.textContent = analysis.label === "Invalid URL" ? "" : `${analysis.score}/100`;

  resultReasons.innerHTML = "";
  for (const reason of analysis.reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    resultReasons.appendChild(li);
  }
}

button.addEventListener("click", () => {
  const value = input.value.trim();
  if (!value) {
    showResult({ label: "Invalid URL", score: 0, reasons: ["Please enter a URL to analyze."] });
    return;
  }
  const analysis = self.PhishingRiskEngine.analyzeUrl(value);
  showResult(analysis);
});

input.addEventListener("keydown", (event) => {
  if (event.key === "Enter") button.click();
});

// Show a quick summary of link scanning results for the current tab, if any.
function loadPageSummary() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab || typeof tab.id !== "number") return;

    chrome.runtime.sendMessage({ type: "GET_TAB_SCAN_RESULT", tabId: tab.id }, (summary) => {
      if (chrome.runtime.lastError || !summary) return;

      pageSummary.hidden = false;
      if (summary.suspiciousLinks > 0) {
        pageSummaryText.textContent =
          `⚠ Found ${summary.suspiciousLinks} suspicious link(s) out of ${summary.totalLinks} on this page.`;
      } else {
        pageSummaryText.textContent = `✅ No suspicious links detected among ${summary.totalLinks} scanned.`;
      }
    });
  });
}

loadPageSummary();
