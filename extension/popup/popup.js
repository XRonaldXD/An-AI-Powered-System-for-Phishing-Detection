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

let currentDomain = null;

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
  resultConfidence.textContent = `Confidence: ${analysis.confidence}%${analysis.listStatus ? " (from your list)" : analysis.scoringMode === "ml" ? " (local ML estimate)" : " (rule-based estimate)"}`;
  resultMode.textContent = invalid ? "" : `Mode: ${analysis.scoringMode === "ml" ? "Local ML" : "Rules-based"}`;

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
    showResult({ label: "Invalid URL", score: 0, reasons: ["Please enter a URL to analyze."], signals: [], confidence: 0 });
    return;
  }
  analyze(value);
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
      if (summary.riskLevel === "high") {
        pageSummaryText.textContent =
          `🔴 High risk: ${summary.suspiciousLinks} suspicious link(s) out of ${summary.totalLinks} on this page.`;
      } else if (summary.suspiciousLinks > 0) {
        pageSummaryText.textContent =
          `🟡 Medium risk: found ${summary.suspiciousLinks} suspicious link(s) out of ${summary.totalLinks} on this page.`;
      } else {
        pageSummaryText.textContent = `🔵 Low risk: no suspicious links detected among ${summary.totalLinks} scanned.`;
      }
    });
  });
}

loadPageSummary();

// ---- Allowlist / denylist management (chrome.storage.local) ----

const allowListEl = document.getElementById("allowList");
const denyListEl = document.getElementById("denyList");

async function getLists() {
  const data = await chrome.storage.local.get(["allowlist", "denylist"]);
  return {
    allowlist: Array.isArray(data.allowlist) ? data.allowlist : [],
    denylist: Array.isArray(data.denylist) ? data.denylist : [],
  };
}

function renderDomains(listEl, key, domains) {
  listEl.innerHTML = "";
  if (!domains.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "None yet";
    listEl.appendChild(li);
    return;
  }
  for (const domain of domains) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = domain;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "small";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      const lists = await getLists();
      await chrome.storage.local.set({ [key]: lists[key].filter((d) => d !== domain) });
      renderLists();
    });
    li.append(name, remove);
    listEl.appendChild(li);
  }
}

async function renderLists() {
  const lists = await getLists();
  renderDomains(allowListEl, "allowlist", lists.allowlist);
  renderDomains(denyListEl, "denylist", lists.denylist);
}

/** Add a domain to one list; a domain lives on only one list at a time. */
async function addDomain(raw, key) {
  const domain = self.PhishingRiskEngine.normalizeDomain(raw);
  if (!domain) return false;
  const other = key === "allowlist" ? "denylist" : "allowlist";
  const lists = await getLists();
  await chrome.storage.local.set({
    [key]: lists[key].includes(domain) ? lists[key] : [...lists[key], domain],
    [other]: lists[other].filter((d) => d !== domain),
  });
  renderLists();
  return true;
}

async function addFromInput(key) {
  if (await addDomain(domainInput.value, key)) domainInput.value = "";
}

document.getElementById("addAllowBtn").addEventListener("click", () => addFromInput("allowlist"));
document.getElementById("addDenyBtn").addEventListener("click", () => addFromInput("denylist"));

async function addCurrentDomain(key) {
  if (!currentDomain) return;
  await addDomain(currentDomain, key);
  analyze(input.value.trim());
}
document.getElementById("trustBtn").addEventListener("click", () => addCurrentDomain("allowlist"));
document.getElementById("blockBtn").addEventListener("click", () => addCurrentDomain("denylist"));

// ---- History ----

const historyList = document.getElementById("historyList");

async function loadHistory() {
  const data = await chrome.storage.local.get("history");
  const history = Array.isArray(data.history) ? data.history : [];
  historyList.innerHTML = "";
  if (!history.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No checks yet";
    historyList.appendChild(li);
    return;
  }
  for (const entry of history) {
    const li = document.createElement("li");
    li.className = labelToClass(entry.label);
    const text = document.createElement("span");
    text.textContent = entry.type === "page"
      ? `Page: ${entry.url} (${entry.suspiciousLinks}/${entry.totalLinks} risky links)`
      : entry.url;
    const meta = document.createElement("span");
    meta.className = "history-meta";
    meta.textContent = `${entry.label}${entry.type === "url" ? ` ${entry.score}` : ""} · ${new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    li.append(text, meta);
    historyList.appendChild(li);
  }
}

document.getElementById("clearHistoryBtn").addEventListener("click", async () => {
  await chrome.storage.local.remove("history");
  loadHistory();
});

renderLists();
loadHistory();

document.getElementById("openOptions").addEventListener("click", (event) => {
  event.preventDefault();
  chrome.runtime.openOptionsPage();
});
