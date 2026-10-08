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

function getFallbackNote(analysis) {
  return analysis.requestedMode === "trained" && analysis.scoringMode !== "trained"
    ? " — trained model unavailable, using " + getModeLabel(analysis)
    : "";
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
  const badge = document.createElement("span");
  badge.className = `mode-badge ${analysis.listStatus ? "trained" : analysis.scoringMode || "rules"}`;
  badge.textContent = modeLabel;
  resultMode.replaceChildren("Mode: ", badge, getFallbackNote(analysis));

  resultSignals.replaceChildren();
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

function setDomainError(message) {
  domainError.textContent = message || "";
  domainError.hidden = !message;
}

async function readLists() {
  const data = await chrome.storage.local.get(["allowlist", "denylist"]);
  return {
    allowlist: Array.isArray(data.allowlist) ? data.allowlist : [],
    denylist: Array.isArray(data.denylist) ? data.denylist : [],
  };
}

function renderDomainList(listEl, key, domains) {
  listEl.replaceChildren();
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
    remove.className = "remove";
    remove.textContent = "×";
    remove.setAttribute("aria-label", `Remove ${domain}`);
    remove.addEventListener("click", async () => {
      const lists = await readLists();
      await chrome.storage.local.set({ [key]: lists[key].filter((d) => d !== domain) });
      loadLists();
    });
    li.append(name, remove);
    listEl.appendChild(li);
  }
}

async function loadLists() {
  const { allowlist: allowed, denylist: denied } = await readLists();
  renderDomainList(allowList, "allowlist", allowed);
  renderDomainList(denyList, "denylist", denied);
}

async function addDomain(domain, key) {
  const lists = await readLists();
  const other = key === "allowlist" ? "denylist" : "allowlist";
  const update = { [other]: lists[other].filter((d) => d !== domain) };
  if (!lists[key].includes(domain)) update[key] = lists[key].concat(domain);
  await chrome.storage.local.set(update);
  await loadLists();
}

async function addFromInput(key) {
  const domain = self.PhishingRiskEngine.normalizeDomain(domainInput.value);
  if (!domain) {
    setDomainError("Enter a valid domain, e.g. example.com");
    return;
  }
  setDomainError("");
  await addDomain(domain, key);
  domainInput.value = "";
}

async function addCurrentDomain(key) {
  if (!currentDomain) return;
  await addDomain(currentDomain, key);
  if (input.value.trim()) analyze(input.value.trim());
}

async function loadHistory() {
  const data = await chrome.storage.local.get("history");
  const history = Array.isArray(data.history) ? data.history : [];
  historyList.replaceChildren();
  if (!history.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No checks yet";
    historyList.appendChild(li);
    return;
  }
  for (const entry of history.slice(0, 10)) {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = `dot ${labelToClass(entry.label)}`;
    const url = document.createElement("span");
    url.className = "history-url";
    url.textContent = entry.url;
    url.title = entry.url;
    const label = document.createElement("span");
    label.className = "history-label";
    label.textContent = entry.label;
    li.append(dot, url, label);
    historyList.appendChild(li);
  }
}

async function loadPageSummary() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number") return;
    chrome.runtime.sendMessage({ type: "GET_TAB_SCAN_RESULT", tabId: tab.id }, (scan) => {
      if (chrome.runtime.lastError || !scan) return;
      pageSummaryText.textContent = `This page: ${scan.suspiciousLinks} suspicious of ${scan.totalLinks} links checked.`;
      pageSummary.hidden = false;
    });
  } catch {
    /* page summary is optional */
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

input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") button.click();
});

loadLists();
loadHistory();
loadPageSummary();
