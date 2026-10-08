/** Options page: sensitivity, allowlist and scoring mode. */
const adapter = self.PhishingScoringAdapter;
const engine = self.PhishingRiskEngine;

const sensitivityEl = document.getElementById("sensitivity");
const domainInput = document.getElementById("domainInput");
const domainError = document.getElementById("domainError");
const allowListEl = document.getElementById("allowList");
const modeEl = document.getElementById("scoringMode");
const activeModeEl = document.getElementById("activeMode");
const modeStatus = document.getElementById("modeStatus");

async function saveSettings(patch) {
  const data = await chrome.storage.local.get("settings");
  await chrome.storage.local.set({ settings: { ...(data.settings || {}), ...patch } });
}

async function renderAllowlist() {
  const { allowlist } = await adapter.loadSettings();
  allowListEl.replaceChildren();
  for (const domain of allowlist) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = domain;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "small";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      const current = (await adapter.loadSettings()).allowlist;
      await chrome.storage.local.set({ allowlist: current.filter((d) => d !== domain) });
      renderAllowlist();
    });
    li.append(name, remove);
    allowListEl.appendChild(li);
  }
}

async function addDomain() {
  const domain = engine.normalizeDomain(domainInput.value);
  domainError.hidden = !!domain;
  if (!domain) {
    domainError.textContent = "Enter a valid domain such as example.com.";
    return;
  }
  const { allowlist, denylist } = await adapter.loadSettings();
  if (!allowlist.includes(domain)) {
    // Mirror the popup: a domain cannot be both trusted and blocked.
    await chrome.storage.local.set({
      allowlist: allowlist.concat(domain),
      denylist: denylist.filter((d) => d !== domain),
    });
  }
  domainInput.value = "";
  renderAllowlist();
}

const MODE_LABELS = { rules: "Rules-based", ml: "Local ML", trained: "Trained model" };

function renderActiveMode(mode) {
  let text = `Active scoring mode: ${MODE_LABELS[mode] || MODE_LABELS.rules}`;
  if (mode === "trained" && !adapter.isTrainedModelAvailable()) {
    text += " — no trained model installed, using Local ML instead (run: node ml/train-model.js <csv> --install, then reload the extension).";
  }
  activeModeEl.textContent = text;
}

async function init() {
  const settings = await adapter.loadSettings();
  sensitivityEl.value = settings.sensitivity;
  modeEl.value = settings.scoringMode;
  renderActiveMode(settings.scoringMode);
  renderAllowlist();
}

sensitivityEl.addEventListener("change", () => saveSettings({ sensitivity: sensitivityEl.value }));
modeEl.addEventListener("change", async () => {
  await saveSettings({ scoringMode: modeEl.value });
  renderActiveMode(modeEl.value);
  modeStatus.textContent = "Mode saved.";
});
document.getElementById("addBtn").addEventListener("click", addDomain);
domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addDomain();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.allowlist) renderAllowlist();
});
init();
