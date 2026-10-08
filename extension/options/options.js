/** Options page: sensitivity, allowlist and optional provider settings. */
const adapter = self.PhishingScoringAdapter;
const engine = self.PhishingRiskEngine;

const sensitivityEl = document.getElementById("sensitivity");
const domainInput = document.getElementById("domainInput");
const domainError = document.getElementById("domainError");
const allowListEl = document.getElementById("allowList");
const modeEl = document.getElementById("scoringMode");
const providerStatus = document.getElementById("providerStatus");

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

async function saveProvider() {
  const endpoint = document.getElementById("providerEndpoint").value.trim();
  if (endpoint && !/^https:\/\//i.test(endpoint)) {
    providerStatus.textContent = "Enter an https:// endpoint.";
    return;
  }
  await saveSettings({
    provider: {
      enabled: modeEl.value !== "rules",
      name: document.getElementById("providerName").value.trim() || adapter.DEFAULT_SETTINGS.provider.name,
      endpoint,
      apiKey: document.getElementById("providerKey").value,
    },
  });
  providerStatus.textContent = "Saved.";
}

async function init() {
  const settings = await adapter.loadSettings();
  sensitivityEl.value = settings.sensitivity;
  modeEl.value = settings.scoringMode;
  document.getElementById("providerName").value = settings.provider.name;
  document.getElementById("providerEndpoint").value = settings.provider.endpoint;
  document.getElementById("providerKey").value = settings.provider.apiKey;
  renderAllowlist();
}

sensitivityEl.addEventListener("change", () => saveSettings({ sensitivity: sensitivityEl.value }));
modeEl.addEventListener("change", async () => {
  await saveSettings({ scoringMode: modeEl.value });
  const { provider } = await adapter.loadSettings();
  providerStatus.textContent =
    modeEl.value !== "rules" && !/^https:\/\//i.test(provider.endpoint)
      ? "Mode saved. Add an https:// endpoint below, otherwise rules are used."
      : "Mode saved.";
});
document.getElementById("addBtn").addEventListener("click", addDomain);
domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addDomain();
});
document.getElementById("saveProviderBtn").addEventListener("click", saveProvider);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.allowlist) renderAllowlist();
});
init();
