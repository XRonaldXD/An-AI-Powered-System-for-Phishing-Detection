# An AI-Powered System for Phishing Detection

A Chrome (Manifest V3) extension that warns users about suspicious/phishing
links while browsing and lets them manually paste a URL to see a phishing
risk score with the reasons behind it.

## Features

- **Popup URL analyzer** — paste any URL and instantly get a risk score
  (0–100), a risk label (Low / Medium / High), and the specific reasons that
  contributed to the score.
- **On-page link scanning** — a content script scans every link on the
  current page, visually highlights ones that look suspicious, and asks for
  confirmation before you navigate to them.
- **Toolbar badge** — the extension icon badge reflects the page risk:
  🔵 blue "OK" = no suspicious links, 🟡 yellow = medium risk (1–2
  suspicious links), 🔴 red = high risk (3 or more). Yellow/red badges show
  the suspicious link count.
- **Clear risk explanation** — every result includes a plain-language
  summary and a breakdown of each contributing signal (title, severity,
  points, and why it matters).
- **Indicators dashboard** — the popup shows the risk label, score meter,
  a confidence estimate, and the list of detected signals.
- **Trusted / blocked domains** — manage an allowlist (warnings suppressed,
  score 0) and a denylist (always High risk) from the popup. Subdomains are
  included, and the denylist wins if a domain matches both. Lists are saved
  in `chrome.storage.local` and applied to open pages immediately.
- **History** — the popup's "Recent checks" shows the latest URL analyses and
  page scan summaries (capped at the 50 most recent, clearable).
- **Visual warnings** — risky links get a red outline, a "⚠ Risky link"
  badge, a tooltip with the top reasons, and an overlay on click that lists
  every signal with "Go back" / "Continue anyway" choices.
- **Shared, modular risk engine** — all scoring logic lives in
  [`extension/lib/risk-engine.js`](extension/lib/risk-engine.js) and is
  reused by the popup, the content script, and the background service
  worker, so it is easy to extend or swap in a real ML model / API later.

- **Options page** — open it from the popup's "Settings" link or the
  extension's details page. Choose a sensitivity (Low / Balanced / High,
  which shifts the Medium/High thresholds), manage the trusted-domain
  allowlist, and optionally configure an external scoring provider.
  Settings are stored in `chrome.storage.local` and applied by the popup,
  content script and background worker.
- **Pluggable scoring adapter** — [`extension/lib/scoring-adapter.js`](extension/lib/scoring-adapter.js)
  is the single scoring interface. With a provider enabled, manual URL
  checks send `POST {"url": "..."}` to your HTTPS endpoint (optional API key
  placed in the `Authorization` header) and expect `{"score": 0-100}` or
  `{"probability": 0-1}` plus optional `"reasons": [...]`, which are added
  to `reasons` prefixed with the provider name. If the provider is
  unconfigured or fails, the rule-based engine is used. No endpoint or key is
  bundled; bulk page-link scanning always stays local.

### Quick start: enable AI mode

1. Host any HTTPS endpoint that accepts `POST {"url": "https://..."}` and
   returns `{"score": 72, "reasons": ["Looks like a brand impersonation"]}`
   (or `{"probability": 0.72}`).
2. Open the extension's **Settings**, choose a **Scoring mode** (Rules-based
   is the default; ML-based uses the model's score; Auto takes the higher of
   model and rules), paste the endpoint (the placeholder `https://your-model-host.example/score` is only
   an example), and click **Save endpoint**.
3. Paste a URL in the popup and click Analyze. The provider's verdict is
   used per the selected mode. If the mode is Rules-based, the endpoint is
   missing, unreachable, times out (4 s default) or returns invalid data,
   the local rule-based result is used automatically.

## Privacy

The extension is fully local. It reads the links on pages you visit and URLs
you paste into the popup, scores them with rules running in your browser, and
stores your allowlist/denylist and recent history in `chrome.storage.local`.
Nothing is sent to any server or third party unless you explicitly enable an
external scoring provider on the options page (then only manually checked
URLs are sent to the endpoint you configured).

## Project structure

```text
extension/
├─ manifest.json        # Manifest V3 configuration
├─ background.js         # Service worker: messaging hub, badge, storage init
├─ content.js             # Scans links on the page and warns on suspicious ones
├─ lib/
│  ├─ risk-engine.js      # Shared rule-based URL risk-scoring logic
│  └─ scoring-adapter.js  # Single scoring interface (provider + rule fallback)
├─ options/                # Options page (sensitivity, allowlist, provider)
├─ popup/
│  ├─ popup.html          # Popup UI markup
│  ├─ popup.css           # Popup styling
│  └─ popup.js            # Popup behavior (manual analysis + page summary)
└─ icons/
   ├─ icon16.png
   ├─ icon48.png
   └─ icon128.png
```

## How the risk score works

`analyzeUrl(url)` inspects a URL for common phishing indicators, including:

- IP address used instead of a domain name
- Excessive subdomains or hyphens in the domain
- Suspicious keywords (e.g. `login`, `verify`, `secure`, `bank`, `wallet`)
- Very long or percent-encoded URLs
- Punycode / IDN domains (often used for lookalike domains)
- `@` symbols that can hide the real destination
- Known URL shorteners
- Missing HTTPS

Each indicator adds to a 0–100 score, which maps to **Low risk**
(`< 35`), **Medium risk** (`35–69`), or **High risk** (`≥ 70`). The engine
returns `{ score, label, reasons, url, signals, confidence, summary, listStatus }`
(and accepts optional `{ allowlist, denylist }`), keeping the same shape for future
upgrades (e.g. calling a machine-learning model or a threat-intel API)
straightforward.

## Installing locally (unpacked)

1. Open `chrome://extensions` in Chrome (or a Chromium-based browser).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the [`extension/`](extension) folder.
4. Pin the extension and click its icon to open the popup.

## Running tests

Requires Node.js 18+ (no dependencies):

```bash
npm test
```

Tests live in [`tests/`](tests) and cover `analyzeUrl` edge cases and the
scoring adapter's provider/fallback behavior.
