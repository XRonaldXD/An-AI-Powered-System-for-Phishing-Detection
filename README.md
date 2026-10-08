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
  worker, so it is easy to extend.

- **Options page** — open it from the popup's "Settings" link or the
  extension's details page. Choose a sensitivity (Low / Balanced / High,
  which shifts the Medium/High thresholds), manage the trusted-domain
  allowlist, and choose the scoring mode (rules-based, local ML or trained model).
  Settings are stored in `chrome.storage.local` and applied by the popup,
  content script and background worker.
- **Three local scoring modes** — pick one in **Settings → Scoring mode**:
  - **Rules-based** (default): the heuristic engine in `risk-engine.js`.
  - **Local ML**: a compact logistic-regression model bundled in
    [`extension/lib/ml-model.js`](extension/lib/ml-model.js). It extracts
    URL-derived features (IP host, `@`, punycode, shorteners, suspicious TLDs,
    keywords, subdomains, hyphens, digit ratio, length, entropy, port, path
    depth), computes a weighted sum, and applies a sigmoid to get a 0–100
    score. The strongest features become the `reasons`/`signals`.
  - **Trained model**: the `phishing-model.json` produced by
    [`ml/train-model.js`](ml/train-model.js), packaged for the extension and
    run by [`extension/lib/trained-model.js`](extension/lib/trained-model.js).
    Install it with `node ml/train-model.js path/to/new_data_urls.csv --install`
    (writes `extension/lib/trained-model-data.js`), then reload the extension
    and choose **Trained model** in Settings. If no valid model is installed
    or it fails, scoring falls back to Local ML, then to rules.
  All modes run entirely in your browser — no endpoint, API key or network
  request is needed. The popup shows which mode produced each result.
- **Scoring adapter** — [`extension/lib/scoring-adapter.js`](extension/lib/scoring-adapter.js)
  is the single scoring interface. Manual popup checks respect the selected
  mode; if the ML model is unavailable or fails, the rules result is used.
  Allowlisted/denylisted domains and invalid URLs are always handled by the
  rules engine, and bulk page-link scanning always stays rules-based for speed.

## Privacy

The extension is fully local. It reads the links on pages you visit and URLs
you paste into the popup, scores them with rules running in your browser, and
stores your allowlist/denylist and recent history in `chrome.storage.local`.
Nothing is sent to any server or third party, in either scoring mode.

## Project structure

```text
extension/
├─ manifest.json        # Manifest V3 configuration
├─ background.js         # Service worker: messaging hub, badge, storage init
├─ content.js             # Scans links on the page and warns on suspicious ones
├─ lib/
│  ├─ risk-engine.js      # Shared rule-based URL risk-scoring logic
│  ├─ ml-model.js         # Bundled local ML classifier (URL features)
│  ├─ url-features.js     # Feature extraction (copy of ml/url-features.js)
│  ├─ trained-model*.js   # Trained model runtime + installed artifact data
│  └─ scoring-adapter.js  # Single scoring interface (rules / ML / trained + fallback)
├─ options/                # Options page (sensitivity, allowlist, scoring mode)
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
scoring adapter's mode switching, local ML and fallback behavior.
