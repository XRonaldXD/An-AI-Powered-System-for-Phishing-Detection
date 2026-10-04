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
- **Shared, modular risk engine** — all scoring logic lives in
  [`extension/lib/risk-engine.js`](extension/lib/risk-engine.js) and is
  reused by the popup, the content script, and the background service
  worker, so it is easy to extend or swap in a real ML model / API later.

## Project structure

```text
extension/
├─ manifest.json        # Manifest V3 configuration
├─ background.js         # Service worker: messaging hub, badge, storage init
├─ content.js             # Scans links on the page and warns on suspicious ones
├─ lib/
│  └─ risk-engine.js      # Shared rule-based URL risk-scoring logic
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
returns `{ score, label, reasons, url }`, keeping the same shape for future
upgrades (e.g. calling a machine-learning model or a threat-intel API)
straightforward.

## Installing locally (unpacked)

1. Open `chrome://extensions` in Chrome (or a Chromium-based browser).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the [`extension/`](extension) folder.
4. Pin the extension and click its icon to open the popup.

## Roadmap ideas

- Replace/augment the rule-based engine with a trained ML model or a
  threat-intelligence API while keeping the same return shape.
- Add an options page for user-configurable sensitivity/allowlists.
- Add automated tests for `analyzeUrl` edge cases.
