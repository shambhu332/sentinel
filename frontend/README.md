# SENTINEL Frontend

Vanilla HTML/CSS/JS dashboard for SENTINEL — the open-source Android security scanner. Djini.AI inspired dark aesthetic.

## Run it

No build step required.

```bash
# from this directory:
python3 -m http.server 8765
# then open http://localhost:8765/index.html
```

Or open `index.html` directly in a modern browser.

## Structure

```
frontend/
├── index.html              landing page
├── app.html                dashboard shell (single-page app, hash router)
├── css/
│   ├── base.css            reset + utilities
│   ├── theme.css           dark theme tokens
│   ├── components.css      buttons, cards, tables, modals, badges
│   ├── app.css             dashboard layout
│   └── landing.css         landing page styles
├── js/
│   ├── app-shell.js        sidebar + topbar + router bootstrap
│   ├── router.js           hash router
│   ├── landing.js          landing interactions
│   ├── utils.js            helpers (el, escape, format, highlight, toast)
│   ├── data/
│   │   ├── agents.js       20 specialized agents
│   │   ├── scans.js        40 mock scans + phase timings + Frida events
│   │   ├── findings.js     80+ findings across scans
│   │   └── projects.js     6 mock projects
│   ├── components/
│   │   ├── sidebar.js
│   │   ├── topbar.js
│   │   ├── modal.js
│   │   ├── scan-modal.js   multi-step scan config
│   │   ├── findings-table.js  expandable rows
│   │   ├── severity-badge.js  badges + breakdown chips
│   │   └── code-block.js   syntax-highlighted code
│   └── pages/
│       ├── dashboard.js    overview + charts + recent scans
│       ├── scans.js        filterable + paginated list
│       ├── scan-detail.js  5-tab scan report
│       ├── agents.js       filterable agent catalog
│       ├── settings.js
│       ├── projects.js
│       ├── reports.js
│       ├── history.js
│       └── docs.js
└── assets/
    ├── logo.svg
    └── favicon.svg
```

## Stack

- Vanilla HTML5, CSS3, ES modules — no frameworks, no bundler
- Google Fonts: Inter + JetBrains Mono
- Lucide icons via CDN
- Chart.js via CDN

## Routes (hash-based)

| Route | Page |
|---|---|
| `#dashboard` | Overview |
| `#scans` | Scan list |
| `#scans/<id>` | Scan detail (5 tabs) |
| `#agents` | Agent catalog |
| `#projects` | Project cards |
| `#reports` | Exported reports |
| `#history` | Chronological timeline |
| `#settings` | LLM/scan/theme settings |
| `#docs` | Quick-start docs |

## Design tokens

Cyan accent (`#00D4FF`) on a deep navy background (`#0A0E27`). Severity colors:
critical red, high orange, medium amber, low blue, info gray.
