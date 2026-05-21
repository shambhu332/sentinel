# SENTINEL — Frontend

Vanilla HTML / CSS / JS web frontend for **SENTINEL**, an open-source multi-agent
Android security scanner. No build step, no framework, no npm install. Everything
runs in the browser from local files.

The only network requests at runtime are to Google Fonts, the Lucide icon CDN,
Chart.js (CDN), and jsPDF (CDN) — all over HTTPS.

---

## Run it

Two options. Pick whichever you prefer.

### Option A — open the files directly

```sh
cd frontend
xdg-open index.html        # Linux
open index.html            # macOS
start index.html           # Windows
```

Some browsers block ES module imports over the `file://` protocol. If `app.html`
shows an empty layout or its console reports a module-loading error, use Option B.

### Option B — serve over a local HTTP port

```sh
cd frontend
python3 -m http.server 8000
# then open http://localhost:8000/index.html
```

Any static server works (`npx serve`, `php -S 0.0.0.0:8000`, etc.) — there is no
build step to run first.

---

## Pages

| File              | URL fragment            | What it is                                          |
|-------------------|-------------------------|-----------------------------------------------------|
| `index.html`      | —                       | Marketing landing page                              |
| `app.html`        | `#dashboard`            | Welcome dashboard (default landing in the app shell) |
| `app.html`        | `#projects`             | Project grid                                        |
| `app.html`        | `#projects/<id>`        | Project detail (Overview / Scans / Findings / Scope / Team / Settings) |
| `app.html`        | `#history`              | Scan history table                                  |
| `app.html`        | `#history/<scanId>`     | Opens the scan-detail slide-over sheet on load      |
| `app.html`        | `#reports`              | Saved reports grid + 5-step report builder          |
| `app.html`        | `#agents`               | Full catalogue of all 20 agents with filters        |
| `app.html`        | `#architecture`         | Long-form architecture explainer                    |
| `app.html`        | `#workspaces`           | Workspace grid                                      |
| `app.html`        | `#workspaces/<id>`      | Workspace detail (Members / Projects / Settings / Audit log) |
| `app.html`        | `#settings`             | User + instance settings                            |
| `app.html`        | `#demo`                 | Interactive simulated scan run                      |
| `404.html`        | —                       | Themed not-found page                               |

---

## Feature checklist

### Landing (`index.html`)
- [x] Sticky navbar that blurs on scroll
- [x] Hero with gradient headline + animated orbs (violet / cyan / mint)
- [x] Terminal mockup with typewriter effect cycling through 3 commands
- [x] Animated stats row (count-up via IntersectionObserver)
- [x] 5-phase pipeline timeline
- [x] 20-agent showcase grid with All / SAST / DAST / Meta tab filter
- [x] LLM router section with animated provider rotation SVG
- [x] Dynamic analysis tabs: Traffic capture / Runtime hooks
- [x] Scope parser preview with mock HackerOne scope card
- [x] Full-pipeline architecture diagram (SVG)
- [x] Tech stack row
- [x] CTA panel with gradient border
- [x] Footer with three columns + social row

### App shell (`app.html`)
- [x] Fixed sidebar with logo, workspace switcher (3 mock workspaces), 8 nav rows, user card, sign-out
- [x] Sidebar collapses to icon-only at <1024px, becomes a hamburger drawer at <768px
- [x] Topbar with breadcrumb, search input, notifications (mock badge), help icon, **+ New scan** button
- [x] New Scan modal — APK picker, project, scope, options (5 toggles), durations, live CLI preview
- [x] Hash-based router with sub-routes (`#projects/<id>`, `#history/<id>`, `#workspaces/<id>`)
- [x] Animated dot-grid background canvas (fixed, behind everything)

### Dashboard
- [x] Greeting + quick stats (total / critical / high / medium)
- [x] Active project card with **Scan now** + **View**
- [x] Severity donut chart (Chart.js)
- [x] Findings trend line chart, last 14 days, Critical + High (Chart.js)
- [x] Recent scans table (top 5) with severity chip row
- [x] Activity feed (4 mock entries)
- [x] Quickstart cards (Demo / Agents / Architecture)
- [x] **Scan now** triggers the simulated scan into the dashboard panel

### Projects
- [x] Filter bar (search / status / workspace)
- [x] 3-column responsive grid of 8 mock projects
- [x] Avatar stacks, status pills, scan / finding counts
- [x] Detail view with 6 tabs: Overview · Scans · Findings · Scope · Team · Settings
- [x] Project metrics, severity distribution, latest scan summary
- [x] Scope tab renders in-scope packages, domains, exclusions, forbidden techniques, reward tiers

### Scan history
- [x] Filters bar (search / project / status / date range)
- [x] Bulk action bar that appears when rows are selected
- [x] Full table — scan ID, project, APK + size, phase dots, severity chips, started, duration, status
- [x] Pagination (10 / 25 / 50 per page)
- [x] Row click opens a 720px slide-over sheet with 5 tabs:
  - Summary (phase timings + severity totals + triage breakdown)
  - Findings (full table)
  - Frida events (timeline — only present when the scan ran Frida)
  - Raw JSON (syntax-highlighted)
  - Warnings

### Reports
- [x] 6 saved-report cards (PDF / HTML / MD / JSON mix) with Preview / Download
- [x] 5-step builder: Source → Template → Sections → Branding → Format
- [x] Live preview pane on the right, updates on every form change
- [x] **PDF** generation via jsPDF (cover page + per-scan findings detail)
- [x] **HTML** generation opens a styled report in a new tab
- [x] **Markdown** generation triggers a `.md` download
- [x] **JSON** generation triggers a `.json` download of the structured scan data

### Agents
- [x] Left filter sidebar — search, category, severity, phase
- [x] Dense responsive card grid (2 columns desktop, 1 mobile)
- [x] All 20 agents present with id, full class name, category, severity range, phase
- [x] Expandable details: what it detects, sample finding, key heuristics, FP rate + notes

### Architecture
- [x] 5-phase pipeline timeline with phase number + components
- [x] Tool layer table (JADX / Androguard / apktool / mitmproxy / frida-server)
- [x] `BaseAgent` code block
- [x] LLM router sequence diagram (SVG)
- [x] `ALL_RUNTIME_HOOKS` Frida script (verbatim from the Python source)
- [x] Crash-proof `ToolResult` code excerpt
- [x] Memory layer section
- [x] Honest real-device validation section (Knox/RKP caveat, anti-debug caveat)

### Workspaces
- [x] 3 workspace cards: Personal · Bug Bounty Hunters · University Capstone
- [x] Detail view: Members · Projects · Settings · Audit log

### Settings
- [x] Profile + About cards
- [x] LLM provider cards (Groq / Cerebras / Ollama) with mock 14-day usage bars (Chart.js)
- [x] Privacy & data + Notifications cards
- [x] Scan defaults card (5 toggles)
- [x] API tokens table (3 mock tokens) with Revoke
- [x] About card with version, commit hash, license, GitHub link

### Demo
- [x] Left column: sample APK picker, scope textarea, option toggles, **Run scan** button
- [x] Right column: phase timeline + live log + animated findings table
- [x] End-to-end animation paced at 14–18 seconds
- [x] Same `scan-runner` is reused by the New-Scan modal flow

---

## Design system

- Dark-only theme. Tokens live in `css/base.css`.
- Severity colours: Critical `#EF4444` · High `#F97316` · Medium `#FBBF24` · Low `#3B82F6` · Info `#6B7280`
- Triage colours: verified `#10B981` · filtered `#EF4444` · uncertain `#FBBF24` · skipped `#6B7280`
- Accent gradient: violet `#7C3AED` → cyan `#22D3EE` → mint `#34D399`
- Fonts: Inter (body) and JetBrains Mono (code / IDs / hashes), both via Google Fonts
- Every interactive element has a visible focus ring
- Every animation respects `prefers-reduced-motion: reduce`
- Responsive breakpoints: 375 · 768 · 1024 · 1440

---

## File layout

```
frontend/
├── index.html, app.html, 404.html
├── css/
│   ├── base.css        — tokens, reset, typography, layout primitives, utilities
│   ├── components.css  — buttons, cards, chips, tables, forms, modals, sidebar, tabs
│   ├── landing.css     — landing-page only sections
│   └── app.css         — app shell + dashboard + view layouts
├── js/
│   ├── data/           — 6 files: agents, workspaces, projects, scans, findings, reports
│   ├── components/     — sidebar, topbar, modal, scan-runner, charts, toast, severity-chip, triage-chip, findings-table
│   ├── views/          — dashboard, projects, workspaces, history, reports, agents, architecture, settings, demo
│   ├── grid-bg.js      — animated dot-grid canvas (auto-mounts)
│   ├── router.js       — hash router for app.html
│   ├── landing.js      — landing-page interactions
│   └── main-app.js     — bootstraps app.html
└── assets/             — logo.svg, favicon.svg, og-image.svg
```

---

## Notes

- All scans, findings, and reports are mock data. No real backend is reached.
- The "+ New scan" flow simulates a real run with `setTimeout` pacing — pace is 14–18 s.
- Scope and finding data is consistent with the Python project at `sentinel/sentinel/` —
  agent IDs, phase names, and pipeline structure match the implementation.
