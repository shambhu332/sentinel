# Claude Code Prompt — SENTINEL Marketing Site + App Shell (vanilla HTML/CSS/JS)

## Project context

You're building the full web frontend for **SENTINEL**, an open-source multi-agent Android security scanner. The Python codebase lives at `~/Desktop/project/sentinel/sentinel/` — leave it alone. Your job is to build the entire frontend in `~/Desktop/project/sentinel/frontend/`, which is currently empty.

The audience is dual:
1. A **teacher reviewing a final-year project** who needs to see depth, polish, and that every project feature is represented in the UI.
2. **Open-source users / bug bounty hunters** evaluating whether to adopt SENTINEL.

Take strong visual inspiration from **https://djini.ai**: dark theme, generous whitespace, gradient hero, glassmorphism cards, animated grid background, clean modern typography, confident "this is a real product" tone. Adapt the aesthetic to a security/research context: deep slate background, electric cyan and violet accents, mono-font code blocks, severity-coloured chips, subtle terminal flourishes.

This is a **fully static frontend with rich mock data**. No real backend, no fetch calls to an API — every scan, project, finding, and report is baked into JS objects in `/data/`. The Demo and Run-scan flows are simulated with `setTimeout` to feel real.

## Tech stack — strict

- **Vanilla HTML5** (multiple pages, plus an app shell that swaps views client-side)
- **Vanilla CSS** with custom properties for theming, **no Tailwind, no SCSS, no PostCSS**, no build step
- **Vanilla JS as ES modules** (`<script type="module">`), no framework, no bundler
- **Google Fonts** via `<link>` (Inter + JetBrains Mono)
- **Lucide icons** via the CDN `<script>` and `data-lucide` attributes (no npm install)
- **Chart rendering** via either inline SVG or [`Chart.js`](https://cdn.jsdelivr.net/npm/chart.js) loaded from a CDN (use this for the dashboard bar/donut charts and trend lines)
- **PDF export** via [`jsPDF`](https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js) loaded from a CDN — used in the Reports tab to generate downloadable PDFs from scan data

No frameworks, no React, no Vue, no Svelte. No npm install. Open `index.html` in a browser and it should just work. The only network requests at runtime are to Google Fonts, the Lucide CDN, Chart.js CDN, and jsPDF CDN — all over HTTPS.

## What SENTINEL actually does (use this for accurate copy — no inventing features)

A 5-phase pipeline that ingests an Android APK and produces triaged security findings:

- **Phase 0 — Ingestion**: SHA-256 hash, workspace setup, manifest extraction.
- **Phase 1 — Parallel Recon**: JADX, Androguard, apktool, and manifest parser run concurrently via `asyncio.gather`. Each is crash-proof — one tool failing never blocks the others.
- **Phase 2 — 20 Analysis Agents**: full catalog in the Agents section below.
- **Phase 3 — LLM Triage**: a `FreeProviderRouter` rotates Groq → Cerebras → local Ollama with rate-limit backoff. Findings get classified as `verified` ✓ / `filtered` ✗ / `uncertain` ? / `skipped` —. Privacy mode pins it to local Ollama only.
- **Phase 4 — Dynamic Analysis (DAST)**: optional, needs a rooted Android device. Launches the app, sets the device WiFi proxy to a local mitmproxy, captures TLS traffic. `--no-proxy` mode skips proxy setup for apps with anti-MITM detection (Signal, banking).
- **Phase 4.5 — Frida Runtime Hooks**: injects JS hooks via standalone frida-server. Hooks `Cipher.getInstance`, `MessageDigest.getInstance`, six pinning libraries (OkHttp `CertificatePinner`, `X509TrustManagerExtensions`, `WebViewClient.onReceivedSslError`, TrustKit, Conscrypt, OkHostnameVerifier). Detects pinning bypass success, "survived" resistance, or absence.

### Full 20-agent catalog (every agent must appear in the Agents tab with id, full name, category, severity range, phase, one-line description)

**Meta & smoke (2)**
- `META_001` ObfuscationDetectorAgent — meta — Info — Phase 2 — Detects obfuscated bytecode, flags scans where coverage may be reduced
- `TEST_001` PipelineSmokeTestAgent — meta — Info — Phase 2 — Self-test that the orchestrator wiring is intact

**SAST static analysis (14)**
- `A_001` InsecureAuthStorage — auth — High — Phase 2 — Auth tokens written to SharedPreferences/SQLite in cleartext
- `A_003` RuntimeCrypto — crypto/DAST — High → Critical — Phase 4.5 — Runtime use of DES/RC4/MD5/ECB observed via Frida
- `A_004` HardcodedSecrets — secrets — High — Phase 2 — API keys, JWTs, AWS credentials embedded in code/resources
- `A_007` InsecureLogging — logging — Medium — Phase 2 — Sensitive data passed to Log.d/Log.v
- `B_002` InsecureRandom — crypto — High — Phase 2 — java.util.Random used for security-sensitive values
- `C_001` InsecureBackup — storage — High — Phase 2 — android:allowBackup="true" exposes app data via adb backup
- `C_002` WorldReadableStorage — storage — High — Phase 2 — Files written with MODE_WORLD_READABLE
- `C_004` InsecureWebView — webview — High — Phase 2 — JS enabled + addJavascriptInterface or loadUrl with user input
- `C_006` InsecureSharedPrefs — storage — High — Phase 2 — Sensitive keys persisted unencrypted in SharedPreferences
- `C_007` WeakCrypto — crypto — Medium → High — Phase 2 — DES/MD5/SHA-1 declared in code
- `F_001` FirebaseMisconfig — cloud — Critical → High — Phase 2 — Public-readable Firestore/Realtime DB rules
- `N_001` MissingCertPinning — network — High — Phase 2 — OkHttp/Retrofit without CertificatePinner configured
- `N_002` CleartextTraffic — network — High — Phase 2 — HTTP URLs or cleartext-traffic permitted in network security config
- `P_001` DeepLinkHijack — platform — High — Phase 2 — Deep link intent filters without verification, hijack risk
- `P_004` ContentProviderIDOR — platform — High — Phase 2 — Exported ContentProviders without URI-level permission checks

**DAST mitmproxy (2)**
- `N_003` ImproperTLS — network — High — Phase 4 — Cert validation failures observed in live traffic
- `N_004` DataInTransit — network — Critical — Phase 4 — PII/credentials transmitted unencrypted

**DAST Frida (1)**
- `N_005` CertPinningBypass — network — High → Info — Phase 4.5 — Pinning libraries probed; severity varies by outcome (bypass = bug, survived = positive observation, absent = no finding)

### Other capabilities the UI must surface

- **Bug bounty scope parsing** — ingest scope from a HackerOne/Bugcrowd URL, JSON file, or pasted text; filters findings by in-scope packages/domains/exclusions, forbidden techniques, reward ranges
- **LLM router** — auto-rotates Groq → Cerebras → Ollama on rate limits; `--private` mode is local-only
- **JSON output** — structured scan report via `--output report.json`
- **CLI built on Click + Rich** — severity-coloured findings table, triage outcome chips, phase timing breakdown
- **FastAPI gateway** — `sentinel serve` exposes `/scan`, `/agents`, `/health`
- **Crash-proof tool layer** — every wrapper returns `ToolResult.ok/fail` instead of raising

## Design language

**Colour tokens** (define in `:root` in `css/base.css`, dark-only):

```css
--bg: #070A12;
--surface: #0E1322;
--surface-2: #141B2E;
--surface-3: #1B2340;
--border: #1F2940;
--border-strong: #2A3454;
--text: #E6EAF2;
--text-dim: #9CA8C0;
--text-mute: #5C6788;

/* Accent gradient — used for hero text, primary buttons, key chips */
--accent-1: #7C3AED;  /* violet */
--accent-2: #22D3EE;  /* electric cyan */
--accent-3: #34D399;  /* mint */
--gradient: linear-gradient(135deg, var(--accent-1), var(--accent-2), var(--accent-3));

/* Severity colours — chip bg at 14% opacity, text at full */
--sev-critical: #EF4444;
--sev-high:     #F97316;
--sev-medium:   #FBBF24;
--sev-low:      #3B82F6;
--sev-info:     #6B7280;

/* Triage colours */
--triage-verified:  #10B981;
--triage-filtered:  #EF4444;
--triage-uncertain: #FBBF24;
--triage-skipped:   #6B7280;
```

**Typography**:
- Body: Inter 400, 16/26
- Headings: Inter 600–700, tighter letter-spacing on hero (`-0.03em`)
- Mono: JetBrains Mono 14, used for code blocks, agent IDs, package names, hash strings, CLI output

**Surfaces & elevation**:
- Cards: `background: var(--surface); border: 1px solid var(--border); border-radius: 14px;`
- Glassmorphism variant (used in hero, modals): `background: rgba(14, 19, 34, 0.6); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.06);`
- Hover: border becomes gradient (use `background-image` trick on a wrapper, or `border-image`), soft glow shadow appears
- Buttons:
  - **Primary**: gradient background, 12px 22px padding, 8px radius, hover lifts 2px with shadow
  - **Secondary**: `surface-2` with 1px solid `border-strong`, white text
  - **Ghost**: transparent with subtle hover background
  - **Icon**: 36×36 square, just an icon

**Background ambience**:
- A fixed `<canvas>` element renders an animated dot grid (40px spacing, 4% opacity, slowly drifting via `requestAnimationFrame`). Single canvas serves the whole site; sits behind everything with `position: fixed; inset: 0; z-index: -1`.
- Three blurred gradient orbs only in the landing hero area — violet top-left, cyan top-right, mint bottom-centre. CSS `filter: blur(120px)` + opacity animation via `@keyframes`, 8–14s loops, offset phases.
- Below the fold of the landing, orbs are absent.
- Inside the app shell, no orbs — just the subtle grid background; the UI must stay focused.

**Motion** (respect `prefers-reduced-motion: reduce` — provide a CSS media query that disables all transforms/animations):
- Hero text: fade-in + 16px-up stagger using CSS transitions triggered by IntersectionObserver
- Section reveals: same pattern, triggered on entry
- Tab switches in the app shell: 200ms fade + 8px translateY
- Card hovers: scale 1.01, gradient border bloom
- Demo scan timeline: phases light up sequentially with a typewriter-style "in progress" indicator, then check off green when complete

## File structure (create exactly this)

```
frontend/
├── index.html                       # Marketing landing page
├── app.html                         # Single-page app shell — hash routing picks the view
├── 404.html
├── css/
│   ├── base.css                     # CSS variables, reset, typography, layout primitives, utilities
│   ├── components.css               # Buttons, cards, chips, tables, forms, modals, sidebar, tabs
│   ├── landing.css                  # Landing-only sections
│   └── app.css                      # App shell, dashboard cards, charts, tab views
├── js/
│   ├── data/
│   │   ├── agents.js                # All 20 agents as typed objects, export const AGENTS = [...]
│   │   ├── workspaces.js            # 3 workspaces with members
│   │   ├── projects.js              # ~8 projects across workspaces, each with metadata
│   │   ├── scans.js                 # ~20 scans across projects, varying status/severity
│   │   ├── findings.js              # ~60 findings across the scans
│   │   └── reports.js               # ~6 saved reports
│   ├── components/
│   │   ├── sidebar.js               # Renders the app sidebar, handles nav
│   │   ├── topbar.js                # Renders the app topbar (workspace switcher, user, new-scan button)
│   │   ├── findings-table.js        # Reusable findings table widget
│   │   ├── severity-chip.js
│   │   ├── triage-chip.js
│   │   ├── modal.js                 # Generic modal + sheet handler
│   │   ├── scan-runner.js           # The simulated scan animation (used in Dashboard and Demo)
│   │   ├── charts.js                # Chart.js wrappers for the dashboard
│   │   └── toast.js                 # Toast notification system
│   ├── views/
│   │   ├── dashboard.js
│   │   ├── projects.js
│   │   ├── workspaces.js
│   │   ├── history.js
│   │   ├── reports.js
│   │   ├── agents.js
│   │   ├── architecture.js
│   │   ├── settings.js
│   │   └── demo.js                  # Interactive scan demo, also reachable from landing
│   ├── router.js                    # Hash-based router for app.html
│   ├── landing.js                   # Landing-page interactions (typewriter, IntersectionObserver reveals)
│   ├── grid-bg.js                   # Canvas-driven animated grid
│   └── main-app.js                  # Bootstraps app.html: mounts sidebar, topbar, initial route
├── assets/
│   ├── logo.svg                     # SENTINEL shield wordmark
│   ├── favicon.svg
│   └── og-image.svg                 # Open Graph image, dark-themed
└── README.md                        # How to run (just open index.html), feature checklist
```

## Page-by-page spec

### Landing — `index.html`

Sections top-to-bottom:

1. **Navbar** (sticky, blurs background on scroll):
   - Left: SVG shield logo + "SENTINEL" wordmark
   - Centre: How it works · Agents · Architecture · Demo
   - Right: "★ Star on GitHub" (links to `github.com/shambhu332/sentinel`), primary CTA "Open dashboard →" linking to `app.html`

2. **Hero**:
   - Background gradient orbs animate behind
   - Eyebrow: `OPEN SOURCE · MULTI-AGENT · ANDROID SECURITY`
   - Headline (gradient text fill, 64–80px): "Find Android vulnerabilities before they ship."
   - Subhead: "SENTINEL is a 20-agent security scanner that combines static analysis, runtime instrumentation, and LLM-powered triage. Decompile, hook, and analyse any APK in under three minutes."
   - Two CTAs: primary "Open the dashboard →" (→ `app.html#dashboard`), secondary "View on GitHub"
   - Below: a terminal mockup with typewriter effect cycling through three example commands:
     - `poetry run sentinel scan corpus/campus.apk --dynamic --frida`
     - `poetry run sentinel scope parse --url hackerone.com/programs/twitter`
     - `poetry run sentinel agents --category network`
   - Realistic output lines stream in below each command via `setTimeout`

3. **StatsRow** (four big numbers, animate from 0 with `IntersectionObserver` + numeric easing):
   - **20** agents · **5** phases · **3** LLM providers · **230** unit tests passing

4. **HowItWorks** — horizontal 5-phase timeline (vertical on mobile). Each phase is a card with phase number (gradient), name, one-line description, icon, and a list of 2–3 tools involved. A connecting line between phases has a moving gradient pulse via CSS keyframes.

5. **AgentShowcase**:
   - Tab strip: All · SAST · DAST · Meta
   - Below: responsive grid (3 cols desktop / 2 tablet / 1 mobile) of all 20 agent cards
   - Each card: agent id (mono, accent), full name, category chip, severity dots, phase pill, one-line description
   - "Browse full catalog →" link to `app.html#agents`

6. **LLMRouter** section — two columns:
   - Left: text explaining provider rotation + privacy mode
   - Right: a small inline SVG showing three provider nodes (Groq, Cerebras, Ollama) with animated lines into a central "Triager" node; one provider pulses red when "rate-limited" and the line redirects to the next

7. **DynamicAnalysis** section with tabs:
   - **Traffic capture**: a stylised flow diagram phone → mitmproxy → laptop, sample captured request boxes
   - **Runtime hooks**: stylised process tree showing Frida injecting into the running app, listing the 6 pinning libraries hooked with ✓/✗ status

8. **ScopeParser** section: "Bug bounty native" — copy plus a mock HackerOne scope card

9. **ArchitectureDiagram** section: a full-width SVG of the whole pipeline (Ingestion → Recon → Agents → Triage → DAST → DAST/Frida → JSON output). Each node has a hover tooltip.

10. **Tech stack row**: Python · Poetry · FastAPI · Click · Rich · mitmproxy · Frida · Androguard · JADX · ChromaDB · Pydantic — small grayscale icons + text

11. **CTASection**: centred panel with gradient border, copy "Start scanning in two commands", a mono code block, two buttons: "Open dashboard →" · "Read the architecture"

12. **Footer**: three columns (Product, Resources, Built by Nehal in Kathmandu), bottom row MIT licence + social icons

### App shell — `app.html`

The dashboard, projects, workspaces, history, reports, agents, architecture, and settings views all live inside this single HTML file. Switching between them is done by `router.js` reading `window.location.hash` (`#dashboard`, `#projects`, etc.), rendering the matching view module into `<main id="view-container">`, and updating the sidebar's active state.

**Layout**:
- Fixed left **Sidebar** (240px wide on desktop, collapsible to 64px icon-only with a toggle):
  - At top: SENTINEL logo
  - Workspace switcher: shows current workspace name + chevron, opens a dropdown to switch between three workspaces (see data section)
  - Nav items (each with Lucide icon + label):
    - Dashboard (`layout-dashboard`)
    - Projects (`folder-kanban`)
    - Scan history (`history`)
    - Reports (`file-text`)
    - Agents (`bot`)
    - Architecture (`network`)
    - Workspaces (`users`)
    - Settings (`settings`)
  - At bottom: user card (avatar circle with initials "NK", name "Nehal", "Personal" label), Sign out button (ghost)
- **Topbar** (fixed, full width minus sidebar):
  - Left: breadcrumb showing current view name
  - Middle: search input ("Search scans, projects, findings…")
  - Right: notifications bell (with mock badge "3"), help icon, **"+ New scan"** primary button (opens the New Scan modal)
- **Main view container** below the topbar, with consistent padding (32px desktop, 20px mobile)

**New Scan modal** (opened from "+ New scan" button anywhere):
- Centred modal, glassmorphism, 640px wide
- Title: "Start a new scan"
- Form sections:
  - **APK**: file-drop zone (visual only; clicking shows toast "Demo only — APK selection is mocked") and a select for "Use sample APK" with options "campus.apk", "signal.apk", "InsecureBankv2.apk"
  - **Project**: dropdown of existing projects + "Create new project…" option
  - **Scope**: optional textarea for bug bounty scope (URL, file path, or inline text)
  - **Analysis options** (toggles): Dynamic analysis (`--dynamic`), Frida hooks (`--frida`), No proxy (`--no-proxy`), Privacy mode (`--private`), LLM triage (`--triage`)
  - **Durations**: two numeric inputs for `--dynamic-duration` (default 30) and `--frida-duration` (default 60)
  - Live-updating CLI preview at the bottom of the modal — a mono code block showing the equivalent `poetry run sentinel scan …` command based on the form state
- Footer: "Cancel" (ghost) + "Start scan" (primary) — clicking Start scan closes the modal, navigates to `#dashboard`, and triggers the scan-runner simulation

### View — Dashboard (`#dashboard`)

A condensed overview. Top to bottom:

1. **Greeting row**: "Welcome back, Nehal" + current date, with a quick-stat strip on the right: Total scans (mock 47) · Critical (3) · High (28) · Medium (12).

2. **Active project card**: shows the currently selected project — name, target package, last scan time, scan count, action buttons "Scan now" (opens New Scan modal pre-filled) and "View details" (→ `#projects/[id]`).

3. **Charts row** (2 columns desktop, 1 on mobile, both rendered via Chart.js):
   - Left: **Severity distribution donut** (Critical/High/Medium/Low/Info counts across all scans this month)
   - Right: **Findings trend line** (last 14 days, one point per day, separate lines for Critical and High)

4. **Recent scans table** (most recent 5):
   - Columns: Project · APK · Started · Duration · Findings (chip count by severity) · Status (pill: completed/running/failed) · Actions (kebab menu → View report / Re-run / Delete)
   - Clicking a row navigates to `#history/[scanId]` (which can route to a detail view inside History)

5. **Recent activity feed** (right side or below on mobile):
   - Plain list of bullet entries with timestamps:
     - "N_005 found pinning bypass in 'campus.apk' · 2h ago"
     - "Scan 'twitter-android' completed with 14 findings · yesterday"
     - "Groq rate-limited, fell back to Cerebras · yesterday"
     - "Bug bounty scope updated for project 'Mobile Banking Audit' · 2d ago"

6. **Quickstart panel**: three colourful cards linking to "Try the demo", "Browse agents", and "Read architecture" — small, with icons.

### View — Projects (`#projects`)

Project management interface. Layout:

1. **Header row**: page title "Projects", a filter row (search input, status dropdown, workspace dropdown, sort), primary button "+ New project".
2. **Project grid** (3 cols desktop / 2 tablet / 1 mobile). Each card:
   - Top-right: status pill (Active / Paused / Completed)
   - Project name (large)
   - Target package(s) — mono chip
   - Workspace badge
   - Stats row: scans count · findings count · last scan
   - Footer: avatar stack for team members (2–4 mock people), action buttons (kebab menu: View / Edit / Archive)
3. Clicking a card → `#projects/[id]` which shows project detail:
   - Project header: name, status, target package, scope summary, team
   - Tabs: Overview · Scans · Findings · Scope · Team · Settings
   - Overview tab content: charts (findings by severity, scans timeline), key metrics, latest scan summary
   - Scans tab: full filterable scan list for this project
   - Findings tab: aggregated findings across all this project's scans
   - Scope tab: rendered scope rules (in-scope packages, domains, exclusions, reward ranges, forbidden techniques)
   - Team tab: member list with role pills (Owner, Reviewer, Viewer) and an "Invite" button (mock)
   - Settings tab: project name, description, LLM provider preference, default scan options, "Archive project" danger zone

### View — Workspaces (`#workspaces`)

Multi-tenant org concept. Three mock workspaces seeded in `data/workspaces.js`:
- **Personal** (Nehal solo, 2 projects)
- **Bug Bounty Hunters** (4 members, 4 projects)
- **University Capstone** (3 members, 2 projects)

The view shows a card per workspace with name, member avatar stack, project count, current plan ("Free / Pro / Enterprise" — Free for all), created date, and a "Manage" button → workspace detail.

Workspace detail (`#workspaces/[id]`):
- Tabs: Members · Projects · Settings · Audit log
- Members tab: table of members with role pills, status pills, last active, "Remove" action
- Projects tab: same project grid filtered to this workspace
- Settings tab: workspace name, description, default LLM provider, default scan options, transfer ownership, delete workspace
- Audit log: ~10 mock entries ("Nehal created project Mobile Banking Audit · 2d ago", "Ashika joined the workspace · 5d ago", etc.)

### View — Scan history (`#history`)

A full data table of every scan ever run.

- **Filters bar**: project dropdown, status dropdown (completed/running/failed), date range picker (mock), severity-min dropdown, text search
- **Bulk action bar** (appears when rows are selected): "Export selected to CSV", "Generate report from selection", "Delete"
- **Table** with these columns:
  - Checkbox
  - Scan ID (mono, monospace, truncated like `oPRq7UyqLAAnw2Wy`)
  - Project
  - APK (with size in MB)
  - Phases (a row of 5 little dots that fill in based on which phases ran — green ✓, grey skipped, red ✗)
  - Findings (chips: red `3` · orange `12` · yellow `4` · blue `0` for Crit/High/Med/Low counts)
  - Started (relative timestamp, with absolute on hover via title attribute)
  - Duration
  - Status pill
  - Actions kebab (View report / Re-run / Download JSON / Delete)
- Pagination: 10/25/50 per page selector + page navigation
- Clicking a row opens **scan detail in a slide-over sheet** (full-height side panel, 720px wide):
  - Sheet header: scan ID, project name, status, started time, "Open full report" button
  - Sheet body tabs:
    - **Summary**: phase timings, total findings by severity, triage breakdown, warnings
    - **Findings**: the full findings table (severity-coloured chips, triage chips, evidence preview)
    - **Frida events**: timeline of captured Frida events (crypto.cipher, tls.bypass, etc.) — only shown if the scan had Frida enabled
    - **Raw JSON**: the full JSON output of the scan, syntax-highlighted (use a simple highlight function — split into lines and wrap keys/strings/numbers in spans)
    - **Warnings**: any phase warnings collected during the scan

### View — Reports (`#reports`)

Report generation interface. Two-section layout:

1. **Saved reports** (top): grid of saved-report cards. Each card shows report title, generated date, scope (which scan/scans/project it covers), format icon (PDF / JSON / HTML / MD), file size, "Download" + "Open preview" buttons.

2. **Report builder** (bottom — the meat of this view): a stepped form:
   - **Step 1: Source** — radio group: "Single scan" (picks one from history), "All scans in project", "Custom selection" (multi-select from a scan list)
   - **Step 2: Template** — radio group with cards: "Executive summary" (1-page overview), "Technical report" (full detail), "Bug bounty submission" (focused on a single finding), "JSON export" (raw structured data)
   - **Step 3: Sections to include** — checkboxes: Cover page, Executive summary, Methodology, Phase timings, Findings detail, Triage breakdown, Recommendations, Architecture diagram, Appendix
   - **Step 4: Branding** — title (text input), subtitle, author name, organisation, logo upload (mock)
   - **Step 5: Format** — radio: PDF / HTML / Markdown / JSON
3. **Preview pane on the right** (sticky): live-updates as you fill the form, shows a styled preview of the report's first page
4. Bottom action bar: "Save draft", "Generate report" (primary)
   - Generating PDF: uses **jsPDF** to produce a real downloadable PDF from the form data plus the demo findings
   - Generating HTML: opens a new tab with a fully-styled HTML report (dark theme matching the app)
   - Generating Markdown: triggers a `.md` download with proper formatting
   - Generating JSON: triggers a `.json` download of the structured scan data

### View — Agents (`#agents`)

Full catalogue of all 20 agents.

- **Filter sidebar (left, 280px)**:
  - Search input
  - Category checkboxes: meta, auth, secrets, logging, crypto, storage, webview, cloud, network, platform, DAST
  - Severity checkboxes: Critical, High, Medium, Low, Info
  - Phase checkboxes: Phase 2, Phase 4, Phase 4.5
- **Main pane**: a dense grid of agent cards (2 cols on wide screens, 1 on mobile)
  - Each card: agent id (mono, gradient bg), full class name, category chip, severity range as coloured dots, phase pill
  - One-line description
  - Expandable "Show details" button reveals: what it detects, sample finding format (mono block), false-positive rate notes, key heuristics
  - "View findings produced by this agent →" link filters History to scans where this agent fired

### View — Architecture (`#architecture`)

Long-form, scrollable explainer. Sections:

1. **Pipeline phases** — vertical timeline with phase number, name, expanded description, list of components involved
2. **Tool layer** — table of tools (JADX, Androguard, apktool, mitmproxy, Frida) with role, language, crash-proof note
3. **Agent base class** — code block showing the `BaseAgent` abstraction (with `is_applicable`, `run`, `produce_finding` methods)
4. **LLM router** — sequence diagram (SVG, hand-drawn) showing fallback flow Groq → Cerebras → Ollama
5. **Frida hook script** — the actual JS source of `ALL_RUNTIME_HOOKS` syntax-highlighted in a mono block (just paste the source from `~/Desktop/project/sentinel/sentinel/tools/frida_runner.py` — keep it accurate)
6. **Crash-proof design** — explainer with code excerpt of `ToolResult` and how every wrapper returns it
7. **Memory layer** — short section on `LightweightMemory` backed by ChromaDB + event publishing
8. **Real-device validation** — honest section listing supported architectures, tested devices, and the known limitation about Samsung devices with Knox/RKP active restricting Frida 16's ptrace operations

### View — Settings (`#settings`)

User and instance settings. Sections (each a card):

1. **Profile**: name, email, avatar (mock), timezone
2. **LLM providers**: cards for Groq, Cerebras, Ollama — each shows status (mock "Connected" / "Not configured"), masked API key input, rate-limit graph (small inline bar)
3. **Privacy & data**: toggle for default privacy mode, data retention dropdown (30 / 90 / 180 / 365 days), "Export all data" button, "Delete account" danger zone
4. **Notifications**: email toggles for scan completion, critical findings, weekly digest
5. **Scan defaults**: default scan options (which flags are enabled by default in new scans)
6. **API tokens**: list of mock API tokens (3 entries) with name, last used, scopes, revoke button + "Create token" button
7. **About**: version `0.1.0`, build commit hash (mock), open-source licence note, link to GitHub

### View — Demo (`#demo` inside app shell, also linked from landing's hero CTA "Try the demo →")

A focused interactive demo of running a scan end-to-end. Layout:

1. Left column (configuration):
   - Sample APK picker: campus.apk / signal.apk / InsecureBankv2.apk (with package name shown under each)
   - Scope textarea (pre-filled with a HackerOne example URL)
   - Toggles: dynamic, frida, no-proxy, private, triage
   - Big "Run scan" button (primary, gradient)

2. Right column (results):
   - **Phase timeline**: vertical with 5 phase cards. As the scan progresses, each phase lights up in sequence with a "in progress" pulse, then resolves to ✓ green when done. Pace it so the whole thing takes 14–18 seconds.
   - **Live log stream**: a mono scrollable area below the timeline, lines append as the scan runs (sample lines: "[A_001] Stopped scanning after 3000 files", "Groq 429 (rate limit), attempt 1", "Frida attached to com.global.edu.campus pid=12288", etc.)
   - **Findings table**: hidden until Phase 3 completes, then animates in with stagger
   - **Summary stats** above the findings: total findings, severity breakdown, triage breakdown, phase timings
3. After the scan completes, a "Generate report from this scan →" button appears, navigating to `#reports` with the scan pre-selected.

## Mock data requirements

### Workspaces (3)
- `ws_personal` — "Personal", owner Nehal, 2 projects
- `ws_bb_hunters` — "Bug Bounty Hunters", 4 members (Nehal owner, Ashika, Pranav, Sumit), 4 projects
- `ws_capstone` — "University Capstone", 3 members (Nehal, Bishal, Anil), 2 projects

### Projects (8 total)

1. **Mobile Banking Audit** (ws_bb_hunters) — target `com.example.banking`, status Active
2. **Campus App Pen-test** (ws_capstone) — target `com.global.edu.campus`, status Active
3. **Twitter Android** (ws_bb_hunters) — target `com.twitter.android`, status Active
4. **Signal Messenger** (ws_personal) — target `org.thoughtcrime.securesms`, status Active
5. **InsecureBankv2 (training)** (ws_personal) — target `com.android.insecurebankv2`, status Completed
6. **Khalti Wallet** (ws_capstone) — target `com.khalti.android`, status Active
7. **Crypto Exchange Client** (ws_bb_hunters) — target `com.fakeexchange.android`, status Paused
8. **Health Records App** (ws_bb_hunters) — target `com.fakehealth.records`, status Completed

Each project has scope rules (some have HackerOne URLs, some inline lists), team members, dates, descriptions.

### Scans (around 20 total across projects)

Mix of statuses (completed, running, failed), severity counts, durations (15s to 4 min), with and without dynamic/frida. Include the realistic scan IDs format like `oPRq7UyqLAAnw2Wy`. At least three scans should have rich Frida event data (for the Scan Detail sheet's Frida tab). One scan should be in "running" status for the dashboard.

### Findings (around 60 total across scans)

Mix across all 20 agents, all severities, all triage outcomes. Each finding needs: agent_id, vuln_class, severity, triage outcome, confidence (0.5–0.95), recommendation, evidence (file path + line + code snippet for SAST, request/response or Frida event for DAST). Several should be `verified ✓ High`, a few `filtered ✗` (showing the LLM doing its job), a couple `uncertain ?`.

### Reports (6 saved)

Mix of formats and templates. Example titles:
- "Mobile Banking Audit — Q3 Executive Summary" (PDF)
- "Campus App full technical report" (HTML)
- "Twitter Android — XSS in deep link" (Bug bounty submission, PDF)
- "Personal scan dump 2025-12" (JSON)
- "InsecureBankv2 training findings" (Markdown)
- "Signal Messenger — pinning analysis" (HTML)

## Quality bar

- Open `index.html` directly from disk and it renders correctly. Same for `app.html`.
- Every interactive element has a visible focus state (outline or ring).
- Every animation respects `prefers-reduced-motion: reduce`.
- Mobile responsive at 375px, 768px, 1024px, 1440px breakpoints.
- All copy is real and accurate to the Python project — no Lorem Ipsum, no invented features.
- Severity, triage, and category chip colours are consistent across every view.
- The sidebar collapses to icon-only at <1024px, becomes a hamburger drawer at <768px.
- Tables are scrollable horizontally on mobile without breaking the layout.
- Color contrast meets WCAG AA on every text/background combo.
- The Demo scan animation feels deliberate — pace each phase so the whole flow takes 14–18s and feels rewarding to watch.
- All TODOs are resolved; no `console.log` leftover; no broken links.
- JSDoc-style comments on all exported functions and major modules.
- The README in `frontend/README.md` lists every page, every feature, and step-by-step how to open it (no install needed).

## Implementation order

Don't try to build everything at once — work in this order, finishing each step before moving on:

1. Scaffold the directory, create empty files
2. `css/base.css` — variables, reset, typography, layout primitives
3. `css/components.css` — buttons, cards, chips, tables, forms, modals, sidebar styles
4. `js/grid-bg.js` — animated grid canvas
5. `js/data/*.js` — all mock data (this is foundational — every view depends on it)
6. `js/components/sidebar.js`, `topbar.js`, `modal.js`, `toast.js`, `severity-chip.js`, `triage-chip.js`
7. `app.html` shell + `js/router.js` + `js/main-app.js`
8. **Dashboard view** first — it's the welcome view, biggest visual payoff
9. Scan history view (a lot of features touch this)
10. Agents view (data-driven, fast win)
11. Projects + Projects detail
12. Workspaces + detail
13. Reports view with the builder + jsPDF integration
14. Architecture view (long-form)
15. Settings view
16. Demo view (the interactive scan simulator)
17. `index.html` landing page — built last so it can link to all the now-existing app views with confidence
18. Polish pass: focus rings, reduced-motion, mobile QA across every view
19. Write `README.md` with the feature checklist

## Constraints

- **Do not** modify `~/Desktop/project/sentinel/sentinel/` — Python code is off-limits
- **Do not** add npm, package.json, or any build/install step
- **Do not** invent features SENTINEL doesn't have — stick to the 20 agents and 5 phases listed
- **Do not** use frameworks (no React, Vue, Svelte, Alpine, htmx, etc.)
- **Do** ask before pulling additional CDNs beyond Lucide, Chart.js, jsPDF, Google Fonts

## Deliverables

When done, give me:
1. A working site — `cd frontend && open index.html` (or `python3 -m http.server` for proper module loading)
2. Every page renders without console errors
3. A short final summary listing: total HTML files, total CSS/JS lines, every view implemented, every interactive feature, and anything intentionally left out

Start by scaffolding the directory and writing `css/base.css` so we can lock the design tokens before any component goes in.