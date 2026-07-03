# Evidence — SENTINEL Frontend Dashboard

Consolidated facts from 5 evidence subagents. No scoring here — that lives in `02-scorecard.md`.

## A. Structural Evidence

- **Total interactive elements:** 102 across 12 surfaces (56 buttons, 17 links, 29+ listeners)
- **Max nesting depth:** 5 (`dashboard.js:111-133` buildOfflineBanner; `scan-detail.js:60-78` headerBanner)
- **Repeated-pattern hotspots:**
  - **Table row pattern** re-implemented 3× — `dashboard.js:278-296`, `scans.js:266-283`, `scan-detail.js:415-431` (same DOM shape, no shared helper)
  - **Offline banner** has 2 distinct implementations + 3 inline reimplementations — `dashboard.js:111-133`, `reports.js:200-221`, `scans.js:58-67`, `history.js:35-42`, `projects.js:31-38`
  - **Severity badge** has 3 separate definitions — `severity-badge.js:4-6`, `scan-detail.js:447-456`, `scan-detail.js:458-489`
- **Empty-state component** reused well (12 call sites of one definition)
- **Sidebar inventory:** 12 nav items in 4 groups (Workspace · Analyze · AI Platform · Configure)
- **Routing inventory:** 13 routes registered; **5 are unimplemented placeholders** (`rag`, `verify`, `exploit`, `devices`, `docs` — `router.js:39-43`)
- **Dead exports:** 1 — `triageBadge` (`severity-badge.js:13`) not referenced by any audited surface

## B. Visual Evidence

- **Token system defined:** `--space-1..20`, semantic `--text-*`, `--sev-*`, `--bg-*` in `theme.css:6-152`
- **Spacing scale actually used:** 19 discrete px values — `[2,4,6,8,10,12,14,16,18,20,24,28,32,36,38,40,48,64,80]`. Drift values 11, 13, 14, 18, 28, 36, 38 fall between token steps — usage is wider than the declared system
- **Type scale:** 10 values `[11,12,13,14,16,18,20,24,32,56]` — tight, consistent
- **Distinct colors:** 38 hex tokens, all semantically grouped (severity, framework, swarm, badge). No orphan values
- **Lowest contrast:** `--text-muted #6B7280` on `--bg-primary #0A0E27` = **3.93 : 1 — FAILS WCAG AA** (`theme.css:27` × `theme.css:8`)
- **All six states present:** empty (`components.css:917`), loading (`components.css:881, 1009`), error (`components.css:780`), success (`components.css:779`), focus (`base.css:69`), disabled (`components.css:25`)
- **Motion inventory:** 7 keyframes; `prefers-reduced-motion: reduce` honored at `base.css:230-239`
- **Dark mode locked:** no light-mode token set; no `prefers-color-scheme` block anywhere

## C. Copy & Honesty Evidence

- **~100+ user-facing strings inventoried** across `index.html`, dashboard, scan-modal, scan-detail, settings, topbar, sidebar
- **Inflations (5):**
  1. **"instantly"** — `index.html:6,58,62` (contradicts "in minutes" later in same paragraph)
  2. **"LLM-powered triage"** as marquee feature — `index.html:7,61,116` (in code it's an opt-in toggle, `scan-modal.js:243`)
  3. **"audit any APK in minutes"** — `index.html:62` (unbounded claim, no SLA)
  4. **"Professional VAPT Report"** — `scan-detail.js:607` (no attestation, methodology, or certifier)
  5. **"Client-ready engagement deliverable"** — `scan-detail.js:609`
- **Dark patterns:** none found
- **Jargon labels (10) — junior researcher would NOT understand without context:**
  - `VAPT` — `scan-detail.js:557, 607`
  - `MASVS` — `finding-detail-view.js:152-154`
  - `Phase 0 / Phase 2 / Phase 4 / Phase 8` used in user copy — `scan-detail.js:11-16, 342, 559`
  - `Frida` — `scan-modal.js:240, scan-detail.js:15`
  - `Adaptive planner` (experimental) — `scan-modal.js:245`
  - `ML strategy` — `scan-modal.js:247`
  - `PoC` (sidebar item, single word) — `sidebar.js:26`
  - `AFL++ JNI fuzzing` — `scan-modal.js:246`
  - `No-proxy mode` — `scan-modal.js:241`
  - `Verify Engine` — `router.js:41`
- **Label → behavior:** 5 sampled (API online pill, Regenerate report, LLM-triage toggle, Download JSON, "No findings yet" vs "No findings produced"). All MATCH.
- **Weak empty/loading copy:** `"Loading…"` bare (`dashboard.js:16`), `"HTTP {status}"` bare (`topbar.js:76`)

## D. Weight & Friction Evidence

- **Initial JS:** 358 KB raw + 99 KB CSS + 1 KB HTML = 459 KB total raw. **~135 KB gzip-9 estimate.**
- **Network requests:** 10 on initial load — including 3 CDN (Google Fonts, unpkg/Lucide, jsdelivr/Chart.js)
- **TTI:** estimated 1.2–1.8s (ESTIMATED; 0 render-blocking, parallel CDN, 1 API fetch)
- **Idle animations:** 0–2 (only `.live-dot` pulse if active scans > 0)
- **Initial attention items:** 8–9 (4 KPI cards + 3 sidebar count badges + conditional offline banner + Quick tour badge)
- **Polling loops:** `setInterval(tickHealth, 30000)` always on (`topbar.js:64`); `setTimeout` every 1500 ms during running scans (`scan-detail.js:8,46`)
- **Heavy assets:** none >50 KB

## E. Accessibility Evidence

- **Contrast — token-by-token:**
  | Token | Ratio vs `--bg-primary` | WCAG AA |
  |---|---|---|
  | text-primary | 16.29 : 1 | ✓ |
  | text-secondary | 7.68 : 1 | ✓ |
  | **text-muted** | **3.93 : 1** | **✗ FAIL** |
  | accent-primary | 10.73 : 1 | ✓ |
  | sev-critical | 5.36 : 1 | ✓ |
- **Keyboard reachability of 10 primary actions — 3 FAIL:**
  - Upload APK drop-zone (`dashboard.js:45`) — `onclick` on `<div>`, no `tabindex` / `keydown`
  - Recent-scans row click (`dashboard.js:278`) — `onclick` on `<tr>`, same issue
  - Findings table row → opens modal (`findings-table.js:120`) — `onclick` on `<tr>`, same issue
- **ARIA landmarks:** 3 (`<aside>`, `<header>`, `<main>` in `app.html:20-22`). No `<nav>` role on sidebar nav; no `<footer>`.
- **Skip-link:** **absent** everywhere
- **Form labels:** settings inputs (`settings.js:36, 142+`) lack semantic `<label for=>` — fails WCAG 1.3.1
- **Icon-only buttons missing aria-label:** 3 in topbar (`topbar.js:38, 42, 45` — notifications / new-scan / help; rely on `data-tip` tooltip only)
