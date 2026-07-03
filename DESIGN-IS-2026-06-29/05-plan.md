# SENTINEL Frontend Redesign — Implementation Plan

Source brief: `04-handoff-prompt.md` (verdict REDESIGN, 17/30).
Phase 0 discovery: `05-plan.md` (this file, §Phase 0).

Phases are ordered by **risk-adjusted leverage**: honesty first (copy-only, zero-risk, immediately restores product credibility), then structural dedup, then interaction and IA (larger blast radius), then a11y polish, then verification.

---

## Phase 0 — Discovery (COMPLETE)

Verified against current code:

**Preserve APIs (copy these — do not reinvent):**
- Routing: `registerRoute(name, handler)` + `initRouter()` in `frontend/js/router.js`; handler signature `(main, params) => void`. Registrations live in `app-shell.js:46-57`.
- Modal: `openModal({ title, body, footer, size, onClose })` and `closeModal()` from `frontend/js/components/modal.js`.
- Severity: `sevBadge(severity, label)`, `sevRow(sev)`, `statusBadge(status, label)`, `triageBadge(triage)` from `frontend/js/components/severity-badge.js`. **Canonical — inline triageChip/verifyChip at `scan-detail.js:447-489` are the duplicates to delete.**
- Finding-detail 7-section layout: `frontend/js/components/finding-detail-view.js:19-52` (header → description → context → metadata → code → repro → remediation). Do not restructure; only flow new copy through it.
- Token system: `frontend/css/theme.css:6-152`. Confirmed groups: bg/text/accent/severity/status/shadows/borders/radii/transitions/z-index plus 30+ domain tokens (compliance, impact, CVSS, device, swarm, PoC, badge).
- `prefers-reduced-motion`: `frontend/css/base.css:230-239` — leave untouched.
- Regenerate-report: `scan-detail.js:564-577` + `api.js:118` (`api.regenerateReport(id)`) + backend `POST /reports/{id}/regenerate`.

**Discovery corrections to brief:**
1. `--space-*` scale is **10 steps** (1,2,3,4,5,6,8,10,12,16,20), not 20. Off-token inline values (11,13,14,18,28,36,38) are hardcoded literals, not variables.
2. `sidebar.js:26` "PoC" label belongs to the `exploit` route entry, not a bare acronym elsewhere. Same fix (expand or remove) applies.
3. All three "onclick" reachability bugs are actually `addEventListener('click', …)` on `<div>` / `<tr>`. Same keyboard-unreachability problem, same fix.
4. `--text-muted` = `#6B7280` at `theme.css:27` — confirmed. Contrast 3.93:1 vs `--bg-primary` `#0A0E27`.

---

## Phase 1 — Honesty pass (copy-only, zero-risk)

**Goal:** Every visible claim maps 1:1 to actual behaviour (principle #6).

**Tasks — string edits only:**

1. `frontend/index.html`
   - Line 6 (title): `"SENTINEL — Android security scanning, instantly"` → `"SENTINEL — Android security scanning"`
   - Line 7 (meta description): remove `"LLM-powered triage"` phrase; describe what the tool does by default (static analysis + Frida hooks; LLM triage is opt-in).
   - Line 58 (hero gradient span): `"instantly."` → drop the span or replace with an accurate qualifier (e.g. `"in one pass."`).
   - Line 61 (hero body): rewrite `"LLM-powered triage"` clause to reflect opt-in reality, OR — if the team commits to default-on — set `scan-modal.js:243` LLM toggle to default checked and keep the copy. Pick one; do not ship both states.
   - Line 62, 116: audit for remaining "instantly" occurrences and remove.

2. `frontend/js/pages/scan-detail.js`
   - Line 607: `"Professional VAPT Report"` → `"VAPT Report"`.
   - Line 609: remove subtitle `"Client-ready engagement deliverable ·"` (keep the surrounding metadata if any).

3. **Before/after table** — record every change in `DESIGN-IS-2026-06-29/06-copy-diff.md` with columns: `file:line | before | after | reason`. Required deliverable for the brief.

**Verify:**
- `grep -nE "instantly|LLM-powered triage|Professional VAPT|Client-ready" frontend/` returns **zero matches** outside of tests/fixtures.
- Open `/` in browser: hero copy no longer promises instantaneity.
- Open a completed scan's VAPT tab: title reads "VAPT Report".

**Anti-patterns:**
- Do not swap one inflated adjective for another ("blazing-fast", "enterprise-grade"). Aim for plain description.
- Do not delete the meta description entirely — rewrite it.

---

## Phase 2 — Structural deduplication (principle #10)

**Goal:** One implementation per pattern.

**Tasks:**

1. **Offline banner extraction.**
   - Create `frontend/js/components/offline-banner.js` exporting `offlineBanner(err?)` → element. Base the DOM on the richest existing implementation (`dashboard.js:111-133` — has icon + settings link).
   - Replace all 5 sites with `import { offlineBanner } from '../components/offline-banner.js'`:
     - `pages/dashboard.js:111-133`
     - `pages/reports.js:200-221`
     - `pages/scans.js:58-67`
     - `pages/history.js:35-42`
     - `pages/projects.js:31-38`
   - Callers should pass the caught error (if any) through so message stays contextual.

2. **Severity chip dedup.**
   - Delete `triageChip` / `verifyChip` inline helpers at `scan-detail.js:447-489`.
   - Replace call-sites with `triageBadge(triage)` / `statusBadge(...)` from `severity-badge.js`. If a callsite needs a variant not covered by the canonical exports, extend `severity-badge.js` — do not fork.

**Verify:**
- `grep -n "wifi-off" frontend/js/pages/` shows **one** import path only (from the new component).
- `grep -nE "triageChip|verifyChip" frontend/js/` returns **zero matches**.
- Manually toggle network offline in devtools on each of the 5 pages; banner still renders identically.
- Scan-detail triage/verify UI unchanged visually.

**Anti-patterns:**
- Do not wrap `offlineBanner` behind an unnecessary options bag — copy the current call surface, no new params.
- Do not delete `severity-badge.js` exports; only delete the *inline duplicates*.

---

## Phase 3 — Useful (principle #2): keyboard reachability + IA prune

**Goal:** Every primary action is keyboard-reachable; sidebar contains only working destinations.

**Tasks:**

1. **Keyboard reachability — convert click-on-`<div>`/`<tr>` to real buttons or ARIA buttons.**

   Pattern to apply at each site (choose per-site — real `<button>` overlay preferred for the upload zone; ARIA button acceptable for table rows):

   ```js
   // ARIA-button pattern (table rows)
   el('tr', {
     class: 'clickable',
     role: 'button',
     tabindex: '0',
     onclick: handler,
     onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handler(e); } }
   })
   ```

   Sites:
   - `frontend/js/pages/dashboard.js:45` — upload drop-zone. Prefer refactor to a `<button class="upload-zone">` if styling permits; otherwise ARIA-button pattern.
   - `frontend/js/pages/dashboard.js:278` — recent-scans row. ARIA-button pattern.
   - `frontend/js/components/findings-table.js:120` — findings row. ARIA-button pattern.

2. **IA prune — decide per placeholder route: implement or remove.**
   - Placeholder routes in `frontend/js/router.js:24-44`: `docs`, `rag`, `verify`, `exploit`, `devices`.
   - Confirmed sidebar entries in `sidebar.js` (breadcrumb labels: "Docs", "Knowledge Base", "Verify Engine", "PoC Generator", "Devices").
   - **Decision required from user** — if all 5 are deferred, remove sidebar entries AND route registrations (leave URL-alias redirects to `/` for 1 release for bookmark grace, then delete). If any survive, they must at minimum render a truthful "coming soon" empty-state that is not clickable-into-a-nowhere-page.

**Verify:**
- Tab through the dashboard from URL bar: focus lands on upload-zone → Enter opens scan modal. Same for recent-scans and findings rows.
- Screen-reader announces each as "button" not "generic".
- `grep -nE "placeholder|comingSoon|TODO" frontend/js/pages/{rag,verify,exploit,devices,docs}.js` — either files removed or content replaced.
- Sidebar renders only routes with working destinations.

**Anti-patterns:**
- Do not restyle a `<div>` to *look* like a button while leaving the semantics broken.
- Do not keep placeholder items "for vision signalling."

---

## Phase 4 — Understandable (principle #4): jargon expansion + onboarding gate

**Goal:** First-time junior researcher names every primary control correctly.

**Tasks:**

1. **Expand jargon at first use.**
   - `frontend/js/components/sidebar.js:26` — if PoC route survives Phase 3, expand label to `"Proof-of-Concept"`.
   - `frontend/js/pages/scan-detail.js:557` — first VAPT usage: `"VAPT (Vulnerability Assessment Report) not yet generated"`.
   - `frontend/js/components/finding-detail-view.js:152` — first MASVS usage: `"MASVS (Mobile Application Security Verification Standard) ${finding.masvs}"` or a tooltip via `title` attribute.
   - `frontend/js/pages/scan-detail.js:342,559` — Phase names get inline gloss: `"Phase 2 (Static Analysis)"`, `"Phase 8 (Reporting)"`.
   - `frontend/js/components/scan-modal.js:243-247` — toggle labels: `"Adaptive planner"` → `"AI Agent Ordering (experimental)"`; `"ML strategy"` → `"AI Finding Prioritiser"`.

2. **Onboarding gate.**
   - `frontend/js/pages/dashboard.js:221-244` — wrap the "How it works / Quick tour" 5-step block in:
     ```js
     if (!localStorage.getItem('sentinel.onboardingSeen')) {
       // render block, include a dismiss button that setItem('sentinel.onboardingSeen','1')
     }
     ```
   - Alternatively: remove the block outright. **Decision required from user.** Recommend gate over delete — the content is useful once.

**Verify:**
- Fresh browser profile shows onboarding block on `/dashboard`; after dismissal, hard refresh keeps it hidden.
- `grep -nE "\\bVAPT\\b|\\bMASVS\\b|\\bPoC\\b" frontend/js/` — every first-in-file occurrence has an inline expansion or `title` attribute.

**Anti-patterns:**
- Do not gate onboarding on session storage (survives navigation but not tabs — user will re-see it every browser open).
- Do not expand every occurrence — only the first-in-screen. Second uses stay compact.

---

## Phase 5 — Thorough (principle #8): a11y polish

**Goal:** WCAG AA on all text tokens; aria-labels on all icon-only buttons; skip-link present.

**Tasks:**

1. **Contrast fix.**
   - `frontend/css/theme.css:27`: `--text-muted: #6B7280` → `--text-muted: #8C96A8` (computed ≥4.5:1 vs `--bg-primary #0A0E27`).
   - After change, spot-check any surface using `--text-muted` for readability; adjust one token, do not scatter overrides.

2. **Topbar aria-labels.**
   - `frontend/js/components/topbar.js:38,42,45` — add `'aria-label': 'Notifications'` (line 38), `'aria-label': 'New scan'` (line 42), `'aria-label': 'Help'` (line 45). Keep the existing `data-tip` for the tooltip.

3. **Skip-link.**
   - `frontend/app.html`: insert as first child of `<body>`:
     ```html
     <a href="#main-view" class="skip-link">Skip to main content</a>
     ```
   - Style in `frontend/css/base.css`: visually hidden until `:focus`, then anchored top-left.
   - Confirm the main content region has `id="main-view"` (app-shell mounts here). If not, add it.

4. **Settings form labels.**
   - `frontend/js/pages/settings.js:36` and 142+ — every `<input>` gets a paired `<label for="id">` OR wrap the input inside a `<label>`. Add `id` attributes where missing.

**Verify:**
- Chrome devtools → Lighthouse Accessibility: score ≥95.
- axe-core devtools extension: zero critical violations on `/dashboard`, `/scans`, `/scans/:id`, `/settings`.
- Tab from URL bar on any page: first focus is skip-link, Enter jumps to main content.
- `grep -n "aria-label" frontend/js/components/topbar.js` — 3 new matches at cited lines.

**Anti-patterns:**
- Do not add `role="main"` alongside `<main>` (redundant).
- Do not use `visibility: hidden` for the skip-link (removes it from tab order — must be reachable, just off-screen).

---

## Phase 6 — Verification & handoff

**Tasks:**

1. **Grep sweep — must all return zero:**
   ```
   grep -nE "instantly|LLM-powered triage|Professional VAPT|Client-ready" frontend/
   grep -nE "triageChip|verifyChip" frontend/js/
   grep -c "wifi-off" frontend/js/pages/*.js   # expect 0 (moved into components/)
   ```

2. **Audit re-score.** Re-run the Rams scorecard against the modified codebase. Target: ≥24/30 with no principle at 1/3. Update `02-scorecard.md` with a new column dated at merge.

3. **States checklist** — for every touched screen (`dashboard`, `scans`, `scan-detail`, `finding-modal`, `vapt`, `settings`): confirm empty / loading / error / success / focus / disabled states each render with copy. Record in `07-states-check.md`.

4. **Cutover criteria.**
   - No `feature/redesign` branch left long-lived — merge to `main` when Phases 1–5 all green.
   - No feature flag around the redesign (no flag-forever states). One exception: onboarding-gate localStorage key.
   - Delete removed sidebar-route files (`pages/rag.js`, etc.) in the same PR that removes their registrations.

5. **Migration.**
   - For each removed route, add a router entry that redirects to `/` for one release (URL alias). Remove aliases in the following minor version.

---

## Decision points blocking Phase 3 / Phase 4

Before Phase 3 starts, the user must decide:
- **Placeholder routes:** ship, remove, or keep with a truthful "planned" state?

Before Phase 4 starts:
- **Onboarding:** localStorage gate (recommended) or remove entirely?

Everything else can proceed on my judgement.
