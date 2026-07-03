# Verdict — SENTINEL Frontend Dashboard

## Verdict: REDESIGN

The SENTINEL frontend audits at **17 / 30** with the gap concentrated in four principles (#2 Useful 1/3, #4 Understandable 1/3, #6 Honest 1/3, #10 Less Design 1/3) — all load-bearing for a security tool whose primary user is a junior researcher. Per the Phase 3 rule (`Total < 20 → REDESIGN`), the call follows mechanically.

## Why REDESIGN and not REFINE

A polish pass cannot close the gap. The failure modes are coupled:

- **Useful #1** fails because the IA includes 5 placeholder routes AND 3 primary actions that mouse-click but can't keyboard-reach. Both are IA / interaction-design decisions, not styling.
- **Honest #6** fails because the marketing copy on the landing page (`index.html`) and the product copy in the scan-detail VAPT toolbar (`scan-detail.js:607-609`) make claims that the implementation contradicts. This isn't a typo pass — it's about deciding what the product actually promises.
- **Understandable #4** fails because 10 jargon labels surface in the user journey without expansion or progressive disclosure. Fixing this means rethinking onboarding and microcopy strategy, not adding tooltips.
- **Less Design #10** fails because of structural duplication (offline banner ×5, table row ×3, severity badge ×3) and a persistent onboarding section that nobody who has scanned an APK once needs to see again.

These are tractable, but they are design decisions — not style overrides.

## What survives (substantial)

The bones are not broken; this is a strategic refresh, not an information-architecture rebuild.

- **Token system** in `theme.css` — 38 semantic colors, 20-step spacing scale, motion timing — keep as-is
- **Component primitives** — `modal.js`, `severity-badge.js` (the canonical one), `empty-state` pattern, `code-block.js`
- **Djini-style finding-detail layout** (`finding-detail-view.js:19-52`) — the seven-section narrative is the most innovative surface in the product (principle #1 = 3)
- **Routing + page-shell architecture** in `app-shell.js` and hash router
- **`prefers-reduced-motion` honoring** at `base.css:230-239`

## Top 3–5 highest-leverage moves

1. **#6 Honest — Strip inflated marketing copy.** Remove "instantly" (×3) from `index.html:6,58,62`; drop the marquee "LLM-powered triage" claim (or commit to default-on); rename "Professional VAPT Report" → "VAPT Report" and remove the "Client-ready engagement deliverable" subtitle at `scan-detail.js:607,609`.

2. **#4 Understandable — Expand jargon at first use.** Phase names get an inline gloss (`Phase 2: Static Analysis`); sidebar "PoC" → "Proof-of-Concept" (`sidebar.js:26`); first occurrence of "VAPT" expands; "Adaptive planner" → "AI Agent Ordering (experimental)" in scan-modal toggles (`scan-modal.js:245-247`).

3. **#2 Useful — Fix keyboard reachability AND prune dead IA.** Add `role="button"` + `keydown` handlers (or use `<button>`) on upload drop-zone (`dashboard.js:45`), recent-scans row (`dashboard.js:278`), and findings-table row (`findings-table.js:120`). Remove the 5 placeholder sidebar routes (`router.js:39-43`) — or implement them — but stop shipping dead nav.

4. **#10 Less Design — Deduplicate the offline banner and retire onboarding noise.** One `offline-banner.js` component, imported by `dashboard.js`, `reports.js`, `scans.js`, `history.js`, `projects.js`. Remove the "How it works / Quick tour" 5-step section from `/dashboard` (`dashboard.js:231`) — or gate it behind a first-visit flag.

5. **#8 Thorough — Fix the contrast + a11y polish in the same pass.** Bump `--text-muted` from `#6B7280` to a token that hits 4.5 : 1 against `--bg-primary` (around `#8C96A8`). Add `aria-label` to the 3 topbar icon buttons (`topbar.js:38,42,45`). Add a skip-link to `app.html`. Add `<label for=>` to settings form inputs.
