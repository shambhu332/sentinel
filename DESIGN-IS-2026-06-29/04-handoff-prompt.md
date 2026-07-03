# Handoff — copy-paste this into a new `/make-plan` session

````
/make-plan Redesign the SENTINEL frontend dashboard. Current design failed a Dieter Rams audit at 17/30 with critical gaps in principles #2 (Useful, 1/3), #4 (Understandable, 1/3), #6 (Honest, 1/3), and #10 (As little design as possible, 1/3).

Verdict paragraph (quoted from 03-verdict.md):
> The SENTINEL frontend audits at 17 / 30 with the gap concentrated in four principles (#2 Useful 1/3, #4 Understandable 1/3, #6 Honest 1/3, #10 Less Design 1/3) — all load-bearing for a security tool whose primary user is a junior researcher. A polish pass cannot close the gap because the failure modes are coupled: the IA includes 5 placeholder routes AND 3 primary actions that mouse-click but can't keyboard-reach (#2); the marketing copy in `index.html` and the product copy in `scan-detail.js:607-609` make claims the implementation contradicts (#6); 10 jargon labels surface in the user journey without expansion (#4); structural duplication (offline banner ×5, table row ×3, severity badge ×3) plus a persistent onboarding section (#10). These are tractable, but they are design decisions — not style overrides.

Why redesign and not refine: total < 20 by the audit rule, AND the failures are coupled across IA, copy, and interaction — not concentrated in styling. Fixing them in place would mean re-deciding what the product promises and how it is reached.

Preserve from current design (NON-NEGOTIABLE — these scored well):
- Token system in `frontend/css/theme.css` lines 6-152 — 38 semantic colours, 20-step `--space-*` scale, motion-timing tokens, severity palette. Discard nothing here.
- Component primitives: `frontend/js/components/modal.js`, `frontend/js/components/severity-badge.js` (the canonical `sevBadge`/`sevRow` exports — but discard the inline triageChip/verifyChip duplicates in `scan-detail.js:447-489`), the `.empty-state` pattern.
- Djini-style 7-section finding-detail layout in `frontend/js/components/finding-detail-view.js:19-52`. This is the highest-scoring surface (principle #1 = 3/3) and the most innovative pattern in the product. Do not refactor its IA; only flow new copy through it.
- `prefers-reduced-motion` honoring at `frontend/css/base.css:230-239`.
- Hash-routing + page-shell architecture in `frontend/js/router.js` + `frontend/js/app-shell.js`. Reuse the registration model; redesign what registers.
- Regenerate-report flow added today (`scan-detail.js:564-577`, backend `POST /reports/{id}/regenerate`).

Discard (these caused the failures):
- 5 placeholder sidebar routes (`rag`, `verify`, `exploit`, `devices`, `docs`) at `frontend/js/router.js:39-43`. Caused failure on #2 Useful. Either ship them or remove them — do not keep dead nav items.
- 5 redundant offline-banner implementations: `dashboard.js:111-133`, `reports.js:200-221`, `scans.js:58-67`, `history.js:35-42`, `projects.js:31-38`. Caused failure on #10. Replace with one shared component imported by all five pages.
- "How it works / Quick tour" 5-step section persisting on every dashboard load at `frontend/js/pages/dashboard.js:231`. Caused failure on #10. Gate behind a first-visit flag in localStorage, or remove.
- `onclick` on bare `<tr>`/`<div>` elements at `dashboard.js:45` (upload drop-zone), `dashboard.js:278` (recent-scans row), `findings-table.js:120` (findings row). Caused failure on #2 Useful (3 of 10 primary actions keyboard-unreachable).
- Inflated marketing copy: "instantly" ×3 at `index.html:6,58,62`; "LLM-powered triage" as marquee at `index.html:7,61,116`; "Professional VAPT Report" + "Client-ready engagement deliverable" at `scan-detail.js:607,609`. Caused failure on #6 Honest.
- Bare jargon labels with no expansion: sidebar "PoC" at `sidebar.js:26`; first-use "VAPT" at `scan-detail.js:557`; first-use "MASVS" at `finding-detail-view.js:152`; "Phase 2 / Phase 8" in user copy at `scan-detail.js:342, 559`. Caused failure on #4 Understandable.

Top 3–5 moves from the audit (verbatim, in priority order):

1. **#6 Honest — Strip inflated marketing copy.** Remove "instantly" (×3) from `index.html:6,58,62`; drop the marquee "LLM-powered triage" claim (or commit to default-on, in which case un-toggle it at `scan-modal.js:243`); rename "Professional VAPT Report" → "VAPT Report" and remove the "Client-ready engagement deliverable" subtitle at `scan-detail.js:607,609`. Evidence: `index.html:6,7,58,61,62,116` ; `scan-detail.js:607,609`.

2. **#4 Understandable — Expand jargon at first use.** Phase names get an inline gloss (`Phase 2: Static Analysis`); sidebar "PoC" → "Proof-of-Concept" (`sidebar.js:26`); first occurrence of "VAPT" on a screen expands to "Vulnerability Assessment Report"; "Adaptive planner" → "AI Agent Ordering (experimental)" and "ML strategy" → "AI Finding Prioritiser" in scan-modal toggles (`scan-modal.js:245-247`). Evidence: `scan-modal.js:243-247`, `sidebar.js:26`, `finding-detail-view.js:152-154`, `scan-detail.js:11-16, 342, 559`.

3. **#2 Useful — Fix keyboard reachability AND prune dead IA.** Convert the upload drop-zone, recent-scans row, and findings-table row from `onclick` on `<div>`/`<tr>` to keyboard-reachable patterns (`role="button"` + `tabindex="0"` + `keydown` for `Enter`/`Space`, OR move the click target onto a real `<button>` overlay). Remove or implement the 5 placeholder sidebar routes. Evidence: `dashboard.js:45,278`, `findings-table.js:120`, `router.js:39-43`.

4. **#10 Less Design — Deduplicate the offline banner and retire onboarding noise.** Extract one `frontend/js/components/offline-banner.js` component; import it from all 5 pages currently re-implementing it. Remove the "How it works / Quick tour" 5-step block at `dashboard.js:231` (or gate behind `localStorage.getItem("sentinel.onboardingSeen")`). Also delete the inline triageChip / verifyChip duplicates at `scan-detail.js:447-489` and use the canonical `severity-badge.js` exports. Evidence: `dashboard.js:111-133, 231`, `reports.js:200-221`, `scans.js:58-67`, `history.js:35-42`, `projects.js:31-38`, `scan-detail.js:447-489`.

5. **#8 Thorough — Close the contrast + a11y polish gap.** Replace `--text-muted #6B7280` (3.93:1 vs `--bg-primary`, fails WCAG AA) with a token that hits ≥4.5:1 (suggested `#8C96A8`). Add `aria-label` to the 3 topbar icon buttons at `topbar.js:38,42,45`. Add a skip-link in `app.html`. Add `<label for=>` to settings form inputs at `settings.js:36, 142+`. Evidence: `theme.css:27`; `topbar.js:38,42,45`; `app.html` (no skip-link); `settings.js:36, 142+`.

Redesign principles in priority order:
1. **#2 Useful** — Every primary action is keyboard-reachable, named after a real screen, and reachable in ≤2 clicks. Sidebar contains only items that take you somewhere.
2. **#6 Honest** — Every visible claim maps 1:1 to actual behaviour. The product describes what it does, not what it aspires to.
3. **#4 Understandable** — A first-time junior security researcher names every primary control correctly. No bare acronyms in nav.
4. **#10 As little design as possible** — One implementation per pattern, imported. No persistent onboarding past first-visit.
5. **#8 Thorough** — WCAG AA across every text token; aria-labels on all icon-only buttons; skip-link present.

Deliverables for the plan:
- New information architecture (sidebar tree with concrete, working routes only — show which 5 placeholders are removed vs implemented).
- New primary flow (low-fi wireframes for Dashboard → Scan list → Scan detail → Finding modal → VAPT, labelled with keyboard tab order at each step).
- Token decisions:
  - New `--text-muted` value with computed contrast ratio ≥ 4.5:1.
  - Confirm `--space-*` scale: 9 steps or 10? Document which 7 off-token values (11, 13, 14, 18, 28, 36, 38) get reabsorbed or kept.
  - First-visit onboarding token (boolean in localStorage + how it shows once).
- States checklist for every redesigned screen: empty / loading / error / success / focus / disabled — confirmed present and with copy.
- Honesty audit on every user-facing string before ship: replace `instantly`, `Professional`, `Client-ready`, `LLM-powered` per the moves above. Provide a before/after table.
- Migration path for users currently on the old design (URL aliases for any removed sidebar routes; deprecation notice if shipping incrementally).
- Cutover criteria: when is `feature/redesign` merged and the old code paths deleted (no flag-forever state).

Anti-patterns to guard against (specific to this REDESIGN):
- Porting `onclick`-on-`<div>` patterns under new styling — the keyboard bug must be fixed at the interaction layer, not hidden by CSS.
- Keeping the placeholder sidebar items "for vision signalling" — if they don't ship, they don't belong in nav.
- Inflating new copy ("Now even more powerful") — re-read the Honesty audit before merging any new microcopy.
- Treating the Preserve list as optional — the token system, the Djini finding-detail layout, and the routing architecture are load-bearing and must survive intact.
- Redesigning to follow a trend (glassmorphism, neumorphism, vibe-coded gradients) rather than the five priority principles above.
````
