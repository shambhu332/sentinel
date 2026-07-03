# Scorecard — SENTINEL Frontend Dashboard

Score range 0–3 per principle. Anchors applied verbatim from the audit rubric. Tie-breaker rule (when uncertain, pick lower) applied.

---

**1. Good design is innovative — Score: 3/3**
   Evidence: Djini-style 7-section finding-detail modal (`finding-detail-view.js:19-52`) is a pattern not seen in peer products (NowSecure / Appknox / Quixxi), and ships with restraint — no animation theatre, no novel interactions for novelty's sake. The product idea — multi-agent VAPT pipeline with chain detection (`COR_001`) and AI-triage (default OFF) — is genuinely fresh for the mobile-AppSec sector.
   Justification: introduces a pattern not seen in 5+ peer products, shipped with restraint.

**2. Good design makes a product useful — Score: 1/3**
   Evidence: 3 of 10 primary actions FAIL keyboard reachability (upload drop-zone `dashboard.js:45`, recent-scans row `dashboard.js:278`, findings-table row `findings-table.js:120`). Sidebar contains 5 placeholder routes that go nowhere (`router.js:39-43`). A junior researcher using keyboard literally cannot drill into a finding; a mouse-first user is funnelled past dead nav items.
   Justification: primary task requires unnecessary detours — not 2 (would need the placeholder routes and the keyboard gap to be fixed).

**3. Good design is aesthetic — Score: 2/3**
   Evidence: 38 colours and a 10-value type scale all flow from `theme.css:6-152` — solid system. Spacing scale drifts into 7 off-token values (11, 13, 14, 18, 28, 36, 38) — between three and five inconsistencies in real use vs the declared `--space-1..20` tokens.
   Justification: a single visible system exists but 3–5 spacing-scale inconsistencies puts this at 2, not 3.

**4. Good design makes a product understandable — Score: 1/3**
   Evidence: 10 jargon labels in user-facing surfaces (`VAPT`, `MASVS`, `Phase 0/2/4/8`, `Frida`, `Adaptive planner`, `ML strategy`, `PoC`, `AFL++ JNI fuzzing`, `No-proxy mode`, `Verify Engine`). Sidebar item "PoC" stands alone with no expansion. "Phase 2 agents are still running" appears in user copy without naming what Phase 2 does (`scan-detail.js:342`).
   Justification: 2–3 controls unclear and jargon present — the rubric's level-1 anchor matches.

**5. Good design is unobtrusive — Score: 2/3**
   Evidence: Sidebar + topbar are quiet, dark, and recede. Dashboard chrome is fuller — 4 KPI cards + offline banner + upload zone + 2 charts + "How it works" 5-step + Recent scans table on one screen. Chrome is visible but not loud; styling stays muted; no autoplay video or decoration.
   Justification: chrome visible but quiet — level-2 anchor.

**6. Good design is honest — Score: 1/3**
   Evidence: 5 inflated claims (`"instantly"` × 3 in `index.html`; `"LLM-powered triage"` marquee, but it's an opt-in toggle at `scan-modal.js:243`; `"Professional VAPT Report"` and `"Client-ready engagement deliverable"` at `scan-detail.js:607,609` with no attestation or methodology disclosure).
   Justification: 2+ inflations — level-1 anchor (not 0 because no dark patterns were found).

**7. Good design is long-lasting — Score: 2/3**
   Evidence: Inter + JetBrains Mono + restrained dark palette + cyan accent reads as current-generation, not trend-bound. One dated marker: dark-only with no `prefers-color-scheme` honoring (`theme.css` defines only `:root` dark; no light variant) — this will read as a 2020s "dark-mode-only" tool in 3 years.
   Justification: 1 dated marker — level-2 anchor.

**8. Good design is thorough down to the last detail — Score: 2/3**
   Evidence: all six required states are present and considered (empty, loading, error, success, focus, disabled). Edges are rough though — `--text-muted` fails AA contrast (3.93 : 1, `theme.css:27`); 3 topbar icon buttons missing `aria-label`; no skip-link; form inputs in settings have no `<label for=>` (`settings.js:36, 142`). Care visible at the system level; detail polish missing at the edge.
   Justification: states present but multiple polish details rough — level-2 anchor.

**9. Good design is environmentally friendly — Score: 2/3**
   Evidence: ~135 KB JS gzipped (under 500 KB), `prefers-reduced-motion` honored at `base.css:230-239`. Below level-3 anchor (<100 KB) because of 3 CDN dependencies (Google Fonts, Lucide, Chart.js). No autoplay video. Dark mode locked; light not respected.
   Justification: <500 KB and motion gated — level-2 anchor.

**10. Good design is as little design as possible — Score: 1/3**
   Evidence: "How it works / Quick tour" 5-step section persists on every dashboard load (`dashboard.js:231`) — removable. Offline banner is re-implemented 5 times (`dashboard.js:111-133`, `reports.js:200-221`, `scans.js:58-67`, `history.js:35-42`, `projects.js:31-38`) — 4 are duplicates. Table-row pattern re-implemented 3× (`dashboard.js`, `scans.js`, `scan-detail.js`). 5 sidebar routes are placeholders. ≥3 removable elements.
   Justification: 3–5 removable elements — level-1 anchor.

---

### Total: **17 / 30**

| Principle | Score |
|---|---|
| 1. Innovative | 3 |
| 2. Useful | 1 |
| 3. Aesthetic | 2 |
| 4. Understandable | 1 |
| 5. Unobtrusive | 2 |
| 6. Honest | 1 |
| 7. Long-lasting | 2 |
| 8. Thorough | 2 |
| 9. Environmentally friendly | 2 |
| 10. As little design as possible | 1 |
| **Total** | **17 / 30** |
