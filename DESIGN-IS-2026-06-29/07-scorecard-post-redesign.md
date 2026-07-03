# Scorecard — SENTINEL Frontend Dashboard (Post-Redesign)

Re-scored against the modified codebase after Phases 1–5 (commits `cc7c2d7` → `dacb6c9`). Merge date column: **2026-07-03**. Anchors and tie-breaker rule ("when uncertain, pick lower") applied identically to the baseline audit.

---

**1. Good design is innovative — Score: 3/3 (Δ 0)**
   Evidence: Djini-style 7-section finding-detail modal (`frontend/js/components/finding-detail-view.js:7-52`) remains. Multi-agent VAPT pipeline + chain detection preserved; no novelty added or removed. Unchanged.

**2. Good design makes a product useful — Score: 3/3 (Δ +2)**
   Evidence: Keyboard reachability closed — upload drop-zone made a real button with `aria-label` (`frontend/js/pages/dashboard.js:43`); recent-scans rows now `role=button` with keydown handler (`dashboard.js:278`); findings-table rows same treatment (`findings-table.js` row handler). Placeholder sidebar routes pruned (Phase 3 IA prune) with router aliases. Every primary task is now reachable by both keyboard and mouse in ≤2 hops.
   Justification: primary tasks straightforward, keyboard parity — level-3 anchor.

**3. Good design is aesthetic — Score: 2/3 (Δ 0)**
   Evidence: System still single, still coherent. Phase 5 fixed one contrast issue (`--text-muted` re-tuned in `theme.css`) but the seven off-token spacing values were not systematically swept. Level-2 anchor still fits.

**4. Good design makes a product understandable — Score: 3/3 (Δ +2)**
   Evidence: Phase 4 jargon expansion — every user-facing acronym now has an inline gloss or tooltip (VAPT, MASVS, Phase 0/2/4/8, Frida, PoC). Onboarding gate added (localStorage `sentinel_seen_tour`) so first-run users get the "How it works" panel once, not on every dashboard load. "Phase 2 agents…" copy now names what Phase 2 does (`scan-detail.js:342`, empty-state copy). Controls are self-descriptive.
   Justification: controls self-descriptive, jargon glossed — level-3 anchor.

**5. Good design is unobtrusive — Score: 3/3 (Δ +1)**
   Evidence: Dashboard chrome trimmed — "How it works" is now onboarding-gated, offline banner deduped to a single component and imported (Phase 2 dedup, `dashboard.js:111` no longer redefines it). Nothing on the default dashboard demands attention beyond what the task requires.
   Justification: nothing demands attention beyond the task — level-3 anchor.

**6. Good design is honest — Score: 3/3 (Δ +2)**
   Evidence: Phase 1 honesty pass — "instantly" removed from `index.html`; "LLM-powered triage" marquee removed (opt-in nature now surfaced at the toggle); "Professional VAPT Report" / "Client-ready engagement deliverable" replaced with truthful methodology copy in `scan-detail.js`. Remaining grep hits are (a) a code comment in `findings-table.js:63` about CVSS bands reading "instantly" (developer prose, not user copy), and (b) a CLI-flag doc row for `--llm-triage` in `docs.js:35` describing what the flag does. Both benign.
   Justification: no inflated claims in user copy — level-3 anchor.

**7. Good design is long-lasting — Score: 2/3 (Δ 0)**
   Evidence: Palette / typography unchanged. Dark-only remains (no `prefers-color-scheme` light variant added — settings.js:219 shows Light theme button disabled). One dated marker persists.

**8. Good design is thorough down to the last detail — Score: 3/3 (Δ +1)**
   Evidence: Phase 5 a11y polish landed — `--text-muted` contrast fixed in `theme.css`; topbar icon buttons got `aria-label`s; skip-link added (reachable, off-screen not `visibility:hidden`); settings form inputs got `<label for=>` associations (`settings.js`). All six states (empty/loading/error/success/focus/disabled) verified present across touched screens (see `07-states-check.md`).
   Justification: states + edge polish both delivered — level-3 anchor.

**9. Good design is environmentally friendly — Score: 2/3 (Δ 0)**
   Evidence: JS budget essentially unchanged (dedup slightly reduced surface, no new deps). `prefers-reduced-motion` still honored. Below the <100 KB anchor because Chart.js / Lucide / Fonts CDN deps remain. Level-2 anchor.

**10. Good design is as little design as possible — Score: 3/3 (Δ +2)**
   Evidence: Phase 2 structural dedup — offline banner reduced from 5 implementations to 1 shared component; table-row pattern unified. Phase 3 IA prune removed 5 placeholder sidebar routes (registrations gone from `router.js`; page files slated for removal with URL aliases per plan §225). "How it works" panel gated behind first-run localStorage key. No removable elements remain visible on the steady-state dashboard.
   Justification: nothing removable without loss — level-3 anchor.

---

### Total: **27 / 30** (Δ +10 from baseline 17/30, target ≥24/30 met)

| Principle | Baseline (2026-06-29) | Post-redesign (2026-07-03) | Δ |
|---|:-:|:-:|:-:|
| 1. Innovative | 3 | 3 | 0 |
| 2. Useful | 1 | 3 | +2 |
| 3. Aesthetic | 2 | 2 | 0 |
| 4. Understandable | 1 | 3 | +2 |
| 5. Unobtrusive | 2 | 3 | +1 |
| 6. Honest | 1 | 3 | +2 |
| 7. Long-lasting | 2 | 2 | 0 |
| 8. Thorough | 2 | 3 | +1 |
| 9. Environmentally friendly | 2 | 2 | 0 |
| 10. As little design as possible | 1 | 3 | +2 |
| **Total** | **17 / 30** | **27 / 30** | **+10** |

No principle scored 1/3 (secondary target met). Two principles remain at 2/3 (Aesthetic — spacing-scale sweep deferred; Long-lasting / Environmental — light-theme + CDN-dep reduction deferred). These are out of scope for the current redesign cycle and tracked as follow-ups.

### Phase commit trail
- `0b327d9` — baseline (pre-redesign HEAD)
- `cc7c2d7` — Phase 1: honesty pass
- `80419fd` — Phase 2: structural dedup
- `ad089b5` — Phase 3: keyboard reachability + IA prune
- `b605279` — Phase 4: jargon expansion + onboarding gate
- `dacb6c9` — Phase 5: a11y polish
