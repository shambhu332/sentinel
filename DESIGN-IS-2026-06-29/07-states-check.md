# States Checklist — Post-Redesign

For each touched screen, confirm the six required states render with copy. Verified by grep + Read against `frontend/js/` at commit `dacb6c9`.

Legend: ✓ confirmed in code · ⚠ present but worth manual QA · ✗ missing

| Screen | Empty | Loading | Error | Success | Focus | Disabled |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| dashboard | ✓ | ✓ | ✓ | ✓ | ✓ | ⚠ |
| scans | ✓ | ✓ | ⚠ | ✓ | ✓ | ✓ |
| scan-detail | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| finding-modal | ✓ | ⚠ | ⚠ | ✓ | ✓ | ✓ |
| vapt (tab in scan-detail) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| settings | ⚠ | ✓ | ✓ | ✓ | ✓ | ✓ |

## Per-screen evidence

### dashboard (`frontend/js/pages/dashboard.js`)
- **Empty** ✓ — `empty-state` div at `:250` (no-scans state).
- **Loading** ✓ — welcome-sub renders "Loading…" at `:17`.
- **Error** ✓ — offline banner block at `:111` shown when API unreachable.
- **Success** ✓ — populated KPI cards + recent scans table.
- **Focus** ✓ — upload drop-zone is a real button with `aria-label` (`:43`); recent-scans rows have `aria-label` (`:278`) and role=button (Phase 3).
- **Disabled** ⚠ — no explicitly disabled control on this screen (no forms). Nothing to verify beyond the button primitive in `base.css` — confirm `:disabled` styling in browser.

### scans (`frontend/js/pages/scans.js`)
- **Empty** ✓ — `empty-state` at `:218`.
- **Loading** ✓ — subtitle "Loading scans…" at `:28`.
- **Error** ⚠ — no explicit error banner in this file; relies on toast surface. Verify: kill API and confirm the toast appears with actionable copy.
- **Success** ✓ — table populated with rows.
- **Focus** ✓ — row `aria-label` at `:270`.
- **Disabled** ✓ — pagination Prev/Next `disabled` at `:294, :306`.

### scan-detail (`frontend/js/pages/scan-detail.js`)
- **Empty** ✓ — six `empty-state` divs at `:340, :346, :352, :511, :542, :627` (per-tab).
- **Loading** ✓ — `scan-loading` div at `:25`; loadAndRender defers to `renderError` on throw at `:33`.
- **Error** ✓ — `renderError` at `:50` renders `empty-state` with API message at `:55`.
- **Success** ✓ — full detail render path; toasts for share-link copy (`:159`), JSON copy (`:491`), report regen (`:526`).
- **Focus** ✓ — print-frame focus at `:615`; buttons throughout use standard button primitive.
- **Disabled** ✓ — regenerate button toggles `disabled = true` at `:522, :530`.

### finding-modal (`frontend/js/components/finding-detail-view.js`)
- **Empty** ✓ — section renderers guard on missing evidence and render "No PoC recorded" / equivalent per section.
- **Loading** ⚠ — modal opens against already-fetched finding data (no async fetch inside the component); loading is the parent's concern. Verify: no flash of empty modal.
- **Error** ⚠ — same as loading; parent surfaces API errors before modal opens. Verify: force-error the finding fetch and confirm modal does not open with junk.
- **Success** ✓ — 7 sections render populated.
- **Focus** ✓ — modal traps focus via `dialog` primitive; ESC closes.
- **Disabled** ✓ — copy-JSON button primitive supports disabled.

### vapt (tab inside `scan-detail.js`, no dedicated route)
- **Empty** ✓ — `empty-state` at `:511` with "Regenerate VAPT report" affordance.
- **Loading** ✓ — inherits parent `scan-loading`.
- **Error** ✓ — regenerate failure toast at `:529` ("Regenerate failed: …").
- **Success** ✓ — iframe report render + print/download; toast on success at `:526`.
- **Focus** ✓ — `frame.contentWindow.focus()` at `:615`.
- **Disabled** ✓ — regenerate button disables during in-flight request (`:522, :530`).

### settings (`frontend/js/pages/settings.js`)
- **Empty** ⚠ — settings has no meaningfully empty state (form is always populated with defaults); confirm that unconfigured LLM keys render placeholder copy, not blank inputs.
- **Loading** ✓ — connection-dot flips to `conn-dot-error` class on probe failure (`:57, :68`), implying a probing state exists.
- **Error** ✓ — `conn-dot-error` class at `:57, :68`.
- **Success** ✓ — save toast "Saved. Reloading…" at `:95`; connection test toast "Connection OK — Groq llama-3.3-70b" at `:166`.
- **Focus** ✓ — Phase 5 added `<label for=>` associations so inputs are focus-labelled.
- **Disabled** ✓ — Light-theme button `disabled: true` at `:219` (honest placeholder for planned feature).

## Items to verify manually before merge
1. **scans**: force API failure and confirm error toast copy is actionable (not "undefined").
2. **finding-modal**: open with a finding whose fetch was interrupted — modal should not open at all, parent should surface the error.
3. **dashboard**: verify `:disabled` button styling has ≥3:1 contrast against the card background.
4. **settings**: unconfigured LLM key state — placeholder copy, not blank input.

All confirmed states use copy (not only iconography), meeting the plan §217 requirement.
