# Scope — SENTINEL Frontend Dashboard Audit

**Date:** 2026-06-29
**Auditor:** Claude Opus 4.7 (orchestrator) + 5 evidence subagents
**Framework:** Dieter Rams' 10 Principles of Good Design

## What is being audited

The entire SENTINEL frontend dashboard at `frontend/` — a vanilla-JS SPA
with hash routing served by the FastAPI gateway. Audit covers every
page reachable from the sidebar:

- `/dashboard` — overview KPIs, upload, recent scans
- `/scans` — scan list
- `/scans/{id}` — scan detail (Findings table, Summary, VAPT, JSON tabs)
- Finding detail modal (xl, opened from any row)
- `/agents` — agent catalog
- `/reports`, `/history`, `/projects`
- `/knowledge`, `/verify`, `/poc` (AI Platform group)
- `/devices`, `/settings`, `/docs`

## Primary user

A **junior security researcher** following a SAST/DAST playbook against
a mobile APK. Secondary user: a CISO / project owner reading the VAPT
pane and executive summary.

## Primary task

Submit an APK → watch the scan complete → drill into a finding →
reproduce the vulnerability using the steps shown → export the VAPT
report.

## Live target

Dev gateway running at `http://localhost:8000/` (returned HTTP 200 at
scope-lock time). Visual + Weight subagents may instrument the live URL
via the `agent-browser` skill; Structural / Copy subagents read source.

## Constraints

- Stack: vanilla HTML/CSS/JS — no framework, ES modules, hash routing
- Theme: self-hosted dark UI; CSS tokens in `frontend/css/`
- Accessibility floor: WCAG 2.1 AA
- Brand: cyan accent, JetBrains-Mono for IDs, Inter / system-ui for UI

## Reference materials

- `frontend/js/pages/` — page renderers
- `frontend/js/components/` — modal, finding-detail, screenshot carousel
- `frontend/css/components.css` — finding-detail tokens
- The 27 Canva prompts in `prompt.md` describe the intended UI

## Out of scope

- The gateway / Python backend
- The 180+ security agents themselves
- Coursework `.docx` deliverables
