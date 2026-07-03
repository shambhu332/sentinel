# Phase 1 Copy Diff

Decision: Option (a) — rewrite copy to reflect that LLM triage is opt-in. Scan-modal toggle default was NOT changed.

| file:line | before | after | reason |
|---|---|---|---|
| frontend/index.html:6 | `SENTINEL — Android security scanning, instantly` | `SENTINEL — Android security scanning` | Drop inflated "instantly" adjective; scans take minutes, not instants. |
| frontend/index.html:7 | `SENTINEL is the open-source Android security scanner with 20 specialized agents, dynamic Frida hooks, and LLM-powered triage.` | `SENTINEL is the open-source Android security scanner: 20 specialized agents run static analysis and dynamic Frida hooks by default, with optional LLM-assisted triage.` | Meta description overstated LLM triage as a default feature. Rewritten to describe true defaults (static + Frida) and mark LLM triage as opt-in. |
| frontend/index.html:58 | `<span class="gradient">instantly.</span>` | `<span class="gradient">in one pass.</span>` | Replace inflated "instantly" with an honest qualifier describing the single-run workflow. |
| frontend/index.html:61-62 | `SENTINEL fuses static analysis, dynamic Frida hooks, and LLM-powered triage across 20 specialized agents — so you can audit any APK in minutes.` | `SENTINEL runs static analysis and dynamic Frida hooks across 20 specialized agents, with optional LLM-assisted triage — so you can audit any APK in minutes.` | Hero body implied LLM triage was always-on. Rewritten to reflect opt-in reality. |
| frontend/index.html:116 (audit) | (no "instantly" occurrence found) | (unchanged) | Audit confirmed no remaining "instantly" occurrences in file after edits above. |
| frontend/js/pages/scan-detail.js:607 | `'Professional VAPT Report'` | `'VAPT Report'` | Drop marketing adjective "Professional"; the report either meets VAPT deliverable standards or it doesn't — labeling doesn't change that. |
| frontend/js/pages/scan-detail.js:609 | `'Client-ready engagement deliverable · ', el('span', { class: 'mono' }, scanId)` | `el('span', { class: 'mono' }, scanId)` | Remove "Client-ready engagement deliverable ·" subtitle — unfounded claim; keeps trailing scanId metadata intact. |
