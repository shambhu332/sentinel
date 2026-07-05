# Eraser.io Prompts — SENTINEL BPMN Diagrams

For each BPMN figure in `coursework.md`, this file provides:

1. **AI-prompt** — paste into Eraser's chat / "Generate diagram with AI" box.
2. **Eraser DSL** — if the AI version drifts from the BPMN style you want, paste this directly into Eraser's code editor (the right-hand panel in any diagram).

Open https://app.eraser.io → New File → Flowchart diagram type → choose **AI** tab or **Code** tab.

---

## Figure 14 — Scan Submission Workflow (BPMN)

### AI Prompt

```
Generate a BPMN-style flowchart titled "Scan Submission Workflow."
Use three swim-lanes (pools) arranged vertically:
  Lane 1: "Customer (Developer / CI)"
  Lane 2: "SENTINEL Gateway"
  Lane 3: "Scan Queue"

Flow:
- Start event (green circle) "APK Ready" in the Customer lane.
- Customer task "Upload APK via Dashboard / CLI / GitHub Action" → Gateway.
- Gateway task "Authenticate user (JWT)" → exclusive gateway "Token valid?"
   - If No → end event (red circle) "401 Unauthorized."
   - If Yes → Gateway task "Validate APK signature & size."
- Gateway task "Apply tenant isolation (Postgres RLS)" → Gateway task "Queue scan job."
- Send message to Scan Queue lane → Scan Queue receive task "Job persisted."
- End event (cyan circle) "Scan-ID returned to client."

Use BPMN-standard shapes (circles for events, rounded rectangles for tasks,
diamonds for gateways), navy and white palette, and label every arrow.
```

### Eraser DSL (paste into Code tab if AI drifts)

```
title Scan Submission Workflow

// === Customer / Developer Lane ===
apk_ready [shape: oval, color: green, label: "APK Ready"]
upload [label: "Upload APK\n(Dashboard / CLI / GH Action)"]

// === Gateway Lane ===
auth [label: "Authenticate user\n(JWT)"]
token_valid [shape: diamond, label: "Token valid?"]
unauth [shape: oval, color: red, label: "401\nUnauthorized"]
validate [label: "Validate APK\nsignature & size"]
isolate [label: "Apply tenant\nisolation (RLS)"]
queue [label: "Queue scan job"]

// === Scan Queue Lane ===
persisted [label: "Job persisted\nto queue"]
end_ok [shape: oval, color: aqua, label: "Scan-ID\nreturned"]

// Flow
apk_ready > upload
upload > auth: submits APK
auth > token_valid
token_valid > unauth: No
token_valid > validate: Yes
validate > isolate
isolate > queue
queue > persisted: emit job
persisted > end_ok
```

---

## Figure 15 — Multi-Agent Scan Execution Workflow (BPMN)

### AI Prompt

```
Generate a BPMN-style flowchart titled "Multi-Agent Scan Execution Workflow."
Use four swim-lanes arranged vertically:
  Lane 1: "Orchestrator"
  Lane 2: "Phase 1 — Static Pre-Processing"
  Lane 3: "Phase 2 — 88 Agents in Parallel"
  Lane 4: "Phase 3 — LLM Triage & Compliance"

Flow:
- Start event (green circle) "Job picked up from queue" in Orchestrator.
- Task "Compute APK SHA-256 + parse AndroidManifest.xml" in Phase 1 lane.
- Task "Decompile APK via JADX" in Phase 1 lane.
- Parallel gateway (BPMN '+') splitting into THREE parallel branches:
   Branch A: "SAST Agents (C_007 weak crypto, A_004 storage, N_002 cleartext…)"
   Branch B: "Dynamic Agents (D_001 clipboard, D_011 WebView, D_018 SMS…)"
   Branch C: "Frida Runtime Agents (cert-pinning bypass, runtime crypto…)"
- Parallel join gateway (BPMN '+').
- Task "Deduplicate findings + scope filter."
- Task "LLM triage suppresses false positives" in Phase 3.
- Task "Stamp OWASP MASVS + NRB + MITRE ATT&CK tags."
- End event (cyan circle) "Findings persisted to scan-context."

Navy palette, BPMN-standard shapes, label every arrow.
```

### Eraser DSL

```
title Multi-Agent Scan Execution Workflow

// === Orchestrator ===
start [shape: oval, color: green, label: "Job picked up\nfrom queue"]

// === Phase 1: Static Pre-Processing ===
hash [label: "Compute APK SHA-256\n+ parse manifest"]
decompile [label: "Decompile APK\nvia JADX"]

// === Phase 2: Parallel Agents ===
split [shape: diamond, color: gold, label: "+\n(parallel fork)"]
sast [label: "SAST Agents\n(C_007, A_004,\nN_002, STG_007…)"]
dast [label: "Dynamic Agents\n(D_001, D_011,\nD_018, D_025…)"]
frida [label: "Frida Agents\n(cert-pinning,\nruntime crypto…)"]
join [shape: diamond, color: gold, label: "+\n(parallel join)"]

// === Phase 3: LLM Triage ===
dedup [label: "Deduplicate +\nscope filter"]
triage [label: "LLM triage\nsuppresses false\npositives"]
tags [label: "Stamp OWASP MASVS\n+ NRB + MITRE\nATT&CK tags"]
persist [shape: oval, color: aqua, label: "Findings\npersisted"]

// Flow
start > hash
hash > decompile
decompile > split
split > sast
split > dast
split > frida
sast > join
dast > join
frida > join
join > dedup
dedup > triage
triage > tags
tags > persist
```

---

## Figure 16 — Report Retrieval and SIEM Export Workflow (BPMN)

### AI Prompt

```
Generate a BPMN-style flowchart titled "Report Retrieval and SIEM Export Workflow."
Use three swim-lanes arranged vertically:
  Lane 1: "Customer / Auditor"
  Lane 2: "SENTINEL Gateway"
  Lane 3: "Reports & Evidence Store"

Flow:
- Start event (green circle) "Customer queries session-ID."
- Gateway task "Authenticate (JWT)" → exclusive gateway "JWT valid?"
   - No → end event (red circle) "401 Unauthorized."
   - Yes → Gateway task "Verify tenant access (Postgres RLS)."
- Exclusive gateway "Which format?" with SIX branches:
   * Branch 1: "Markdown report (.md)"
   * Branch 2: "HTML report (.html)"
   * Branch 3: "JSON report (.json)"
   * Branch 4: "SARIF bundle (.sarif)"
   * Branch 5: "SIEM bundle (.zip)"
   * Branch 6: "PoC bundle (.zip)"
- Each branch fetches its artefact from the Reports & Evidence Store.
- Merge gateway → Task "Write audit-trail entry."
- End event (cyan circle) "Artefact streamed to client."

BPMN-standard shapes, navy and teal palette, label every arrow.
```

### Eraser DSL

```
title Report Retrieval and SIEM Export Workflow

// === Customer / Auditor ===
query [shape: oval, color: green, label: "Customer queries\nsession-ID"]

// === Gateway ===
auth [label: "Authenticate (JWT)"]
jwt_valid [shape: diamond, label: "JWT valid?"]
unauth [shape: oval, color: red, label: "401\nUnauthorized"]
tenant_rls [label: "Verify tenant access\n(Postgres RLS)"]
fmt [shape: diamond, color: gold, label: "Which\nformat?"]

// === Reports & Evidence Store ===
md [label: "Markdown\nreport (.md)"]
html [label: "HTML\nreport (.html)"]
json [label: "JSON\nreport (.json)"]
sarif [label: "SARIF\nbundle (.sarif)"]
siem [label: "SIEM\nbundle (.zip)"]
poc [label: "PoC\nbundle (.zip)"]

// === Merge + Audit ===
merge [shape: diamond, color: gold, label: "X\n(merge)"]
audit [label: "Write audit-trail\nentry"]
done [shape: oval, color: aqua, label: "Artefact\nstreamed"]

// Flow
query > auth
auth > jwt_valid
jwt_valid > unauth: No
jwt_valid > tenant_rls: Yes
tenant_rls > fmt
fmt > md: markdown
fmt > html: html
fmt > json: json
fmt > sarif: sarif
fmt > siem: siem
fmt > poc: poc
md > merge
html > merge
json > merge
sarif > merge
siem > merge
poc > merge
merge > audit
audit > done
```

---

## Bonus — Entity Relationship Diagram (Figure 12, also feasible in Eraser)

Eraser is excellent for ERDs. If you also want to redo Figure 12 here:

### AI Prompt

```
Generate an entity relationship diagram titled "SENTINEL Entity Relationship Diagram."
Entities with their key attributes:
  - Customer (BFI / Developer): customer_id PK, name, tenant_id, contact_email
  - APK Submission: submission_id PK, customer_id FK, apk_sha256, uploaded_at
  - Scan Session: session_id PK, submission_id FK, status, started_at, completed_at
  - Agent: agent_id PK, vuln_class, phase, severity_default
  - Finding: finding_id PK, session_id FK, agent_id FK, severity, confidence,
             cvss_vector, owasp_ref, nrb_ref
  - Evidence: evidence_id PK, finding_id FK, type (snippet|screenshot|trace), path
  - Report: report_id PK, session_id FK, format (md|html|json|sarif), created_at
  - Auditor: auditor_id PK, name, tenant_scope

Relationships:
  - Customer 1—N APK Submission
  - APK Submission 1—1 Scan Session
  - Scan Session 1—N Finding
  - Agent 1—N Finding
  - Finding 1—N Evidence
  - Scan Session 1—N Report
  - Auditor M—N Report (via access_grant)

Navy palette, crow's-foot notation.
```

### Eraser DSL

```
title SENTINEL Entity Relationship Diagram

Customer [icon: user] {
  customer_id pk
  name string
  tenant_id string
  contact_email string
}

APK_Submission {
  submission_id pk
  customer_id fk
  apk_sha256 string
  uploaded_at datetime
}

Scan_Session {
  session_id pk
  submission_id fk
  status enum
  started_at datetime
  completed_at datetime
}

Agent [icon: cpu] {
  agent_id pk
  vuln_class string
  phase string
  severity_default enum
}

Finding {
  finding_id pk
  session_id fk
  agent_id fk
  severity enum
  confidence float
  cvss_vector string
  owasp_ref string
  nrb_ref string
}

Evidence {
  evidence_id pk
  finding_id fk
  type enum
  path string
}

Report {
  report_id pk
  session_id fk
  format enum
  created_at datetime
}

Auditor [icon: user-check] {
  auditor_id pk
  name string
  tenant_scope string
}

// Relationships
Customer.customer_id < APK_Submission.customer_id
APK_Submission.submission_id - Scan_Session.submission_id
Scan_Session.session_id < Finding.session_id
Agent.agent_id < Finding.agent_id
Finding.finding_id < Evidence.finding_id
Scan_Session.session_id < Report.session_id
Auditor.auditor_id <> Report.report_id
```

---

## How to use these in Eraser

1. Open https://app.eraser.io and sign in.
2. **New File → choose "Flowchart"** (or "Entity Relationship Diagram" for the ERD).
3. **Option A (AI):** Click the ✨ AI button at the bottom-right of the canvas. Paste the *AI Prompt* block. Eraser generates the diagram from natural language.
4. **Option B (Code):** Click the **`< >`** (code) toggle in the top-right. Paste the *Eraser DSL* block. The canvas updates live as you type.
5. **Export as PNG:** File → Export → PNG → choose a transparent or white background, 2× resolution. Drop the PNG into the corresponding `🎨 Figure N` placeholder in `SENTINEL_Coursework.docx`.

---

## Figure 22b — Before / After Process Map (Flowchart)

### AI Prompt

```
Generate a horizontal side-by-side comparison flowchart titled
"Mobile App Security Review — Manual vs. SENTINEL-Automated Workflow."

LEFT column (label: "BEFORE — Manual Review"):
Vertical flow of six sequential rounded rectangles connected by arrows:
  1. "Collect APK"           (analyst downloads build)
  2. "Decompile & Unpack"    (jadx / apktool, ~2 hrs)
  3. "Static Review"         (grep secrets, read Smali, 2–3 days)
  4. "Dynamic Testing"       (manual mitmproxy, tap through, 1–2 days)
  5. "Triage & Dedupe"       (spreadsheet, human severity calls)
  6. "Write Report"          (Word doc, manual screenshots)
Footer badges: "~10 days per app", "2 senior analysts",
"Coverage varies", "Findings: unstructured."

CENTER: a large horizontal arrow labeled "SENTINEL"
with subtitle "9× faster · reproducible · CI-ready."

RIGHT column (label: "AFTER — SENTINEL-Automated"):
Horizontal pipeline of eight connected hex tiles:
  1. "Ingest APK / IPA"
  2. "Decompile (auto jadx)"
  3. "SAST + Knowledge Graph"
  4. "Dynamic Capture (mitmproxy + UI Driver)"
  5. "API Traffic Map (BOLA / Mass-Assignment / Data-Exposure)"
  6. "Active Exploit Driver (auto-PoC)"
  7. "LLM Triage (dedupe + severity + category)"
  8. "SARIF + PDF Report"
Floating callout badges around it:
"Autonomous UI driver", "API_002/003/004 agents",
"Reproducible PoCs", "NRB / AML-CFT aligned."
Footer badges: "~1 day per app", "1 analyst supervises",
"9× scan optimization", "Findings: SARIF + structured JSON."

Navy + teal + coral palette. Sans-serif labels. Clean flat style.
```

### Eraser DSL

```
title Mobile App Security Review — Manual vs SENTINEL-Automated

// BEFORE column
before_hdr [shape: oval, color: coral, label: "BEFORE\nManual Review"]
b1 [label: "Collect APK"]
b2 [label: "Decompile & Unpack\n(jadx / apktool, ~2 hrs)"]
b3 [label: "Static Review\n(grep, read Smali, 2–3 days)"]
b4 [label: "Dynamic Testing\n(manual mitmproxy, 1–2 days)"]
b5 [label: "Triage & Dedupe\n(spreadsheet, human calls)"]
b6 [label: "Write Report\n(Word doc, manual screenshots)"]
b_stats [shape: oval, color: coral, label: "~10 days · 2 analysts\nCoverage varies · Unstructured"]

before_hdr > b1 > b2 > b3 > b4 > b5 > b6 > b_stats

// SENTINEL bridge
sentinel [shape: diamond, color: gold, label: "SENTINEL\n9× faster · reproducible · CI-ready"]
b6 > sentinel

// AFTER pipeline
after_hdr [shape: oval, color: aqua, label: "AFTER\nSENTINEL-Automated"]
a1 [label: "Ingest\nAPK / IPA"]
a2 [label: "Decompile\n(auto jadx)"]
a3 [label: "SAST + Knowledge Graph"]
a4 [label: "Dynamic Capture\n(mitmproxy + UI Driver)"]
a5 [label: "API Traffic Map\n(BOLA / MassAssign / DataExpo)"]
a6 [label: "Active Exploit Driver\n(auto-PoC)"]
a7 [label: "LLM Triage\n(dedupe + severity + category)"]
a8 [label: "SARIF + PDF Report"]
a_stats [shape: oval, color: aqua, label: "~1 day · 1 analyst\n9× optimization · SARIF"]

sentinel > after_hdr > a1 > a2 > a3 > a4 > a5 > a6 > a7 > a8 > a_stats
```

---

## Style consistency tips

To make all three BPMN diagrams visually consistent:

- Use the same colour code throughout: **green = start**, **red = error end**, **aqua / cyan = success end**, **gold / yellow = gateway**, **navy outline = task**.
- Use the same shape rules: ovals for events, rounded rectangles for tasks, diamonds for gateways.
- Set the same canvas zoom and arrow style before exporting each PNG.
- Right-click → "Match style across diagrams" if Eraser shows the option in your workspace.

---

*Output: paste the three BPMN PNGs at Figures 14, 15, 16 in the report; optionally replace Figure 12 ERD with the Eraser version.*
