# STA309IAE — Design Thinking and Innovation
## SENTINEL: An AI-Augmented Multi-Agent Mobile VAPT Platform for Nepal's Fintech Sector
## Coursework Report

**Submitted to:** Mr. Rupak Rajbanshi
**Submitted by:** [Your Name]
**Softwarica ID:** [240xxx]
**Coventry ID:** [153xxxxx]
**Batch:** Ethical 34

> 🎨 **Cover Page** — see `prompt.md` #0

---

## Abstract

Mobile applications have become the primary delivery channel for banking, payments, and identity services in Nepal, yet security testing of these applications remains slow, expensive, and reliant on scarce expertise. Existing approaches rely on either commercial static scanners that miss runtime classes of vulnerabilities, or manual penetration-testing engagements that take weeks and cost over USD 20,000 per assessment. This study presents the conceptual design and process-level prototype of **SENTINEL**, a multi-agent, AI-augmented Vulnerability Assessment and Penetration Testing (VAPT) platform tailored to Nepal's fintech and Banking & Financial Institution (BFI) ecosystem. The paper concentrates on design thinking and business-process modelling rather than the implementation of every cryptographic primitive. The findings indicate that a multi-agent VAPT platform, paired with a Large-Language-Model triage layer and an evidence-rich reporting pipeline, can compress the cost, time, and expertise barriers of mobile security assessment into a single ten-minute workflow that serves developers, security teams, compliance officers, and regulators simultaneously.

**Keywords:** *Mobile Application Security, Multi-Agent VAPT, Design Thinking, Business Process Management (BPM), BPMN, Large Language Models, Static + Dynamic Analysis, Compliance Mapping, OWASP MASVS, Nepal Fintech, Frida Instrumentation, Reporting Entity, SARIF, MITRE ATT&CK.*

> 🎨 **Infographic K — Keywords Word-Cloud** — see `prompt.md` #K

---

## Acknowledgement

I would like to sincerely thank my module leader, **Mr. Rupak Rajbanshi**, for his guidance, structured feedback, and the clarity he brought to every stage of this project. His teaching shaped the way I approached problem framing and process modelling. I am also grateful to **Softwarica College of IT & E-Commerce** for the academic environment and resources made available throughout the module. Finally, I would like to acknowledge the developers, compliance officers, and security engineers from Nepal's fintech sector who shared their lived experience of mobile security testing — their candid feedback during the empathise phase reshaped the SENTINEL prototype from a developer-only tool into the multi-stakeholder evidence platform it is today.

---

## Table of Contents

| Section | Page |
|---|---|
| Abstract | i |
| Acknowledgement | ii |
| Table of Contents | iii |
| List of Figures | v |
| List of Tables | vi |
| List of Abbreviations | vii |
| Introduction | 1 |
| Problem Statement | 2 |
| Aim and Objectives of SENTINEL | 3 |
| Scope of the Study | 3 |
| Limitations and Assumptions | 4 |
| Concept to Reality: Multi-Agent VAPT Rationale | 5 |
| Transition from Manual Pen-Testing to Automated VAPT Model | 5 |
| Design Thinking Approach | 6 |
| Empathise Phase: Stakeholder Understanding | 7 |
| Define Phase: Problem Framing and Insights Synthesis | 8 |
| &nbsp;&nbsp;&nbsp; Empathy Map Analysis | 8 |
| &nbsp;&nbsp;&nbsp; POEMS Observations | 10 |
| &nbsp;&nbsp;&nbsp; Root Cause Analysis using 5 Whys Technique | 11 |
| &nbsp;&nbsp;&nbsp; How Might We (HMW) Problem Statement | 12 |
| &nbsp;&nbsp;&nbsp; Point of View (POV) Statement | 13 |
| Ideation and Solution Development | 14 |
| &nbsp;&nbsp;&nbsp; Ideation Process Overview | 14 |
| &nbsp;&nbsp;&nbsp; Divergent Thinking: Alternative VAPT Models | 15 |
| &nbsp;&nbsp;&nbsp; Convergent Thinking: Final SENTINEL Model Selection | 16 |
| Business Model Development | 17 |
| &nbsp;&nbsp;&nbsp; SENTINEL Platform Prototype Overview | 18 |
| &nbsp;&nbsp;&nbsp; Feasibility Analysis | 19 |
| &nbsp;&nbsp;&nbsp; Applications of Business Process Management (BPM) | 20 |
| &nbsp;&nbsp;&nbsp; Business Process Model and Notation (BPMN) | 21 |
| &nbsp;&nbsp;&nbsp; SENTINEL Workflow Summary Table | 23 |
| &nbsp;&nbsp;&nbsp; Product Life Cycle of the SENTINEL Platform | 24 |
| &nbsp;&nbsp;&nbsp; SENTINEL Customer Value Chain | 25 |
| Feedback and Analysis | 26 |
| &nbsp;&nbsp;&nbsp; Stakeholder Feedback | 27 |
| &nbsp;&nbsp;&nbsp; Key Findings | 28 |
| &nbsp;&nbsp;&nbsp; Risks and Improvement Areas | 28 |
| Learning Outcomes | 29 |
| &nbsp;&nbsp;&nbsp; Professional Exposure | 29 |
| &nbsp;&nbsp;&nbsp; Personal Development | 29 |
| &nbsp;&nbsp;&nbsp; Future Career Prospects | 30 |
| Conclusion | 31 |
| References | 32 |
| Appendix | 33 |

---

## List of Figures

| Figure | Title | Page |
|---|---|---|
| Figure 1 | Traditional Mobile-App VAPT Process in Nepal's Fintech Ecosystem | 1 |
| Figure 2 | Pain Points in Existing Mobile-App Security Process | 2 |
| Figure 3 | Manual Pen-Testing to Automated Multi-Agent VAPT (Conceptual View) | 5 |
| Figure 4 | Design Thinking Framework Applied to SENTINEL | 6 |
| Figure 5 | Developer Empathy Map | 8 |
| Figure 6 | Security Engineer & Compliance Officer Empathy Map | 9 |
| Figure 7 | 5 Whys Root Cause Analysis of Manual VAPT Bottleneck | 11 |
| Figure 8 | Ideation Process Overview | 14 |
| Figure 9 | Divergent Thinking — Alternative VAPT Models | 15 |
| Figure 10 | Convergent Thinking — Final SENTINEL Model Selection | 16 |
| Figure 11 | Phases of Business Model Development | 17 |
| Figure 12 | SENTINEL Entity Relationship Diagram | 18 |
| Figure 13 | SENTINEL Feasibility Analysis | 19 |
| Figure 14 | Scan Submission Workflow (BPMN) | 21 |
| Figure 15 | Multi-Agent Scan Execution Workflow (BPMN) | 22 |
| Figure 16 | Report Retrieval and SIEM Export Workflow (BPMN) | 22 |
| Figure 17 | SENTINEL Platform Product Life Cycle | 24 |
| Figure 18 | SENTINEL Customer Value Chain | 25 |
| Figure 19 | SENTINEL Prototype Review — Feedback & Analysis | 26 |
| Figure 20 | Learning Outcomes | 29 |
| Figure 21 | SENTINEL Dashboard — Scan Submission | 33 |
| Figure 22 | SENTINEL Dashboard — Finding Detail View with Evidence | 33 |
| Figure 23 | SENTINEL Dashboard — Executive Risk Summary | 34 |
| Figure 24 | SENTINEL Dashboard — Compliance & Audit Bundle | 34 |
| Figure 25 | SWOT Analysis | 35 |
| Figure 26 | SENTINEL — Business Model Canvas | 35 |
| Figure 27 | PESTLE Analysis | 36 |

---

## List of Tables

| Table | Title | Page |
|---|---|---|
| Table 1 | POEMS Observation | 10 |
| Table 2 | HMW — How Might We Canvas | 12 |
| Table 3 | Point of View Statement Canvas | 13 |
| Table 4 | SENTINEL Workflow Summary | 23 |
| Table 5 | Stakeholder Feedback Summary | 27 |
| Table 6 | Personal Development Summary | 29 |

---

## List of Abbreviations

| Abbr. | Expansion |
|---|---|
| **ADB** | Android Debug Bridge |
| **AML** | Anti-Money Laundering |
| **APK** | Android Application Package |
| **BFI** | Bank and Financial Institution |
| **BPM** | Business Process Management |
| **BPMN** | Business Process Model and Notation |
| **CFT** | Counter-Financing of Terrorism |
| **CI/CD** | Continuous Integration / Continuous Delivery |
| **CVSS** | Common Vulnerability Scoring System |
| **DAST** | Dynamic Application Security Testing |
| **HMW** | How Might We |
| **IPC** | Inter-Process Communication |
| **JWT** | JSON Web Token |
| **LLM** | Large Language Model |
| **MASVS** | Mobile Application Security Verification Standard |
| **MITRE ATT&CK** | MITRE Adversarial Tactics, Techniques, and Common Knowledge |
| **NRB** | Nepal Rastra Bank |
| **OWASP** | Open Worldwide Application Security Project |
| **POEMS** | People, Objects, Environments, Messages, Services |
| **POV** | Point of View |
| **PLC** | Product Life Cycle |
| **PoC** | Proof of Concept |
| **RLS** | Row-Level Security |
| **SaaS** | Software as a Service |
| **SARIF** | Static Analysis Results Interchange Format |
| **SAST** | Static Application Security Testing |
| **SIEM** | Security Information and Event Management |
| **SOC2** | Service Organization Control 2 |
| **VAPT** | Vulnerability Assessment and Penetration Testing |

---

## INTRODUCTION

Mobile applications are now the dominant interface for delivering banking, digital wallet, micro-loan, payment, and identity services in Nepal. According to Nepal Rastra Bank's payment system statistics (NRB, 2024), more than 80% of retail digital transactions in the country are initiated from a smartphone application. With the breadth of services delivered through mobile, the attack surface has grown proportionally — exposed deep links, insecure storage of session tokens, weak cryptographic primitives, and runtime tampering have all become common bug classes in mobile audits of Nepalese fintech apps (OWASP, 2024).

Although mobile security assessment is a critical control under Nepal's evolving digital-payment regulations and the broader AML/CFT requirements (NRB, 2008; FATF, 2025), the current practice of conducting it remains institution-specific, manual, and slow. Each BFI engages a separate penetration-testing consultancy per release, each consultancy uses a different methodology and reporting format, and each developer team receives a static PDF that is hard to action against tight release schedules.

From the customer side, the consequences of this fragmented and slow security assurance process are real: unpatched vulnerabilities reach production, sensitive data leaks become commonplace, and customer trust in digital financial services erodes. From the BFI side, security testing is treated as a quarterly compliance overhead rather than a continuous quality gate.

> 🎨 **Figure 1 — Traditional Mobile-App VAPT Process in Nepal's Fintech Ecosystem** — see `prompt.md` #1

---

## PROBLEM STATEMENT

The absence of a centralised, automated, evidence-rich mobile-application VAPT capability in Nepal's fintech sector has led to several systemic issues. Developers are dependent on infrequent external pen-tests, which are slow to commission and expensive to run. Security engineers within BFIs are forced to operate complex open-source tools such as Frida, Drozer, and mitmproxy without dedicated training or workflow tooling, leading to inconsistent coverage from one engagement to the next. Compliance officers face increasing audit pressure but have no consolidated evidence trail tying each technical finding back to the relevant regulation. As a result, the existing process makes secure mobile-application delivery longer, more expensive, and harder to defend during an NRB or external audit. The fact that institutions cannot easily reuse each other's verified detection-rules makes it even harder to spread security improvements across the ecosystem (BCBS, 2016).

> 🎨 **Figure 2 — Pain Points in Existing Mobile-App Security Process** — see `prompt.md` #2

---

## AIM AND OBJECTIVES OF SENTINEL

The primary aim of the study is to design **SENTINEL**, a multi-agent, AI-augmented mobile-application VAPT platform that enables secure, standardised, and reusable security assessment across Nepal's fintech and BFI ecosystem.

The objectives of the project are:

1. To reduce the time, cost, and expertise required for a complete mobile-application security assessment.
2. To improve detection consistency and coverage across institutions through a shared multi-agent library.
3. To enhance regulatory compliance and audit readiness via automatic OWASP MASVS, NRB, and AML/CFT citation mapping.
4. To make scan execution faster than the weekly mobile-application release cadence of a typical fintech team.
5. To propose a scalable VAPT framework that combines static analysis, dynamic instrumentation (Frida), and LLM-driven triage into a single workflow.

---

## SCOPE OF THE STUDY

This study emphasises the conceptual design and the workflow-level prototype of a multi-agent VAPT platform applicable across Nepal's fintech ecosystem. It includes all NRB-licensed BFIs and fintech operators; developers and compliance officers are treated as primary users. The study also covers the application of core artefacts such as the Android Application Package (APK), supplemented by manifest, decompiled source, and runtime instrumentation evidence. LLM-driven triage and SARIF-based interoperability with SIEM platforms is included (MITRE, 2024). The emphasis is on process design, stakeholder interaction, and operational feasibility rather than on full-scale technical development or enterprise deployment.

---

## LIMITATIONS AND ASSUMPTIONS

The study is limited to a conceptual and process-oriented SENTINEL prototype and does not include the implementation of every detection rule, every cryptographic verification, or live deployment into a production BFI environment. Proposed improvements for the future include iOS scanner extension and on-device firmware analysis for the wider digital-payment ecosystem. The study presupposes regulatory collaboration with NRB, institutional preparedness within BFIs, and developer acceptance as essential prerequisites for the effective implementation and functioning of the SENTINEL platform in Nepal.

---

## CONCEPT TO REALITY: MULTI-AGENT VAPT RATIONALE

The growing complexity of mobile-financial services in Nepal has exposed the limitations of institution-specific, manual penetration-testing practices. A fintech customer often maintains active relationships with multiple BFIs, digital wallets, and capital-market platforms, which means a single weak mobile application can compromise an identity that is reused across the entire ecosystem.

By enabling a verified multi-agent VAPT engine to be invoked on every release, on every APK, the SENTINEL platform solves this problem. Detection rules authored once by an expert agent contributor are immediately available to every BFI consuming the platform. Compliance evidence — code snippets, runtime screenshots, MITRE ATT&CK tags — is captured the moment a finding is generated, not weeks later when an audit demands it. On the regulatory side, SENTINEL aligns with NRB's stated ambitions for digital transformation and risk-based supervision (NRB, 2024).

### Transition from Manual Pen-Testing to Automated Multi-Agent VAPT Model

The transition from a manual, consultancy-led penetration-testing model to an automated multi-agent VAPT platform represents both an ideological change in institutional culture and an advancement in process design. Under the current model, mobile-security findings are siloed in the report of a specific consultancy for a specific release, with no compatibility or standardisation across BFIs.

On the contrary, in the proposed SENTINEL model, every scan invokes the same 88-agent library, emits findings in the same structured Finding schema, and persists evidence in the same workspace layout. Reporting entities (BFIs) submit the APK; the platform returns a SARIF + PDF + executive-summary bundle. The shift reduces time-to-insight from weeks to minutes, reduces operating cost per scan to near zero, and increases consistency in security data across the financial ecosystem, which is essential for effective AML and CFT controls.

> 🎨 **Figure 3 — Manual Pen-Testing to Automated Multi-Agent VAPT (Conceptual View)** — see `prompt.md` #3

---

## DESIGN THINKING APPROACH

The SENTINEL platform is a service-oriented initiative that affects developers, security engineers, compliance officers, and the regulator simultaneously. The user experience and operational realities of mobile-security work are frequently overlooked in favour of compliance checklists and technology dashboards in traditional system-design approaches.

Design thinking provides a human-centred and structured approach to problem-solving (Brown, 2008). In Nepal's diverse fintech environment, it helps balance usability, data security, regulatory compliance, and operational efficiency. This approach enables SENTINEL to improve developer convenience, reduce duplicated effort across institutions, and support long-term sustainability of the security-assurance function (ISO, 2019).

> 🎨 **Figure 4 — Design Thinking Framework Applied to SENTINEL** — see `prompt.md` #4

---

## EMPATHISE PHASE: STAKEHOLDER UNDERSTANDING

This phase is concerned with understanding the needs and challenges faced by every stakeholder associated with the mobile-security process.

1. **Developers and Engineering Managers:** Repeated waiting for a third-party pen-test, having no security feedback in the developer loop, and receiving findings that arrive too late to act upon before the next release. A scalable VAPT platform must integrate directly into CI/CD, present findings inline in the code workflow, and remain usable without security expertise.

2. **Security Engineers and AppSec Teams:** Mobile security work is both a regulatory requirement and an operational burden. Inconsistent results across engagements, manual evidence gathering, and longer triage times are the result of toolchain fragmentation. Security teams need a system that lowers operational effort, increases detection consistency, and guarantees evidence completeness.

3. **Compliance Officers and Regulators:** NRB, as the central regulatory authority, focuses on governance, AML/CFT compliance, and supervisory oversight (NRB, 2008; FATF, 2025). Compliance officers within BFIs require evidence packets that explicitly map each technical finding to the regulation it violates. Together, they require SENTINEL to function as a trusted national reference workflow with strong governance and access controls.

---

## DEFINE PHASE: PROBLEM FRAMING; INSIGHTS SYNTHESIS

The define phase translates the stakeholder observations from the empathise stage into clearly defined problems and design insights. This phase ensures that the SENTINEL solution addresses root causes and provides a strong foundation for ideation and solution development.

### Empathy Map Analysis

By analysing what users think, feel, say, and do during the mobile-security workflow, the empathy map unites stakeholder perspectives (Brown, 2008). While the security engineer is worried about coverage, inconsistency, and triage workload, the developer is irritated by delayed feedback and unclear remediation guidance. Regulators prioritise transparency, evidence integrity, and audit readiness. This analysis highlights a need for a standardised, reusable, and trustworthy VAPT mechanism while maintaining regulatory control.

> 🎨 **Figure 5 — Developer Empathy Map** — see `prompt.md` #5
>
> 🎨 **Figure 6 — Security Engineer & Compliance Officer Empathy Map** — see `prompt.md` #6

### POEMS Observations

The POEMS framework (People, Objects, Environments, Messages, Services) is used to closely observe and highlight the need for a unified VAPT system that makes mobile-security testing simpler and more consistent across Nepal's fintech sector.

> 🎨 **Table 1 — POEMS Observation** — see `prompt.md` #T1

| POEMS Lens | Observations |
|---|---|
| **P – People** | Mobile developers shipping weekly releases; AppSec engineers triaging findings; compliance officers preparing for NRB audits; CISOs reporting to the board; external pen-test consultancies. |
| **O – Objects** | Android Application Packages (APKs); Frida runtime instrumentation; ADB tooling; CI/CD pipelines; mitmproxy capture logs; PDF audit reports; SARIF bundles. |
| **E – Environments** | Fragmented mobile-dev laptops; sand-boxed Android test devices; shared SOC dashboards; long email threads delivering PDF reports; CI build agents in the cloud. |
| **M – Messages** | "We can't ship until security signs off." "The pen-test report just landed — we have 3 days to remediate." "We can't reuse findings from the last scan." "System is slow, please wait for the result." |
| **S – Services** | Manual pen-testing engagements; ad-hoc Frida hook scripts; isolated MobSF runs; PDF report distribution; manual evidence-screenshot collection. |
| **Comments on User Experience** | Developers feel locked out of security feedback. Security engineers experience repeated cognitive load from manual hook authoring. Compliance officers cannot reconcile evidence with regulations until very late. |
| **General Thoughts** | The observations reveal a lack of interoperability and shared mobile-security tooling. A multi-agent platform with LLM triage can reduce duplication, improve evidence quality, and enhance regulatory readiness. |

### Root Cause Analysis using 5 Whys Technique

The 5 Whys technique is applied to identify the underlying causes of slow, expensive, and inconsistent mobile-security assessment. The analysis reveals the repeated cost-and-time burden occurs because institutions operate independently of any shared detection-rule infrastructure. This gap continues to exist because of fragmented vendor markets, limited interoperability between security tools, and a long history of relying on bespoke human-led consultancies. Identifying these root causes confirms that the problem is systemic rather than procedural, requiring a coordinated, automated solution (BCBS, 2016).

> 🎨 **Figure 7 — 5 Whys Root Cause Analysis of Manual VAPT Bottleneck** — see `prompt.md` #7

### How Might We (HMW) Problem Statement

Based on the insights gathered, the central design challenge is articulated using the *How Might We* framework:

> ***How might we design a fast, evidence-rich, and shareable mobile-application VAPT platform that reduces repetitive penetration-testing effort for fintech teams, improves operational efficiency for security engineers, and enhances regulatory oversight for NRB and compliance authorities?***

This HMW statement guides the solution toward balancing usability, compliance, and scalability (Brown, 2008).

> 🎨 **Table 2 — HMW Canvas** — see `prompt.md` #T2

| The core design challenge | Primary stakeholders / extreme users | Feature, tool, or process | Context or environment | Purpose or motivation |
|---|---|---|---|---|
| **HMW Questions** | **WHOM** | **WHAT** | **WHERE** | **WHY** |
| How might we design an automated, multi-agent VAPT platform that fits a weekly mobile-release cadence across Nepal's fintech sector? | Mobile developers; AppSec engineers in BFIs; compliance officers; NRB supervisory staff; external auditors. | A multi-agent VAPT engine with 88 specialised agents, LLM-driven triage, automatic evidence capture, and SARIF / SIEM export. | NRB-licensed BFIs and digital-wallet operators across Nepal, integrated with CI/CD pipelines and audit-evidence workflows. | To eliminate repeated, manual pen-tests, improve developer feedback time, ensure consistent detection across institutions, and strengthen regulatory oversight. |
| **Action-Subject-Outcome** | **Action:** Develop a multi-agent, AI-augmented VAPT platform that enables shared, repeatable mobile-security assessment. **Subject:** The SENTINEL platform with 88 agents, LLM triage, and SARIF interoperability. **Outcome:** Fintech teams complete security assessment in minutes per release, reusing detection rules and evidence schemas across institutions to deliver consistent, regulator-aligned identity-assurance nationwide. | | | |

### Point of View (POV) Statement

The Point of View statement combines user needs and insights into a clear problem definition:

> *Mobile-application development teams in Nepal's fintech sector need a fast, multi-stakeholder, evidence-rich VAPT workflow because today's institution-specific, manual penetration-testing process brings frustration to developers, inefficiency to security engineers, and audit risk to compliance officers and regulators.*

> 🎨 **Table 3 — Point of View Canvas** — see `prompt.md` #T3

| Users | Needs | Insights |
|---|---|---|
| **Developer** | A scan that runs inside CI, fails the build on new criticals, and shows the offending line of code. | Developers don't read PDFs. Without code-level feedback they cannot remediate before the next release. |
| **Security Engineer (Extreme User)** | Runtime instrumentation, taint flow, and screenshot evidence without writing Frida scripts by hand each time. | Manual instrumentation does not scale across ten weekly releases. Engineers need leverage, not labour. |
| **Compliance Officer** | Every finding stamped with the OWASP / NRB / AML reference it violates. | Audits fail on evidence trails, not on findings. Late mapping is the operational pain. |
| **NRB / Regulator** | A trusted national reference workflow and detection-rule corpus with strong governance and audit trails. | Fragmented detection rules across BFIs make supervisory comparison and risk-based oversight harder. |
| **External Auditor** | A SARIF / SIEM bundle that can be ingested into existing SOC platforms. | Custom PDF formats slow down audits and prevent automation downstream. |
| **Bottom Banner** | Users across Nepal — developers, security engineers, compliance officers, regulators, and external auditors — need a fast, shared, evidence-rich VAPT platform because fragmented manual processes cause delays, inconsistency, and higher compliance burden across the financial ecosystem. | |

---

## IDEATION AND SOLUTION DEVELOPMENT

The ideation phase takes forward the well-articulated problem statement and insights generated during the previous phases. It takes into account convenience for developers, governance requirements, and regulatory expectations, among many other operational realities. It is essential to note that this stage of organising ideas ensures that the chosen model of automated VAPT is not only rational but also practical.

### Ideation Process Overview

The ideation stage integrates the insights gathered from stakeholders, the limitations imposed by the regulator, and the realities of mobile-engineering operations to create possible VAPT solution alternatives. Instead of choosing a solution immediately, alternatives are discussed first to make sure the final solution is feasible and scalable. The structured evaluation helps find solutions that can adapt to new regulations and technologies, ensuring the SENTINEL system stays useful over time (Nissinen, 2013).

> 🎨 **Figure 8 — Ideation Process Overview** — see `prompt.md` #8

### Divergent Thinking: Alternative VAPT Models

Several alternative VAPT models were considered during divergent thinking.

1. **Bilateral Pen-Test Sharing** — pairs of BFIs share pen-test results directly.
2. **Federated Detection Network** — BFIs share detection rules via a common standard without a central platform.
3. **Institution-Led Automated Scanner** — each BFI runs its own scanner with bespoke rules.
4. **Multi-Agent Centralised VAPT Platform (SENTINEL)** — a single shared engine, multiple delivery channels.

> 🎨 **Figure 9 — Divergent Thinking: Alternative VAPT Models** — see `prompt.md` #9

### Convergent Thinking: Final SENTINEL Model Selection

During the convergent phase, the top alternatives were compared against important factors such as detection coverage, evidence richness, regulatory governance, ease of implementation, and customer experience. In the end, the **Multi-Agent Centralised VAPT Platform** (SENTINEL) was the best path forward.

It provides one-time scan submission, secure use of detection rules across institutions, and governance aligned with NRB and OWASP MASVS. With LLM-driven triage and runtime instrumentation via Frida, it further enhances the entire assurance process.

> 🎨 **Figure 10 — Convergent Thinking: Final SENTINEL Model Selection** — see `prompt.md` #10

---

## BUSINESS MODEL DEVELOPMENT

This section describes a conceptual prototype of the SENTINEL platform from a business and operational standpoint. Instead of focusing on system architecture or low-level software design, the prototype shows how different stakeholders work together in the SENTINEL ecosystem. It highlights process feasibility, efficiency gains, and value creation within a multi-tenant, regulator-aligned framework (Pigneur, 2010).

> 🎨 **Figure 11 — Phases of Business Model Development** — see `prompt.md` #11

### SENTINEL Platform Prototype Overview

The SENTINEL platform allows a fintech development team to upload an APK once and immediately receive a complete VAPT report covering 88 agent checks, runtime evidence, CVSS scoring, MITRE ATT&CK tagging, OWASP MASVS mapping, and a downloadable PoC bundle. The customer team submits the build through the dashboard, CLI, or CI/CD action, and the platform validates the build, dispatches it to the orchestrator, runs all applicable agents in parallel, suppresses false positives via the LLM triage layer, and delivers the artefacts to the requesting team.

Once verified, every finding is shared back with the developer, the security team, the compliance officer, and (via SARIF) the SOC. Authorised auditors can retrieve evidence through the JWT-protected gateway with explicit access controls and full audit trails (MITRE, 2024).

> 🎨 **Figure 12 — SENTINEL Entity Relationship Diagram** — see `prompt.md` #12

### Feasibility Analysis

A feasibility study examines how useful and long-lasting the proposed SENTINEL platform would be within Nepal's fintech ecosystem. The evaluation looks at technical readiness, operational viability, legal and regulatory compliance, and the ability to remain economically sustainable.

> 🎨 **Figure 13 — SENTINEL Feasibility Analysis** — see `prompt.md` #13

- **Technical Feasibility** — The SENTINEL concept is technically achievable within Nepal's current digital landscape. Most BFIs already operate on cloud-ready CI/CD systems that can call SENTINEL APIs, supported by widely available Android SDK, ADB, Frida, semgrep, and mitmproxy tooling.

- **Operational Feasibility** — SENTINEL standardises scan submission, multi-agent execution, and report retrieval. This enhances overall efficiency, reduces parallel reinvention of detection rules, and simplifies the audit process.

- **Legal & Regulatory Feasibility** — The model aligns with existing AML/CFT obligations and supports NRB's supervisory mandate. Centralised governance enhances audit readiness and compliance reporting. Consent-based scan submission encourages responsible use of detection insights.

- **Financial Feasibility** — Initial investment is needed for platform development and governance. Long-term costs are minimised by streamlined scanning processes and reusable agent contributions. Sustainability can be achieved through institutional participation fees and tiered SaaS pricing, without direct charges to end-customers.

### Applications of Business Process Management (BPM)

Business Process Management (BPM) is used to standardise and improve SENTINEL workflows across participating institutions. BPM helps clearly define roles, responsibilities, and process handoffs between developers, the SENTINEL platform, the AI triage layer, and the compliance / reporting entities. By removing ambiguity, BPM strengthens consistency, efficiency, and accountability throughout the VAPT lifecycle.

In technologically enabled and multi-stakeholder environments like SENTINEL, BPM also supports governance by aligning operational processes with regulatory objectives and institutional responsibilities. Furthermore, BPM provides a structural foundation for continuous process improvement and adaptation as regulatory requirements, threat landscapes, and detection-rule libraries evolve over time (Mendling, 2020).

### Business Process Model and Notation (BPMN)

BPMN diagrams are employed to visually document the SENTINEL process in a format that is easily understood by both technical and non-technical stakeholders. The key BPMN flows include:

#### 1. Scan Submission Workflow

The developer (or CI build job) submits the APK through the SENTINEL gateway, the gateway authenticates the user, performs tenant isolation, and queues the scan job for the orchestrator.

> 🎨 **Figure 14 — Scan Submission Workflow (BPMN)** — see `prompt.md` #14

#### 2. Multi-Agent Scan Execution Workflow

The orchestrator hashes the APK, parses the manifest, decompiles the code, dispatches 88 agents across parallel workers, and writes findings back to the central scan-context. The Adaptive Planner rewrites the dynamic plan based on Phase-2 signals, and the LLM triage layer suppresses false positives before persistence.

> 🎨 **Figure 15 — Multi-Agent Scan Execution Workflow (BPMN)** — see `prompt.md` #15

#### 3. Report Retrieval and SIEM Export Workflow

Using the customer's session ID and JWT, the gateway streams the appropriate artefact (Markdown report, HTML report, JSON, SARIF bundle, or SIEM bundle), subject to consent, tenant isolation, and audit trail.

> 🎨 **Figure 16 — Report Retrieval and SIEM Export Workflow (BPMN)** — see `prompt.md` #16

### SENTINEL Workflow Summary Table

> 🎨 **Table 4 — SENTINEL Workflow Summary** — see `prompt.md` #T4

| Workflow | Trigger | Key Steps | Output |
|---|---|---|---|
| **Scan Submission** | Developer / CI uploads APK | Gateway authenticates, validates the file size and signature, applies tenant isolation, queues job | Scan job accepted, session ID returned |
| **Multi-Agent Scan Execution** | Job picked up by orchestrator | Hash + manifest parse + decompile → 88 agents in parallel → LLM triage → compliance mapping | Findings persisted to scan-context, evidence written to workspace |
| **Report Retrieval** | Customer / auditor queries session | Gateway authorises, streams the requested artefact (MD / HTML / JSON / SARIF / SIEM bundle / PoC) | Artefact delivered to the requesting client |
| **Continuous Improvement** | New agent contributed by community | Lint + unit tests + integration test against InsecureBank-class reference apps → version bump → roll-out | Updated agent library distributed to all tenants |

### Product Life Cycle of the SENTINEL Platform

The SENTINEL platform is expected to follow a phased product life cycle. The **introduction** phase would include pilot operations with two or three early-adopting Nepalese fintech BFIs. The **growth** phase would see an escalating number of institutions embracing the platform and customer awareness rising as detection-rule coverage matures. At **maturity**, SENTINEL functions as standard national infrastructure with stable operations and consistent NRB-aligned audit support. **Ongoing enhancements** ensure the platform remains effective amid regulatory and technological changes (Gowda, 2022).

> 🎨 **Figure 17 — SENTINEL Platform Product Life Cycle** — see `prompt.md` #17

**Risk Management at Maturity** — SENTINEL may slip toward decline if (a) a large cloud provider bundles a free competitor, (b) regulatory shifts demand new evidence categories the platform cannot capture, or (c) the agent-contribution community stalls. The contingency plan combines three strategies: **mitigate** (invest in differentiation — extended MITRE coverage, SOC2 / ISO 27001 certification, multi-year BFI contracts); **innovate ahead of time** (launch iOS scanner and embedded-firmware scanner before maturity peaks); **add investment partners** (cloud / SIEM vendor strategic round for distribution leverage).

### SENTINEL Customer Value Chain

The SENTINEL value chain shows how value is added at every step of the customer journey, from APK submission to evidence consumption. Developers experience faster feedback and fewer late-stage remediation cycles, while BFIs benefit from improved efficiency, consistent detection coverage, and reduced compliance burden. Regulators gain enhanced visibility across the financial system and improved capabilities for risk-based supervision (CERSAI, 2023).

> 🎨 **Figure 18 — SENTINEL Customer Value Chain** — see `prompt.md` #18

---

## FEEDBACK AND ANALYSIS

This section examines the proposed SENTINEL prototype by considering how key stakeholders are likely to react and what risks could get in the way of implementation. The goal is to see if the solution is realistic, acceptable, and sustainable for Nepal's fintech ecosystem.

> 🎨 **Figure 19 — SENTINEL Prototype Review: Feedback & Analysis** — see `prompt.md` #19

### Stakeholder Feedback

- **Developers** would welcome SENTINEL because it integrates directly with CI, provides feedback within the development loop, and exposes precise code locations for every finding.

- **Security Engineers** can derive significant value from automated runtime instrumentation, consistent evidence capture, and reduced manual hook authoring. They may be cautious about agent quality, false-negative rate, and the operational overhead of agent contribution.

- **Compliance Officers** will likely support SENTINEL because it provides automatic OWASP MASVS, NRB, and AML/CFT mapping per finding, eliminating the late-mapping pain that currently dominates audit preparation.

- **Regulators** are expected to support SENTINEL due to stronger supervisory visibility, clearer governance, and better AML/CFT monitoring (FATF, 2025). Centralised audit trails and controlled tenant isolation can also improve confidence in compliance outcomes.

> 🎨 **Table 5 — Stakeholder Feedback Summary** — see `prompt.md` #T5

| Stakeholder | Key Needs | Current Pain Points | SENTINEL Value Delivered |
|---|---|---|---|
| **Developers** | Fast, in-CI security feedback | Late pen-test arrival, opaque PDFs | Inline code findings, CI-gated build, MASVS-mapped remediation |
| **Security Engineers** | Coverage + runtime evidence with low effort | Manual Frida scripting, inconsistent hooks | 88 agents in parallel, automatic Frida hooks, screenshot evidence |
| **Compliance Officers** | Regulation-mapped findings on submission | Late evidence mapping, brittle PDF mapping | Auto OWASP / NRB / AML tags per finding |
| **NRB / Regulators** | Supervisory visibility, control of detection corpus | Limited cross-BFI insight, weak audit trails | Tenant-isolated dashboard, central detection-rule governance |

### Key Findings

Standardised multi-agent procedures enhance uniformity across institutions, and reusable detection rules minimise operational work. LLM triage facilitates restricted human review while maintaining a small but high-signal manual queue. The prototype demonstrates that preparation for implementation and governance is just as important as detection technology. Adoption is more likely to be successful if stakeholders remain involved during implementation and BFIs are onboarded progressively.

### Risks and Improvement Areas

The key risks would be resistance to change, perceived loss of vendor-pen-test revenue, initial setup cost, and technical integration challenges. LLM cost inflation may also be difficult for smaller BFIs. These challenges may slow adoption during early phases and affect user confidence if not properly managed (World Bank, 2014).

Phased rollout, raising developer awareness, practical training, and strong data-protection policies can all help reduce these problems. Future versions of the plan may focus on better handling of agent-contribution licensing, support for on-device iOS scanning, and tighter integration with the SOC tooling already deployed within Nepalese BFIs.

---

## LEARNING OUTCOMES

> 🎨 **Figure 20 — Learning Outcomes** — see `prompt.md` #20

### Professional Exposure

Working on the SENTINEL platform gave me a clearer picture of how large, multi-stakeholder digital systems are planned, designed, and assessed. It also showed how developers, security engineers, compliance officers, and regulators each interpret the same artefact (an APK) through very different lenses. Using design thinking, BPM/BPMN workflows, feasibility checks, and value-chain analysis improved my ability to map processes, spot bottlenecks, and propose practical improvements within regulatory limits.

### Personal Development

> 🎨 **Table 6 — Personal Development Summary** — see `prompt.md` #T6

| Critical Development | Analytical Thinking | Creative Thinking |
|---|---|---|
| I learned to question existing penetration-testing practices, identify what is not working, and defend why an automated multi-agent approach is necessary. | I became more capable of analysing complex multi-system workflows and seeing how each change cascades, by breaking down complicated processes into discrete steps. | During ideation, I explored multiple VAPT models and synthesised them into a more elegant final flow. This showed that novel ideas are possible even in heavily regulated environments. |

### Future Career Prospects

These lessons are directly applicable to positions in cybersecurity engineering, application-security consulting, mobile platform engineering, digital governance, and regulatory technology (RegTech). Learning about multi-agent automation, process optimisation, and stakeholder-driven design has given me a strong base for professional roles that must balance user experience, operational efficiency, and compliance.

These skills also help in working effectively with regulators, technology vendors, and BFIs to build safe digital infrastructure. They make it easier to assess risk, follow ethical data governance practices, and adapt to changing rules and technology in the financial industry.

---

## CONCLUSION

The project explored the challenges of existing mobile-application VAPT practices in Nepal and examined how an automated multi-agent approach could improve efficiency, consistency, and user experience across the fintech sector. The study showed that institution-specific, consultancy-led penetration-testing creates unnecessary delays for developers, inflates operational workload for security engineers, and complicates compliance reporting for regulators. By analysing stakeholder needs and applying design-thinking principles, the project identified that these issues are not isolated problems but systemic gaps caused by fragmented processes and the absence of a shared detection-rule and evidence framework. The SENTINEL multi-agent VAPT platform provides an operational solution by making possible a single-submission scan, automatic LLM-driven triage, standardised evidence capture, and SARIF / SIEM interoperability, all under regulator-aligned governance and in compliance with NRB and AML/CFT obligations. The feasibility study shows the solution can be deployed within the existing technological and regulatory environment in Nepal. SENTINEL enhances developer feedback, strengthens detection consistency, and aligns with the broader objectives of Nepal's digital-financial inclusion strategy. Moreover, the framework lays a foundation for future integration with iOS and on-device firmware scanning, providing room for the platform to mature alongside the financial-technology ecosystem.

---

## REFERENCES

1. **Bank, N. R.** (2008). *Money Laundering Prevention Act*. Kathmandu: Nepal Rastra Bank.
2. **Bank, W.** (2014). *Digital Identity Toolkit*. Washington: World Bank.
3. **BCBS** (2016). *Guidance on the application of the Core Principles for Effective Banking Supervision to the regulation and supervision of institutions relevant to financial inclusion*. Basel: Basel Committee on Banking Supervision.
4. **Brown, T.** (2008). Design Thinking. *Harvard Business Review*, pp. 84–92.
5. **CERSAI** (2023). *Central KYC Records Registry Operating Guidelines*. New Delhi: CERSAI.
6. **FATF** (2025). *International Standards on Combating Money Laundering and the Financing of Terrorism & Proliferation*. Paris: Financial Action Task Force.
7. **Gowda, A.** (2022). Managing New Products' Product Life Cycle. *International Journal of Innovative Research in Engineering and Management*, 9(5), 78-84.
8. **ISO** (2019). *ISO 9241-210: Human-centred Design for Interactive Systems*. Geneva: International Organization for Standardization.
9. **Mendling, J.** (2020). Building a complementary agenda for business process management and digital innovation. *European Journal of Information Systems*, 29(3), 208–219. doi: 10.1080/0960085X.2020.1755207
10. **MITRE Corporation** (2024). *MITRE ATT&CK for Mobile*. McLean, VA: The MITRE Corporation.
11. **Nepal Rastra Bank** (2024). *Payment System Statistics — Annual Report*. Kathmandu: NRB.
12. **Nissinen, N. M.** (2013). An Approach to Construct Criteria for Evaluating Alternatives in Decision-Making. *International Journal of Business, Human and Social Sciences*, 7(8), 2263–2265.
13. **OWASP** (2024). *Mobile Application Security Verification Standard (MASVS) v2.0*. Open Worldwide Application Security Project.
14. **Pigneur, A. O.** (2010). *Business Model Generation: A Handbook for Visionaries, Game Changers, and Challengers*. New Jersey: John Wiley & Sons.
15. **Verizon** (2024). *2024 Data Breach Investigations Report*. New York: Verizon Business.

---

## APPENDIX

> 🎨 **Figure 21 — SENTINEL Dashboard: Scan Submission** — see `prompt.md` #21
>
> 🎨 **Figure 22 — SENTINEL Dashboard: Finding Detail View with Evidence** — see `prompt.md` #22
>
> 🎨 **Figure 23 — SENTINEL Dashboard: Executive Risk Summary** — see `prompt.md` #23
>
> 🎨 **Figure 24 — SENTINEL Dashboard: Compliance & Audit Bundle** — see `prompt.md` #24
>
> 🎨 **Figure 25 — SWOT Analysis** — see `prompt.md` #25
>
> 🎨 **Figure 26 — SENTINEL Business Model Canvas** — see `prompt.md` #26
>
> 🎨 **Figure 27 — PESTLE Analysis** — see `prompt.md` #27

---

*End of Coursework Report — SENTINEL: An AI-Augmented Multi-Agent Mobile VAPT Platform for Nepal's Fintech Sector — STA309IAE Design Thinking and Innovation*
