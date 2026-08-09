# SENTINEL THESIS — INFOGRAPHIC PROMPTS FOR CANVA AI
## All 37 Figure Prompts (Figures 2–38) + Placement Guide

---

### HOW TO USE THESE PROMPTS IN CANVA

1. Open **Canva** → Click **"Create a design"** → Select **"Infographic"**
2. Click **"Magic Design"** or the **AI prompt box**
3. Copy and paste the prompt for the figure you want
4. After generating, set canvas size to **1240 × 1748 px** (A4 portrait)
5. Download as **PNG at 300 DPI** for clean thesis print quality

---

### GLOBAL COLOUR SCHEME (Apply to ALL figures)

| Colour Role | Hex Code | Usage |
|---|---|---|
| Primary Dark Blue | `#1F4E79` | Headers, main boxes, titles |
| Secondary Blue | `#2E74B5` | Supporting boxes, arrows |
| Light Blue | `#DEEAF1` | Backgrounds, alternating rows |
| White | `#FFFFFF` | Text on dark backgrounds |
| Red / Alert | `#E74C3C` | Warnings, critical items |
| Green / Success | `#27AE60` | SENTINEL results, best values |
| Font | Calibri or similar clean sans-serif | All text |

---

### PLACEMENT GUIDE — WHERE TO INSERT EACH FIGURE IN THE THESIS

| Figure | Section | Insert Position |
|--------|---------|----------------|
| Figure 1 | Cover / Title Page | Title page — actual screenshot, no Canva prompt needed |
| Figure 2 | 01 · Introduction | After the opening paragraph introducing SENTINEL |
| Figure 3 | 02 · Problem Context and Motivation | After Nepal-specific vulnerability statistics |
| Figure 4 | 02 · Problem Context and Motivation | After listing the four root causes |
| Figure 5 | 03 · Cybersecurity Theories | After introducing Prospect Theory and Kahneman |
| Figure 6 | 03 · Cybersecurity Theories | After explaining the seven-level proof gate concept |
| Figure 7 | 04 · Optimising Security via RAG and LLM | After describing the RAG pipeline |
| Figure 8 | 04 · Optimising Security via RAG and LLM | After describing the LLM triage router |
| Figure 9 | 05 · Research Aim | At the end of the Research Aim section |
| Figure 10 | 06 · Research Objectives | At the end of the Objectives section |
| Figure 11 | 07 · Contribution and Significance | After describing the three contributions |
| Figure 12 | 08 · Justification of the Study | After Nepal fintech vulnerability statistics |
| Figure 13 | 09 · Research Questions | After presenting RQ1 and RQ2 |
| Figure 14 | 10 · Research Hypotheses | After stating H1 and H2 |
| Figure 15 | 11 · Research Methodology | After describing the Agile sprint approach |
| Figure 16 | 11 · Research Methodology | After the evaluation strategy description |
| Figure 17 | 12 · Ethical Considerations | After the seven ethical principles |
| Figure 18 | 13 · Literature Review | After the MobSF discussion |
| Figure 19 | 13 · Literature Review | After the QARK discussion |
| Figure 20 | 13 · Literature Review | After the gap analysis paragraph |
| Figure 21 | 14 · Case Studies | After Case Study 1 (MobSF) |
| Figure 22 | 14 · Case Studies | After Case Study 2 (QARK) |
| Figure 23 | 14 · Case Studies | After Case Study 3 (Manual Analysis) |
| Figure 24 | 14 · Case Studies | After Case Study 4 (Commercial AI Tools) |
| Figure 25 | 16 · Integration of Tools and Technologies | After the architecture overview paragraph |
| Figure 26 | 16 · Integration of Tools and Technologies | After the ten-phase pipeline description |
| Figure 27 | 16 · Integration of Tools and Technologies | After the multi-specialised agent architecture |
| Figure 28 | 16 · Integration of Tools and Technologies | After the three-tier memory architecture |
| Figure 29 | 16 · Integration of Tools and Technologies | After the ChromaDB RAG knowledge base description |
| Figure 30 | 16 · Integration of Tools and Technologies | After the LLM triage router description |
| Figure 31 | 16 · Integration of Tools and Technologies | After the seven-level proof gate description |
| Figure 32 | 18 · Findings (RQ1) | After the RQ1 opening answer paragraph — actual terminal screenshot |
| Figure 33 | 18 · Findings (RQ1) | After the detection coverage metrics paragraph |
| Figure 34 | 18 · Findings (RQ2) | After the RQ2 opening answer paragraph |
| Figure 35 | 18 · Findings (RQ1) | After the proof gate funnel description |
| Figure 36 | 19 · Future Works | After the future roadmap description |
| Figure 37 | 20 · Conclusion | After the summary paragraph |
| Figure 38 | Appendix A | Master architecture diagram |

---

## FIGURE 2 — Keywords Word Cloud

**Canva AI Prompt:**
Create a professional academic word cloud infographic on a white background. Words vary in size by importance. Largest words (dark navy #1F4E79): "Android Security", "Multi-Specialised Agents", "RAG", "LLM Triage", "OWASP MASVS". Medium words (medium blue #2E74B5): "ChromaDB", "Proof Gate", "Vulnerability Detection", "Groq", "Automated Assessment", "Nepal", "APK Analysis", "Ethical Hacking", "Frida", "Dynamic Analysis". Smaller words (steel blue): "SQLi", "SSRF", "Insecure Storage", "Jadx", "Androguard", "MobSF", "QARK", "False Positive Reduction", "Kathmandu", "Fintech", "Redis", "PostgreSQL", "MinIO". Clean academic style, no icons, Calibri font. Caption below in italic 10pt: "Figure 2: Key terminology map for the SENTINEL research domain."

---

## FIGURE 3 — Nepal Mobile Cybersecurity Threat Landscape

**Canva AI Prompt:**
Create a professional academic infographic titled "Nepal's Mobile Cybersecurity Threat Landscape" in dark navy #1F4E79 header bar with white bold text. A4 portrait, light blue #DEEAF1 background. Three columns of stat boxes. Left column (red #E74C3C boxes): "72% of Nepalese internet users access via smartphone only", "58% of Nepalese fintech apps contain at least one HIGH severity OWASP flaw (NRB, 2023)", "Fewer than 12 certified mobile security testers in Nepal". Middle column (navy #1F4E79 boxes): "47 APKs tested in SENTINEL evaluation corpus", "Kathmandu Valley fintech sector growing 34% annually", "NRB IT Guidelines mandate annual mobile security audits". Right column (green #27AE60 boxes): "SENTINEL achieves 94.3% vulnerability coverage", "8.3 minutes average assessment time", "8.3% false positive rate". Below: simple Nepal map outline with dots at Kathmandu, Pokhara, Biratnagar labelled "Primary fintech hubs". Caption in italic 10pt: "Figure 3: Nepal's mobile cybersecurity gap and SENTINEL's role in addressing it."

---

## FIGURE 4 — Four Root Causes of Android Security Assessment Failures

**Canva AI Prompt:**
Create a professional academic infographic titled "Four Root Causes of Android Security Assessment Failures" in dark navy #1F4E79 bold header. A4 portrait white background. Centre: large dark navy circle labelled "Security Assessment Gap". Four arrows pointing outward to four large rounded rectangles. Top (red #E74C3C): clock icon + "Manual analysis takes 5–8 hours per APK and cannot scale to hundreds of applications". Right (orange #E67E22): target icon + "Rule-based static scanners miss 40–60% of logic-level flaws (OWASP, 2023)". Bottom (purple #8E44AD): graph icon + "No tool correlates static evidence with live runtime behaviour across all OWASP MASVS categories". Left (blue #2E74B5): shield icon + "No structured progressive evidence standard — findings cannot serve as regulatory audit evidence". Below: light blue box: "SENTINEL addresses all four causes through its ten-phase automated pipeline." Caption italic 10pt: "Figure 4: The four systemic root causes of Android security assessment failures that SENTINEL resolves."

---

## FIGURE 5 — Prospect Theory Mapped onto the Seven-Level Proof Gate

**Canva AI Prompt:**
Create a professional academic infographic titled "Prospect Theory and the Seven-Level Proof Gate" in dark navy #1F4E79 bold header, white background, A4 portrait. Two-part layout. Top half: S-curve graph (Kahneman's value function). X-axis: "Evidence Strength (Low to High)". Y-axis: "Analyst Confidence Gain". Curve rises steeply then flattens. Red dot at low end labelled "Pattern Detection Level 1 — high marginal value". Green dot at mid-right labelled "Runtime Confirmation Level 4 — sufficient confidence". Steep section annotated: "Early corroboration corrects cognitive bias". Flat section: "Diminishing return — Level 5–7 adds governance, not detection". Bottom half: seven horizontal bars stacked, darkest navy at top lightening to pale blue, labelled: "L1 Pattern Detection", "L2 Corroboration", "L3 LLM Reasoning", "L4 Runtime Confirmation", "L5 Evidence Storage", "L6 Human Approval", "L7 Exploit Confirmation". Caption italic 10pt: "Figure 5: Prospect Theory (Kahneman, 2011) mapped onto SENTINEL's seven-level proof gate design rationale."

---

## FIGURE 6 — Seven-Level Proof Gate Detail

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL Seven-Level Proof Gate" in dark navy #1F4E79 bold header, white background, A4 portrait. Vertical waterfall diagram. Seven horizontal bands top to bottom, gradient darkest navy to lightest blue. Row 1 (darkest): "LEVEL 1 — Pattern Detection: Static byte-pattern or ASM signature match by at least one agent". Row 2: "LEVEL 2 — Corroboration: Two or more independent agents confirm the same code path". Row 3: "LEVEL 3 — LLM Reasoning: Groq Llama 3.3 70B classifies finding as exploitable, confidence ≥ 0.7". Row 4: "LEVEL 4 — Runtime Confirmation: Frida dynamic hook validates behaviour on live device". Row 5: "LEVEL 5 — Evidence Storage: PostgreSQL record and MinIO artefact bundle sealed". Row 6: "LEVEL 6 — Human Approval: Analyst reviews and endorses — MANDATORY before CONFIRMED status". Row 7 (lightest): "LEVEL 7 — Exploit Confirmation: Read-only PoC execution logged". Lock icon between L5 and L6 labelled "Human gate". Caption italic 10pt: "Figure 6: The seven progressive evidence levels SENTINEL requires before classifying a vulnerability as confirmed."

---

## FIGURE 7 — SENTINEL RAG Pipeline

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL RAG Pipeline — From Corpus to Contextual Knowledge" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Left-to-right flow with five stages and arrows. Stage 1 (dark navy box): "Knowledge Corpus — OWASP MASVS v2.1 (273 controls) + CWE (1,200 entries) + OSV advisories (850 entries) = 2,323 passages". Arrow → Stage 2 (medium blue): "Chunking — 512-token passages, 64-token overlap". Arrow → Stage 3 (dark navy): "Sentence Transformer — all-MiniLM-L6-v2 — 384-dimensional dense vectors — Runs locally, no API key". Arrow → Stage 4 (medium blue): "ChromaDB Vector Store — cosine similarity index — hnsw:space=cosine — Upsert-safe build". Arrow → Stage 5 (green #27AE60): "Query: APK finding → embed → top-4 passages retrieved — 12–18ms latency". Below: white info box: "Retrieved passages injected into LLM triage prompt to provide OWASP MASVS-aligned classification context." Caption italic 10pt: "Figure 7: The SENTINEL RAG pipeline from corpus ingestion to contextual passage retrieval."

---

## FIGURE 8 — LLM Triage Router

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL LLM Triage Router — Three-Provider Priority Chain" in dark navy #1F4E79 bold header, white background, A4 portrait. Vertical decision flowchart. Top box (dark navy): "Vulnerability Candidate + RAG Context → LLM Triage Request". Arrow down → diamond: "Groq API available? (Llama 3.3 70B, temperature=0.0)". YES → right green box #27AE60: "Primary: Groq Cloud — Llama 3.3 70B — Sub-second inference — Redis cached 24h TTL". NO → down → diamond: "Cerebras API available?". YES → right blue box #2E74B5: "Secondary: Cerebras Cloud — Same Llama 3.3 70B weights — Auto failover". NO → down → orange box #E67E22: "Fallback: Local Ollama — qwen2.5-coder:7b — Zero network dependency — Always available". Below all three merge → dark navy box: "Structured JSON verdict: {exploitable: bool, confidence: float, cwe_id: string, severity: CRITICAL/HIGH/MEDIUM/LOW}". Note: "4-shape JSON tolerance parser. 47% Redis cache hit rate across 47-APK corpus." Caption italic 10pt: "Figure 8: The three-tier LLM triage router with automatic failover ensuring 100% pipeline availability."

---

## FIGURE 9 — Research Aim Diagram

**Canva AI Prompt:**
Create a professional academic infographic titled "Research Aim" in dark navy #1F4E79 bold header, white background, A4 portrait. Centre: large navy circle "SENTINEL Research Aim". Four arrows to four light blue #DEEAF1 rounded rectangles. Top: "Design and develop an intelligent multi-agent automated Android APK security assessment framework integrating RAG and LLM triage". Right: "Deploy multi-specialised agents across fourteen OWASP MASVS vulnerability categories within a ten-phase pipeline". Bottom: "Validate SENTINEL against MobSF, QARK, and manual analysis across a 47-APK corpus including Nepalese fintech applications". Left: "Develop a structured ethical governance model satisfying GDPR and NRB Cyber Resilience Guidelines (2023)". Caption italic 10pt: "Figure 9: The four dimensions of the SENTINEL research aim."

---

## FIGURE 10 — Research Objectives Mind Map

**Canva AI Prompt:**
Create a professional academic infographic titled "Research Objectives — Five Goals" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Mind map: centre circle "SENTINEL Objectives" (navy, white text). Five branches to rounded rectangles. Branch 1 (top-left, navy): "[Learn and Understand] O1: Analyse Android security assessment practice, OWASP MASVS taxonomy, and Nepalese fintech regulatory context". Branch 2 (top-right, medium blue #2E74B5): "[Learn and Understand] O2: Investigate RAG, LLM triage, and multi-specialised agent orchestration for binary APK analysis". Branch 3 (right, navy): "[Learn and Understand] O3: Examine MobSF, QARK, and commercial AI tools to identify detection coverage and governance gaps". Branch 4 (bottom, green #27AE60): "[Design and Develop] O4: Design and build SENTINEL's ten-phase pipeline, RAG knowledge base, LLM router, proof gate, and three-tier memory". Branch 5 (left, medium blue): "[Feedback and Submit] O5: Validate ethical governance model, document findings including limitations, submit comprehensive thesis". Caption italic 10pt: "Figure 10: The five research objectives guiding SENTINEL's design, development, and evaluation."

---

## FIGURE 11 — Three Primary Contributions

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL's Three Primary Contributions to Knowledge" in dark navy #1F4E79 bold header, white background, A4 portrait. Three large horizontal panels stacked. Panel 1 (navy #1F4E79, white text): Large "01". "Technical Contribution — First open-source framework combining multi-specialised agent orchestration, ChromaDB RAG embeddings, Groq LLM triage, and seven-level proof gate for Android APK security. 94.3% coverage in 8.3 minutes." Panel 2 (medium blue #2E74B5, white text): Large "02". "Academic Contribution — Empirical validation across 47 APKs including Nepalese fintech applications. +41.6pp coverage over MobSF. +34.1pp FPR reduction over QARK. 53× faster than manual analysis." Panel 3 (light blue #DEEAF1, dark navy text): Large "03". "Ethical Contribution — Seven-principle governance model: authorisation gates, privacy-preserving analysis, auditable AI verdicts, mandatory human approval at Level 6, harm-avoidance PoC gating. NRB Cyber Resilience Guidelines (2023) compliant." Caption italic 10pt: "Figure 11: The three primary contributions of SENTINEL to technical, academic, and ethical knowledge."

---

## FIGURE 12 — Nepal Fintech Vulnerability Statistics

**Canva AI Prompt:**
Create a professional academic infographic titled "Justification: Vulnerability Prevalence in Nepalese Fintech Mobile Applications" in dark navy #1F4E79 bold header, white background, A4 portrait. Horizontal bar chart. Y-axis: five categories — "Digital Banking Apps", "Mobile Wallets (eSewa, Khalti)", "Insurance Platforms", "Investment/Stock Apps", "Microfinance Apps". X-axis: 0% to 80%. All bars dark navy #1F4E79. Data labels: Digital Banking 68%, Mobile Wallets 58%, Insurance 61%, Investment 54%, Microfinance 72%. Chart title: "Percentage with at Least One HIGH or CRITICAL OWASP Flaw (NRB Audit, 2023)". Below chart: three red #E74C3C alert boxes: "Nepal has no mandatory pre-launch mobile app security certification", "Fewer than 12 certified mobile security testers in Nepal (NRB, 2023)", "NRB mandates annual audits — fewer than 20% conducted at required technical depth (NRB, 2023)". Caption italic 10pt: "Figure 12: Vulnerability prevalence in Nepalese fintech applications, justifying SENTINEL's research focus."

---

## FIGURE 13 — Research Questions Visual

**Canva AI Prompt:**
Create a professional academic infographic titled "Research Questions" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Two large panels side by side. Left panel (navy #1F4E79, white text): Bold "RQ1" top. "How can a multi-specialised agent framework integrating Retrieval-Augmented Generation (RAG) knowledge retrieval and Large Language Model (LLM) triage improve Android APK vulnerability detection coverage and false positive rates compared to existing single-method automated assessment tools, when evaluated across a corpus of real-world applications including Nepalese fintech APKs?" Italic label: "[Technical — drives Sections 16, 17, 18]". Right panel (medium blue #2E74B5, white text): Bold "RQ2" top. "What are the ethical implications of deploying an automated AI-driven Android application security assessment framework, and how can a structured governance model incorporating authorisation gates, privacy-preserving analysis, algorithmic transparency, and mandatory human oversight ensure responsible and auditable operation?" Italic label: "[Ethical — drives Sections 12, 17, 18]". Below: navy connector box: "Together RQ1 and RQ2 span the full scope of responsible automated security assessment research." Caption italic 10pt: "Figure 13: The two research questions structuring the SENTINEL investigation."

---

## FIGURE 14 — Research Hypotheses

**Canva AI Prompt:**
Create a professional academic infographic titled "Research Hypotheses and Validation Outcomes" in dark navy #1F4E79 bold header, white background, A4 portrait. Two hypothesis blocks stacked with space between. Block 1 (rounded rectangle, navy #1F4E79, white text): "H1 — Technical: If a multi-specialised agent framework combining static decompilation, dynamic Frida instrumentation, RAG-enriched knowledge retrieval, and LLM verdict classification is applied to Android APK assessment, then detection coverage will exceed 80% and false positive rate will fall below 15% — statistically significant improvements over MobSF, QARK, and manual analysis." Green arrow → small green box: "CONFIRMED — 94.3% coverage, 8.3% FPR (Section 18)". Block 2 (rounded rectangle, medium blue #2E74B5, white text): "H2 — Ethical: While multi-specialised agent automation can substantially enhance coverage and reduce assessment time, deployment without authorisation gates, privacy controls, algorithmic transparency, and mandatory Level 6 human approval will introduce risks of unauthorised testing, data exposure, and opaque AI verdicts — risks the seven-level proof gate substantially mitigates." Green arrow → small green box: "CONFIRMED — All seven governance principles satisfied (Section 17, 18)". Caption italic 10pt: "Figure 14: The two research hypotheses and their empirical validation outcomes."

---

## FIGURE 15 — Agile Research Methodology Sprint Cycle

**Canva AI Prompt:**
Create a professional academic infographic titled "Research Methodology — Agile Iterative Development" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Circular agile cycle with five stages clockwise. Each stage: navy circle with white number and label. Stage 1 (top): "1 — Requirements: OWASP MASVS study, Nepal fintech threat analysis, tool gap review". Stage 2 (right): "2 — Design: Ten-phase pipeline, multi-specialised agent taxonomy, proof gate model, RAG knowledge base". Stage 3 (bottom): "3 — Implement: Python codebase, ChromaDB RAG, Groq LLM router, Frida hooks, Redis/PostgreSQL/MinIO memory". Stage 4 (left): "4 — Evaluate: 47-APK corpus, MobSF/QARK/manual baselines, three-metric comparison". Stage 5 (top-right): "5 — Review: Ethical audit, findings documentation, thesis submission". Medium blue #2E74B5 arrows connecting clockwise. Centre circle: "3 Iterations — 6 months". Below: "Mixed method: quantitative metrics (coverage, FPR, time) + qualitative ethical audit (Hevner et al., 2004)". Caption italic 10pt: "Figure 15: The Agile iterative methodology applied across SENTINEL's three development cycles."

---

## FIGURE 16 — Comparative Evaluation Design

**Canva AI Prompt:**
Create a professional academic infographic titled "Evaluation Strategy — Comparative Benchmark Design" in dark navy #1F4E79 bold header, white background, A4 portrait. 2×2 grid. Top-left (navy, white): "SENTINEL — Multi-agent + RAG + LLM + Proof Gate". Top-right (medium blue, white): "MobSF — Open-source static + emulator dynamic". Bottom-left (medium blue, white): "QARK — Static component analysis (deprecated 2019)". Bottom-right (navy, white): "Manual Analysis — Expert pentester 7.4 hrs/APK". Centre diamond: "47-APK Test Corpus including Nepalese fintech applications". Three metric boxes below: Box 1 (green #27AE60): "Metric 1: Detection Coverage (%) — proportion of true vulnerabilities found". Box 2 (blue): "Metric 2: False Positive Rate (%) — incorrect alerts as % of all alerts". Box 3 (navy): "Metric 3: Assessment Time — wall-clock minutes per APK". Caption italic 10pt: "Figure 16: The three-metric comparative evaluation design used to validate SENTINEL against baseline tools."

---

## FIGURE 17 — Ethical Governance Framework

**Canva AI Prompt:**
Create a professional academic infographic titled "Ethical Governance Framework — Seven Principles" in dark navy #1F4E79 bold header, white background, A4 portrait. Seven horizontal bands alternating navy and medium blue, all white text. Band 1 (navy): "1 — Authorisation: Hard constraint at Phase 1 — pipeline will not execute without signed authorisation form in PostgreSQL audit table". Band 2 (blue): "2 — Data Minimisation: Only APK binary and generated artefacts stored — user data, credentials, PII never requested or retained". Band 3 (navy): "3 — Privacy by Design: Per-scan Docker container isolation — automated artefact deletion at assessment agreement expiry". Band 4 (blue): "4 — Algorithmic Transparency: Every LLM verdict stored with model ID, temperature, prompt hash, RAG passage document IDs". Band 5 (navy): "5 — Human Oversight: Level 6 approval MANDATORY — no CONFIRMED status without analyst endorsement regardless of AI confidence". Band 6 (blue): "6 — Accountability: Full audit trail in PostgreSQL — submitting party, finding, approval, timestamp". Band 7 (navy): "7 — Harm Avoidance: Level 7 PoC is read-only by default — requires Level 6 approval — no live exploitation of production systems". Caption italic 10pt: "Figure 17: The seven ethical principles embedded in SENTINEL's operational governance model."

---

## FIGURE 18 — Literature: MobSF Analysis

**Canva AI Prompt:**
Create a professional academic infographic titled "Literature Review: MobSF — Mobile Security Framework" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Two columns. Left header (navy, white): "MobSF Strengths". Four green #27AE60 boxes: "Widely adopted in academic research — standard baseline comparator", "Integrated static + basic emulator dynamic analysis", "REST API for pipeline integration", "Broad Android, iOS, and Windows Mobile coverage". Right header (navy, white): "MobSF Limitations". Four red #E74C3C boxes: "52.7% detection coverage in SENTINEL corpus", "38.1% false positive rate — analyst fatigue risk", "Cannot instrument native JNI libraries", "No progressive evidence standard — all findings equally weighted". Bottom: navy bar white text: "SENTINEL addresses: +41.6pp coverage gain via multi-specialised agents. RAG enrichment reduces FPR from 38.1% to 8.3%." Caption italic 10pt: "Figure 18: MobSF strengths and limitations as identified in the SENTINEL literature review."

---

## FIGURE 19 — Literature: QARK Analysis

**Canva AI Prompt:**
Create a professional academic infographic titled "Literature Review: QARK — Quick Android Review Kit" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Two columns. Left header (navy, white): "QARK Strengths". Four green #27AE60 boxes: "LinkedIn-developed — strong exported component and Intent analysis", "Command-line CI/CD integration", "Reliable ContentProvider and manifest flag detection", "Structured XML output". Right header (navy, white): "QARK Limitations". Four red #E74C3C boxes: "41.2% detection coverage — lowest of all baselines", "42.4% false positive rate — highest of all baselines", "Deprecated since 2019 — no OWASP MASVS v2 support", "No dynamic analysis — misses all runtime-only vulnerabilities". Bottom: navy bar white text: "SENTINEL addresses: +53.1pp coverage gain. Proof gate reduces FPR from 42.4% to 8.3%." Caption italic 10pt: "Figure 19: QARK limitations as identified in the SENTINEL literature review, motivating the proof gate architecture."

---

## FIGURE 20 — Literature Gap Analysis

**Canva AI Prompt:**
Create a professional academic infographic titled "Literature Gap Analysis — What Existing Tools Cannot Do" in dark navy #1F4E79 bold header, white background, A4 portrait. Five gap boxes vertically stacked, alternating navy and medium blue, all white text. Gap 1: "No tool integrates static decompilation, dynamic Frida instrumentation, and AI-assisted triage in a single automated pipeline covering all 14 OWASP MASVS categories". Gap 2: "No tool applies RAG knowledge retrieval to contextualise vulnerability findings against OWASP MASVS, CWE, and OSV corpora before LLM classification". Gap 3: "No tool uses a progressive proof gate to escalate evidence confidence through seven levels before confirming a finding for analyst review". Gap 4: "No tool provides a structured ethical governance model with authorisation gates, mandatory human approval, and full audit trail for NRB regulatory submissions". Gap 5: "No tool has been validated specifically against Nepalese fintech APKs within the Nepal Rastra Bank regulatory context". Bottom: large green box #27AE60: "SENTINEL addresses all five gaps — a novel open-source contribution to the Android security assessment field." Caption italic 10pt: "Figure 20: Five critical literature gaps that the SENTINEL framework resolves."

---

## FIGURE 21 — Case Study 1: MobSF on Nepalese Digital Wallet

**Canva AI Prompt:**
Create a professional academic infographic titled "Case Study 1 — MobSF Assessment of a Nepalese Digital Wallet Application" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Three sections. Top (navy, white): "Application Profile — Nepalese mobile wallet APK — 2.3 MB — 47 activities — 12 exported components — API level 30 — ProGuard enabled". Middle: three columns. "MobSF Found" (green): "Cleartext HTTP traffic", "Backup flag enabled", "Debuggable flag set". "MobSF Missed" (red #E74C3C): "ContentProvider SQL injection (runtime-only)", "JNI memory corruption (native layer)", "Insecure biometric fallback (logic-level)". "SENTINEL Found" (green bold): All six vulnerabilities above. Bottom (navy, white): "MobSF coverage on this APK: 37.5%. SENTINEL coverage: 100%. Critical SQLi flaw missed by MobSF could expose 18,000 user account records." Caption italic 10pt: "Figure 21: Case Study 1 — MobSF versus SENTINEL on a Nepalese digital wallet application."

---

## FIGURE 22 — Case Study 2: QARK on a Banking App

**Canva AI Prompt:**
Create a professional academic infographic titled "Case Study 2 — QARK Assessment of a Kathmandu Commercial Bank Application" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Three sections. Top (navy, white): "Application Profile — Kathmandu bank app — 8.7 MB — 83 activities — ProGuard tier-2 obfuscation — API level 33". Middle: two columns. Left (red #E74C3C header "QARK Result"): "23 issues flagged — 42% false positives — Missed SSRF in custom WebView URL loader — Missed JNI key storage — Missed runtime cert bypass". Right (green #27AE60 header "SENTINEL Result"): "14 issues flagged — 8.3% false positive rate — SSRF detected via Agent D_083 scheme_confusion_payloads — JNI key storage confirmed via Frida hook Level 4 — Cert bypass confirmed at Level 4". Bottom (navy, white): "QARK's 42% FPR buried the SSRF (rated CRITICAL) under false alarms. SENTINEL proof gate isolated and escalated it for immediate patching." Caption italic 10pt: "Figure 22: Case Study 2 — QARK false positive rate versus SENTINEL precision on a Kathmandu banking application."

---

## FIGURE 23 — Case Study 3: Manual Analysis vs SENTINEL

**Canva AI Prompt:**
Create a professional academic infographic titled "Case Study 3 — Manual Penetration Testing versus SENTINEL Automated Assessment" in dark navy #1F4E79 bold header, white background, A4 portrait. Horizontal timeline comparison. Top row (navy label "Expert Analyst"): blocks from 0h to 7.4h: "0–1h: APK decompilation and manifest review", "1–3h: Smali code reading and class mapping", "3–5h: Frida manual scripting and dynamic testing", "5–7h: Report drafting and verification". Label end: "7.4 hours — 53.4% coverage — NPR 150,000–300,000 per assessment". Bottom row (green #27AE60 label "SENTINEL"): single small block: "8.3 minutes — ten-phase pipeline — 94.3% coverage — open-source, no licence cost". Four comparison metric boxes: "Coverage: SENTINEL +40.9pp", "Time: SENTINEL 53× faster", "Reproducibility: SENTINEL 100% — same APK always same finding set", "Cost: Estimated 30× lower". Caption italic 10pt: "Figure 23: Case Study 3 — time, coverage, and cost comparison between manual analysis and SENTINEL."

---

## FIGURE 24 — Case Study 4: Commercial AI Tools vs SENTINEL

**Canva AI Prompt:**
Create a professional academic infographic titled "Case Study 4 — Commercial AI Security Tools versus SENTINEL" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Comparison table. Three columns: "Feature", "Commercial AI Platforms (Checkmarx, Veracode, NowSecure)", "SENTINEL". Rows alternating white and #DEEAF1. Headers row (navy, white): feature names. Rows: "Analysis Approach" — "Static SAST + limited dynamic" vs "Static + Frida dynamic + RAG + LLM triage". "RAG Integration" — "No" vs "Yes — ChromaDB, OWASP+CWE+OSV, 2,323 passages". "LLM Triage" — "Proprietary, opaque" vs "Groq Llama 3.3 70B — open, auditable verdict record". "Evidence Standard" — "Binary pass/fail" vs "Seven-level proof gate". "NRB Compliance" — "No specific support" vs "NRB 2023 evidence package format". "Open Source" — "No — USD 10,000+ per year" vs "Yes — MIT licence". "Audit Trail" — "Limited" vs "Full PostgreSQL trail — model ID, prompt hash, RAG citations". Caption italic 10pt: "Figure 24: Case Study 4 — SENTINEL versus commercial AI security tools on seven critical dimensions."

---

## FIGURE 25 — SENTINEL Overall Architecture

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL System Architecture — High-Level Overview" in dark navy #1F4E79 bold header, white background, A4 portrait. Three-tier architecture top to bottom. Top tier (navy, white): "Input Layer — APK File + Signed Authorisation Form + Analyst Identity". Arrow down. Middle tier: four boxes in a row, medium blue #2E74B5 white text: "Phase 1–3: Static Analysis (Androguard + Jadx + Apktool + Multi-Specialised Agents × 14 OWASP MASVS categories)" | "Phase 4–5: AI Intelligence (ChromaDB RAG top-4 + Groq Llama 3.3 70B + Proof Gate L1–L3)" | "Phase 6–7: Dynamic Analysis (ADB device + Frida 16.x hooks + Runtime confirmation L4)" | "Phase 8–10: Output (Evidence assembly L5 + Human approval L6 + PoC gate L7 + NRB report)". Arrow down. Bottom tier three boxes (navy, white): "Redis: Hot — sub-millisecond — LLM verdict cache 24h TTL — 47% hit rate" | "PostgreSQL: Warm — ACID persistent — confirmed findings + full audit trail" | "MinIO: Cold — S3-compatible — APK binary + Frida logs + PoC bundles". Caption italic 10pt: "Figure 25: SENTINEL's three-tier architecture spanning input, intelligence pipeline, and storage layers."

---

## FIGURE 26 — Ten-Phase Assessment Pipeline

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL Ten-Phase Assessment Pipeline" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Ten numbered boxes connected by downward arrows, alternating navy and medium blue. Box 1 (navy): "Phase 1 — APK Ingestion: SHA-256 deduplication, Docker workspace isolation, authorisation gate verification". Box 2 (blue): "Phase 2 — Manifest Analysis: Androguard permission audit, exported component enumeration, API level check". Box 3 (navy): "Phase 3 — Static Code Analysis: Jadx DEX decompilation, Apktool resource extraction, multi-specialised agent parallel dispatch". Box 4 (blue): "Phase 4 — RAG Enrichment: ChromaDB top-4 retrieval per finding, OWASP MASVS + CWE + OSV context injected". Box 5 (navy): "Phase 5 — LLM Triage: Groq Llama 3.3 70B verdict — exploitable, confidence, CWE ID, severity". Box 6 (blue): "Phase 6 — Dynamic Setup: ADB device lease, Frida 16.x server push, application instrumentation". Box 7 (navy): "Phase 7 — Runtime Confirmation: Frida hooks validate static findings on live device — Level 4 proof gate". Box 8 (blue): "Phase 8 — Evidence Assembly: PostgreSQL record + MinIO artefact bundle sealed — Level 5". Box 9 (navy): "Phase 9 — Human Approval: Analyst endorses or rejects — MANDATORY Level 6 gate". Box 10 (green #27AE60): "Phase 10 — Report Generation: PDF + JSON, CVSS v3.1 scores, remediation guidance, NRB evidence package". Caption italic 10pt: "Figure 26: The ten sequential phases of the SENTINEL automated assessment pipeline."

---

## FIGURE 27 — Fourteen OWASP MASVS Categories

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL Agent Coverage — Fourteen OWASP MASVS Vulnerability Categories" in dark navy #1F4E79 bold header, white background, A4 portrait. 4×4 grid of rounded rectangle tiles (last two merged into summary). Alternating navy and medium blue, all white text. Tile 1: "MASVS-STORAGE — Insecure data storage, cleartext credentials, SD card leakage". Tile 2: "MASVS-CRYPTO — Weak ciphers, hardcoded keys, broken RNG". Tile 3: "MASVS-AUTH — Broken authentication, insecure biometrics, token leakage". Tile 4: "MASVS-NETWORK — Cleartext traffic, TLS misconfiguration, certificate pinning bypass". Tile 5: "MASVS-PLATFORM — Intent injection, ContentProvider SQLi, clipboard leakage". Tile 6: "MASVS-CODE — Debuggable flag, backup enabled, anti-tampering bypass". Tile 7: "MASVS-RESILIENCE — Anti-debug bypass, emulator detection, root detection bypass". Tile 8: "MASVS-PRIVACY — PII logging, analytics leakage, excessive permissions". Tiles 9–14: "SSRF", "IAP Bypass", "JNI Memory Corruption", "WebView XSS", "Deep Link Hijack", "Hardcoded Secrets". Note below: "Multi-specialised agents assigned per category — each carries category-specific payload sets and detection signatures." Caption italic 10pt: "Figure 27: The fourteen OWASP MASVS vulnerability categories covered by SENTINEL's multi-specialised agent taxonomy."

---

## FIGURE 28 — Three-Tier Memory Architecture

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL Three-Tier Memory Architecture" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Three horizontal bands stacked. Top (dark navy #1F4E79, white): "HOT TIER — Redis In-Memory Cache — Sub-millisecond read latency — Stores: active scan state, LLM verdict cache (24h TTL), agent retry counters — 47% cache hit rate across 47-APK corpus — Prevents duplicate LLM calls". Middle (medium blue #2E74B5, white): "WARM TIER — PostgreSQL Relational Store — Millisecond persistent reads — ACID compliant — Stores: all confirmed findings, complete audit trail (submitter, agent, LLM verdict, analyst approval, timestamp), CVSS scores — NRB audit evidence format". Bottom (#DEEAF1, dark navy text): "COLD TIER — MinIO Object Store (S3-compatible) — Stores: APK binaries, Frida instrument logs, raw disassembly outputs, PoC script bundles, full evidence archives — Cost-efficient long-term forensic artefact retention". Arrows between tiers: "Promoted from cold on access" and "Written through to warm on confirmation". Caption italic 10pt: "Figure 28: SENTINEL's three-tier memory architecture balancing access speed, persistence, and storage cost."

---

## FIGURE 29 — ChromaDB RAG Embeddings Detail

**Canva AI Prompt:**
Create a professional academic infographic titled "ChromaDB RAG Knowledge Base — Embedding and Retrieval Detail" in dark navy #1F4E79 bold header, white background, A4 portrait. Left-to-right flow five stages. Stage A (navy): "Source Corpus — OWASP MASVS v2.1: 273 controls — CWE database: 1,200 entries — OSV advisories: 850 entries — Total: 2,323 passages". Arrow → Stage B (blue): "Chunking — 512-token passages — 64-token overlap — Markdown-aware splitter". Arrow → Stage C (navy): "Sentence Transformer — all-MiniLM-L6-v2 — 384-dimensional dense vectors — CPU-local, no API key required". Arrow → Stage D (blue): "ChromaDB Collection — hnsw:space=cosine — Approximate nearest neighbour — Upsert-safe: re-runnable without duplication". Arrow → Stage E (green #27AE60): "Query — APK finding text → embed → top-4 cosine neighbours → {document, metadata, score} — 12–18ms latency". Stat box below: "Typical retrieval: 12–18ms. Corpus build time: 4.2 minutes. Re-build is idempotent." Caption italic 10pt: "Figure 29: ChromaDB embedding pipeline from source corpus to top-4 contextual passage retrieval."

---

## FIGURE 30 — LLM Router and Redis Caching

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL LLM Router — Provider Priority and Redis Caching" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Two sections side by side. Left (navy border): "Provider Priority Chain". Three stacked boxes: Priority 1 (green #27AE60): "Groq — Llama 3.3 70B — Cloud — Sub-second — Preferred". Priority 2 (blue #2E74B5): "Cerebras — Llama 3.3 70B — Cloud — Auto failover when Groq rate-limited". Priority 3 (orange #E67E22): "Ollama local — qwen2.5-coder:7b — Self-hosted — Always available — Zero network dependency". Right (navy border): "Redis Response Cache Flow". "LLM request arrives → SHA-256 hash of full prompt → Redis GETEX → HIT (47% of cases): return cached verdict in <1ms → MISS: call LLM provider → store result 24h TTL → return verdict". Stat box: "47% cache hit rate across 47-APK corpus. Saves ~0.8s per cached call." Caption italic 10pt: "Figure 30: The LLM router priority chain and Redis caching layer ensuring fast, cost-efficient triage."

---

## FIGURE 31 — Proof Gate Escalation Flow

**Canva AI Prompt:**
Create a professional academic infographic titled "Seven-Level Proof Gate — Escalation Decision Flow" in dark navy #1F4E79 bold header, white background, A4 portrait. Vertical decision flowchart. Start box (navy): "Vulnerability Candidate Detected by Agent". → Diamond: "Level 1: Static pattern match confirmed by ≥1 agent?" NO → red box "DISMISSED". YES → down. → Diamond: "Level 2: ≥2 independent agents corroborate same code path?" NO → DISMISSED. YES → down. → Diamond: "Level 3: LLM triage verdict = exploitable, confidence ≥ 0.7?" NO → orange "NEEDS REVIEW". YES → down. → Diamond: "Level 4: Frida runtime hook confirms behaviour on live device?" NO → yellow "STATIC ONLY (flagged)". YES → down. → Box (navy): "Level 5: Evidence sealed to PostgreSQL + MinIO artefact bundle". → Diamond: "Level 6: Human analyst endorses finding?" NO → red "REJECTED". YES → down. → Box (green #27AE60): "CONFIRMED VULNERABILITY — CVSS scored — NRB report included — Level 7 PoC available on request". Stat note: "8,420 raw flags → 534 confirmed across 47-APK corpus (93.7% reduction)". Caption italic 10pt: "Figure 31: The seven-level proof gate decision flow from initial agent detection to confirmed vulnerability status."

---

## FIGURE 32 — Real APK Scan Screenshot

**NOTE:** This is an actual terminal screenshot from a SENTINEL scan session. No Canva prompt needed. Run SENTINEL against a test APK and screenshot the terminal showing Phase 3 agent findings and Phase 5 LLM triage verdicts. Crop to show the most informative output. Save as Figure32_scan_screenshot.png.

Caption text to use: *"Figure 32: SENTINEL terminal output during assessment of a Nepalese fintech APK — showing Phase 3 multi-specialised agent findings and Phase 5 LLM triage verdicts."*

---

## FIGURE 33 — Performance Comparison Bar Chart

**Canva AI Prompt:**
Create a professional academic infographic titled "Findings RQ1 — Performance Comparison Across Assessment Tools" in dark navy #1F4E79 bold header, white background, A4 portrait. Grouped bar chart. X-axis: three metric groups: "Detection Coverage (%)", "False Positive Rate (%)", "Assessment Time (hours, scaled ÷10)". Y-axis: 0–100. Four bars per group. SENTINEL = green #27AE60, MobSF = blue #2E74B5, QARK = orange #E67E22, Manual = navy #1F4E79. Data — Detection Coverage: SENTINEL 94.3, MobSF 52.7, QARK 41.2, Manual 53.4. False Positive Rate: SENTINEL 8.3, MobSF 38.1, QARK 42.4, Manual 31.2. Assessment Time (÷10 for scale): SENTINEL 0.014 (8.3min), MobSF 0.28 (17min), QARK 0.25 (15min), Manual 74 (7.4hrs, shown as 74). Data label above each bar. Bold annotation on coverage: "SENTINEL +41.6pp vs MobSF". Legend: colour key for four tools. Caption italic 10pt: "Figure 33: Performance comparison across detection coverage, false positive rate, and assessment time for all four evaluated tools."

---

## FIGURE 34 — RQ2 Ethical Framework Satisfaction

**Canva AI Prompt:**
Create a professional academic infographic titled "Findings RQ2 — Ethical Framework Satisfaction Audit" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Radar / spider chart with seven axes: "Authorisation", "Data Minimisation", "Privacy by Design", "Transparency", "Human Oversight", "Accountability", "Harm Avoidance". Two overlaid polygons. SENTINEL: green #27AE60 at 100% on all seven axes (outer polygon). Typical automated tool (no governance): orange #E67E22 at ~40% average (inner polygon). Legend: green = SENTINEL, orange = Comparable tools without governance. Annotations at each SENTINEL axis point: "Authorisation: hard Phase 1 gate", "Transparency: model ID + prompt hash in every verdict", "Human Oversight: Level 6 mandatory", "Harm Avoidance: Level 7 read-only PoC". Caption italic 10pt: "Figure 34: RQ2 ethical audit — SENTINEL satisfies all seven governance principles where comparable tools average approximately 40%."

---

## FIGURE 35 — Proof Gate False Positive Reduction Funnel

**Canva AI Prompt:**
Create a professional academic infographic titled "Proof Gate False Positive Reduction — Evidence from 47-APK Corpus" in dark navy #1F4E79 bold header, white background, A4 portrait. Vertical funnel diagram, wide at top narrowing to bottom. Six funnel levels. Level label on left, count on right in large bold navy text. Level 1 "Agent raw flags (all agents, all 47 APKs)": 8,420. Level 2 "After Level 2 corroboration (≥2 agents agree)": 3,108. Level 3 "After Level 3 LLM triage (confidence ≥0.7)": 1,247. Level 4 "After Level 4 Frida runtime confirmation": 623. Level 5 "After Level 5 evidence sealing": 611. Level 6 "After Level 6 human approval (82.4% endorsed)": 534. Red percentage arrows between levels showing reduction. Bottom green box #27AE60: "534 confirmed vulnerabilities — 8.3% false positive rate — down from 38.1% (MobSF) and 42.4% (QARK)". Caption italic 10pt: "Figure 35: The proof gate funnel showing how 8,420 raw agent flags are refined to 534 analyst-confirmed vulnerabilities."

---

## FIGURE 36 — Future Works Roadmap

**Canva AI Prompt:**
Create a professional academic infographic titled "Future Works Roadmap — SENTINEL Next Development Phases" in dark navy #1F4E79 bold header, light blue #DEEAF1 background, A4 portrait. Horizontal timeline left (Year 1) to right (Year 3+). Three phase boxes. Phase 1 (dark navy, white, Year 1): "Immediate Extensions — iOS IPA support via Frida iOS targets — Nepal fintech-specific OWASP MASVS profile with NRB API patterns and Nepali-language analysis — NRB evidence package format PDF/A with digital signature — Public 47-APK corpus release for academic benchmarking". Phase 2 (medium blue #2E74B5, white, Year 2): "Technical Upgrades — Federated learning for GradientBoostingClassifier retry selector (addresses training data diversity without sharing artefacts) — Analyst engagement monitoring in Level 6 review interface (addresses overreliance risk) — Automated CVSS v4.0 scoring — CI/CD GitHub Action integration". Phase 3 (green #27AE60, dark text, Year 3+): "Ecosystem Goals — Academic partnership with Tribhuvan University cybersecurity programme — Community agent plugin registry for new OWASP MASVS categories — OWASP tool directory listing — SaaS deployment option for Nepalese fintech firms". Caption italic 10pt: "Figure 36: Three-phase future development roadmap for SENTINEL from immediate extensions to ecosystem goals."

---

## FIGURE 37 — Conclusion Summary Visual

**Canva AI Prompt:**
Create a professional academic infographic titled "SENTINEL — Conclusion: Key Achievements" in dark navy #1F4E79 bold header, white background, A4 portrait. Four quadrant boxes 2×2. Top-left (navy, white): "RQ1 Answered — 94.3% detection coverage — 8.3% false positive rate — 8.3-minute assessment — Significant improvement over MobSF (52.7%), QARK (41.2%), Manual (53.4%)". Top-right (medium blue #2E74B5, white): "RQ2 Answered — Seven ethical principles satisfied — Authorisation gates, privacy by design — Mandatory Level 6 human oversight — NRB Cyber Resilience Guidelines (2023) compliant — Transparent auditable AI verdicts". Bottom-left (green #27AE60, dark navy text): "H1 Confirmed — Coverage 94.3% (target: >80%) — FPR 8.3% (target: <15%) — Hybrid multi-method pipeline validated by 47-APK empirical evaluation". Bottom-right (navy, white): "H2 Confirmed — Proof gate enforces accountability — Human approval mandatory — Overreliance risk identified and documented — GDPR + NRB satisfied — Open-source MIT licence". Centre: small white circle "SENTINEL". Caption italic 10pt: "Figure 37: SENTINEL's four achievement pillars confirming both research questions and both hypotheses."

---

## FIGURE 38 — Master Architecture Diagram (Appendix A)

**Canva AI Prompt:**
Create a professional academic master architecture infographic titled "SENTINEL Complete System Architecture — Master Reference Diagram" in dark navy #1F4E79 bold header, white background, A4 LANDSCAPE (1748 × 1240 px). Full pipeline left to right. Far left: "INPUT — APK File + Authorisation Form". Arrow → "PHASES 1–3: Static Analysis" block (navy): Androguard, Jadx, Apktool, Multi-Specialised Agents × 14 OWASP MASVS categories. Arrow → "PHASES 4–5: AI Intelligence" block (medium blue): ChromaDB RAG top-4, Groq Llama 3.3 70B LLM triage, Proof Gate L1–L3. Arrow → "PHASES 6–7: Dynamic Analysis" block (navy): ADB device lease, Frida 16.x hooks, Runtime confirmation L4. Arrow → "PHASES 8–10: Output" block (green #27AE60): Evidence assembly L5, Human approval L6 (MANDATORY), PoC gate L7, PDF + NRB package. Below pipeline: "MEMORY LAYER" banner with three boxes: Redis (hot, 24h TTL) → PostgreSQL (warm, ACID) → MinIO (cold, forensic). Far right: "ANALYST — Level 6 mandatory review — Endorses / rejects — Submits NRB evidence package". All Calibri font, clear borders, medium blue arrows. Caption italic 10pt: "Figure 38: SENTINEL complete system architecture — master reference diagram for all ten phases, memory tiers, and human oversight points."

---

*End of INFOGRAPHIC_PROMPTS.md — 37 figure prompts for Figures 2–38.*
*Updated to match 20-section thesis structure.*
*SENTINEL BSc (Hons) Ethical Hacking & Cybersecurity — Softwarica College × Coventry University UK.*
