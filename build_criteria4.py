"""Build a standalone, brief-compliant docx for Criteria 4 — Reflection on Outcomes
covering Parts A, B, and C with all required sub-sections and infographic placeholders."""
from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

OUT = "SENTINEL_Criteria4_Reflection.docx"

doc = Document()

# --- page setup ---
for section in doc.sections:
    section.top_margin = Cm(2.0)
    section.bottom_margin = Cm(2.0)
    section.left_margin = Cm(2.2)
    section.right_margin = Cm(2.2)

# default font
style = doc.styles["Normal"]
style.font.name = "Calibri"
style.font.size = Pt(11)


def add_para(text, size=11, bold=False, italic=False, align=None,
             color=None, space_before=0, space_after=4):
    p = doc.add_paragraph()
    if align is not None:
        p.alignment = align
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    run = p.add_run(text)
    run.font.name = "Calibri"
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    if color is not None:
        run.font.color.rgb = RGBColor(*color)
    return p


def add_heading(text, level=1):
    sizes = {0: 22, 1: 16, 2: 13, 3: 12}
    p = add_para(
        text,
        size=sizes.get(level, 12),
        bold=True,
        color=(0x0B, 0x5E, 0x4A),  # dark green
        space_before=10,
        space_after=6,
    )
    return p


def add_figure_box(caption, description):
    """Shaded placeholder block for an infographic to be inserted later."""
    table = doc.add_table(rows=1, cols=1)
    cell = table.rows[0].cells[0]
    # cell shading
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), "EAF6F0")
    tcPr.append(shd)
    cell.text = ""
    cap = cell.paragraphs[0]
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = cap.add_run(caption)
    r.bold = True
    r.font.size = Pt(11)
    r.font.color.rgb = RGBColor(0x0B, 0x5E, 0x4A)

    desc_p = cell.add_paragraph()
    desc_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    dr = desc_p.add_run(description)
    dr.italic = True
    dr.font.size = Pt(10)
    dr.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

    placeholder = cell.add_paragraph()
    placeholder.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pr = placeholder.add_run("[ INSERT INFOGRAPHIC HERE ]")
    pr.bold = True
    pr.font.size = Pt(10)
    pr.font.color.rgb = RGBColor(0x88, 0x88, 0x88)

    doc.add_paragraph()  # spacing after the box


# =========================================================================
# COVER
# =========================================================================
add_para("STA309IAE — Design Thinking and Innovation", size=14, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_before=40)
add_para("Softwarica College of IT & E-Commerce", size=11,
         align=WD_ALIGN_PARAGRAPH.CENTER)
add_para("in collaboration with Coventry University", size=11, italic=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, space_after=20)

add_para("SENTINEL", size=22, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         color=(0x0B, 0x5E, 0x4A))
add_para("An AI-Augmented Multi-Agent Mobile VAPT Platform",
         size=13, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER)
add_para("for Nepal's Fintech Sector",
         size=13, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=40)

add_para("CRITERIA 4", size=24, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         color=(0x0B, 0x5E, 0x4A))
add_para("REFLECTION ON OUTCOMES", size=18, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER)
add_para(
    "Part A — Prototype & Design Thinking Application   |   "
    "Part B — Innovation in Business Process   |   "
    "Part C — Learning Outcomes",
    size=11, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=30,
)

add_para("Submitted to: Mr. Rupak Rajbanshi", size=11,
         align=WD_ALIGN_PARAGRAPH.CENTER)
add_para("Prepared by: [Your Name]   |   Batch: Ethical 34", size=11,
         align=WD_ALIGN_PARAGRAPH.CENTER)

doc.add_page_break()

# =========================================================================
# PART A
# =========================================================================
add_heading("Part A — Prototype and Design Thinking Application", level=1)

# ---- A1 (b) Existing Application Description (≈150 words) ----
add_heading("A1 (b) — Description of an Existing Application "
            "Solving the Problem in this Domain", level=2)
add_para("(≈150 words)", italic=True, size=10, color=(0x66, 0x66, 0x66))

add_para(
    "The mobile-application security market is already populated by tools "
    "such as MobSF (open source), Veracode Mobile, Checkmarx, NowSecure, "
    "and Snyk. MobSF — the most widely adopted free option in Nepal — "
    "scans an APK and emits a single static PDF that lists manifest "
    "misconfigurations, hard-coded secrets, and a generic OWASP MASVS "
    "checklist. Commercial alternatives such as Veracode and Checkmarx "
    "ship richer rules but are licensed per developer seat at "
    "USD 30k–80k per year, which is impractical for Nepal's small fintech "
    "engineering teams. Critically, none of these tools chain static (SAST) "
    "and dynamic (DAST) evidence together, none generate runnable "
    "proof-of-concept exploits, and none auto-map findings to Nepal Rastra "
    "Bank directives or the AML/CFT framework. Compliance officers are "
    "therefore left to manually reconcile vendor reports against regulatory "
    "clauses after every release — a four-hour review cycle that does not "
    "scale with weekly mobile-banking release cadences."
)

add_figure_box(
    "Figure A1: Existing Mobile-Security Tool Landscape",
    "MobSF · Veracode · Checkmarx · Snyk vs. SENTINEL — "
    "highlighting evidence, regulatory, and cost-cadence gaps.",
)

# ---- A1 follow-up: influence ----
add_heading("Influence — What Drove a New Prototype", level=2)
add_para(
    "Three structural gaps in the existing landscape influenced SENTINEL: "
    "(i) fragmented evidence — SAST, DAST, and runtime telemetry live in "
    "separate tools; (ii) regulatory blind spots — no global vendor maps "
    "to Nepal Rastra Bank directives or AML/CFT obligations; and "
    "(iii) cost-to-cadence mismatch — per-engagement consultancy at "
    "USD 20k and per-seat licensing both fail the \"weekly release\" "
    "reality of Nepal's BFIs. SENTINEL was conceived to close all three "
    "gaps within a single audit-ready evidence pipeline that is "
    "regulation-aware by default."
)

# ---- A2 Using Design Thinking for the Prototype (≈300 words) ----
add_heading("A2 — Using Design Thinking for the SENTINEL Prototype", level=2)
add_para("(≈300 words)", italic=True, size=10, color=(0x66, 0x66, 0x66))

add_para(
    "Design thinking shaped every layer of SENTINEL. Empathise — nine "
    "stakeholder interviews and three shadowed pen-tests surfaced \"time "
    "poverty\" among developers and \"audit anxiety\" among compliance "
    "officers. Define — the team reframed the project from \"another "
    "mobile scanner\" to \"a shared evidence pipeline,\" the single "
    "pivotal insight of the coursework. Ideate — two divergent workshops "
    "generated 60 raw concepts; convergent voting against weighted "
    "criteria selected the multi-agent centralised model over bilateral "
    "sharing or institution-led scanners. Prototype — five sprints across "
    "ten weeks delivered 88 agents, a six-phase orchestrator "
    "(manifest → SAST → DAST → Frida → IMPACT → reporting), and a "
    "Djini-style Finding Detail View with screenshots, code snippets, and "
    "replay steps. Test — validation against six real Android applications "
    "achieved 92% parity with independent pen-testers and surfaced 18 "
    "additional findings."
)

add_figure_box(
    "Figure A2: SENTINEL Prototype Wireflow",
    "Six-stage pipeline — Upload → Manifest+SAST → DAST+Frida → "
    "IMPACT → LLM Triage → Audit-Ready Report.",
)

add_heading("1. Why the New Flow is More Efficient", level=3)
add_para(
    "A single APK upload triggers parallel agent execution that completes "
    "in minutes rather than two weeks. Frida and ADB auto-capture "
    "screenshots, code lines, and reproduction commands instead of "
    "analysts compiling them by hand. LLM-assisted triage compresses raw "
    "findings from a 7% false-positive rate to 2%, eliminating a "
    "four-hour manual review per report. End-to-end, scan time drops by "
    "approximately 9× and cost-per-engagement drops by roughly 200×."
)

add_heading("2. Compare and Contrast", level=3)
add_para(
    "MobSF emits a static PDF and offers no DAST chaining; Veracode is "
    "expensive and offers no NRB mapping; consultancy pen-tests are "
    "evidence-rich but slow and unrepeatable. SENTINEL combines the speed "
    "of a scanner, the depth of a consultancy, and the compliance posture "
    "of an in-house GRC tool, priced per scan (~USD 100) rather than per "
    "seat or per engagement."
)

add_heading("3. Why Customers Would Choose SENTINEL", level=3)
add_para(
    "Developers gain CI-speed feedback on every commit; security engineers "
    "gain runtime evidence with replay; compliance officers gain "
    "auto-mapped OWASP MASVS, NRB, and AML/CFT citations; regulators gain "
    "sector-wide supervisory visibility. The value proposition is not "
    "\"cheaper scanning\" but a unified, audit-ready, regulation-aware "
    "evidence pipeline tailored to Nepal's fintech context — a positioning "
    "no incumbent currently occupies."
)

doc.add_page_break()

# =========================================================================
# PART B
# =========================================================================
add_heading("Part B — Innovation in Business Process", level=1)
add_para("(≈300 words)", italic=True, size=10, color=(0x66, 0x66, 0x66))

add_heading("(a) What is Innovation?", level=2)
add_para(
    "Schumpeter (1934) defined innovation as the introduction of a new or "
    "significantly improved product, process, marketing approach, or "
    "organisational method that creates economic value. Business-process "
    "innovation specifically targets how value is created and delivered, "
    "rather than what is delivered — making it the most impactful lever "
    "for service-oriented organisations such as cybersecurity SaaS "
    "platforms."
)

add_heading("(b) Business-Process Innovation in Cybersecurity SaaS", level=2)
add_para(
    "In the application-security sector, business-process innovation "
    "typically takes three forms: (i) shifting security \"left\" into the "
    "developer's CI pipeline so vulnerabilities are caught before release; "
    "(ii) replacing periodic consultancy engagements with continuous, "
    "on-demand scans; and (iii) automating evidence collection so audit "
    "reports are generated rather than written. Industry precedents "
    "illustrate each pattern. Snyk embedded vulnerability scanning "
    "directly into GitHub pull requests, eliminating a separate AppSec "
    "gate. Wiz replaced point-in-time cloud audits with a continuous "
    "graph-based posture engine. Datadog transformed manual incident "
    "triage into auto-correlated traces. Each company innovated the "
    "process, not just the toolset, and captured significant market share "
    "by doing so."
)

add_heading("(c) Why Innovation was Necessary for SENTINEL — "
            "and How it Helped", level=2)
add_para(
    "Nepal's fintech sector ships mobile releases weekly, but the "
    "prevailing VAPT process required USD 20k and a two-week wait per "
    "engagement — incompatible with that cadence and unaffordable for "
    "smaller BFIs. Evidence arrived as static PDFs that compliance "
    "officers manually reconciled against NRB directives, adding four "
    "hours of review per report. The existing process structurally could "
    "not scale; innovation was not optional."
)
add_para(
    "SENTINEL redesigned the process end-to-end. Parallel orchestration of "
    "88 agents compressed scan time by 9× (two weeks → minutes). "
    "LLM-assisted triage eliminated the four-hour manual review by cutting "
    "false positives from 7% to 2%. Auto-captured screenshots, code "
    "snippets, and Frida traces replaced manual evidence compilation. The "
    "aggregate effect is a service approximately 100× faster and 200× "
    "cheaper than consultancy. Value is created for every stakeholder, "
    "while subscription revenue (~USD 100 per scan × thousands of monthly "
    "scans) sustains the platform operator — closing the loop on both "
    "value creation and revenue generation."
)

add_figure_box(
    "Figure B: Business Process Innovation Map (SENTINEL)",
    "Hub-and-spoke — Developer · Security Engineer · Compliance Officer · "
    "Regulator · Platform Operator → Create Value + Generate Revenue.",
)

doc.add_page_break()

# =========================================================================
# PART C
# =========================================================================
add_heading("Part C — Learning Outcomes", level=1)
add_para("(≈200 words)", italic=True, size=10, color=(0x66, 0x66, 0x66))

add_para(
    "This module reshaped how I approach engineering problems. Before "
    "STA309IAE, I treated technical projects as feature lists — decide "
    "what to build, then look for users. Learning design thinking "
    "inverted that instinct. The Empathise and Define phases taught me to "
    "invest serious time understanding stakeholders before writing code; "
    "the nine interviews I conducted for SENTINEL surfaced the insight "
    "that compliance officers, not developers, were the most underserved "
    "stakeholder — a finding I would never have reached through technical "
    "brainstorming alone. Reframing the project from \"mobile scanner\" "
    "to \"evidence pipeline\" during Define was the single most valuable "
    "lesson of the module."
)
add_para(
    "Applying Ideate, Prototype, and Test taught me that fast, "
    "low-fidelity iteration beats lengthy planning: five sprints in ten "
    "weeks produced a working 88-agent system because we tested against "
    "real APKs early rather than chasing completeness."
)
add_para(
    "Personally, I gained the discipline of writing structured "
    "documentation, defending design decisions with evidence, and "
    "translating technical capability into business language for "
    "regulators and executives. These skills transfer directly to "
    "cybersecurity engineering, AppSec consulting, and product roles in "
    "Nepal's growing fintech ecosystem, where empathetic, evidence-led "
    "innovation is increasingly valued and rewarded."
)

add_figure_box(
    "Figure C: Learning Outcomes",
    "Three-node triangle — Professional Exposure · Personal Development · "
    "Future Career Prospects — connected by mutual-reinforcement arrows.",
)

# =========================================================================
# Appendix — Requirement Checklist (helps the user verify nothing is missing)
# =========================================================================
doc.add_page_break()
add_heading("Appendix — Brief Compliance Checklist", level=1)

checklist = [
    ("Part A1 (b)", "Description of an existing application/service in domain (≈150 words)", "✓"),
    ("Part A1", "Influence — what drove a new prototype", "✓"),
    ("Part A1", "Infographic placeholder (Figure A1)", "✓"),
    ("Part A2", "Use of design thinking for prototype (≈300 words)", "✓"),
    ("Part A2", "Infographic placeholder — prototype wireflow (Figure A2)", "✓"),
    ("Part A2 summary 1", "How new flow is more efficient", "✓"),
    ("Part A2 summary 2", "Compare and contrast vs. existing tools", "✓"),
    ("Part A2 summary 3", "Why customers would choose SENTINEL", "✓"),
    ("Part B (a)", "Definition of innovation", "✓"),
    ("Part B (b)", "Business-process innovation in cybersecurity SaaS with examples", "✓"),
    ("Part B (c)", "Why innovation was necessary and how it helped", "✓"),
    ("Part B", "Infographic placeholder — value creation + revenue (Figure B)", "✓"),
    ("Part C", "Learning outcomes (≈200 words) — module + personal experience", "✓"),
    ("Part C", "Infographic placeholder (Figure C)", "✓"),
]

tbl = doc.add_table(rows=1 + len(checklist), cols=3)
tbl.style = "Light Grid Accent 1"
hdr = tbl.rows[0].cells
hdr[0].text = "Section"
hdr[1].text = "Requirement"
hdr[2].text = "Status"
for cell in hdr:
    for p in cell.paragraphs:
        for r in p.runs:
            r.bold = True
for i, (sec, req, status) in enumerate(checklist, start=1):
    row = tbl.rows[i].cells
    row[0].text = sec
    row[1].text = req
    row[2].text = status

doc.save(OUT)
print("wrote", OUT)
