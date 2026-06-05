# TAINT_001 — Data-Flow Taint Analysis

Tracks attacker-controlled values from where they enter an Android app
(intent extras, UI text, cursor reads, HTTP bodies) to where they
become dangerous (raw SQL, WebView, command exec, file paths,
SharedPreferences with sensitive keys, log calls). Every emitted
finding ships with a **complete source → … → sink trace** — file path,
line number, and code excerpt for every hop — so a reviewer can open
the offending file at the right line without further investigation.

## Why we didn't use FlowDroid

FlowDroid is a Soot-based research analyser. Integrating it means
shipping a JVM dependency, parsing IFDS-formatted result graphs, and
accepting several minutes of analysis time per APK before any output
appears. For a CI/triage tool that needs to deliver readable findings
in seconds, that cost is wrong. We instead built a custom tracer on
**tree-sitter-java** — small enough that the algorithm fits in
`tracer.py` (~620 LOC), fast enough that the whole step is sub-second
on typical decompiled trees, and transparent enough that adding a
new source or sink is a two-line edit to `taint_config.py`.

The trade-off is honest: TAINT_001 is *not* a sound analyser. We
explicitly accept some recall loss in exchange for explainability,
speed, and a low false-positive rate. The "Limitations" section below
documents exactly what we miss.

## Sources, sinks, sanitizers

All three tables live in
[`sentinel/agents/taint/taint_config.py`](../sentinel/agents/taint/taint_config.py).

### Sources — attacker-controlled input

| Family | Methods matched | Note |
|---|---|---|
| Intent | `getStringExtra`, `getIntExtra`, `getLongExtra`, `getBooleanExtra`, `getSerializableExtra`, `getParcelableExtra`, `getExtras`, `getData`, `getDataString` | The canonical Android entrypoint |
| UI | `getText` (on `EditText`, `TextView`, …) | |
| Cursor | `getString`, `getBlob` (with `receiver_hint="Cursor"`) | Other apps may have written to the exported provider |
| Prefs | `getString` (with `receiver_hint="getSharedPreferences"`) | Rooted-device threat model |
| HTTP | `string`, `bytes` (with `receiver_hint="body"`) | OkHttp idiom `response.body().string()` |

Sources do not themselves carry a vuln class — they just mark "this
value is untrusted." The sink decides what kind of vulnerability the
flow represents.

### Sinks — security-sensitive consumers

| Sink | Vuln class | Severity | Notes |
|---|---|---|---|
| `rawQuery(sql, …)` arg 0 | `SQL_INJECTION` | High | |
| `execSQL(sql)` arg 0 | `SQL_INJECTION` | High | |
| `WebView.loadUrl(url)` arg 0 | `WEBVIEW_XSS` | High | |
| `WebView.loadData(html, …)` arg 0 | `WEBVIEW_XSS` | High | |
| `WebView.evaluateJavascript(js, …)` arg 0 | `WEBVIEW_XSS` | High | |
| `Runtime.exec(cmd)` arg 0 | `COMMAND_INJECTION` | **Critical** | receiver must contain `Runtime` |
| `new ProcessBuilder(args)` arg 0 | `COMMAND_INJECTION` | **Critical** | |
| `new File(path[, …])` args 0 + 1 | `PATH_TRAVERSAL` | High | |
| `openFileOutput(name, …)` arg 0 | `PATH_TRAVERSAL` | High | |
| `SharedPreferences.Editor.putString(key, value)` arg 1 | `INSECURE_STORAGE_FLOW` | Medium | only when key matches `token`/`password`/`jwt`/… |
| `Log.{d,v,i,w,e}(tag, msg)` arg 1 | `SENSITIVE_LOG` | Low | receiver must contain `Log` |

### Sanitizers — flow terminators

| Sanitizer | Applies to | Effect |
|---|---|---|
| `Integer.parseInt`, `Long.parseLong`, `Integer.valueOf` | SQLi / Path / Cmd / WebView | Numeric coercion |
| `TextUtils.htmlEncode` | WebView XSS, sensitive logs | HTML escape |
| `URLEncoder.encode` | WebView XSS, Cmd, Path | %xx encoding |
| `compileStatement`, `bindString`, `bindLong` | SQLi only | Parameter binding |
| `getCanonicalPath` | Path traversal | Idiomatic part of an allow-list check |

A flow that passes through *any* sanitizer whose `applies_to_classes`
covers the candidate vuln class is dropped silently (no finding
emitted). Sanitizers are the single most important false-positive
cutter in this kind of analyser — every direct `Integer.parseInt`
between source and SQL sink kills the report.

## Algorithm

For each `.java` file under the decompiled tree we

1. parse it with `tree-sitter-java`,
2. enumerate the declared methods (recording `class.method` pairs so a
   later caller lookup can distinguish two unrelated classes that
   happen to use the same method name),
3. build a **def-use map** for each method body — variable name →
   list of expression nodes that could be its current value at any
   program point (the initialiser of each `local_variable_declaration`,
   the right-hand side of every `assignment_expression`),
4. for every `method_invocation` whose name matches a SINK pattern,
   walk each tracked argument expression backward through the def-use
   chain until we land on one of
   * a **source** call → tainted (depth 0),
   * a **sanitizer** call → flow terminates as clean (no finding),
   * a literal (string, int, null, …) → benign,
   * a method **parameter** with no in-method redefinition → trigger
     IPA pass (see below),
   * any unrecognised callable → benign (conservative — we'd rather
     miss a flow than ship FPs).

### Inter-procedural pass

When the backward slice resolves a sink argument to a method
parameter, the analyser climbs the call graph up to **`MAX_IPA_DEPTH`
= 3** hops:

1. find every caller of the enclosing method (by simple name),
2. filter the candidate callers using receiver-text matching:
   * empty / `this` receiver → caller must be in the same class,
   * receiver matches a class name → that class only,
   * receiver is an unfamiliar expression → permissive,
3. take the call-site argument at the same positional index,
4. recurse on that expression as a fresh backward slice (`depth + 1`).

This is what catches `entry(intent) → lookup(name) → rawQuery(name)`
patterns that an intra-procedural-only analyser misses entirely.

### Confidence

| Hops | Confidence | Meaning |
|---|---|---|
| 0 | 0.9 | Sink and source in the same method |
| 1 | 0.8 | One call-graph hop |
| 2 | 0.7 | Two hops |
| 3 | 0.6 | Three hops — hardest to confirm, lowest confidence |

Findings with confidence below 0.85 get their base severity downgraded
by one notch so deep-IPA hints don't outrank verified direct flows in
the report.

### Performance bounds

* `per_file_timeout_s` (default 8.0) caps how long any one file may
  consume; the analyser checks the deadline at every method boundary.
* `MAX_FILES` (default 1500) bounds the total walk — comfortably above
  any application-code subset of a JADX decompile we've seen.
* `_MAX_FINDINGS_PER_SCAN` (200) caps emitted findings; the cap keeps
  the highest-confidence ones first.

## Refreshing or extending the tables

Adding a source or sink is a 1–2 line edit:

```python
# in taint_config.py
SOURCES = (
    ...,
    SourceSpec("getHeader", "HTTP request header", receiver_hint="Request"),
)
SINKS = (
    ...,
    SinkSpec(
        method_name="openConnection", arg_indices=(0,),
        vuln_class="SSRF", severity=Severity.HIGH,
        owasp="M4: ...", masvs="MASVS-NETWORK-1",
        recommendation="Validate the URL host against an allow-list.",
    ),
)
```

No tracer changes needed — the engine reads the tables directly.

## Limitations

These are deliberate, documented engineering decisions, not bugs:

1. **No reflection.** `Class.forName().getMethod().invoke()` chains
   completely bypass our analysis. Out of scope for a lightweight
   analyser; needs a points-to + class-hierarchy model.
2. **No field sensitivity.** A taint stored in `this.userInput` and
   read elsewhere in the class is not tracked. Modelling object fields
   correctly requires alias analysis that is much larger than the
   1000-LOC budget this whole component lives in.
3. **No array / collection tracking.** Taint in
   `list.get(0)` after `list.add(taintedValue)` is invisible — the
   engine treats container reads as benign.
4. **No reflection-style method dispatch.** Calls resolved via
   interface or virtual dispatch are matched only on simple name. The
   `ProjectIndex.callers_of` filter rejects obvious cross-class
   collisions but cannot disambiguate two same-named methods that share
   a parent class hierarchy.
5. **Single decompiled tree per scan.** Cross-DEX or split-APK flows
   aren't followed; we trust JADX's per-DEX output.
6. **No path/condition sensitivity.** A guard like
   `if (isSafe(x)) sink(x);` is not interpreted — the analyser sees
   the sink regardless of the surrounding condition. Sanitizers that
   sit *between* the source assignment and the sink are what we
   actually rely on to suppress false positives.
7. **Source / sink coverage is curated.** Other static analyzers ship
   thousands of rules; ours ship ~30. We chose precision over breadth.
   Add to `SOURCES` / `SINKS` to extend.

These are listed in the order we'd address them if extending the
analyser. (1) and (3) would each be a multi-week project; (6) could
be added with a small CFG-walking pass.

## Trace format

Each finding carries an `evidence.trace` list of dicts and a
human-readable `evidence.trace_summary` string. The list is ordered
source → intermediate hops → sink. Each entry has:

```json
{
  "file": "/abs/path/Foo.java",
  "line": 42,
  "code": "String x = intent.getStringExtra(\"q\");",
  "kind": "source|variable|call|sink",
  "label": "Intent extra (string)"
}
```

The UI renders the summary; programmatic consumers walk the list.
