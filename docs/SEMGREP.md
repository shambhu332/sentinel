# SemgrepAgent (SG_001)

## What it does

`SemgrepAgent` runs [Semgrep](https://semgrep.dev) against the
decompiled Java tree produced by Phase 1 (JADX) and converts every
match into a SENTINEL `Finding`. Unlike the existing regex-based agents
(C_007, A_004, etc.), Semgrep parses source into an AST and matches on
syntactic structure — so `Cipher.getInstance("DES")` matches whether
the literal is split across lines, wrapped in a method call, or
spelled with the fully-qualified class name. Rules are plain YAML; new
ones can be added without touching Python.

This is the broad-coverage complement to the targeted regex agents,
not a replacement.

## Rules catalogue (18 rules)

| Rule ID | sentinel_vuln_class | Severity | CWE | What it flags |
|---|---|---|---|---|
| `webview-javascript-interface-exposure` | `WEBVIEW_JS_INTERFACE` | HIGH | CWE-749 | `addJavascriptInterface(...)` — bridges Java methods to JS |
| `webview-allow-file-access` | `WEBVIEW_FILE_ACCESS` | MEDIUM | CWE-200 | `setAllowFileAccess(true)` on `WebSettings` |
| `webview-universal-file-access` | `WEBVIEW_UNIVERSAL_ACCESS` | HIGH | CWE-200 | `setAllowUniversalAccessFromFileURLs(true)` |
| `webview-javascript-enabled` | `WEBVIEW_JS_ENABLED` | LOW | CWE-79 | `setJavaScriptEnabled(true)` — low confidence (often legitimate) |
| `crypto-des` | `WEAK_CRYPTO` | HIGH | CWE-327 | `Cipher.getInstance("DES")` and friends |
| `crypto-ecb-mode` | `WEAK_CRYPTO` | HIGH | CWE-327 | `Cipher.getInstance("AES")` (defaults to ECB), `AES/ECB/...` |
| `crypto-md5` | `WEAK_CRYPTO` | MEDIUM | CWE-327 | `MessageDigest.getInstance("MD5")` |
| `crypto-sha1` | `WEAK_CRYPTO` | LOW | CWE-328 | `MessageDigest.getInstance("SHA-1"/"SHA1")` |
| `crypto-insecure-random` | `INSECURE_RANDOM` | MEDIUM | CWE-330 | `new java.util.Random()` |
| `tls-hostname-verifier-allow-all` | `TLS_HOSTNAME_VERIFICATION_DISABLED` | CRITICAL | CWE-297 | `ALLOW_ALL_HOSTNAME_VERIFIER` or anonymous `verify(...) { return true; }` |
| `tls-trust-all-certs` | `TLS_TRUST_ALL_CERTS` | CRITICAL | CWE-295 | `X509TrustManager` with empty `checkServerTrusted` |
| `tls-cleartext-http-url` | `CLEARTEXT_TRAFFIC` | MEDIUM | CWE-319 | Hardcoded `http://...` literals (skips loopback) |
| `storage-mode-world-readable` | `INSECURE_STORAGE` | HIGH | CWE-732 | Any API using `MODE_WORLD_READABLE` |
| `storage-mode-world-writeable` | `INSECURE_STORAGE` | HIGH | CWE-732 | Any API using `MODE_WORLD_WRITEABLE` |
| `storage-external-storage` | `EXTERNAL_STORAGE_USAGE` | LOW | CWE-922 | `Environment.getExternalStorageDirectory()` |
| `sql-raw-query-concatenation` | `SQL_INJECTION` | HIGH | CWE-89 | `rawQuery("..." + x, ...)`, `execSQL("..." + x)` |
| `command-exec-concatenation` | `COMMAND_INJECTION` | CRITICAL | CWE-78 | `Runtime.exec("..." + x)`, `new ProcessBuilder("..." + x)` |
| `pending-intent-mutable` | `PENDING_INTENT_MUTABLE` | MEDIUM | CWE-927 | `PendingIntent.getActivity/Broadcast/Service` without `FLAG_IMMUTABLE` |

## Adding new rules

1. Create `sentinel/agents/semgrep/rules/<category>-<short-name>.yaml`.
2. Set `id:` to match the filename (without `.yaml`). Semgrep enforces this.
3. Use `languages: [java]`.
4. Pick the Semgrep severity (`ERROR` / `WARNING` / `INFO`) and the
   SENTINEL severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`). The
   SENTINEL one wins for finding routing; Semgrep's is for the CLI.
5. Populate `metadata`:
   - `sentinel_vuln_class` — stable UPPER_SNAKE_CASE label
   - `sentinel_severity` — see above
   - `sentinel_confidence` — float as a **quoted string** (`"0.85"`)
     because Semgrep's metadata parser rejects raw floats
   - `owasp_masvs`, `cwe` — reference strings
6. Validate: `poetry run semgrep --validate --config sentinel/agents/semgrep/rules/<file>.yaml`
7. Re-run agent tests: `poetry run pytest tests/unit/test_semgrep_agent.py -v`
8. If the new rule targets a class of bug not yet covered, add a
   fixture Java file under `tests/fixtures/semgrep/` and a test case.

Optional but recommended: extend `_build_recommendation` in
`semgrep_agent.py` with rule-specific remediation text (otherwise a
generic fallback is used).

## How findings flow through the pipeline

```
1. Phase 1: JADX decompiles APK → ctx.decompiled_dir
2. Phase 2: SemgrepAgent.is_applicable() — checks decompiled_dir + rules_dir exist
3. SemgrepAgent.analyze():
     subprocess.run(["semgrep", "--config", rules_dir, "--json",
                     "--quiet", "--metrics=off", "--no-git-ignore", source_dir])
4. JSON parsed → one SENTINEL Finding per Semgrep `results[]` entry:
     • path           → evidence.file
     • start.line     → evidence.line
     • metadata.sentinel_vuln_class    → Finding.vuln_class
     • metadata.sentinel_severity      → Finding.severity (with fallback)
     • metadata.sentinel_confidence    → Finding.confidence (clamped 0-1)
     • metadata.owasp_masvs            → Finding.masvs + evidence.owasp_masvs
     • metadata.cwe                    → evidence.cwe
     • check_id                        → evidence.semgrep_rule_id
     • extra.lines                     → evidence.matched_lines
     • extra.message                   → evidence.message
5. BaseAgent.run() applies scope filtering, persists to memory.
6. Phase 3: LLMTriager processes SG_001 findings alongside the others.
7. Phase 5: findings exported to JSON / TUI table.
```

## Limitations

- **No control-flow / data-flow analysis** in this iteration. The rules
  match syntactic patterns; they cannot tell whether the matched code
  is reachable from an attacker-controlled entry point or whether the
  vulnerable value is actually attacker-influenced.
- **No inter-procedural taint tracking** yet (Day 2 of the SAST roadmap).
- **Java only** for now. Kotlin produces compiled bytecode that JADX
  still emits as Java; Kotlin-source rules are a future enhancement.
- **False-positive rate is rule-dependent**. The base confidences are
  tuned with this in mind:
  - `webview-javascript-enabled` (LOW, 0.40) is often legitimate; we
    flag it but lean on LLM triage to suppress benign cases.
  - `tls-cleartext-http-url` (MEDIUM, 0.65) skips loopback but
    still catches sample / mock URLs in production code.
- **No support for the Semgrep community rule packs** (`p/owasp-top-ten`
  etc.). The agent only loads the in-repo rules so we can vet false
  positives before adopting external rule packs.
- **Obfuscated APKs**: if JADX cannot decompile, SemgrepAgent skips
  cleanly via `is_applicable()` returning False. The pipeline carries
  on with the other agents.
- **Performance**: subprocess wall-clock is capped at 300 seconds. On
  very large decompiled trees a timeout returns zero SG_001 findings
  without crashing the rest of the scan.

## Tested results

Running against `corpus/InsecureBankv2.apk`:

- 53 SG_001 findings across 7 vuln classes
  (`CLEARTEXT_TRAFFIC`, `EXTERNAL_STORAGE_USAGE`, `PENDING_INTENT_MUTABLE`,
   `WEAK_CRYPTO`, `WEBVIEW_JS_ENABLED`, `INSECURE_RANDOM`, `SQL_INJECTION`)
- Run-time overhead: ~10–20s for a typical app's decompiled tree
- Zero crashes; degrades gracefully when the binary is missing
