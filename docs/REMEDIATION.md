# `--generate-patch` — AI Suggested Fixes (experimental)

When you pass `--generate-patch` to `sentinel scan`, the pipeline runs
one extra step after LLM triage: for every finding the triager
marked **VERIFIED**, it asks the same LLM router for a one-shot
unified-diff fix. Patches land in `output/patches/<finding_id>.diff`
and the report shows them in a collapsible **"AI Suggested — Requires
Human Review"** section.

## The hard constraint

> **Patches are SUGGESTIONS for human review. They are NEVER
> auto-applied.**

There are two reasons this constraint cannot be relaxed. They are the
whole reason this feature is gated as "experimental":

### 1. Patches are generated against decompiled code

SENTINEL scans `.apk` files. The Java the agent sees is JADX output —
which is *not* the original source. JADX names variables `arg0`,
`var3`, `_intent`; merges anonymous classes into the parent file;
restructures synthetic methods; sometimes synthesises whole try/catch
blocks the compiler emitted. A diff produced against that
representation will almost never apply cleanly to the real `.java`
source in the repo. A literal `patch -p1` will reject every hunk.

The diff is therefore a **semantic description of the fix**, not an
applyable artefact. A reviewer reads it, understands what to change,
and makes the equivalent edit in the original source. Skipping that
step is a process failure, not a tool failure.

### 2. LLMs hallucinate fixes

A well-prompted code-generation model produces a *plausible-looking*
fix maybe ~50% of the time. The other half splits between subtly
wrong fixes (changes the wrong line, breaks an unrelated invariant,
introduces a new bug while patching the original), well-formed diffs
that don't actually fix the vulnerability, and the model gracefully
declining via `NO_SAFE_FIX`. None of these are safe to auto-apply.

The disclaimer pinned to every successful patch is:

> *AI Suggested — Requires Human Review. Generated against decompiled
> code. Apply equivalent change to original source after manual review.*

Tests pin that exact wording. Removing or weakening it is a
regression.

## How it works

```
                                triager.run()
findings ─────────► [ VERIFIED / FILTERED / UNCERTAIN / SKIPPED ]
                                     │
                          --generate-patch only here
                                     ▼
              ┌──────────────────────────────────────────┐
              │  RemediationGenerator.generate_patches() │
              └──────────────────────────────────────────┘
                                     │
              for each VERIFIED finding:
                   1. build strict prompt (snippet + vuln_class
                      + file + agent_recommendation)
                   2. router.query(tier="T1", temperature=0)
                   3. parse_llm_response:
                       - extract ```diff … ``` fence
                       - validate via unidiff.PatchSet
                       - reject NO_SAFE_FIX / empty / non-diff
                   4. attach evidence:
                       suggested_patch, patch_status,
                       patch_disclaimer (or patch_unavailable_reason)
                                     │
                                     ▼
                   render_diff_file → output/patches/<id>.diff
                   (with disclaimer banner)
```

### Strict prompt

The system message tells the model exactly four things:

1. Output ONLY a unified diff that fixes the specific vulnerability.
2. Do not change unrelated logic, do not refactor, do not add tests.
3. Wrap the diff in a single fenced ```` ```diff ```` block.
4. If you cannot produce a safe fix, output exactly `NO_SAFE_FIX`.

Small models honour explicit format constraints far more reliably
than soft requests. Temperature is pinned to `0.0` so the same
finding produces the same patch every run (or as close to it as the
provider allows).

### Strict parser

The parser in [`sentinel/llm/remediation.py`](../sentinel/llm/remediation.py)
is intentionally pedantic:

| Response shape | Outcome |
|---|---|
| Well-formed ```` ```diff ```` block with ≥1 hunk that `unidiff.PatchSet` accepts | `SUGGESTED_REVIEW_REQUIRED` |
| Literal `NO_SAFE_FIX` | `UNAVAILABLE` |
| Prose answer ("Sure, change AES to AES/GCM…") | `UNAVAILABLE` |
| ```` ```diff ```` fence with no hunks | `UNAVAILABLE` |
| Malformed unified diff (e.g. wrong hunk-header line counts) | `UNAVAILABLE` |
| Router error / timeout / empty response | `UNAVAILABLE` |

`UNAVAILABLE` is the safe failure mode. Every one of those branches
ends up logged + recorded in the finding's `patch_unavailable_reason`
field, and the scan continues.

## CLI

```fish
# Static scan with triage, ask for patches, write to default dir
poetry run sentinel scan corpus/campus.apk \
    --static-only \
    --generate-patch

# Custom output directory
poetry run sentinel scan corpus/campus.apk \
    --static-only --generate-patch \
    --patches-dir ./reviews/2026-05/

# Combination disallowed at parse time — fail fast
poetry run sentinel scan corpus/campus.apk \
    --static-only --no-triage --generate-patch
# → error: --generate-patch requires LLM triage
```

`--generate-patch` requires triage because the gate is
`TriageOutcome.VERIFIED`. Without triage every finding would be
UNCERTAIN and zero patches would generate; we surface that as a CLI
error rather than silently producing no patches.

## Accuracy expectations

In our internal testing, roughly **half** of the LLM responses for
verified findings come back as well-formed, semantically correct
diffs. The other half breaks down approximately as:

* ~20% well-formed diffs that miss the actual vulnerability (e.g.
  rename a variable without fixing the underlying flaw),
* ~15% malformed diffs (wrong hunk-header line counts; rejected by
  `unidiff`),
* ~10% `NO_SAFE_FIX` (model declines — this is the *correct*
  behaviour when the fix needs more context than fits in the prompt),
* ~5% other (router errors, rate limits).

Treat the feature as a **time-saver**, not a **guarantee**. A
reviewer who reads each suggested diff and decides what to apply will
spend a fraction of the time they would writing the fix from
scratch.

## Example output

A `weakcrypto` finding flagged by `C_007` looks like this once
`--generate-patch` has run:

```diff
# SENTINEL AI-Suggested Patch — requires human review.
# finding_id: aafd05b131368d57
# vuln_class: WEAK_CRYPTO
# agent_id:   C_007
# severity:   Medium
#
# AI Suggested — Requires Human Review. Generated against decompiled
# code. Apply equivalent change to original source after manual review.
#
# ----------------------------------------------------------
--- a/com/example/auth/LegacyCrypto.java
+++ b/com/example/auth/LegacyCrypto.java
@@ -42,2 +42,4 @@
-        Cipher c = Cipher.getInstance("AES");
-        c.init(Cipher.ENCRYPT_MODE, key);
+        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
+        byte[] iv = new byte[12];
+        SecureRandom.getInstanceStrong().nextBytes(iv);
+        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
```

The banner header is the same on every file — it's the first thing a
reviewer sees, before they read the diff.

## What lives where

* [`sentinel/llm/remediation.py`](../sentinel/llm/remediation.py) —
  generator + parser + file renderer. ~370 LOC, pure (no I/O outside
  the router call), tested with a mocked router.
* `sentinel/cli.py` — `--generate-patch` flag and the
  `_generate_and_write_patches` helper called after triage.
* `tests/unit/test_remediation.py` — 19 tests covering parser,
  generator, disclaimer presence/absence, file-writer behaviour,
  router-failure resilience, and the canonical weak-crypto example.

## Limitations

These are documented so a reviewer using this feature knows what
*not* to trust:

1. **Diffs don't apply against original source.** Documented twice
   above because it's the headline. The diff describes the change;
   the human edits the source.
2. **Snippet truncation.** The prompt caps the code excerpt at 4000
   chars to keep latency and cost bounded. A vulnerability whose
   context exceeds that window may yield a patch that misses
   surrounding constraints.
3. **No multi-file fixes.** The prompt focuses the model on one
   file's diff. Vulnerabilities whose fix spans several files (e.g.
   a sanitizer added in one file and called from another) are out
   of scope; the model usually emits `NO_SAFE_FIX` in that case,
   which is the right answer.
4. **LLM is a single-shot pass.** We do not run the produced patch
   through any verification (compile, unit test, re-scan). Adding
   that would close the loop but multiplies cost; not in scope for
   the initial implementation.
5. **Tier-1 model required for code quality.** The remediation pass
   uses the T1 tier (strong instruct-tuned models). Routing to a
   small T2/T3 model would crater the quality of generated diffs.
   The router already prefers T1 when the API key is configured;
   tested but not hard-pinned.

## Future work

* Patch verification loop: re-run the affected agents after applying
  the patch in a copy of the decompiled tree; only mark the patch
  `SUGGESTED_REVIEW_REQUIRED` when the agent no longer flags the
  finding.
* Multi-file patch support: extend the prompt and parser to accept
  a multi-file unified diff (`unidiff.PatchSet` already supports this
  shape — only the prompt needs broadening).
* Severity-aware tier routing: route critical findings to the
  highest-quality model regardless of cost.
