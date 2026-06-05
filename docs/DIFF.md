# SENTINEL Diff Mode — APK-vs-APK Regression Scanning

Compare two APK builds, emit a finding-by-finding delta, and gate
release pipelines on regressions. The diff is APK-first: SENTINEL
doesn't see git diffs, it sees two `.apk` files. That makes the gate
work uniformly for any build system that produces an APK — Gradle,
Flutter, React Native, third-party reproducibles, even an APK
downloaded from the Play Store.

## Quickstart

```fish
poetry run sentinel diff \
    --base corpus/campus_v1.apk \
    --head corpus/campus.apk \
    --fail-on critical,high \
    --format markdown
echo $status   # 0 = no new criticals/highs, 1 = blocked
```

The command prints a PR-comment-ready markdown block and exits with
status `1` if any new finding's severity matches `--fail-on`. Pipe
the output into a `gh pr comment` and you have a regression gate
that posts itself.

## How it works

### Finding fingerprints

Two scans of the same APK never produce identical Finding objects —
each run gets a fresh `session_id`, a fresh per-scan workspace, and a
fresh `created_at` timestamp. Identity has to come from somewhere
else: SENTINEL uses a **fingerprint hash** over four normalised
inputs:

| Input | Source | Normalisation |
|---|---|---|
| `agent_id` | finding | verbatim |
| `vuln_class` | finding | verbatim |
| file path | `evidence.source_file` / `sink_file` / `file` / `path` / TAINT trace tail | workspace-prefix + session-id + decompiler-tool prefix all stripped |
| code snippet | `evidence.code` / `snippet` / `context` / TAINT trace tail | leading line numbers + trailing `// …` comments removed; whitespace collapsed |

The output is 16 hex characters of SHA-256 — roughly 10⁻¹⁹ collision
odds in any realistic repo. The full implementation lives in
[`sentinel/core/diff.py`](../sentinel/core/diff.py) and is pure (no
I/O), so unit tests can run it on mock findings in microseconds.

### Delta computation

```
new        = head finding-set − base finding-set
fixed      = base finding-set − head finding-set
unchanged  = base ∩ head
```

`compute_delta(base, head)` returns a `DiffSummary` carrying the
three lists in emission order: head-order for `new` and `unchanged`,
base-order for `fixed`. Stable order means the same input produces
the same report bytes every time — easy to commit, easy to diff.

### CI gate

`gate_exit_code(summary, fail_on={Severity.CRITICAL, Severity.HIGH})`
returns `1` iff any finding in `summary.new` has a severity in the
configured set. The CLI exposes this via `--fail-on`:

```fish
--fail-on critical,high   # default; production gate
--fail-on critical        # block only the worst regressions
--fail-on low             # paranoid mode: any new finding fails
```

### Baseline store

After each diff the command writes both APKs' finding sets to
`data/baselines.sqlite`. Schema:

```sql
CREATE TABLE baselines (
    apk_hash    TEXT NOT NULL,   -- SHA-256 of the APK
    fingerprint TEXT NOT NULL,   -- 16-hex from finding_fingerprint()
    agent_id    TEXT NOT NULL,
    vuln_class  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    file        TEXT NOT NULL,   -- normalised path
    snippet     TEXT NOT NULL,   -- normalised snippet
    first_seen  TEXT NOT NULL,   -- ISO timestamp, never overwritten
    last_seen   TEXT NOT NULL,   -- ISO timestamp, bumped on each diff
    PRIMARY KEY (apk_hash, fingerprint)
);
CREATE INDEX ix_baselines_apk ON baselines(apk_hash);
```

`first_seen` answers "when did this bug first appear?" — useful for
backfilling a vulnerability disclosure timeline. `last_seen` tells
you the most recent build in which a fingerprint was observed. The
file is gitignored (under the broader `data/*` rule) and trivially
rebuildable, so it's data, not source.

Pass `--no-baseline` to skip persistence — useful in stateless CI
runners.

## GitHub Actions example

Drop this into `.github/workflows/security-diff.yml`. It downloads
the `main`-branch APK as the baseline, builds the PR APK as `head`,
runs the diff, and posts the markdown block as a PR comment. Exits
non-zero (failing the job) if any new critical or high finding
appears.

```yaml
name: SENTINEL Security Diff

on:
  pull_request:
    paths:
      - 'app/**'

jobs:
  diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build PR APK
        run: ./gradlew assembleRelease
        # produces app/build/outputs/apk/release/app-release.apk

      - name: Download baseline APK from main branch
        run: |
          gh release download main-latest --pattern '*.apk' --dir baseline/
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Install SENTINEL
        run: |
          pip install poetry
          poetry install --no-interaction

      - name: Run SENTINEL diff
        id: sentinel
        continue-on-error: true   # let the comment post even on gate fail
        run: |
          poetry run sentinel diff \
            --base baseline/app-release.apk \
            --head app/build/outputs/apk/release/app-release.apk \
            --fail-on critical,high \
            --format markdown \
            --output diff.md

      - name: Post diff to PR
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('diff.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });

      - name: Fail if gate tripped
        if: steps.sentinel.outcome == 'failure'
        run: exit 1
```

## Limitations

These are documented up-front so a reviewer knows what *not* to rely
on:

1. **Fingerprints drift under heavy refactors.** Moving
   `com/example/foo/Bar.java` to `com/example/util/Bar.java` produces
   a different fingerprint — the old fingerprint registers as "fixed"
   and the new one as "new". The diff is correct (the bug moved), but
   a reviewer skimming the headline could mistake noise for action.
   Same caveat for variable renames that flow into the code snippet.
   Mitigation: keep the gate on `critical,high` so the only false
   "new" entries that ever fail CI are severe enough to warrant a
   second look anyway.

2. **Code-snippet normalisation is heuristic.** We strip leading
   `<digits>:` line-number prefixes, trailing `// …` comments, and
   collapse whitespace. We do NOT normalise variable names, literal
   reformatting, or string-concatenation reordering. JADX is
   deterministic across versions, so in practice the same byte tree
   produces the same snippet — but if you swap decompilers you will
   see false "new" reports.

3. **Per-scan workspace is created fresh.** Diffing the same APK
   against itself runs the full static pipeline twice and produces an
   identical fingerprint set (zero new, zero fixed). Useful as a
   sanity check; expensive in CI.

4. **No triage in diff mode.** The diff runs static-only with no
   LLM triage step — the rationale is that triage shifts findings
   in/out of the result set non-deterministically (different LLM
   outputs run-to-run), which would bias the new/fixed sets. The
   gate is therefore stricter than `sentinel scan` output: every raw
   finding counts.

5. **APK SHA-256 collisions across versions.** Two builds with the
   same SHA (rebuild-from-cache scenario) share a baseline row. We
   key on the APK hash, not the version code; collisions are silent
   no-ops.

6. **One APK per baseline row.** The store is *per-APK*, not per-
   repo. Comparing v1 → v2 → v3 means three separate `(apk_hash,
   fingerprint)` rows even if v2 and v3 share fingerprints. This
   keeps the schema flat at the cost of duplication; the alternative
   (a global fingerprint table joined to per-APK observation rows)
   adds query complexity we didn't need.

## Refresh / cleanup

The baseline file is rebuildable:

```fish
rm data/baselines.sqlite        # nukes the store
poetry run sentinel diff …      # next diff re-creates schema + rows
```

There is no migration story; the schema is so small that any future
column addition can recreate the table.
