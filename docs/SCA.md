# SCA_001 — Supply Chain Vulnerability Scanner

Detects third-party Java/Android libraries embedded in an APK and
cross-references their versions against an offline OSV.dev Maven CVE
snapshot. Findings name the CVE, its CVSS score, and the version the
user should upgrade to.

The scan never touches the network at runtime — the CVE database is
refreshed out-of-band by `scripts/fetch_osv_db.py`.

## How detection works (3-tier)

The agent walks every candidate detection technique in priority order
and keeps the highest-confidence answer per `groupId:artifactId`. A
coordinate is identified by **at most one** tier; lower tiers don't
double-fire when a higher tier already produced a version.

| Tier | Source | Path / probe | Confidence | Notes |
|---|---|---|---|---|
| 1 | `META-INF/maven/<g>/<a>/pom.properties` | Unzip APK, parse properties | `0.95` | Authoritative when present. Maven writes these deterministically into every JAR it builds. |
| 2 | Version-marker regex over decompiled Java + Androguard string table | e.g. `okhttp/3.x.y`, `gson … 2.8.5`, `Retrofit … 2.9.0` | `0.80` | Conservative patterns from `_VERSION_MARKERS`. Only matches documented formats so coincidental strings don't trigger. |
| 3 | DEX class-path prefix presence | e.g. `com/squareup/okhttp3/` in `get_all_classes()` | `0.40` | Emitted with `version="UNKNOWN"`. Reports every CVE for the coordinate since we can't prove the install is patched — surface, not noise. |

The list of marker regexes (`_VERSION_MARKERS`) and class-path
fingerprints (`_CLASSPATH_FINGERPRINTS`) lives in
`sentinel/agents/supply_chain/sca_agent.py`. Add entries when you
encounter a new commonly-bundled library.

## OSV CVE database

### Layout

`data/osv_maven.sqlite` (gitignored — refresh locally):

```sql
CREATE TABLE vulns (
    group_artifact   TEXT NOT NULL,   -- "com.squareup.okhttp3:okhttp"
    vuln_id          TEXT NOT NULL,   -- "GHSA-..." or "CVE-..."
    cvss             REAL NOT NULL,   -- 0.0–10.0
    severity         TEXT NOT NULL,   -- Critical/High/Medium/Low
    summary          TEXT NOT NULL,
    affected_ranges  TEXT NOT NULL,   -- JSON-encoded OSV `ranges`
    fixed_version    TEXT
);
CREATE INDEX ix_group_artifact ON vulns(group_artifact);
```

Each row is one `(advisory × affected-Maven-package)` pair. A CVE that
covers two coordinates inserts two rows; querying by `group_artifact`
returns every CVE touching that coordinate.

### Refresh command

```fish
poetry run python scripts/fetch_osv_db.py
```

Downloads the public OSV.dev Maven ecosystem dump
(`https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip`,
~50 MiB) and rebuilds the SQLite. Upstream refreshes daily — re-run
this whenever you want newer CVE coverage. A non-default destination
or pre-downloaded zip can be supplied:

```fish
# write to a custom path
poetry run python scripts/fetch_osv_db.py --db /tmp/osv.sqlite

# build from a zip you fetched out-of-band (offline workstation)
poetry run python scripts/fetch_osv_db.py --zip /path/to/all.zip
```

At scan time the agent looks for the DB in this order:

1. `SCAAgent(config={"osv_db_path": "..."})` — used by tests.
2. `SENTINEL_OSV_DB` environment variable.
3. `data/osv_maven.sqlite` (default, resolved from CWD).

A missing DB emits a single WARNING log line and produces zero
findings; SCA_001 never crashes the pipeline.

## CVE matching — semver ranges, not lexicographic compare

The agent uses the `packaging` library (`packaging.version.Version`)
for proper semver comparisons against the `events` list inside each
OSV `range`. A version is considered "in" a range when:

```
intro_version  ≤  detected_version  <  fixed_version
```

i.e. `introduced` is **inclusive**, `fixed` is **exclusive**.
`last_affected` (when present in lieu of `fixed`) is treated as
inclusive. A version that fails to parse falls back to "skip this
advisory" so we never produce false positives from non-semver strings.

## Severity mapping

| CVSS | Severity |
|---|---|
| `≥ 9.0` | `Critical` |
| `≥ 7.0` | `High` |
| `≥ 4.0` | `Medium` |
| `< 4.0` | `Low` |

`packaging`-related severity adjustments and triage are out of scope
here; LLM triage runs after SCA_001 and can downgrade individual
findings the same way it does for any other agent.

## Finding shape

Each match emits:

| Field | Value |
|---|---|
| `agent_id` | `SCA_001` |
| `vuln_class` | `VULNERABLE_DEPENDENCY` |
| `severity` | from CVSS bucket |
| `confidence` | tier-derived (0.95 / 0.80 / 0.40) |
| `owasp` | `M11: Outdated Components` |
| `masvs` | `MSTG-CODE-5` |
| `evidence.library` | `groupId:artifactId` (lowercased) |
| `evidence.version` | detected version, or `"UNKNOWN"` (tier 3) |
| `evidence.cve` / `osv_id` | the advisory id |
| `evidence.cvss` | numeric base score |
| `evidence.fixed_version` | first `fixed` event, or `"unknown"` |
| `evidence.detection_method` | `"pom.properties"` / `"version-marker"` / `"classpath"` |
| `evidence.evidence_paths` | paths/strings that triggered detection |
| `recommendation` | `"Upgrade {coord} to {fixed} or later. Tracked as {cve} (CVSS X.X)."` |

## Limitations & future work

* **Stripped or merged dependencies** can hide their version: R8/ProGuard
  may delete `META-INF/maven/` and minify the marker strings. We still
  detect the library via tier 3 (class-path), but the CVE applicability
  is necessarily UNKNOWN. Class-byte fingerprinting (matching shipped
  `.class` SHA-256s against Maven Central reference jars) would close
  this gap — not yet implemented.
* **AAR / META-INF re-bundling**. Some Gradle plugins merge `META-INF`
  contents into a single namespaced directory. We tolerate this via
  `glob("META-INF/maven/**/pom.properties")` but very aggressive
  shading can still hide entries.
* **NPM / PyPI / RubyGems ecosystems** are not consulted. Maven coverage
  is sufficient for ~95% of Android bundles; cross-ecosystem support
  would require a multi-database fetch.
* **Transitive Gradle dependencies without their own `pom.properties`**
  do not appear. Maven `pom.xml` is parsed only when the build embeds
  the properties file alongside; we don't reconstruct the full
  dependency graph from a Gradle lockfile.

## Reproducing the campus.apk run

```fish
poetry run python scripts/fetch_osv_db.py
poetry run sentinel scan corpus/campus.apk --static-only \
    --json-output /tmp/sca.json --no-triage
cat /tmp/sca.json | jq '[.findings[] | select(.agent_id=="SCA_001")] | length'
```
