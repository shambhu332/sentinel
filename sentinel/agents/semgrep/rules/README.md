# SemgrepAgent rules

One rule per YAML file. The `id` in each file matches the filename
(without `.yaml`) — Semgrep enforces this.

Conventions:

- `languages: [java]` (Java only this iteration)
- `severity:` is Semgrep's tri-state (`ERROR` / `WARNING` / `INFO`) used
  for Semgrep's own CLI. SENTINEL uses the `metadata.sentinel_severity`
  value instead: one of `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`.
- `metadata.sentinel_vuln_class` is the stable string that lands on the
  emitted `Finding.vuln_class`. Use UPPER_SNAKE_CASE and keep it short.
- `metadata.sentinel_confidence` is a float 0.0–1.0 representing the
  base confidence before LLM triage downgrades or upgrades it.
- `metadata.owasp_masvs` and `metadata.cwe` are reference strings
  surfaced in the finding's `evidence` block.

Add a new rule:

1. Drop a new `<category>-<short-name>.yaml` in this directory.
2. Set `id` to match the filename.
3. Validate: `poetry run semgrep --validate --config <file>`.
4. Re-run the agent's unit tests:
   `poetry run pytest tests/unit/test_semgrep_agent.py -v`.
