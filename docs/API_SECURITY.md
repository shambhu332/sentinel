# Backend API Security Agents

SENTINEL's `API_*` agents attack the **backend** the mobile app talks to
rather than the app itself. Every agent in this family consumes the
mitmproxy capture SENTINEL produces during dynamic analysis
(`workspace/{session_id}/dynamic/mitm_capture.jsonl`) and either
inventories, replays, or cross-references it against the client code.

All four agents run inside Phase 4 (post-DAST) and require `--dynamic`.
Live-replay agents (`API_002`, `API_003`) additionally honour
`BountyScope.domain_in_scope` — nothing goes on the wire against a host
that isn't declared in scope.

## Agent roster

| ID       | Class                         | Kind             | Emits                              | Signal                                                                             |
|----------|-------------------------------|------------------|------------------------------------|------------------------------------------------------------------------------------|
| API_001  | `OpenAPIInferrerAgent`        | Passive          | Endpoint inventory + advisories    | Group flows by templated path; call out unauthenticated mutating verbs             |
| API_002  | `BOLAVerifierAgent`           | Active replay    | CRITICAL on confirmed BOLA         | Replay authenticated GETs with mutated IDs; compare response body to baseline      |
| API_003  | `MassAssignmentFuzzerAgent`   | Active fuzz      | CRITICAL / HIGH on accepted field  | Inject additive privileged keys into POST/PUT/PATCH JSON bodies                    |
| API_004  | `DataExposureAgent`           | Post-processing  | HIGH on server-only sensitive keys | Match response leaf keys against sensitive catalogue; grep decompiled sources      |

Source lives under `sentinel/agents/api_security/` and every agent is
registered in `cli.py`'s dynamic-agent list.

## Shared plumbing — `sentinel/tools/api_parser.py`

The parser turns a JSONL capture into three primitives all API agents share:

* **`load_flows(path)`** → `list[CapturedFlow]`. Accepts both the current
  `mitm_capture.jsonl` filename and the legacy `mitmproxy_flows.jsonl`
  name from the original design brief. Malformed lines and addon error
  records are skipped, not raised.
* **`group_by_endpoint(flows)`** → `dict[EndpointKey, list[CapturedFlow]]`.
  Buckets by `(host, method, templated_path)`. Numeric segments, UUIDs,
  16+-char hex, and 20+-char opaque tokens collapse to `{id}` so
  `/users/42` and `/users/9001` share a group.
* **`extract_auth_headers(flow)`** and **`extract_object_ids(flow)`**.
  Auth-headers preserve the wire's original casing (so the replay is
  byte-identical). ID extraction covers URL path segments and top-level
  JSON body keys matching `id`, `*_id`, `*Id`.

## Scope enforcement

`BountyScope.domain_in_scope(host)` was added alongside these agents so
live-replay is gated the same way SAST findings already are. It supports
wildcard patterns like `*.example.com`. `BaseAgent._within_scope()`
consumes `finding.evidence['host']` when the scope declares any
in-scope domains, so all four API agents include the host in their
evidence dict — findings against out-of-scope hosts are dropped before
they reach the memory store.

---

## API_002 — BOLA Verifier

**Goal.** Prove that a token bound to user A can read user B's data.

**Preconditions.** At least one captured `GET` request that (a) carries
an `Authorization` (or other credential) header and (b) has an ID-shaped
URL path segment.

**Mutation plan (bounded — this is on purpose).**

| Original ID type | Probes | Order |
|------------------|--------|-------|
| Numeric          | 3      | `+1`, `-1`, canary |
| Opaque token     | 1      | canary only         |

`asyncio.sleep(1)` runs between probes; the first hit short-circuits the
loop so BOLA-positive endpoints don't get hammered.

**Detection heuristic.** Response must be `2xx` **and** materially
different from the baseline. When both baseline and response parse as
JSON, matching identifying keys (`id`, `email`, `username`, `name`) with
distinct values are the strongest signal. Otherwise a >50-char size
delta is the fallback.

**Evidence emitted.**

```json
{
  "host": "api.example.com",
  "endpoint": "/v1/users/42",
  "method": "GET",
  "original_id": "42",
  "mutated_id": "43",
  "baseline_status": 200,
  "mutated_status": 200,
  "replay_logs": [
    {"url": "https://api.example.com/v1/users/43",
     "status": 200, "verdict": "bola",
     "response_snippet": "..."}
  ],
  "auth_header_names": ["Authorization"]
}
```

A curl reproduction is also written to `Finding.reproduction_commands`.

**Config keys.**

| Key                 | Default | Purpose                                 |
|---------------------|---------|-----------------------------------------|
| `delay_seconds`     | `1.0`   | Sleep between probes                    |
| `timeout_seconds`   | `15.0`  | httpx client timeout                    |
| `canary_id`         | `"1"`   | Deliberately obvious probe target       |

---

## API_003 — Mass Assignment Fuzzer

**Goal.** Prove that a backend accepts extra privilege-escalation fields
the mobile client never sends.

**Payloads.** One at a time — no combinatorial fuzzing.

| Payload                | Signal key   |
|------------------------|--------------|
| `{"is_admin": true}`   | `is_admin`   |
| `{"role": "admin"}`    | `role`       |
| `{"price": 0}`         | `price`      |

Extensible via `config['payloads']`.

**Safety rules.**

* Only fires on POST/PUT/PATCH with an authenticated JSON dict body.
* **Baseline collision skip.** If the captured body already carries the
  signal key, that payload is skipped — overriding an existing field is
  a different vulnerability class and a common source of false
  positives.
* At most one payload per endpoint after the first hit.
* Same 1s rate limit and scope gate as API_002.

**Severity tiers.**

| Server response                              | Severity          |
|----------------------------------------------|-------------------|
| 2xx + echoes injected key/value in body      | CRITICAL (0.9)    |
| 2xx without reflection                       | HIGH (0.7)        |
| 4xx (any)                                    | No finding — healthy |
| 5xx                                          | Ambiguous — no finding |

**Evidence.** Same shape as API_002 with `signal_key`, `payload`,
`reflected_in_response`, per-attempt `replay_logs`, and a full curl
reproduction that merges the payload into the captured body.

---

## API_004 — Excessive Data Exposure

**Goal.** Flag response fields the API returns but the mobile app never
consumes. Post-processing only — no HTTP calls.

**Sensitive-key catalogue** (case-insensitive substring match).

```
ssn, social_security,
credit_card, card_number, cardnumber, cvv, cvc,
password_hash, password_digest, pwd_hash, salt,
internal_ip, private_ip, internal_host, internal_url,
api_secret, client_secret
```

`credit_card_last4` trips on `credit_card`; `creditCardNumber` trips on
`card_number`. Extend via `config['extra_sensitive_keys']`.

**Client cross-reference.** For each sensitive hit, the agent greps the
concatenated corpus of `.java`, `.kt`, `.xml`, `.smali`, and `.json`
files under `decompiled_dir` and `resources_dir` (capped at 15 000 files
per root). The match is word-boundary regex, checked against both:

* the original snake_case key name (`password_hash`), and
* its camelCase alias (`passwordHash`) — Kotlin/Java field names
  routinely rebind JSON keys through this transform.

If **neither** spelling appears anywhere in the corpus, the field is
server-only → HIGH finding, 0.8 confidence. If either appears, the app
consumes the field and no finding is emitted.

**Deduplication.** Findings are keyed by `(host, endpoint, key_name)`,
so a chatty endpoint returning `ssn` on every response produces exactly
one finding.

**Evidence.**

```json
{
  "host": "api.example.com",
  "endpoint": "/v1/users/42",
  "method": "GET",
  "response_status": 200,
  "key_name": "password_hash",
  "key_path": "$.user.auth.password_hash",
  "sensitive_match": "password_hash",
  "sample_value_masked": "$a***.."
}
```

Values are masked before landing in the finding — a redacted first/last
character pair for anything longer than 8 characters, `***` otherwise.

---

## Testing

Every agent ships with its own unit tests under `tests/unit/`:

| File                              | Cases | Focus                                          |
|-----------------------------------|-------|------------------------------------------------|
| `test_api_parser.py`              | 25    | Templating, grouping, ID/auth extraction, malformed-line tolerance |
| `test_bola_verifier.py`           | 10    | Positive BOLA, baseline-match negative, 403 negative, scope gate, mutation bound |
| `test_mass_assignment.py`         | 13    | Applicability gates, reflection tier, 4xx rejection, baseline-collision skip |
| `test_data_exposure.py`           | 13    | Nested / array key detection, snake→camel client lookup, dedup, config extension |

Run all four together:

```bash
python -m pytest tests/unit/test_api_parser.py \
                  tests/unit/test_bola_verifier.py \
                  tests/unit/test_mass_assignment.py \
                  tests/unit/test_data_exposure.py -q
```

## Anti-patterns to preserve

* Do **not** widen the mutation plans in `API_002`/`API_003` — the
  entire point is that we prove the class without becoming an
  enumeration tool. Bounty-program compliance and the "safety" bullet
  in the design brief both depend on it.
* Do **not** delete `_walk_leaf_pairs` in favour of a flat key set — the
  JSONPath in the evidence is what makes `API_004` findings actionable
  for triage.
* Do **not** move the sensitive-key catalogue into a config file
  without a code-side default. Operators who forget to configure it
  should still get the four canonical detections listed in the design
  brief.
