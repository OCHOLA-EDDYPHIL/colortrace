# Threat model

## Protected assets

Operator identity, Grafana and cloud credentials, incident/evidence integrity, approved reference and fixture artifacts, response-plan approval, simulator action boundary, audit history, and availability of the judged demo.

## Trust assumptions

Google Cloud and Grafana managed control planes, configured administrators, and pinned build dependencies are trusted within documented limits. The fixture oracle is trusted only by evaluation, not by the runtime investigator. Model output and all external content are untrusted.

## Threats and required controls

| Threat | Consequence | Controls / tests |
|---|---|---|
| Prompt injection in logs/traces/metadata | Agent follows attacker text | Treat as quoted data; strict tool policy; no arbitrary command/query; injection fixtures; deterministic authority |
| Model invents evidence or cause | Unsafe diagnosis/action | Evidence IDs required; confirmed claims deterministic; unsupported cases unresolved; no model evidence type |
| Overbroad Grafana access | Data exposure or mutation | Dedicated read-only service account; tool allow-list; write tools disabled; private stdio MCP; query/time/result budgets |
| Credential leakage | Account compromise | Secret Manager; redaction; no tokens in tasks/logs/issues; secret scan; rotation procedure |
| Public MCP/API mutation | Unauthorized operations | No MCP listener; OIDC and authorization on mutation endpoints; public route tests; deny by default |
| Plan substitution/TOCTOU | Human approves one plan, another executes | Content hash and versions bound to approval; expected-version checks; reauthorization at execution; immutable plan |
| Replay/duplicate task | Duplicate investigation/action | Stable idempotency keys; unique constraints; recorded outcome replay; concurrent tests |
| Action escapes simulator | Production impact | Typed simulator namespace, compile-time/deployment allow-list, separate service identity, no production connectors/secrets |
| Ground-truth leakage | Fake diagnosis/performance | Separate oracle storage/path; schema and network tests; inspect prompts/MCP responses/UI payloads |
| Artifact tampering | False evidence/recovery | Digest verification, immutable storage, provenance, hash-linked event records |
| Stale/misaligned telemetry | Wrong causal conclusion | Event/retrieval times, fixed windows, freshness policy, trace correlation, incomplete->unresolved |
| Malicious image/media | Parser exploit/resource exhaustion | Generated/authorized assets, size/type limits, sandboxed/pinned validators, decompression limits |
| SQL/query injection | State/data compromise | Typed parameters, ORM, allow-listed query templates, no model-built SQL/LogQL/PromQL |
| Supply-chain compromise | Runtime/code compromise | lockfiles, pinned images/actions, dependency/SBOM/license scans, provenance review |
| Cross-user/IDOR access | Incident or approval exposure | Object authorization, role tests, opaque IDs, public prepared-demo boundary |
| XSS via evidence display | Browser compromise | escape/sanitize untrusted content; CSP; no raw HTML; security UI tests |
| Denial via tool loops/cost | Availability/cost loss | per-run tool/token/time/result budgets, Cloud Tasks limits, rate limits, cancellation, telemetry |
| Disallowed AI dependency | Submission noncompliance | dependency/config/env/endpoint/container/IaC scans; runtime provider assertion |
| Audit ledger mutation | Loss of accountability | append-only application permissions, hash chain verification, backup/export tests |

## Abuse cases

The operator cannot approve an outdated plan, an anonymous viewer cannot mutate, Gemini cannot call a write tool, a crafted log cannot create an action, a repeated task cannot repeat an action, and an incomplete trace cannot be promoted to a confirmed cause.

## Residual limitations

The hackathon system is not a production render-farm security boundary. Logical append-only records do not eliminate malicious cloud/database administrator risk. A declared reference policy may be wrong creatively. These limits must be visible in product and submission claims.

## Security release gate

No critical/high reachable defect, exposed secret, public mutation path, write-enabled MCP tool, production action route, unpinned critical dependency, or fail-open diagnosis/action behavior may remain at feature freeze or release candidate.
