# Product contract

Status: **locked for feasibility; implementation blocked by Gate G0**

## Product thesis

ColorTrace is an evidence-backed color-pipeline incident-response system for VFX teams. It turns a real Grafana alert about visually divergent but technically successful renders into a bounded investigation, deterministic impact calculation, human-approved simulator response, and verified recovery.

## Primary user

A VFX pipeline technical director owns the operational investigation. They need to identify the first meaningful runtime color-state divergence, distinguish affected from safe work, understand uncertainty, approve only the exact safe simulator action plan, and close the incident after recovery evidence is complete.

A colorist or QC owner remains authoritative when an approved reference or comparison policy is disputed. ColorTrace does not resolve creative intent.

## Canonical incident

- Workers A and B use the same nominal `config.ocio` and identical config hash.
- Runtime environment/context or search-path differences make Worker B resolve a stale/shadowed external LUT.
- The resolved LUT content hashes differ.
- Every render job reports technical success.
- Only jobs whose evaluated transform consumes the divergent resource disagree with a declared approved reference.
- At least one job on Worker B is verified safe.
- At least one affected source frame has a downstream derivative.
- A plausible non-causal signal is present to test rejection.
- Hidden fixture ground truth is unavailable to Gemini and the MCP evidence path.

## Required product behavior

1. Accept a real Grafana alert identifier and create an incident.
2. Correlate metrics, logs, traces, alert state, runtime context, job identity, and resource fingerprints through the official Grafana MCP server.
3. Let Gemini/ADK form bounded hypotheses and request approved read-only tools.
4. Persist every observation with source, query/tool input, time range, retrieval time, content digest, and evidence status.
5. Run deterministic resource, image/reference, lineage, and scope validators.
6. Show confirmed, inferred, rejected, and unresolved claims without presenting Gemini output as evidence.
7. Produce a versioned plan with exact targets, exclusions, rationale, unresolved items, and idempotency key.
8. Require authenticated human approval bound to plan hash and incident version.
9. Execute only approved commands against synthetic workers/jobs.
10. Verify recovery from new Grafana evidence and deterministic outputs.
11. Require human closure.

## Evidence semantics

- `confirmed`: supported by sufficient authoritative evidence under a named policy.
- `inferred`: reasoned but not directly established; never sufficient alone for an action.
- `rejected`: contradicted or ruled out by authoritative evidence.
- `unresolved`: evidence is missing, stale, contradictory, inaccessible, or insufficient.

Gemini output is never evidence. `ociocheck` establishes structural validity/loadability, not visual or creative correctness. Reference comparison establishes agreement with a declared versioned reference and policy, not universal correctness.

## Success criteria

The canonical fixture must produce exact causal resource identification, 100% affected-scope precision and recall, 100% safe-work preservation, complete decisive-evidence citations, no unsupported diagnosis when evidence is incomplete, no unauthorized or duplicate action, and deterministic recovery verification.

## Change control

Changing the user, incident class, authority model, evidence semantics, action boundary, or product loop requires a superseding ADR and gate decision. A feature that does not support this contract is out of scope.
