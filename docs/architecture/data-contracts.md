# Data and evidence contracts

This document fixes semantic ownership before implementation. Concrete Pydantic/OpenAPI/SQL schemas will be versioned under `packages/domain` and `packages/contracts` after G0.

## Identifiers and versions

All entities use opaque stable IDs and integer aggregate versions. Digests use an explicit algorithm prefix (initially `sha256:<hex>`). Times are UTC RFC 3339 with source/event time distinguished from observation/retrieval time.

## Incident

Required fields: ID, canonical incident type, state, version, originating Grafana alert reference, correlation window, created/updated timestamps, current diagnosis/plan references, and closure actor/time. State changes use compare-and-swap on version.

## Evidence observation

An observation is immutable and contains:

- evidence ID and schema version;
- incident ID;
- source kind (`grafana_metric`, `grafana_log`, `grafana_trace`, `grafana_alert`, `artifact`, `validator_result`);
- MCP tool/query or validator policy identity and version;
- normalized query inputs and time window;
- event/source/retrieval times and freshness result;
- raw artifact/content digest and safe display excerpt;
- producer identity/version;
- correlation keys;
- collection outcome and error classification;
- chain predecessor and event hash.

A model summary points to evidence IDs but is not an observation.

## Claim

A claim contains subject, predicate, typed object/value, status (`confirmed`, `inferred`, `rejected`, `unresolved`), evidence IDs, policy/rule ID, derivation version, created time, and optional contradiction links. A decisive confirmed claim requires authoritative evidence and a deterministic rule. An inferred claim cannot authorize an action.

## Runtime color-state manifest

Per evaluated job/frame:

- nominal config URI and config content digest;
- OCIO version and structural validation result;
- context/environment keys from an allow-listed set with sensitive values excluded;
- search paths in resolved order;
- selected transform and processor/cache identity;
- every resolved external resource URI plus content digest and resolution provenance;
- input/source artifact digest;
- output artifact digest;
- worker/job/shot/frame/correlation identifiers;
- manifest policy and generator versions.

A config digest alone is explicitly insufficient.

## Reference-comparison result

Contains candidate and approved-reference digests, comparison policy/version, declared color/viewing context, image tool/version, dimensions/channels, deterministic metrics and thresholds, pass/fail/unresolved, generated difference artifact digest, and reason codes. It proves only policy-based agreement with that reference.

## Lineage and scope

Lineage edges are typed (`source_frame_to_render`, `render_to_derivative`) and content/version-addressed. Scope output contains the causal resource/transform condition, affected source frames, affected downstream derivatives, verified-safe work, unknown work, derivation policy/version, exact input evidence/manifests, and deterministic output digest.

## Response plan

Immutable plan versions contain incident/version, diagnosis claim IDs, included/excluded/unknown targets, typed commands, preconditions, expected outcomes, unresolved acknowledgements, policy version, creator provenance, content hash, and supersession link.

## Approval and action

Approval binds exact plan/incident versions and hash, target set, approver identity/auth context, acknowledgement set, timestamp, and idempotency key. Action records bind approval, typed command schema/version, simulator target namespace, execution key, attempt/outcome, and evidence. Free-form model text is never executable.

## Model/tool invocation

Record provider (`vertex_ai`), model ID/version, Google ADK version, prompt/policy version, tool inventory/version, normalized arguments, input evidence IDs, output digest, latency, token/usage metadata where available, result/error class, and trace correlation. Prompt content must not include secrets or hidden fixture truth.

## Audit ledger

Every mutation produces an append-only logical event with actor, action, aggregate/version, request/idempotency ID, payload digest, prior-event hash, event hash, and time. Database administrators remain a platform trust assumption; application APIs cannot update or delete ledger rows.

## Compatibility

Schemas carry explicit versions. Readers reject unknown major versions. Changes require migration, fixture, contract, and replay tests plus a documented backward-compatibility decision.
