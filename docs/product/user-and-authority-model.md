# User and authority model

## Roles

### VFX pipeline technical director

The primary operator. They launch or review an investigation, inspect evidence and uncertainty, edit/reject/approve a response plan, monitor recovery, and close the incident. Approval is an authenticated decision, not a UI convenience.

### Color/QC owner

Owns creative intent and reference suitability. If the declared reference, viewing transform, tolerance, or comparison policy is disputed, the incident remains unresolved until this role supplies a valid decision. The single-user demo represents this as an explicit escalation rather than a second full persona.

### Public demo viewer

May inspect the prepared incident in read-only mode. They cannot initiate investigations, approve plans, execute actions, change evidence, or close incidents.

## System authorities

| Concern | Authority | Not authoritative |
|---|---|---|
| Operational observations | Grafana-returned metrics/logs/traces/alerts with provenance | Gemini summaries |
| Config/resource identity | Content-addressed manifests and deterministic validators | File names, worker labels |
| Structural OCIO validity | Pinned OCIO tooling/`ociocheck` | Successful render exit code |
| Reference agreement | Versioned deterministic image-comparison policy | Visual intuition or model prose |
| Affected/safe scope | Deterministic lineage and transform-use calculation | Worker identity alone |
| Hypothesis ordering | Bounded Gemini/ADK workflow | Hidden fixture truth |
| Action authorization | Authenticated pipeline TD approval | Gemini, API caller, simulator |
| Action execution | Idempotent simulator adapter | Browser or LLM-generated command |
| Recovery verification | New evidence plus deterministic validators | Execution success response |
| Closure | Human pipeline TD | Automatic state transition |

## Approval contract

Approval binds:

- incident ID and version;
- response-plan ID, version, and content hash;
- exact included and excluded targets;
- exact typed commands and policy version;
- acknowledged unresolved items;
- approver identity and authentication context;
- timestamp and idempotency key.

Any plan, target, policy, evidence-dependency, or incident-version change invalidates approval. Authorization is rechecked at execution time.

## Agent boundary

Gemini may summarize evidence, propose hypotheses, request allow-listed read tools, compare candidate explanations, and draft a plan. It may not create authoritative evidence, change state directly, construct arbitrary executable commands, approve, execute, verify recovery, or close incidents.

## Fail-closed rules

Missing identity, stale/contradictory evidence, broken trace correlation, MCP failure, unsupported schema version, unknown transform/resource linkage, or disputed reference policy produces `unresolved` and blocks action.
