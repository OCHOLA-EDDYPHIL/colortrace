# ADR 0009: Require exact human approval for simulator-only actions

- Status: Accepted
- Date: 2026-08-11

## Context

Automated quarantine/rerender can waste work or affect production. The hackathon can prove a safe action loop without claiming production authority.

## Decision

Actions target only the synthetic simulator and require an authenticated human approval bound to incident version, immutable plan hash, exact targets, typed commands, and unresolved acknowledgements. Edits invalidate approval. Actions are idempotent. Humans close incidents.

## Consequences

No production adapters or credentials are shipped. Gemini cannot approve or execute. Execution success is not recovery proof; new operational evidence and deterministic validation are mandatory.
