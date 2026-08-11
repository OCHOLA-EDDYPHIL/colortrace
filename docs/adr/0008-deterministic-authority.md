# ADR 0008: Give deterministic validators authority over decisive facts

- Status: Accepted
- Date: 2026-08-11

## Context

Gemini is useful for navigating cross-system evidence but is probabilistic and can fabricate or overstate conclusions. Color-state, image, and lineage checks can be deterministic under explicit policies.

## Decision

Gemini may propose hypotheses and plans, but deterministic validators are authoritative for config/resource identity, declared-reference comparison, lineage, affected/safe scope, and recovery. Confirmed decisive claims cite validator and source evidence.

## Consequences

Model prose is never evidence. Missing inputs produce unresolved. `ociocheck` means structural validity only, and reference comparison means agreement with a declared policy only. Validators and policies are versioned and tested against hidden fixtures.
