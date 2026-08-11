# ADR 0002: Use same-config, shadowed external LUT as canonical incident

- Status: Accepted for G0 validation
- Date: 2026-08-11

## Context

A changed `config.ocio` hash is too obvious and does not show cross-system reasoning. OCIO behavior can depend on external resources, context variables, and ordered search paths even when the nominal config bytes match.

## Decision

Two workers use byte-identical configs while one resolves a stale/shadowed LUT. Only jobs consuming the affected transform diverge; one job on that worker remains safe. Include downstream lineage and a distractor.

## Consequences

The fixture must use real OCIO processing and content-address all resolved resources. Scope cannot be worker-based. If practitioners or the spike show this mechanism is unrealistic or visually illegible, G0 must pivot rather than disguise the failure.
