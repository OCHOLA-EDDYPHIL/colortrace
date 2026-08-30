# ADR 0001: Use one canonical bounded color-recovery scenario

## Status

Accepted.

## Context

A render can complete successfully and still use the wrong color transform. ColorTrace needs one
clear scenario that shows how this fault is found and corrected without putting unrelated outputs
at risk.

## Decision

Use the generated shot-safe scenario as the canonical product story. An incorrect LUT affects
three source frames and one derivative. Three other frames form the protected set.

ColorTrace detects the mismatch, investigates it through bounded read-only queries, establishes
the affected and protected scope with deterministic validators, and prepares a five-command plan
with one LUT replacement. A human may then authorize that exact plan for the simulator. Fresh
verification checks both the corrected outputs and the unchanged protected outputs before an
immutable receipt records the completed recovery.

The scenario, telemetry, images, action target, and reset state are generated. The workflow does
not connect to a production media system.

## Consequences

The interface, contracts, tests, and demonstration describe the same understandable recovery.
The narrow action target makes the safety boundary visible and keeps every run repeatable. New
scenarios may reuse the workflow, but they must define their own scope and action contract.

The product flow is shown in
[`docs/architecture/product-flow.svg`](../architecture/product-flow.svg).
