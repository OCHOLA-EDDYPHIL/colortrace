# ADR 0002: Keep AI advisory and action authority deterministic

## Status

Accepted.

## Context

Gemini can help connect logs, metrics, traces, and visible color symptoms. Its explanation is
useful to the operator, but model output must not decide what is true or gain permission to change
the color pipeline.

## Decision

ColorTrace first collects a required alert baseline. Gemini may then select one read-only query at
a time from a fixed Grafana MCP catalog whose arguments remain server-owned. Each selection is
bound to the returned observation and its deterministic disposition. The investigation stops when
the evidence includes an exact signal and a cohort signal, or when its three-query budget is
exhausted. Gemini may explain the accepted observations, but its output remains advisory.

Deterministic validators establish the color-state facts, affected and protected scope, and
inputs to the proposed plan. The response-plan service creates the exact action proposal. A human
approves or rejects it. Approval is bound to the current run, incident, plan, target, and versions,
and a service-only dispatcher may consume that authority once.

Rejection, withheld approval, changed bindings, missing proof, or an unknown prior outcome admits
no new action. Recovery still requires fresh deterministic verification and human confirmation.

## Consequences

Gemini makes the investigation easier to understand while deterministic code and human intent
remain in control. The model cannot authorize, dispatch, or close a recovery. Invalid or
incomplete analysis stops safely before mutation. Persisting the bounded selection trace makes the
adaptive path reviewable without exposing private model reasoning.

The authority boundary is shown in
[`docs/architecture/system-boundary.svg`](../architecture/system-boundary.svg).
