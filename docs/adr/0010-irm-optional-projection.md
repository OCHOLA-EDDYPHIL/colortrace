# ADR 0010: Keep Grafana IRM an optional projection

- Status: Accepted
- Date: 2026-08-11

## Context

Grafana IRM could improve incident presentation, but requiring it adds integration and authority ambiguity. Cloud SQL already owns workflow state, while Grafana telemetry/alerting is essential to evidence.

## Decision

Do not require IRM for the critical path. If time and access permit, project ColorTrace incident status into IRM without accepting IRM changes as authoritative approval, action, verification, or closure decisions.

## Consequences

The core partner integration remains live Grafana metrics/logs/traces/alerts through MCP. IRM failure cannot block or mutate the canonical workflow. Any projection must be clearly labeled and idempotent.
