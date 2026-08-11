# ADR 0005: Run official Grafana MCP privately over stdio

- Status: Accepted for G0 validation
- Date: 2026-08-11

## Context

The hosted Grafana Cloud MCP endpoint uses interactive OAuth and does not document a machine service credential suitable for the worker. The official OSS `grafana/mcp-grafana` supports service-account authentication and stdio.

## Decision

Pin official OSS `grafana/mcp-grafana` and launch it as a private stdio child process inside the worker container. Use a dedicated least-privilege read-only Grafana service-account token; disable write tools and allow-list necessary read tools.

## Consequences

No MCP network endpoint is exposed. Worker lifecycle owns the subprocess. Token rotation, tool inventory, query/result budgets, and provenance are required. If real ADK-to-MCP integration fails G0, the concept must pivot or stop.
