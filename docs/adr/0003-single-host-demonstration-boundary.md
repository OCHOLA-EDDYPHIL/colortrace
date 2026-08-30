# ADR 0003: Use a gated single host for the complete demonstration

## Status

Accepted.

## Context

The complete workflow needs the browser, workflow service, simulator, telemetry, Grafana MCP, and
Vertex AI. A distributed application topology adds operational boundaries that do not improve the
authority or recovery story of the generated scenario.

## Decision

Use `infra/single-host` as the gated hosted profile. One Compute Engine VM runs Caddy, web,
runtime, Grafana, and telemetry containers. The generated simulator executes inside the runtime
boundary. Vertex AI remains outside the host and is reached with the attached runtime identity.

Caddy is the only public ingress. It terminates TLS, applies the shared access gate, and exposes
only the browser and demonstration routes. Runtime, Grafana, telemetry, and simulator interfaces
remain on internal or host-loopback paths. SQLite workflow state and simulator state persist on
the VM disk so an interrupted request or restart can be reconciled.

The profile has a fixed operating window. It acts only on the generated simulator and has no
production media connection.

## Consequences

One host preserves the important service and trust boundaries with a direct restart and recovery
path. It keeps the complete experience operable without a managed database or distributed task
transport. The profile is not highly available, and its shared access gate is not individual user
identity.

The conceptual boundary is shown in
[`docs/architecture/system-boundary.svg`](../architecture/system-boundary.svg). Operator steps are
in [`docs/operations/single-host.md`](../operations/single-host.md).
