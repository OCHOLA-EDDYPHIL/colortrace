# ADR 0001: Focus ColorTrace on one closed incident loop

- Status: Accepted for G0 validation
- Date: 2026-08-11

## Context

A generic observability or render copilot would be difficult to differentiate, validate, and demonstrate. The strongest evidence and technical fit concern successful renders that diverge because runtime color state differs.

## Decision

Build one incident workspace for one user and one canonical shadowed-LUT incident, from real Grafana alert through investigation, deterministic scope, human-approved simulator recovery, new-evidence verification, and human closure.

## Consequences

Depth, causal proof, and safety take precedence over incident breadth. Generic chat, production remediation, multi-tenancy, and additional incident classes are excluded. G0 may pivot or stop if the incident or integration is not credible.
