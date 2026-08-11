# ADR 0006: Make Cloud SQL PostgreSQL canonical workflow state

- Status: Accepted
- Date: 2026-08-11

## Context

Approvals, incident versions, idempotency, and audit relationships require transactional state. Grafana and optional IRM are operational evidence/projection systems, not suitable authorities for this workflow.

## Decision

Store incidents, claims, evidence metadata, plans, approvals, actions, and audit events in Cloud SQL PostgreSQL. Store large immutable artifacts in Cloud Storage by digest. Use Cloud Tasks for asynchronous delivery.

## Consequences

Schema migrations and transactional concurrency tests are mandatory. Storage/SQL consistency is verified by digest and reconciliation. Grafana outages impede investigation but cannot corrupt approval state.
