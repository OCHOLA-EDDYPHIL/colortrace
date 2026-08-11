# ADR 0007: Use append-only hash-linked evidence and audit events

- Status: Accepted
- Date: 2026-08-11

## Context

A credible incident response must preserve what was observed, derived, approved, and executed. Mutable summaries cannot support replay or detect application-level history changes.

## Decision

Represent evidence and audit history as append-only logical events in PostgreSQL with canonical payload digests and predecessor hashes. Store large raw artifacts immutably by digest. Corrections append superseding events.

## Consequences

Application roles cannot update/delete ledger rows. Chain verification and replay tests are required. This detects application-level alteration but does not claim protection from a malicious cloud/database administrator.
