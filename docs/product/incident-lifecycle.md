# Incident lifecycle

## State machine

```text
alerted
  -> investigation_requested
  -> investigating
  -> diagnosis_ready | evidence_incomplete | unresolved
  -> awaiting_approval
  -> plan_approved | plan_rejected
  -> recovering
  -> verifying
  -> recovery_verified | recovery_failed | unresolved
  -> closed
```

## Transition requirements

| Transition | Required proof |
|---|---|
| alert to requested | Valid Grafana alert reference and deduplicated incident key |
| requested to investigating | Authorized request, worker task accepted, correlation window fixed |
| investigating to diagnosis ready | Decisive operational evidence plus passing deterministic validators |
| investigating to incomplete/unresolved | Recorded missing, stale, contradictory, or inaccessible evidence |
| diagnosis ready to awaiting approval | Versioned plan generated from exact deterministic scope |
| awaiting approval to approved | Authenticated human approves the exact current plan hash/version |
| awaiting approval to rejected | Authenticated human rejection and reason |
| approved to recovering | Authorization revalidated; idempotent command accepted by simulator adapter |
| recovering to verifying | All command outcomes recorded; no execution outcome treated as recovery proof |
| verifying to verified | New Grafana evidence and deterministic comparison pass the recovery policy |
| verifying to failed/unresolved | Deterministic failure or insufficient new evidence recorded |
| verified to closed | Explicit authenticated human closure |

## Invariants

- Transitions not listed above are rejected.
- The API, worker, and simulator all validate transitions; no client decides state.
- Evidence and audit events are append-only.
- Retry delivery cannot create a second investigation, approval, or action.
- An edited plan returns to `awaiting_approval` with no valid approval.
- A rejected plan cannot execute.
- Failed or unresolved verification cannot close.
- Closure does not erase unresolved observations or evidence history.

## Concurrency and idempotency

Every mutation carries an expected incident version. Conflicts return without overwriting. Task and action keys are derived from stable incident/operation identifiers. Replays return the recorded result. Worker leases and task timestamps are observable but do not become evidence about color causality.

## Evidence time

Each observation records event time, query window, retrieval time, source clock where available, and freshness policy. Recovery verification uses evidence emitted after the approved action began; pre-action data cannot satisfy recovery criteria.
