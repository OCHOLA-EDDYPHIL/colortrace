# ColorTrace roadmap

The authoritative executable roadmap is GitHub milestones and issues. This document records gate ordering and prevents implementation from bypassing feasibility.

## Order

1. **M0 — Product contract and feasibility:** lock rules, product, architecture, evidence, fixture, UX, practitioner validation, and real integration spikes; Gate G0 chooses ColorTrace, pivot, or stop.
2. **M1 — Executable vertical slice:** deterministic fixture, telemetry/Grafana, secure MCP adapter, validators, bounded Gemini workflow, alert-to-response packet; Gate G1.
3. **M2 — Complete product loop / alpha:** incident workspace, evidence/scope, immutable approval, simulator recovery, verification and closure; Gate G2.
4. **M3 — Evidence-backed beta / feature freeze:** fail-closed security, reliability evaluation, practitioner claims, impact reporting, UX/accessibility; Gate G3.
5. **M4 — Hosted release candidate:** deploy, public-readiness/reproducibility, judge-access and failure tests; Gate G4.
6. **M5 — Demo and submission candidate:** timed capture, public captioned video, submission assets, cold audit; Gate G5.
7. **M6 — Final submission:** submit with buffer, preserve judged build.
8. **M7 — Post-hackathon:** explicitly deferred extensions.

## Critical path

```text
contract/rules/ADRs
-> fixture + Grafana/ADK/MCP + deterministic validation spikes
-> G0
-> repository/product foundation
-> fixture -> telemetry -> MCP/validators -> bounded agent
-> vertical slice -> G1
-> workspace/approval -> simulator recovery/verification -> G2
-> security/reliability/validation -> G3
-> hosted/public readiness -> G4
-> demo/submission audit -> G5 -> submit
```

Parallel work consumes locked contracts; it does not invent alternate schemas or fixture truth. Issues labeled `gate` are explicit stop/go decisions. M1 and later product implementation remains blocked until G0 closes with a proceed decision.
