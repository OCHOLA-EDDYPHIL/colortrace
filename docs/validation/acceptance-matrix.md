# Acceptance and release matrix

## Gate G0 — feasibility and scope lock

All must pass before product implementation:

- Real Google ADK/Gemini call reaches pinned official `mcp-grafana` from a Grafana alert ID.
- Every decisive operational fact used for diagnosis is retrieved through Grafana MCP.
- Fixture proves identical config digest and different resolved LUT digest.
- Real deterministic color processing produces a reference mismatch.
- Deterministic lineage returns exact affected, downstream, safe, and unknown sets.
- At least 9/10 end-to-end correlation attempts succeed.
- Normal alert propagation does not regularly exceed 60 seconds.
- MCP timeout, missing span/manifest, or decisive contradiction returns unresolved with no invented cause.
- MCP path is private, authenticated, read-only, and least privilege.
- Fixture is deterministic, visually legible, and distributable.
- No-Grafana counterfactual cannot establish the diagnosis.
- Theme remains color-pipeline-native and demo loop remains coherent.

## Gate G1 — vertical slice

A real alert triggers live MCP evidence collection, deterministic validation, exact affected/safe scope, and a response packet. The worker cannot read oracle truth. A missing-trace run is unresolved. Evidence and invocation provenance survive replay.

## Gate G2 — alpha product loop

The operator completes alert-to-evidence-to-plan-to-approval-to-simulator recovery-to-new-evidence verification-to-human closure in under three minutes. No unapproved action executes, any plan edit invalidates approval, safe work remains untouched, and execution success alone cannot verify recovery.

## Gate G3 — beta and feature freeze

| Measure | Threshold |
|---|---:|
| Canonical root finding | 100% |
| Affected-frame precision and recall | 100% / 100% |
| Safe-work preservation | 100% |
| Decisive confirmed claims with evidence citations | 100% |
| Unsupported diagnosis in incomplete cases | 0% |
| Unauthorized or duplicate actions | 0 |
| Trace-correlation failure in release suite | <= 1/50 |
| Critical/high defects | 0 |
| Stable structured facts across repeated runs | 100% |

Also required: prompt-injection tests, authorization/object-access tests, stale evidence and clock-skew tests, duplicate/concurrent delivery tests, hidden/permuted fixtures, manual-runbook baseline, no-Gemini baseline, no-Grafana counterfactual, accessibility and target-resolution UX pass, and reviewed claims.

## Gate G4 — hosted release candidate

Clean-session hosted access, identity, Grafana/MCP authentication, cold start, private services, secrets, migrations, fixture reset, licensing/provenance, public read-only flow, failure states, and reproduction instructions all pass. Any unresolved public access, credential, fail-closed, or legal issue is no-go.

## Gate G5 — immutable submission candidate

Timed demo, captioned public video, architecture asset, repository, hosted URL, submission fields, partner eligibility evidence, claims, attribution, and cold dry run pass. Freeze commit/image/config IDs and archive evidence.

## M6 final checks

Submit by the internal target, verify receipt and public assets from a clean session, preserve the judged build, and change only catastrophic failures.

## Test artifact requirements

Each run records seed/fixture digest, commit and image versions, configuration/policy versions, incident ID, trace IDs, oracle result (evaluation-only), calculated result, timings, failures/retries, and evidence artifact digests. Aggregate reports must not obscure individual failures.
