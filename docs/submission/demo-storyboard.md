# Three-minute demo storyboard

Target: a technically credible, visually legible product narrative, not a slide deck or chat transcript.

## 0:00–0:20 — problem and alert

Show two technically successful outputs that differ visibly. State: “Both renders succeeded, but they look different.” Open the real Grafana alert and ColorTrace incident. Establish the pipeline TD and the need to identify exact affected and safe work.

## 0:20–0:55 — live operational investigation

Launch investigation from the alert. Show trace/log/metric evidence arriving through official Grafana MCP with correlation and timestamps. Reveal identical `config.ocio` digest, then different resolved LUT digests/search resolution. Show a non-causal distractor rejected. Keep tool provenance visible without exposing secrets.

## 0:55–1:30 — deterministic proof and scope

Show real OCIO/manifest and reference-comparison results. Emphasize that Gemini proposes hypotheses but validators confirm facts. Open affected scope: three affected frames, a downstream derivative, and a safe job on the implicated worker. State why worker-wide rerender is wrong.

## 1:30–2:00 — human authority

Open the versioned response plan with exact inclusions/exclusions, plan hash, unresolved items, and simulator-only commands. Demonstrate that editing invalidates approval, then approve the final plan as the authenticated pipeline TD.

## 2:00–2:35 — targeted recovery

Execute quarantine/rerender against the simulator. Show idempotent target outcomes and safe work untouched. New telemetry reaches Grafana. Do not present execution success as recovery proof.

## 2:35–2:55 — verification and closure

Run deterministic comparison on new outputs, show matching resource state and approved reference, then explicitly close as a human. Display the audit timeline.

## 2:55–3:00 — thesis

“ColorTrace uses Grafana as the evidence plane, Gemini as a bounded investigator, deterministic tools as authority, and a human for action and closure.”

## Capture requirements

Record at target judge resolution, large readable text, cursor discipline, stable seeded fixture, fallback capture, no credentials/personal data, English narration and reviewed captions. Demonstrate one concise fail-closed case in the main recording or immediately accessible evidence if timing permits.
