# Practitioner validation guide

## Objective

Test whether the problem, workflow, authority model, and value are credible to VFX pipeline and color practitioners. Do not sell the concept or claim prevalence from a convenience sample.

## Target participants

Prioritize pipeline TDs/engineers, render-farm or production technology operators, color pipeline/OCIO owners, finishing/QC practitioners, and technical supervisors who have diagnosed cross-machine visual inconsistencies. Record role category and environment scale only with consent; keep identities and private details outside the repository.

## Opening

Explain that this is product discovery, ask permission to take anonymized notes, avoid requesting proprietary media/configs/logs, and ask about the most recent real incident before presenting ColorTrace.

## Questions

1. Tell me about the last case where renders succeeded but looked inconsistent across machines or stages.
2. How was it detected, and by whom?
3. What evidence did you gather first? Which systems held it?
4. How did you distinguish configuration, external resources, context/environment, source media, and creative intent?
5. How often are external LUTs or color resources resolved outside the main config? How are they versioned?
6. What makes scope calculation difficult—shots, frames, transforms, derivatives, caches, or handoffs?
7. What work was rerun or manually inspected? How did you decide what was safe?
8. What is the consequence in time, deadline risk, compute, or trust? Use ranges and avoid confidential amounts.
9. What would make an automated diagnosis untrustworthy?
10. Which evidence must be deterministic, and where is human judgment mandatory?
11. Who could approve quarantine or rerender? What audit record is required?
12. Where do Grafana or other observability tools fit today? If absent, what system is the evidence plane?
13. Would a focused workspace add value beyond current OCIO tools/render manager/Grafana? Why or why not?
14. Which incident would be a stronger first case than a shadowed external LUT?
15. What would you need to see in a three-minute demonstration to believe this is real?
16. Who owns budget and adoption, and what integration/security blocker would stop a pilot?

## Concept test after discovery

Present the same-config/shadowed-LUT scenario neutrally. Ask the participant to identify unrealistic assumptions, missing evidence, wrong role boundaries, unacceptable automation, and the minimum credible fixture. Do not ask “Would you use it?” without requesting a concrete next action or comparison to current behavior.

## Pass/fail signals

Proceed evidence includes repeated unaided recognition of the problem, concrete current-workflow pain, agreement that exact scope/safe work matters, credible Grafana/evidence fit, and willingness to review a fixture or pilot. Pivot/stop evidence includes the mechanism being implausible, existing tools making the workflow trivial, no meaningful consequence, a different primary user/authority, or required production integrations exceeding the deadline.

## Synthesis

Separate verbatim/anonymized facts from researcher inference. Report sample bias, negative cases, unresolved questions, and claim changes. Never put participant identities, private transcripts, employer-confidential data, or unsupported market statistics in the public repository.
