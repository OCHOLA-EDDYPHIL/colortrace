# Security policy

## Supported versions

ColorTrace has no released version yet. Security fixes apply to the current default branch and the immutable judged release once one exists.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, sensitive logs, or personal data. Use GitHub private vulnerability reporting when enabled. Until then, contact the repository owner through a private GitHub channel and include the affected component, impact, reproduction steps, and suggested mitigation. Do not test against systems or data you do not own or have explicit authorization to assess.

## Security boundaries

The hackathon release:

- queries Grafana through a private authenticated read-only `mcp-grafana` stdio subprocess;
- keeps Grafana tokens and cloud credentials in Secret Manager;
- authorizes mutations and approvals with Google Identity Platform/OIDC;
- allows public read-only demo access but never anonymous mutation;
- executes actions only against the deterministic simulator;
- uses immutable, typed action commands bound to an approved plan hash;
- treats logs, traces, MCP results, prompt context, and image metadata as untrusted data;
- records hash-linked audit events and immutable artifact digests;
- fails closed when evidence, identity, correlation, or policy checks are incomplete.

See `docs/security/threat-model.md` for threats and controls.

## Explicitly prohibited

- Public or unauthenticated MCP endpoints
- Grafana write tools in the investigation worker
- Production render-farm, scheduler, or workstation actions
- Secrets in source, logs, images, fixtures, CI output, or issue bodies
- Real production telemetry or proprietary media in the public repository/demo
- Prompt-directed execution of arbitrary commands, queries, or state changes
- Runtime AI providers other than Vertex AI/Gemini or agent frameworks other than Google ADK

## Disclosure handling

Security reports are acknowledged privately, triaged by impact and reachability, fixed with regression tests, and disclosed only after a patch or mitigation exists. The judged build is changed after submission only for a catastrophic security or availability defect, with the change documented.
