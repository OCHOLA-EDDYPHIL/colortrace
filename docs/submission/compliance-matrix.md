# Hackathon compliance matrix

Status: public rules audited on 2026-08-11. Authenticated submission-field capture and
private entrant eligibility confirmation remain Gate G0 blockers.

The target contest is **Agentic Cinema: The Blockbuster Hackathon**, entering the
**Grafana partner track**. The [official rules](https://agentic-cinema.devpost.com/rules)
are the binding source; the [contest overview](https://agentic-cinema.devpost.com/) and
[Grafana resources](https://agentic-cinema.devpost.com/details/grafana-resources)
supplement them. See the [rules evidence](rules-evidence.md) for the dated review and known
conflicts.

## Submission baseline

| Requirement | First-party source, accessed 2026-08-11 | Project evidence | Gate state |
|---|---|---|---|
| New original project created during the contest period | [Rules §7](https://agentic-cinema.devpost.com/rules) | Earliest repository commit is 2026-08-11, after the 2026-07-27 start | verified |
| Functional agent using Gemini and Google Cloud Agent Builder | [Rules §7](https://agentic-cinema.devpost.com/rules) and [resources](https://agentic-cinema.devpost.com/resources) | Vertex AI Gemini plus Google ADK/Agent Engine invocation records | planned; prove at G0 |
| Google-only runtime AI and agent tooling | [Rules §7B](https://agentic-cinema.devpost.com/rules) | Dependency, endpoint, configuration, container, SBOM, and IaC policy scans | locked boundary; implementation pending |
| Grafana partner integration | [Rules §7B](https://agentic-cinema.devpost.com/rules) and [Grafana resources](https://agentic-cinema.devpost.com/details/grafana-resources) | Active runtime calls to official `grafana/mcp-grafana` or the hosted Grafana Cloud MCP endpoint | planned; G0 hard gate |
| Grafana is operationally necessary | [Grafana resources](https://agentic-cinema.devpost.com/details/grafana-resources) | Decisive facts come through MCP; no-Grafana counterfactual cannot diagnose | planned; G0 hard gate |
| Supported platform | [Rules §7B](https://agentic-cinema.devpost.com/rules) | Hosted web application | planned |
| Hosted project URL | [Rules §7B](https://agentic-cinema.devpost.com/rules) | Clean-session hosted deployment evidence | required before submission |
| Public source repository | [Rules §7B](https://agentic-cinema.devpost.com/rules) | Public GitHub repository containing all source, assets, and reproduction instructions | required before submission |
| Commercially usable OSI license | [Rules §12](https://agentic-cinema.devpost.com/rules) and [OSI Apache-2.0](https://opensource.org/license/apache-2-0) | Apache-2.0 plus dependency and asset compatibility report | repository license present; audit pending |
| Text description | [Rules §7B](https://agentic-cinema.devpost.com/rules) | Features, functionality, technologies, data sources, findings, and learnings | required before submission |
| Public demo video | [Rules §7B](https://agentic-cinema.devpost.com/rules) | YouTube or Vimeo, no longer than three minutes, English or English-subtitled | required before submission |
| Partner selection | [Contest overview](https://agentic-cinema.devpost.com/) and [Rules §7A](https://agentic-cinema.devpost.com/rules) | Grafana track selected in the authenticated submission form | owner action pending |
| Completed Devpost form | [Rules §§6–7](https://agentic-cinema.devpost.com/rules) | Exact authenticated fields recorded and completed | owner capture pending; blocks G0 |
| Submission deadline | [Rules §§5 and 7](https://agentic-cinema.devpost.com/rules) | Internal target 2026-09-07 18:00 UTC / 21:00 EAT | verified three-hour buffer |
| Entrant eligibility | [Rules §4](https://agentic-cinema.devpost.com/rules) | Private owner confirmation against the official-rule checklist | owner confirmation pending; blocks G0 |
| Third-party rights | [Rules §§7, 12, and 15](https://agentic-cinema.devpost.com/rules) | Provenance ledger, compatible licenses, permissions, and original demo assets | planned |
| Judging readiness | [Rules §8](https://agentic-cinema.devpost.com/rules) | Viability pass plus implementation, design, impact, and idea evidence | planned |

## Runtime exclusion policy

Submitted runtime code, containers, infrastructure, environment templates, and dependencies
must contain no non-Google AI model, AI API, or agent framework. The official rules name AWS,
Microsoft, OpenAI, and Anthropic as prohibited examples. Non-AI third-party services and
standard frameworks remain allowed when their licenses and terms permit use.

Developer tooling that is not shipped must not be represented as submitted runtime and must
not leak generated private material into the repository or submission.

## Grafana track contract

- Grafana must be actively used at runtime through its MCP integration; a README mention or
  AI Observability instrumentation alone does not qualify.
- The official open-source `grafana/mcp-grafana` server with a service-account token is allowed
  for unattended server-side use. The hosted MCP endpoint instead uses interactive OAuth.
- Metrics, logs, traces, dashboards, alerts, and incidents may be queried through MCP. ColorTrace
  keeps the accepted read-only, least-privilege boundary and does not need write tools to qualify.
- Grafana AI Observability is optional supporting evidence, not the partner integration itself.

## Entrant-only confirmations

The owner must confirm privately, without publishing sensitive details, that all of these are
true before issue #1 can close:

- age-of-majority and residence requirements are satisfied;
- no sanctions, denied-party, government-employment, contest-entity employment, household,
  immediate-family, or other conflict exclusion applies;
- employer, client, university, or other third-party policies permit entry and receipt of a prize;
- the owner controls the Devpost email account and can provide verification if selected;
- all submitted work, data, media, trademarks, and third-party integrations have the required
  rights and permissions;
- the owner accepts the binding rules, privacy terms, publicity terms, and arbitration terms.

Record only the fact and date of private confirmation in the issue. Do not record the underlying
identity, residence, employment, sanctions, tax, or contact information in the repository.

## Open organizer inconsistencies

| Conflict | Conservative handling | Owner and no-go date |
|---|---|---|
| Rules section 6 names `rapid-agent.devpost.com` and `aiinaction.devpost.com`, while every live contest page is under `agentic-cinema.devpost.com` | Use the live Agentic Cinema portal; authenticated portal mismatch blocks submission | Owner verifies by 2026-08-17 18:00 UTC |
| Overview says three identical prize buckets but displays five partner tracks | Do not repeat the bucket-count claim | Owner; remove claim unless corrected by 2026-08-31 18:00 UTC |
| Overview lists Grafana prizes as $7,500 / $4,500 / $3,000; official rules list $7,500 / $3,000 / $2,000 | Treat official-rule values as controlling for risk planning and make no public prize-value claim | Owner; seek clarification by 2026-08-31 18:00 UTC if prize value affects entry |
| Public pages do not expose the authenticated form's exact fields | Do not infer or prefill them | Owner captures fields by 2026-08-17 18:00 UTC; unresolved state blocks G0 |

## Claims policy

Only claim what repository artifacts demonstrate. Do not claim universal color correctness,
industry prevalence, specific savings, production safety, buyer demand, prize value, or release
readiness without evidence. State that actions are simulator-only and the incident fixture is
synthetic.
