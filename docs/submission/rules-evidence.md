# Agentic Cinema rules evidence

Access date: **2026-08-11**

This appendix records the first-party sources and rule interpretations used by the ColorTrace
compliance contract. It is not legal advice and does not replace the binding official rules.

## Sources

| Source | Evidence used |
|---|---|
| [Contest overview](https://agentic-cinema.devpost.com/) | Challenge, partner tracks, public submission summary, displayed prizes, and judging summary |
| [Official rules](https://agentic-cinema.devpost.com/rules) | Eligibility, dates, binding requirements, accepted SDKs, judging, prizes, IP, privacy, and dispute terms |
| [Hackathon resources](https://agentic-cinema.devpost.com/resources) | Google Cloud agent tooling, ADK/Agent Engine recommendation, hosting, safety, and credit information |
| [Grafana track resources](https://agentic-cinema.devpost.com/details/grafana-resources) | Qualifying MCP use, free-tier statement, hosted OAuth, open-source server option, and optional AI Observability |
| [Google Cloud service terms](https://cloud.google.com/terms/services) | Scope of permitted Google Cloud AI services referenced by the rules |
| [OSI Apache-2.0 listing](https://opensource.org/license/apache-2-0) | Commercially usable open-source license confirmation |

## Verified contest facts

- Contest period: 2026-07-27 09:00 PT through 2026-09-07 14:00 PT.
- On the deadline date, Los Angeles observes PDT (UTC-7). The deadline is therefore
  2026-09-07 21:00 UTC and 2026-09-08 00:00 EAT.
- Internal submission target: 2026-09-07 18:00 UTC / 21:00 EAT, preserving three hours.
- ColorTrace's first commit is dated 2026-08-11, within the contest period.
- Teams may contain at most four eligible individuals; an individual entry is permitted.
- The submitted project must run on web, Android, or iOS and must be installable and consistently
  runnable as described.
- A hosted project URL, text description, public code repository, partner-track selection,
  completed form, and public demo video are mandatory.
- The public repository must contain source, assets, instructions, an OSI-approved license, and
  actual runtime calls to Google Cloud and the selected partner service.
- The demo must show the functioning project, be no longer than three minutes for judging, be
  publicly visible on YouTube or Vimeo, and be in English or include English subtitles.
- Written submission material must be in English and the project must support English use.
- Entries can be saved as drafts before the deadline; substantive changes are not allowed after
  the contest period without organizer permission.

## Technology interpretation

- The rules require Gemini and Google Cloud Agent Builder and accept `google-adk`, `google-genai`,
  `google-generativeai`, or `google-cloud-aiplatform` as runtime evidence.
- The resource guide recommends native ADK and Agent Engine. ColorTrace's Vertex AI Gemini plus
  Google ADK boundary is consistent with that route, but G0 must prove a real invocation.
- Only Google Cloud AI tools and built-in AI features of the selected partner are allowed.
  Non-Google AI APIs, models, and agent frameworks are prohibited in the submitted runtime.
- Grafana qualification requires active runtime use of Grafana MCP. The official open-source
  server or hosted Grafana Cloud endpoint is allowed; AI Observability alone is insufficient.
- The open-source MCP server is the documented option for unattended deployments. Its dedicated
  service-account token must remain least privilege and must never enter the repository.

## Evaluation and release implications

Stage one is a pass/fail viability screen for complete submission materials, challenge fit, and
real use of both Google Cloud and the partner product. Stage two equally weights:

1. technological implementation;
2. design;
3. potential impact;
4. quality of the idea.

The hosted build, public repository, video, and form are therefore release requirements rather
than optional presentation polish. Evidence must show a coherent product, not only a technical
spike.

## Rights, privacy, and owner-only checks

- Entrants retain ownership subject to the licenses granted by the rules; submitted source must
  use a commercially usable OSI-approved license.
- The video license granted to Google and partners is perpetual, worldwide, royalty-free, and
  non-exclusive for evaluation and promotion.
- Entrants warrant originality and the rights to all submitted code, data, media, and integrations.
- Registration and winner verification may require identity, address, telephone, tax, banking,
  eligibility, and authorization information. None of that information belongs in this repository.
- Prize acceptance may require a response and completed verification documents within short
  organizer deadlines; the monitored contact channel must remain current after submission.

## Conflicts retained for explicit handling

The official pages contain material copy and prize inconsistencies:

- the rules point to unrelated Devpost domains in the entry instructions;
- the overview describes three prize buckets while showing five partner tracks;
- the overview and official rules disagree on second- and third-place Grafana amounts.

The compliance matrix records conservative handling, an owner, and a no-go date for each. No
unsupported prize or portal claim may appear in submission material.
