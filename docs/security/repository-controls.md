# Repository controls

Status: to be completed after GitHub repository creation.

## Intended controls

- Private until public-readiness audit
- `main` protected by repository ruleset
- Pull request required where plan capabilities permit
- Required checks: formatting, lint, typecheck, unit, contract, secret, license/provenance, and Google-only AI policy
- Conversations resolved and linear history required
- Force pushes and branch deletion blocked
- Squash merge only; head branches deleted after merge
- Administrator bypass limited to documented emergencies
- Issues enabled; Projects, wiki, and discussions disabled initially

## Solo-account constraint

GitHub may not support self-approval or some rules on the current private plan. Unavailable controls must be recorded here after API verification, represented by the pull-request checklist and CI where possible, and enabled when the repository becomes public or the plan supports them.

## Audit log

Populate after configuration with the exact ruleset ID, active settings, unavailable settings and API errors, required check names, and verification date. Do not claim a control is active until API verification succeeds.
