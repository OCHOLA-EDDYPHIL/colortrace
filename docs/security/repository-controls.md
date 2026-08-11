# Repository controls

Status: active controls verified through the GitHub API on 2026-08-11.

## Active repository settings

- Private until the public-readiness audit
- Default branch: `main`
- Issues enabled; Projects, wiki, and discussions disabled
- Squash merge only; merge commits and rebase merge disabled
- Head branches automatically deleted after merge
- Initial CI completed successfully, including repository policy, scaffold, and secret scans

## Active `main` ruleset

Ruleset **Protect main**, ID `20709186`, is active on the default branch:

- pull request required;
- stale reviews dismissed on push;
- review conversations resolved;
- linear history required;
- branch deletion and non-fast-forward updates blocked;
- strict required status checks:
  - `Repository policy`
  - `Scaffold checks`
  - `Secret scan`
- repository administrators may bypass. Bypass is reserved for documented emergencies.

Although the ruleset API reports merge, squash, and rebase as allowed methods within the pull-request rule, repository-level settings disable merge commits and rebase merge, leaving squash as the effective method.

## Current limitations and staged controls

- Required approving review count is zero. A solo repository owner cannot provide an independent approval; the pull-request checklist and required CI provide the current compensating controls. Require at least one independent approval when a collaborator is available or repository policy makes it practical.
- The scaffold has no product packages, so formatting, language lint/typecheck, unit, generated-contract, license/provenance, and runtime AI-policy jobs are not yet separately meaningful. `Repository policy` currently validates the contract scaffold, sensitive/private path policy, workspace license, and pre-G0 implementation prohibition. Add stable required jobs when M1 bootstraps each toolchain.
- GitHub's dependency-review action is unavailable for this private repository without GitHub Advanced Security; the first pull-request run failed with “Dependency review is not supported on this repository.” The workflow was removed rather than left as a permanently failing control. Restore and require it when the repository becomes public or the feature is enabled; until then, lockfile, SBOM, and license/provenance checks must provide the dependency gate as M1 adds dependencies.
- GitHub Actions are version-tag pinned (`@v4`, `@v5`, `@v2`) rather than immutable commit-SHA pinned. Resolve this in the M1 public-ready CI bootstrap before public release.
- Branch rules cannot prevent opening M1 issues, so the roadmap uses explicit dependency links and issue text: M1 work is blocked until Gate G0 records `proceed`.

Do not claim an unavailable or staged control is active. Re-audit this file at G0, the first pull request, feature freeze, and public-readiness review.
