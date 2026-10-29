# Development and verification workflow

Keep a stack in draft while developing it. Mark its top ready when the combined
change can land. Prepare a Stable or Preview release when there is something to
ship. CI follows those decisions; it has no weekly or monthly schedule.

## Workflows and checks

| Workflow | Trigger | Work |
|---|---|---|
| Verify pull request | PR opened, updated, reopened, marked ready, or converted to draft; also manual | Inexpensive checks on draft standalone PRs and draft stack tops. Ready candidates also run the full merge gate. |
| Verify release candidate | Manual | Debug and Release builds for the selected Stable or Preview product, with optional migration-scale qualification and CodeQL. |
| Verify CodeQL | Manual, or called by release qualification | Swift security analysis on the Intel runner. |

A workflow contains jobs; GitHub shows each job as a check. Formatting, lint,
script fixtures, and dependency checks are steps within **Verify repository
checks**. **Verify workflows** and **Verify secrets** remain separate jobs.
The four Swift test groups run in parallel and feed the required **Verify Swift
tests** result. **Verify products (Stable Release)** builds the unsigned app,
checks bundle identities and helper isolation, and exercises its bundled CLIs.

The five required check names and their GitHub Actions provider are recorded in
[the main ruleset](../.github/main-ruleset.json). Main requires PRs, blocks force
pushes and deletion, and permits squash merges. No external reviewer approval
is mandatory. The maintainer's exception permission applies through PRs only.

## Develop a draft stack

Run relevant local tests while editing. Push draft standalone PRs or update the
top of a registered stack to get formatting, correctness lint, dependency review,
script checks, workflow audits, and secret scanning. Intermediate stack layers
skip repeated CI. These inexpensive checks do not compile the Swift test suite
or build the app.

Keep the top draft until the combined change is ready for full verification.
If a ready candidate needs more development, convert it back to draft. That
cancels its superseded PR run and returns it to the inexpensive checks.

## Verify and merge a candidate

Mark a standalone PR or the stack top ready. CI runs all four Swift groups and
the Stable Release product check alongside the inexpensive checks. New pushes
to a ready candidate require another pass; an older green result does not
verify changed source.

Keep intermediate stack PRs draft while the ready top is tested. Once the top
passes, mark the remaining layers ready and merge the complete stack with the
native stack tools:

```sh
gh stack merge --yes --squash
```

GitHub applies main's protections to every layer. Skipped intermediate checks
allow the complete verified stack to merge; they do not certify an intermediate
result. Before merging part of a stack, make the selected result its top with
the native stack tools and verify it. GitHub supports a protection exception
only for the bottom PR, not for merging a whole stack.

A small Stable fix follows the same PR merge gate and can go straight to a
Stable release without a Preview release. There is no automatic post-merge run.

To request the full candidate checks without changing draft status:

```sh
gh workflow run verify.yml --ref <candidate-branch>
```

The PR dependency-advisory comparison runs on PR events, where the stack's trunk
and head are known. A manual run still checks dependency declarations and pins;
it does not replace that PR comparison. Manual workflow buttons become available
after their definitions reach the default branch.

## Choose additional qualification

Use **Verify release candidate** when the change or release needs the additional
coverage. Select Stable or Preview; it builds and checks that product in both
Debug and Release. This is useful for Preview work, configuration changes, or
release preparation. It does not repeat the full Swift suite.

Include the 300-entry migration qualification when migration, recovery, or
storage behavior changes. Include CodeQL before a Stable release containing
production changes, or when security-sensitive work needs analysis during
development. For example:

```sh
gh workflow run verify-qualification.yml --ref <candidate-branch> \
  -f product=preview -F migration_scale=true -F codeql=true
```

To request only CodeQL:

```sh
gh workflow run verify-codeql.yml --ref <candidate-branch>
```

Review findings, failures, extraction diagnostics, and the source revision
reported by the run. An optional job skipped because it was not selected is not
a passing qualification. CodeQL uses the same pinned extraction steps whether
run independently or through qualification.

These CI product checks are unsigned. Installed-app behavior, signing,
notarization, Gatekeeper, Secure Enclave/user-presence behavior, and real recovery
hardware still need the relevant local qualification. Follow the
[release runbook](release.md) for the distributable artifact.

## Prepare and publish a release

Put the version bump in the candidate before final PR verification. It can be
part of the small fix PR or a final layer on the feature stack. If the change
has already landed, prepare a separate version PR. Merge through the usual gate,
then build and publish from clean main matching the remote version commit.

Stable and Preview are selected by the release tag. Stable tags use `vX.Y.Z`;
Preview tags use numbered `alpha`, `beta`, or `rc` suffixes. The
[release runbook](release.md#operator-runbook) contains the commands and artifact
checks. Publication and the Homebrew update are explicit operator actions.

## Leave the project dormant

There are no scheduled build, test, qualification, or CodeQL runs. Dependabot
alerts continue monitoring the dependency graph independently. Both security
update PRs and version update PRs remain disabled. Existing Action pins are
checked for known advisories when workflow audits next run; no background
workflow audit is scheduled.

Before resuming work or shipping after a long pause, inspect the dependency
alerts and run the candidate checks. Request CodeQL and the applicable release
qualification as part of preparing that release.
