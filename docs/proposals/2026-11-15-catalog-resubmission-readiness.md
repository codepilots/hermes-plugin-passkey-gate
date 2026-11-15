# passkey-gate: readiness for resubmitting to the catalog

15 November 2026 · Autumn Thomson (review by Claude)

## Status on 15 November 2026, after the release

Items 1 to 5 are done. v0.10.0 is released at `fa737f7` (tagged and pushed), the catalog entry is re-pinned to it,
and `catalog-entry/PR.md` is rewritten as an update to the entry already in the catalog. Checked against the pin on
Hermes v0.23.1: 493 tests in a fresh clone, `hermes plugins validate --install-deps` with no warnings, a pinned
install identical to the tag, `scripts/e2e_hermes.py` 53 of 53, CI green, and Hermes's
`scripts/validate_plugin_catalog.py` accepts the entry.

Still open:
- **The catalog PR has not been opened.** The entry and PR text are ready in `catalog-entry/`.
- Item 6: no independent adversarial review of the transport code. The PR text says so and cites the static scan.
- Item 7: no live run of a phone deny, the no-answer timeout, the TUI or the Desktop app. The PR text lists these.
- Item 8: only run on Hermes v0.23.1; the PR text says "tested on v0.23.1" with the 0.23.0 source check.
- From the scan: the 13 unconfirmed candidates, unhashed dependencies, and the unpinned install in the e2e script.
- One of about ten full test runs printed a stray "Exception occurred during processing of request" line from a
  local test server while still passing. Not reproduced, cause unknown.

The rest of this document is the review as written before the release, with notes added under items 1, 6 and 8.

## Summary

A whole-project review before resubmitting to the Hermes plugin catalog. The code is in good shape; the catalog
entry and its PR text are out of date, and one validation warning needs dealing with. Nothing was changed in this
pass.

The entry still describes v0.8.1. Since then the plugin gained the approval transport, `passkey_hermes_prompts`,
the bundled skills, `gate_cancel`, argument checking and a structured error contract, in 14 commits that have no
tag. Items 1 to 5 below are what stands between the repository and a resubmission; items 6 to 8 are decisions.

## Where things stand

Checked on 15 November 2026, against `b7f82b7` (pushed to `origin/main`):

| Check | Result |
|---|---|
| `hermes plugins validate plugin` | Passes every check. Security scan `safe`. Declared tools, hooks and middleware match what `register()` does. One warning (item 1) |
| Tests | 481 pass at `b7f82b7`; 493 with the uncommitted item 1 and scan fixes |
| Lint | `ruff check plugin tests scripts` clean |
| CI | GitHub Actions green on `b7f82b7` and the two commits before it |
| Versions | `plugin.yaml` and `pyproject.toml` both 0.9.0; `CHANGELOG.md` has `[0.9.0]` and an `[Unreleased]` section |
| Docs | README and changelog describe the current behaviour |

Hermes on the machine used is v0.23.1.

## Should fix before resubmitting

### 1. The validator warns about a private Hermes import

**Done on 15 November 2026 (not yet committed).** Neither option below was needed: Hermes publishes
`agent.redact:redact_sensitive_text` in its plugin API (`hermes_cli/data/plugin_api.json`), and the private
function is that plus a display pass that escapes hidden characters and collapses padding. `transport.py` now
calls the published function and gives the approve-once cover only to plain printable ASCII commands that
redaction leaves unchanged. `hermes plugins validate plugin` now passes with no private-import warning; 486 tests
pass (5 new); lint is clean. Two behaviour changes, both in the changelog: a command with non-ASCII characters
keeps Hermes's second prompt, and an unanswered request for a command with hidden characters or long padding keeps
Hermes's "User denied" wording. The function exists in Hermes 0.23.0 with the same `force` argument; it was
declared public on 6 November 2026, which is in v0.23.1 (item 8).

The original finding: `hermes plugins validate` reported:

> private core imports (catalog rule 9: public surfaces only; these can break on any release):
> `transport.py:106 agent.redact.redact_approval_display`

The warning doesn't fail validation, but the existing PR text states that validation reports no undocumented-module
warnings, which is no longer true. `transport.py` uses the function in two places (`prompt_text`, to decide whether
Hermes's redaction would change a command, and `reword_silence`).

Options:
- **Drop the import.** Hermes already hands the transport the redacted command in `request.command`, so the cover
  could be matched on that. This changes how the approve-once cover matches commands, so it needs its own tests,
  and the existing limit (two commands that differ only in a redacted secret look identical) must be re-examined.
- **Ask Hermes for a public seam** and keep the import until it exists. The PR would have to explain the warning.

### 2. v0.9.0 was never tagged, and `[Unreleased]` is large

The latest tag is `v0.8.1`. `[Unreleased]` holds `gate_cancel`, the unknown-argument refusal, the error contract
(`error_code` and `next_step` on every refusal), the bundled skills, the reword hook, clearer mint errors, the
status hint for the owner lane, and the failure-path demo script.

Cut a release (0.10.0 is suggested, since it adds a tool), move `[Unreleased]` under it, tag it, then re-pin the
catalog entry to that commit.

### 3. `catalog-entry/passkey-gate.yaml` is stale

| Field | Entry says | Now |
|---|---|---|
| `sha` | `1042d6c` | the new release commit |
| `version` | `0.8.1` | the new release |
| `provides_tools` | 3 tools | add `gate_cancel` |
| `provides_hooks` | `pre_tool_call`, `pre_llm_call`, `post_gateway_admission` | also `post_tool_call`, `pre_approval_request`, `post_approval_response`, `transform_tool_result` |
| Description, disclosure | no mention of the points below | add them |

The description's disclosure must now also say that the plugin:
- posts one message into the conversation, the approval link for a command Hermes flagged (with
  `passkey_hermes_prompts` on), and one line if it can't;
- can change Hermes's approval settings (`security.approval.transport` and `transport_fallback`) during setup, after
  asking;
- rewrites the wording of one blocked tool result, only when a passkey request went unanswered;
- ships two read-only skills, registered where Hermes supports it.

Not checked: how the catalog's CI compares the entry with `plugin.yaml`. A mismatch is a risk.

### 4. `catalog-entry/PR.md` is stale

- Describes v0.8.1 and its review fix.
- "354 tests" (now 481).
- "`gate_verify` waits for at most 120 seconds" (now 300).
- "Hermes surfaces used" lacks `register_approval_transport`, `register_skill`, `ctx.post_message` and the new hooks.
- Says validation reports no undocumented-module warnings (see item 1).
- The Validation section (tests, `plugin validate`, e2e) was run against `1042d6c` on Hermes v0.23.0 and must be re-run
  against the new pin.

### 5. Re-run the end-to-end script against the new pin

`scripts/e2e_hermes.py` goes through Hermes's real plugin manager, tool registry, hook dispatch and approval engine
in a throwaway Hermes home, with a software authenticator in place of the phone. It was not run in this review. It
installs the published plugin from GitHub, so it tests what users get; run it after the release is tagged.

## Decisions

### 6. The approval-transport code has had no independent review

The remediation ledger records this for the v0.9.0 transport. Everything added since is also self-reviewed: the
reword hook (`transform_tool_result`), `gate_cancel`, and the unknown-argument refusal. The last submission relied on
two adversarial reviews.

Either commission a review of `transport.py`, the `pre_approval_request` hook, `gate_cancel` and the reword hook, or
state plainly in the PR that these parts are self-reviewed, with the threat-model section as the account of their
limits. `gate_cancel` only removes authority and needs the exact action text, which keeps its surface small.

**Static scan run on 15 November 2026** (`scan_534a624332b650da303c3d32`, the working tree at `b7f82b7` plus the
item 1 change). It reviewed 22 of 27 files, executed nothing, and reports itself incomplete (tests and docs are
not read by a standard scan). Result: 0 critical or high, 2 medium, 8 low; dependency check clean. This is an
automated static review, not the adversarial human-style review the last submission had; say so in the PR.

| Finding | Severity | Outcome |
|---|---|---|
| Empty `config-canary` read as "never configured" | Medium | Fixed, with tests |
| `scripts/e2e_hermes.py` installs the plugin unpinned from GitHub | Medium | Not changed. It installs the default branch on purpose, to test what users get; `#plugin` is the subdirectory, not a branch. Could take an optional commit to check against |
| Non-list `owner_senders` read as empty | Low | Fixed: every lane is gated, `status` says why |
| Unusable authority pattern skipped silently | Low | Fixed: the hook blocks every gated call, naming the rule, until it is fixed; `status` names it too. This replaces the earlier finding-22 decision to skip |
| Exception text in the hook's block message | Low | Fixed: type only |
| `challenge_id` unencoded in the verify URL | Low | Fixed |
| Notary file read without a size cap | Low | Fixed: 1 MiB cap |
| Catalog entry pins v0.8.1 | Low | Items 2 and 3 of this document |
| CI actions pinned by tag, not commit | Low | Fixed: pinned to commit SHAs (checkout v4.4.0, setup-python v5.6.0). Dependencies are still unhashed |
| Dependency ranges without a lockfile or hashes | Low | Not changed; Hermes installs from the manifest's ranges, so a lockfile would only cover CI |

From the scan's unconfirmed candidates, one was fixed: `consume_approval` no longer treats an unrecognised kind as
a settings approval. The other 13 are not addressed; the ones worth a look are the pin file being read without a
no-follow check, the service unit written without one, and authority patterns running with no per-call time limit.
After these fixes: 493 tests pass, lint clean.

### 7. Some live paths were never exercised in Hermes itself

The ledger lists a deny on the phone, the no-answer timeout, the TUI and the Desktop app as still to run live. The
reworded "the user did NOT deny this" result depends on matching Hermes's exact message text, so a change to that
text upstream would silently turn it off. It has been tested in simulation (`scripts/failure_paths.py`) and in the
unit tests, not through a live timeout.

One live no-answer run on a chat surface would confirm the reworded result reaches the agent. An upstream ask for a
distinct "no answer" result from a transport would remove the dependence on message text.

### 8. The Hermes version floor is only tested at 0.23.1

The manifest says `requires_hermes: ">=0.23.0"`. Everything has been run on v0.23.1. The approval hooks and skill
registration have existed since April 2026, but Hermes's docs carry no per-API version notes, so whether the
transport and `ctx.post_message` are all present in 0.23.0 is unconfirmed. The optional pieces are registered
defensively and degrade without them. Word the PR as "tested on 0.23.1", or test on 0.23.0.

**Checked on 15 November 2026 against the Hermes git history (read, not run).** Every Hermes API the plugin uses is
present at the `v0.23.0` tag (5 November 2026): `register_approval_transport`, `register_skill`,
`ctx.post_message`, the `pre_approval_request` and `post_approval_response` hooks, `transform_tool_result`, and
`agent.redact.redact_sensitive_text`. The one difference is that 0.23.0 has no published plugin-API list, so the
redaction function only became officially public in 0.23.1. The plugin has still only been run on 0.23.1.

## Housekeeping

- `docs/proposals/2026-11-improvement-proposal.md` is untracked.
- The profile's installed copy of the plugin has the local repository path as its source. Reinstall with the GitHub
  command in the README to switch it back.
- Hermes `approvals.mode` is `smart` on this machine, so flagged commands can be approved without reaching the
  passkey. `status` warns about it; `hermes config set approvals.mode manual` closes it. Not a catalog matter.
- Feedback from the earlier catalog review was not available to this review. If it raised points beyond these, add
  them here.

## Suggested order

1. Decide the private import (item 1) and make that change with tests.
2. Cut the release: version, changelog, tag (item 2).
3. Refresh the catalog entry and PR text to the new pin (items 3 and 4).
4. Run the end-to-end script against the pin (item 5), and one live no-answer run if possible (item 7).
5. Settle the review question (item 6) and the wording of the version floor (item 8), then open the PR.
