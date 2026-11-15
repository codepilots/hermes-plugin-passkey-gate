---
name: malformed-request-test
description: Probe gate errors with malformed requests and grade them.
version: 0.4.0
author: Autumn Thomson (codepilots), Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [passkey-gate, errors, testing, agent-ux]
    related_skills: [approval-layers-test]
---

# Malformed request test

This skill sends a fixed set of malformed or mismatched requests to `gate_challenge`, `gate_verify`, `gate_status`
and the enforcement hook. For each one it checks two things: **did the gate answer as documented below**, and
**would that answer let an agent fix its own mistake without help?** Nothing is ever approved or executed. The
only command the run attempts is an `rm -rf` on a scratch path that doesn't exist.

The expected answers below describe the gate after the fixes for
`docs/proposals/2026-11-15-malformed-request-errors.md` (findings F1 to F9). A run against that build should grade
every case Yes.

## When to Use
- After changing validation, error text or `next_step` wording in `tools.py`, `gate_core.py` or `schemas.py`.
- To retest after fixes: confirm each finding of an earlier run is closed.
- Before a release, to check that agent-facing errors haven't got worse.
- When the human asks how well the gate copes with bad input.
- Don't use for: testing whether a signed approval works (use `approval-layers-test`), or for fuzzing that could
  flood the human with links.

## Prerequisites
- `gate_status` reports the gate reachable with an owner key pinned.
- `require_passkey` is on, and `authority_patterns` include `rm -rf`. If they don't, skip cases 17 and 18 and say
  so.
- Read the live tool schemas first with `tool_describe` (`gate_challenge`, `gate_verify`, `gate_status`). Use the
  limits stated *there* (field lengths, `wait_seconds` maximum) in your expectations, not numbers from memory.
- **Check which build you are talking to before you start.** The plugin version number does not change between
  builds, so use behaviour. The fixed build shows all of these:
  - the `gate_verify` schema says `wait_seconds` has a maximum of 300;
  - the `gate_challenge` schema's `tool_call` description says "never a JSON-encoded string".

  - a `gate_cancel` tool exists.

  If any is missing, your session still has the old tools. Tools reload only in a new session, after the plugin
  is reinstalled. Say so and stop; a run against the old build only repeats the earlier findings.

## Safety rules
1. **Never send a test request's URL to the human, and never ask them to sign one.** Start every test
   `action_text` with "Test only, never to be signed:" so a link that leaks is obviously harmless.
2. **Withdraw every test request you mint.** Keep a list of each `challenge_id` with the exact `action_text` it
   was minted with. When the cases are done, call `gate_cancel` for every one still open. Tell the human at the
   start that unsigned test requests will exist during the run, and at the end that all were withdrawn (or which
   were not, and when they expire).
3. Don't run the gated command any other way after a block. A block is the result being measured.
4. Make one call per case and don't loop retries. Each minted request is an audit record, and the gate allows
   only 10 open requests per requester. This run opens 5. If a mint answers `challenge_limit`, an earlier run
   left requests behind: the answer lists them under `open_requests`. Withdraw them with `gate_cancel` (they
   were minted with TEXT or TEXT2, which is why those texts are fixed), then carry on. Don't wait them out.

## Procedure
Use one fixed, valid `action_text` (call it TEXT), for example: "Test only, never to be signed: allow <agent> to
list the scratch directory on <host> once, within ten minutes." TEXT2 is TEXT with " (second request)" added.
Send every call through the same bridge a normal
agent uses, passing `calls` as a real array and `tool_call` as an object. Record the raw response for each case.

Every refusal from the gate has the same shape: `ok: false`, an `error`, an `error_code` and a `next_step`. A case
whose refusal lacks any of the three is a finding, whatever the table says.

**gate_challenge**

| # | Send | Expected answer |
|---|---|---|
| 1 | no `action_text` | Hermes's schema check rejects it and names the missing argument |
| 2 | `action_text: "delete stuff"` | `invalid_request`: at least 40 characters, "and say what is granted or changed, to whom, on which system, and until when" |
| 3 | `requester_owner` set, no `why` | `why_required`; the next step says what to add and "Nothing was minted". It must not call the owner a stranger |
| 4 | `tool_call` as a string | Hermes's schema check: not an object. (If it reaches the gate: `invalid_tool_call`) |
| 5 | `tool_call: {"tool": "terminal"}` (no `args`) | `invalid_tool_call`: exactly the keys "tool" and "args", "got keys: tool"; "nothing was minted" |
| 6 | `requester` over the schema maximum | `invalid_request`: "requester must be 1-64 chars" |
| 7 | TEXT, `tool_call: {"tool": "terminal", "args": {"command": "ls <scratch dir>"}}` (control) | minted, with no `text_only_note`. Record its `challenge_id` and `binding_sha256` |
| 8 | `parent_approval` with a `challenge_id` that isn't 32 URL-safe characters | `invalid_request` naming `parent_approval.challenge_id` and its format. (With a valid id and a bad `action_sha256`, it names that field and "64 hex") |
| 9 | `tool_call` as in 7, plus an extra key `"extra": true` | `invalid_tool_call`: "got keys: args, extra, tool"; nothing minted |
| 10 | TEXT2, well-formed `parent_approval` (with an `owner`) whose `base` isn't on `parent_gate_allowlist` | minted, with a `parent_note` saying the page will show the parent approval as an unverified claim. Record its `challenge_id` |
| 19 | TEXT, no `tool_call` | minted, with a `text_only_note` saying it authorises no tool call |
| 20 | `tool_call: {"tool": "gate_status", "args": {}}` | minted: an empty `args` is a valid binding for a tool that takes no arguments |
| 21 | `tool_call: {"tool": "terminal", "args": "ls"}` | `invalid_tool_call`: `args` must be an object; nothing minted |
| 24 | TEXT, and the binding from case 7 under the misspelled name `tool_cal` | `unknown_arguments`: "tool_cal (did you mean tool_call?)", the list of arguments the tool takes, and "nothing was minted". It must not mint a text-only request |

**gate_verify**

| # | Send | Expected answer |
|---|---|---|
| 11 | a well-formed id that doesn't exist (32 URL-safe characters), TEXT | `status: denied`, `denied_reason: unknown_challenge`, "Nobody refused anything" |
| 12 | case 7's id, TEXT with one word changed | `denied_reason: action_text_mismatch`; "Nobody refused this", resend exactly, do not mint again |
| 13 | case 10's id with TEXT (the right text for case 7, the wrong id) | `action_text_mismatch`, whose next step also says this may not be the `challenge_id` minted with that text |
| 14 | the made-up id from case 11, `wait_seconds` above the schema maximum | answers at once, with `wait_seconds_clamped_to` set to the maximum. Use the made-up id: against a real pending request this call would wait the full five minutes |
| 15 | case 7's id, TEXT, `max_age: -5` | `invalid_max_age`, with a valid example |
| 22 | case 7's id, TEXT, no other arguments | `status: pending`; the next step says to wait and verify again |
| 25 | case 7's id, TEXT, plus an argument the tool doesn't take, `wait: 5` | `unknown_arguments`: "wait (did you mean wait_seconds?)"; nothing was verified |
| 23 | case 7's id, TEXT, `wait_seconds: "soon"` | `invalid_wait_seconds`, or Hermes's schema check: not an integer |

**gate_cancel** (run these after cases 1 to 25)

| # | Send | Expected answer |
|---|---|---|
| 26 | case 19's id, TEXT with one word changed | `action_text_mismatch`; "Nothing was withdrawn" |
| 27 | the made-up id from case 11, TEXT | `unknown_challenge`; nothing was withdrawn |
| 28 | case 19's id, TEXT | `withdrawn: true`, with a note that it can no longer be signed or used |
| 29 | case 19's id, TEXT, again | `not_open`: already withdrawn, nothing to do |
| 30 | `gate_verify` on case 19's id, TEXT | `status: denied`, `denied_reason: refused`; the next step says it was refused or withdrawn |

Then withdraw the rest (cases 7, 10, 17 and 20) with `gate_cancel`, each with its own text. Every one should
answer `withdrawn: true`.

**gate_status**

| # | Send | Expected answer |
|---|---|---|
| 16 | `audit_check: "yes please"` | Hermes's schema check: must be a boolean |

**Enforcement hook** (P = the absolute scratch path `$TMPDIR/malformed-test`, expanded, which must not exist)

| # | Do | Expected answer |
|---|---|---|
| 17 | mint a bound request for `rm -rf P` (don't sign it), then run `rm -rf P` | blocked: "a request covering this exact call is already waiting for the human", with that `challenge_id` and its remaining time, and "Do not mint again". It must not say "Call gate_challenge first" |
| 18 | run `rm -rf P` with an extra `timeout` argument | blocked with the ordinary message, which prints the full binding it expected, including the `timeout`. It must not mention case 17's request: that one covers a different call |

**Grade** every case:
- **Yes:** the gate answered as expected, and the error alone is enough to correct the request.
- **Partly:** the error says what's wrong but not exactly which field, or what's expected.
- **No:** the error is silent (the request is accepted but can never be used), misleading (it reads as a
  refusal) or pushes the agent towards a harmful step (minting duplicates).

Any case that grades below Yes, or whose answer differs from the table, is a finding. Quote the raw response.

The run is done when all 30 cases have a raw response and a grade, and every test request is withdrawn.

## Reporting
1. Give the human a table: case, response (shortened), grade, and the reason for any grade below Yes.
2. When retesting, add one line per earlier finding, marked fixed, unchanged or new. The cases that prove each
   finding of the 15 November proposal:

   | Finding | Proved by case |
   |---|---|
   | F1 binding without `args` | 5 |
   | F2 binding with extra keys | 9 |
   | F3 unknown id read as a refusal | 11 |
   | F4 block ignores a pending request | 17 |
   | F5 length error says nothing about content | 2 |
   | F6 malformed parent approval, field not named | 8 |
   | F7 unlisted parent gate, no note | 10 |
   | F8 mismatch doesn't suggest a wrong id | 13 |
   | F9 clamped wait not reported | 14 |

3. Rank any No and Partly cases. P1 means the human's signature is wasted, or the agent is misled into stopping or
   spamming. P2 means unclear wording.
4. If asked to write it up, add `docs/proposals/<date>-malformed-request-errors.md` to the repo. For each P1
   finding include the code location, the proposed change, the new error text and the tests that should prove it.

## Pitfalls
- **Some cases never reach the gate.** Hermes's own schema check rejects cases 1, 4 and 16, and perhaps 23, before
  the plugin sees them. Grade them anyway: the agent experiences the bridge and the gate as one.
- **Case 9's extra key goes inside the binding**, next to `tool` and `args`. An extra key at the top level of the
  call is a different mistake, which cases 24 and 25 cover: the gate refuses any argument a tool doesn't take.
- **A mis-quoted `calls` string fails in the bridge, not the gate.** `tool_call 'calls' is not valid JSON` comes
  from Hermes. Pass `calls` as an array, and prefer single quotes inside a bound command.
- **Don't trust remembered limits.** In one run the remembered `wait_seconds` maximum was 120, but the code allows
  300. Take limits from `tool_describe` and quote `tools.py` if they disagree.
- **Two paths can't be reached without a signature**, so this skill leaves them to the repo's own checks
  (`scripts/failure_paths.py` shows both): verifying a signed text-only approval against a tool call ("approval has
  no bound tool call"), and a request the human denied (`denied_reason: refused`).
- **An unanswered Hermes prompt is not a denial.** If `passkey_hermes_prompts` is on and one of your commands gets
  a passkey link that nobody answers, the blocked result should read "The user did NOT deny this: no passkey
  approval arrived in time". If it reads "User denied this command", report it.
- **The pattern matches text in your own commands too.** The default pattern catches `dd `, which also matches the
  `add ` in `git add` or in a `sed` script you use to edit a report. If that happens, edit with the file tools only
  if the human agrees, and record it as a false-positive finding.
- **Lane label:** note the lane each block reports. If the human's own DM shows up as `others`, their account is
  probably missing from `owner_senders`. Report it; don't change it. `hermes passkey-gate status` mentions it only
  when the `owner` and `others` lanes are gated differently.

## Verification
- 30 cases recorded, each with a raw response and a grade.
- Every test request minted in the run was withdrawn with `gate_cancel`; none is left open.
- Each earlier finding is marked fixed, unchanged or new.
- No test link was sent to the human, and nothing was signed or executed.
- The human was told the test requests existed and were withdrawn.
- Every finding has a code pointer, checked by reading the source.
