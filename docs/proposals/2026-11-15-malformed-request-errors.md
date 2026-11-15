# passkey-gate: errors on malformed requests

15 November 2026 · Autumn Thomson (test run by Bramble)

## Summary

Bramble sent 18 malformed or mismatched requests to a live gate (v0.9.0, enforcement on) and checked one thing for
each: does the error tell the agent enough to fix its own mistake? Nothing was approved or executed.

Most errors are good. They carry an `error_code` and a concrete `next_step`, and say that "nothing was approved or
executed". **Four gaps leave an agent stuck or misled, and two of them waste the human's signature.** This
proposal fixes those four, plus five smaller wording issues. Each fix is small, local and testable.

| Priority | Finding | Effect |
|---|---|---|
| P1 | F1. A `tool_call` without `args` is accepted | Mints an approval that can never authorise the call. The signature is wasted |
| P1 | F2. A `tool_call` with extra keys is accepted | Same: the binding hash can never match a real call |
| P1 | F3. An unknown `challenge_id` reads as a refusal | The agent believes the human said no and stops |
| P1 | F4. A block doesn't mention a matching request that's still pending | The agent mints duplicates and spams the human with links |
| P2 | F5–F9 | Wording: what's wrong is stated, but not exactly which field or what's expected |

## Method

All calls went through the deferred tool bridge (`tool_call`), as an agent would make them. Test requests were
labelled "Test only, never to be signed" and left to expire. The gated command was `rm -rf` on a scratch path that
doesn't exist.

| # | Request | Response | Can the agent fix it? |
|---|---|---|---|
| 1 | `gate_challenge` without `action_text` | Hermes schema check: missing argument, full schema shown | Yes |
| 2 | `action_text` = "delete stuff" | `invalid_request`: "action_text must be at least 40 characters" | Partly (F5) |
| 3 | `requester_owner` set, no `why` | `why_required`, with exactly what to add; "Nothing was minted" | Yes |
| 4 | `tool_call` as a string | Hermes schema check: "not of type 'object'" | Yes |
| 5 | `tool_call: {"tool": "terminal"}` (no `args`) | **Minted** | No (F1) |
| 6 | `requester` of 80 characters | `invalid_request`: "requester must be 1-64 chars" | Yes |
| 7 | Well-formed control request | Minted | — |
| 8 | `parent_approval` with malformed id/sha | `invalid_request`: "challenge_id/action_sha256 malformed" | Partly (F6) |
| 9 | `tool_call` with an extra key `"extra"` | **Minted**, with binding `a4a2…`, not the `bbbd…` the real call has | No (F2) |
| 10 | Well-formed `parent_approval`, base `https://evil.example.com` (not on the allowlist) | Minted. Only `text_only_note` comes back | Partly (F7) |
| 11 | `gate_verify`, made-up `challenge_id` | `status: denied`, no `denied_reason`; "if this was a genuine refusal, do not mint again" | No (F3) |
| 12 | Right id, edited `action_text` | `denied_reason: action_text_mismatch`; "Nobody refused this… resend character for character" | Yes |
| 13 | Right text, wrong (existing) id | Same `action_text_mismatch` | Partly (F8) |
| 14 | `wait_seconds: 500` (max 120) | `pending`, nothing about the clamp | Partly (F9) |
| 15 | `max_age: -5` | `invalid_max_age`, with an example value | Yes |
| 16 | `gate_status` with `audit_check: "yes please"` | Hermes schema check: not a boolean | Yes |
| 17 | Gated command runs while a matching bound request is **pending** | Blocked: "no approved passkey challenge covers it… Call gate_challenge first" | No (F4) |
| 18 | Same command with `timeout: 30` added | Blocked; the message prints the binding it expected, including `"timeout": 30` | Yes, by comparing it with the minted binding |

## P1 fixes

### F1, F2. Validate the shape of a binding strictly at mint time

`gate_core.py` (around line 629) accepts any dict whose `tool` is a string and whose `args`, *if present*, is a
dict. `tool_call.get("args", {})` lets a missing `args` through. Extra keys pass, and `canonical_binding_json`
hashes them, so the binding can never equal what `canonical_for_hook` derives from a real call. The v0.7 review
item A30 targeted exactly this ("could never match a real call"); these two shapes still get through.

**Change:**
- Require `set(tool_call) == {"tool", "args"}`.
- Require `args` to be a dict. `{}` stays valid for tools that take no arguments; omitting `args` is an error.

**Error:**
`tool_call must have exactly the keys "tool" and "args" (got: tool, extra); pass every argument you will run with
inside args, and {} for a tool that takes none`

Use error code `invalid_tool_call`, with next step "Fix tool_call and mint again; nothing was minted."

**Tests:** both shapes are rejected, and the message names the offending keys. `{"tool": "gate_status", "args": {}}`
still mints and still matches the hook's binding for a call with no arguments.

### F3. Say "no such request" when the gate has no such id

`tools.py:_local_denial_cause` returns `None` when the row doesn't exist, so the agent gets the generic "denied"
text, which reads as the human refusing. Because the HTTP answer stays identical for every denial, ids still
can't be probed remotely. This process can already tell a text mismatch apart, so naming a missing id reveals
nothing new to the local agent.

**Change:** return `"unknown_challenge"` when `row is None`, and set:
- `denied_reason: unknown_challenge`
- next step: "No request with this challenge_id exists on this gate (typo, an id from another gate, or an old
  database). Nobody refused anything. Check the challenge_id returned by gate_challenge; if you no longer have it,
  mint a new request."

**Test:** verifying a well-formed but non-existent id gives `unknown_challenge`. The HTTP `/verify` response is
unchanged, so ids can't be enumerated.

### F4. When blocking, point to a matching request that's still pending

`tools.py` around line 758 looks only for *approved* rows (`pending_for_binding`). It then tells the agent to
"Call gate_challenge first", even when an unsigned request for the identical binding already exists. An agent that
follows the message mints a duplicate and sends the human a second link.

**Change:** before the generic message, look up `status='pending' and binding_sha256=? and expires_at>=now`,
newest first. If one exists, block with:

"Passkey gate: a request covering this exact call is waiting for the human (challenge_id X, expires in N min).
Do not mint again. Make sure the human has the link, wait for their signature (gate_verify with wait_seconds can
poll), then retry this identical call."

**Tests:**
- With a pending matching request, the block names it and doesn't say "Call gate_challenge first".
- With an expired pending request, the generic message comes back.
- The message never reveals pending requests for a *different* binding.

## P2: wording

- **F5:** the length error could add the content rule the schema already states: "…and say what is granted, to
  whom, on which system, and until when".
- **F6:** say which `parent_approval` field is malformed and what format it expects (`challenge_id`: 32 URL-safe
  characters; `action_sha256`: 64 hex).
- **F7:** a `parent_approval.base` that isn't on `parent_gate_allowlist` deserves a mint-time note: "this parent
  gate is not on your allowlist, so the page will show the parent approval as an unverified claim". Today the
  agent learns this only if the human mentions it.
- **F8:** `action_text_mismatch` could add: "…or this is not the challenge_id you minted with that text".
- **F9:** when `wait_seconds` is clamped, add `wait_seconds_clamped_to: 120` to the response.

## Related observation: this DM was gated as `others`

Every block during the run said "Gated lane: others — a chat from someone else, a scheduled job, or an unknown
origin". Yet the session was Autumn's own Discord DM. Most likely `owner_senders` doesn't include her Discord
account (`discord:<user id>`). That's safe, since every lane is gated by default. But a lane-specific policy, for
example gating `others` more strictly, would treat her as a stranger. Either add the account, or have
`hermes passkey-gate status` say when the owner lane is configured but empty.

## Effort and risk

Five small edits in `gate_core.py` and `tools.py`, plus about ten tests: roughly half a day. F1 and F2 tighten
input validation. The only clients that break are ones already minting approvals that can never be used. F3 and F4
change only the wording of the local tool's answers; the HTTP API and the enforcement decision are unchanged.
