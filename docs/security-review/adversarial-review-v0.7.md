# Adversarial security review — passkey-gate v0.7.1 + unreleased changes

- **Reviewed:** the working tree on 8 November 2026: tag `v0.7.1`
  (`e82f224`) plus the uncommitted v0.7.2 candidate (setup wizard
  "existing passkey" path, config canary, approval-page and docs changes).
- **Method:** four independent adversarial reviewers, each with one attack
  surface and the threat model and remediation ledger as context: (1) crypto
  and approval semantics, (2) the HTTP/web surface, (3) the v0.7 machinery
  (setup, service, codes, exposure, outbound fetches), (4) the agent's point
  of view. Each wrote and ran its own probes against throwaway gates. Every
  finding rated MEDIUM or above, and most LOW ones, was then **re-verified
  independently** by the primary reviewer with separate probes or a code
  trace, and the canary fail-open (M3) was reproduced inside a real Hermes
  v0.23 install. Probe scripts were kept outside the repository.
- **Suite at review time:** 217 passed.
- **Status:** this document records the findings as found. Fixes are
  tracked in the [remediation ledger](remediation.md) as items A1–A30
  (H1, M1, M3, M4, M5 and L1 fixed in v0.7.2; M2 mitigated; M8 documented).

## Summary

**The core holds.** No reviewer found a way to get `verified: true`, a hook
"allow", or a settings change applied without a genuine signature from the
pinned owner key. Signature checks, nonce binding, single-use consumption
under concurrency, expiry, and HTML escaping all held up under attack.

**The weaknesses are around the core:**

- **One HIGH:** the setup wizard can pin an attacker's key if a local
  program is squatting on the gate's old port (H1). This contradicts the
  threat model, which says such an impostor "cannot cause a pin".
- **A fail-open:** a corrupted config-canary file makes the enforcement hook
  throw, and Hermes treats a throwing hook as "allow" (M3). This was
  introduced by the canary change in the same session as this review.
- **Misleading the human:** an approval shown as a harmless command can be
  spent on turning enforcement off (M1), and the settings-change phrase
  hides what is being removed (M5).
- **Enforcement patterns are a weak deny-list**, and the setup default is
  trivially evaded (M2). The docs present it as protection.
- **Replay of settings approvals** through a `GATE_DATA` override (M4).
- **Availability:** anonymous requests can flood the audit log (M6), lock
  the human out of the approval page (L3), or fill the connection slots (L4).

| Severity | Count |
|---|---|
| HIGH | 1 |
| MEDIUM | 8 |
| LOW | 16 |
| INFO | 5 groups |

"Proven" means a probe demonstrated it; "reasoned" means a code trace, not
run. "Verified" marks findings the primary reviewer reproduced independently.

## HIGH

### H1 — Setup pins a port-squatter's key (A1)

*Proven by reviewer 3; chain verified by code trace.* `setup_wizard.py`
`_other_on_port`, `step_address`/`_probe`; `cli.py` `cmd_set`.

**Attacker:** any local process that can bind a loopback port, including
another OS user's. No access to the gate's data is needed.

1. The gate's HTTPS address already forwards to `127.0.0.1:A` (an existing
   `tailscale serve` rule or a reverse proxy), and the gate is down.
2. The attacker binds port A.
3. The operator runs `setup`. It reports that port A is used by another
   program and, on the default answer, moves the gate to A+1 with `set port`.
   The HTTPS address is not moved, so it still forwards to the attacker.
4. `step_address` accepts any HTTP 200 from `{origin}/health` and reports
   "Reachable". It never checks that the answer comes from this gate.
5. The registration link (with the one-time token in its fragment) is opened
   on the attacker's page. Its script passes the token to the real gate on
   A+1 and registers the attacker's own key. Registration with a software
   authenticator and a self-filled `clientDataJSON` origin is accepted, as
   it is by design for any holder of the token.
6. The attacker's page shows the phone that key's confirmation code. The
   operator types it, and `step_confirm` pins it, because the credential
   really is in the gate's database. Later approval pages pass through the
   attacker too.

The confirmation code protects against a rogue registration racing the
operator's, but it is displayed by whoever serves the gate's address, so it
gives no protection against whoever controls that page.

**Fix:** check the gate's identity at the address before minting a link
(`/health` must report `service: passkey-gate` and this gate's instance id,
plus a nonce challenge, since the instance id can be computed); when the port
moves while an address is set, re-run `expose` or refuse to continue; and
correct the threat model.

## MEDIUM

### M1 — A tool-call approval is accepted as a settings-weakening approval (A2)

*Proven by reviewer 1; verified by code trace.* `cli.py`
`_verify_weakening_approval`; `gate_core.py` `consume_approval`.

`consume_approval`'s docstring says it claims a "text-bound" challenge, but
neither it nor the verification before it checks that the challenge has no
bound tool call. An agent mints a challenge whose `action_text` is the exact
settings phrase (for example `weakening_phrase("require_passkey", False)`)
and whose `tool_call` is harmless (`read_file README.md`). The approval page
leads with "THE EXACT COMMAND YOU ARE APPROVING" and tells the human the
command, not the prose, is what executes. The human approves a file read; the
agent runs `set require_passkey false --approve <id>`, and enforcement is off.

**Fix:** settings approvals must be text-only and marked as settings
approvals by the gate itself (a server-set `kind` column, not the
agent-chosen requester name), with their own page banner.

### M2 — Enforcement patterns are a trivially evaded deny-list (A3)

*Proven by reviewers 1 and 4; verified.* `setup_wizard.py` `DEFAULT_PATTERN`;
`tools.py` `hook_verdict`; README "Enforcement"; block message.

With the default pattern `^terminal .*(rm -rf|curl |scp |dd )`, only the
literal spellings are blocked. `rm -fr`, `rm -r -f`, a double space,
`find -delete`, `wget …|sh`, `curl` followed by a tab, and any other tool
(`execute_code` with `shutil.rmtree`, file-write tools) are all allowed.
Patterns run over JSON-escaped text, so ordinary regex intuition fails: a
newline becomes `\n`, which defeats `\b`; quotes become `\"`; non-ASCII is
escaped; `^rm` never matches because the subject starts with the tool name.
Such patterns still pass validation. The block message tells the model to
retry the identical call, but not that reaching the same effect another way
is a violation, so even a non-malicious agent tends to route around it.

The original review named pattern evasion (finding 10), but no user-facing
document says the patterns can be routed around, and the README quick start
says enforcement "blocks risky terminal commands".

**Fix:** state the limit plainly in the README and threat model; make the
default gate whole tools (`^(terminal|execute_code|write_file|patch) `)
rather than command substrings; consider an allowlist mode; match against
decoded argument values; warn at `set` time about patterns that can't match;
tell the model that equivalent commands or other tools are a policy
violation.

### M3 — A corrupted canary file makes the hook fail open (A4)

*Proven by reviewer 1; **verified in real Hermes v0.23**.* `cli.py`
`_expected_canary`, `config_canary_problem`; `__init__.py`
`_on_pre_tool_call`, `register`.

`config_canary_problem` catches only `OSError` around reading the canary
copy. A file that isn't valid UTF-8 raises `UnicodeDecodeError`, which
escapes `_on_pre_tool_call`; Hermes drops exceptions from hooks, so the call
proceeds. In the verification run: healthy canary → `block`; canary
overwritten with non-UTF-8 bytes → no directive (allowed); restored →
`block`. If the file is bad at startup, `register()` raises before the hook
is registered at all.

Triggering it needs the data folder's content corrupted (disk error,
interrupted write, or someone with write access), but it breaks the plugin's
fail-closed contract, which is why it is rated above its trigger difficulty.
Introduced by the config-canary change made in the same session.

**Fix:** catch every exception around the canary read; wrap the whole hook
body so any exception returns a block; register the hook before loading
settings in `register()`; accept `task_id` as optional so a future Hermes
signature change can't also fail open.

### M4 — `GATE_DATA` override lets a settings approval be replayed (A5)

*Proven by reviewer 1 (real gate in a separate process); verified by code
trace.* `gate_core.py` `data_dir`.

`data_dir()` prefers the `GATE_DATA` environment variable over the Hermes
plugin data folder. `_verify_weakening_approval` checks the record fetched
from the real gate, but the pin lookup, `consume_approval`, the canary and the
audit log use the overridden folder. An agent with a shell (the same
capability `set --approve` is designed for) copies the owner's public key (it
is public, served in every approved `/verify` record) into a folder it
controls, then runs `GATE_DATA=/tmp/x hermes passkey-gate set … --approve
<id>` repeatedly. One genuine approval of `require_passkey=false` can be
re-applied any number of times, with nothing in the real audit log.

**Fix:** ignore `GATE_DATA` inside a Hermes runtime (or refuse if it differs
from the plugin data folder), and verify a settings approval against the
local row, so verification and consumption use the same store.

### M5 — The settings-change phrase hides what is removed (A6)

*Proven by reviewer 4; verified.* `cli.py` `weakening_phrase`.

The phrase the human signs shows only the new value. Changing the default
pattern to `^Terminal …` (capital T, which never matches the `terminal`
tool) is correctly classified as weakening, but the page reads like the
existing rule: nothing shows the old value or that a pattern is effectively
removed. The same applies to `origin`, `rp_id` and `parent_gate_allowlist`.

**Fix:** put old → new and an explicit diff ("REMOVES pattern …", "ADDS
trusted gate …") into the phrase; this also binds the approval to the state
it was granted against.

### M6 — Anyone who can reach the gate can flood the audit log (A7)

*Proven by reviewer 2; verified (50 anonymous requests → 50 audit lines).*
`gate_core.py` `audit`, `Handler.do_POST`.

Bad registration tokens, unknown request ids and malformed bodies each
write an audit line, with no authentication or rate limit. The reviewer
measured about 940 lines per second (about 20 GB a day). Each append re-reads
the whole log under a lock, so cost grows with log size and lands on the
agent's hook and `gate_challenge` too, and junk lines are indistinguishable
from real events. Reachable by tailnet peers, local processes, and websites
via DNS rebinding (L5).

**Fix:** don't audit unauthenticated garbage (or rate-limit it); cache the
chain head instead of re-reading the file; add a POST rate limit.

### M7 — Terminal escape sequences reach the operator through `show` (A8)

*Proven by reviewer 4; verified.* `cli.py` `cmd_show`; `gate_core.py`
`create_challenge`.

`requester`, `requester_owner` and `why` keep control characters, and `show`
prints them raw. An agent can plant sequences that erase or rewrite lines in
the operator's terminal (for example forging `status: approved` or hiding the
URL) or, on terminals that allow OSC 52, write the clipboard.

**Fix:** reject control, bidi and zero-width characters in those fields at
creation, and escape them on output.

### M8 — Approvals bind the command text, not what it depends on (A9)

*Reasoned by reviewer 4.* `tools.py` hook binding.

The binding covers `{tool, args}` only. If the human approves `bash
./cleanup.sh` or `rm -rf "$TARGET"`, the agent can rewrite the script or
change the variable with ungated calls before running the byte-identical
approved call within the request lifetime. Approvals are also not tied to
the requesting agent or session. Threat-model finding 15 covers arguments
changing after the hook, not this indirection.

**Fix:** document it; warn on the approval page when a command references
variables, relative paths or scripts; optionally bind the session or working
directory when Hermes provides them.

## LOW

| # | Finding | Evidence | Ledger |
|---|---|---|---|
| L1 | `probe()`/`local_health()` follow redirects and read unbounded responses; `expose`'s TLS probe and `status` accept any `"status": "ok"` without checking the instance (same root cause as H1). | proven, verified (redirected squatter reported as "ours") | A10 |
| L2 | The "10 open requests per agent" cap is per self-declared name; rotating names fill the global cap of 100, after which even the CLI's own settings-change request can't be created. The README overstates the limit. | proven, verified | A11 |
| L3 | The gate-wide GET cap lets anyone lock the human out of the approval page for as long as they keep flooding (the CHANGELOG says "briefly"); 404s count, and `setup` then misreports the port as held by another program. | proven | A12 |
| L4 | Slow clients can hold all 64 connection slots; the 30 s timeout is per socket operation, not per request. | proven (at a reduced cap) | A13 |
| L5 | No `Host` header check: a DNS-rebinding website gets same-origin access to the local gate, reads `/health` (including the tailnet name), and can drive M6 and L3. | proven, verified | A14 |
| L6 | Bidi and invisible Unicode in action text, requester, owner and why render raw (the page can display text different from what is signed); prose can imitate the page's own headings, push the bound command below the fold, or claim to be `hermes-cli`. The bound command block itself is safe (ASCII-escaped). | proven (rendered in headless Chromium) | A15 |
| L7 | A config the canary rejects is still applied to runtime settings (origin, RP ID, request lifetime, peer allowlist) before the check; a bound challenge then mints with the untrusted lifetime. | proven | A16 |
| L8 | `set rp_id` counts as first-time (free) when the config's value is empty but a default RP ID is in effect; denial of service only. | proven | A17 |
| L9 | Upgraded v0.7.1 installs have no armed canary, and nothing tells upgraders to run `setup`; the threat model's "no copy means never configured" is untrue for them. | reasoned | A18 |
| L10 | Newlines in `HERMES_HOME` or the executable path inject lines into the systemd unit (`ExecStartPre=…`). Needs control of the operator's environment. | proven, verified | A19 |
| L11 | The SSRF filter for peer-gate fetches doesn't block 100.64.0.0/10 (Tailscale's range, including 100.100.100.100) or other non-global ranges. | proven, verified | A20 |
| L12 | Peer-gate and health fetches read responses with no size limit and no overall deadline. | reasoned | A21 |
| L13 | The new "use a passkey that's already registered" path drops the "registered after the QR" restriction and silently picks the oldest match, where `pin --code` refuses ambiguity; an operator without the code may copy one from `credentials`, which lists rogue codes too. Not documented in the threat model. | reasoned | A22 |
| L14 | Deny on a request that is no longer pending (including an approved one) returns HTTP 200 with `"status": "denied"`; the page handles it, API clients may not. | proven | A23 |
| L15 | Strengthening `set` changes are free and can deny service: a `.*` pattern blocks everything, a catastrophic-backtracking regex hangs the hook, `challenge_ttl 1` expires every approval. | reasoned | A24 |
| L16 | Settings-cache freshness depends on `hermes_cli.config.get_config_path`; if it fails, the agent process never reloads settings changed elsewhere, although `set` says changes apply at once. | proven (simulated) | A25 |

## INFO

- **Registration and approval edges (A26):** `registration_finish` doesn't
  recheck the bootstrap token's expiry (a session opened just before expiry
  can finish up to 5 minutes later); the approval `UPDATE` has no expiry
  guard (harmless, rechecked later).
- **Disclosure (A27):** `/health`'s `audit_head` is a live activity signal
  and re-reads the whole log; anyone with an approval link can also deny it
  (fails safe; undocumented).
- **File handling (A28):** the canary's temporary file, the serve record and
  the mint-token read follow symlinks (only someone with data-folder write
  access can plant one); a planted serve record can make `expose` remove
  another service's rule; `audit_notary_path` isn't a protected setting.
- **Canary edges (A29):** arming is check-then-act with no lock (a race can
  leave a permanent fail-closed); `config_canary` isn't in `config_schema`,
  so a settings form that rewrites the block from the schema might drop it
  (not checked); `gate_verify` and `set --approve` trust the challenge in the
  fetched record rather than the local row.
- **Robustness (A30):** a torn last line in the audit log makes
  `gate_status` raise; `gate_challenge` accepts a non-object `tool_call`
  (shown as "the exact command", never executable); the prose-only guard
  never fires with the default pattern.

## Checked and found sound

- **Local verification** (`local_verify.check`) never raises on malformed
  input and checks: signed challenge equals the recorded one and starts with
  `sha256(text)`; client data type and origin; RP ID hash; user-presence and
  user-verification flags; the signature over
  `authenticatorData ‖ sha256(clientDataJSON)`; equality with the pinned key.
- **Nonce and binding:** `sha256(text) ‖ binding ‖ 16 random bytes`; a
  text-only nonce can never cover a binding.
- **The hook** re-derives the canonical call from the live arguments,
  re-hashes the stored call, requires the nonce to cover the binding, and
  re-verifies against the pinned key; a rogue approval can't shadow a genuine
  one. Consumption is one conditional `UPDATE`: a 12-thread race gave exactly
  one allow. Exceptions inside `hook_verdict` block.
- **Expiry** is consistent across approval, `/verify` and consumption.
- **Signature counter** checks run atomically before an approval flips.
- **Settings classification** covers reordering, duplicates, type confusion
  and lifetime changes; replays of a spent approval are refused (apart from
  M4).
- **Pins:** created with `O_EXCL|O_NOFOLLOW`, never replaced, P-256 only;
  peer pins can't authorise local actions; finding 26's lookup is intact.
- **Confirmation codes:** unambiguous normalisation; `pin --code` requires
  exactly one match.
- **Web:** every agent-controlled field is HTML-escaped; strict CSP,
  `frame-ancestors 'none'`, `X-Frame-Options: DENY`, nosniff, no-referrer,
  no-store; `app.js` writes only `textContent`; the H10 CSRF defence, F5 HTTP
  bounds and finding 27 minimisation are intact; `/static/` traversal fails;
  the bootstrap token stays in the URL fragment and is single-use under
  races; the mint token is created exclusively and compared in constant time.
- **Outbound fetches:** redirects refused, origins parsed (finding 23),
  exact allowlist matching, F4's resolve-once DNS pinning intact; IPv4-mapped
  and other special IPv6 forms are rejected.
- **Tailscale and service commands** use argument lists with fixed or
  integer values; no command injection.

## Recommended order of fixes

1. **H1, M3, M1:** the pin can be stolen, enforcement can fail open, and a
   harmless-looking approval can turn enforcement off.
2. **M2, M5, M4:** patterns and the settings phrase mislead; settings
   approvals can be replayed.
3. **M6, M7, L5, L1, L6:** flooding, terminal and page spoofing, rebinding.
4. The remaining LOW and INFO items, and the threat-model corrections (H1's
   false sentence, M2's limit, M8, L9, L13).
