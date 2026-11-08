# Adversarial security review — passkey-gate (as of pin `69bcd7e6`, v0.4.0)

> **Historical record.** This review is kept exactly as written, as evidence of
> what was found. It describes v0.4.0 (commit `69bcd7e6`), reconciled with two independent reviewer reports on 5 November 2026.
> File paths, line numbers and behaviour refer to that version, and many of
> the problems it describes have since been fixed.
> For what was fixed and what is still open, see the [remediation ledger](security-review/remediation.md); for the residual risks that are accepted rather than fixed, see the [threat model](security-review/threat-model.md).

Reviewed by an adversarial pass over the full source (gate_core, local_verify,
tools, cli, expose, schemas, static/app.js), plus two independent reviewers
(full-source passes; their findings were folded in on 5 Nov 2026 — see
"Independent reviewer findings" and the Reconciliation, below. The review is
final as of this date.) The goal was to break the stated model:
"no agent-side path to approval; the human's signature is the only authority."

Verdict up front: **the WebAuthn core is sound, but the plugin as packaged does
not yet deliver its headline guarantee.** Two of the findings below are
show-stoppers for shipping as a *security* plugin: (1) the signed text is not
necessarily what gets executed, and (2) the trust anchors are all writable by
the very agent the model is supposed to constrain — an agent with ordinary
Hermes terminal/file access can register its own software authenticator and
re-pin the owner key, approving itself end-to-end. My own test suite already
contains the working exploit (`tests/test_gate.py::SoftAuthenticator`).

## CRITICAL

### 1. The approval page never shows the bound tool call — the human signs prose, the agent executes something else
- **Where:** `plugin/gate_core.py` `create_challenge` stores only
  `binding_sha256 = canonical_binding(tool_call)` (line ~277) and discards the
  tool_call itself; `approval_page` (lines ~489–536) renders only
  `action_text`; `tools.hook_verdict` (lines 178–204) executes whatever
  canonical args hash to that binding.
- **Exploit:** `gate_challenge({action_text: "List the workshop directory so I
  can check repo state", tool_call: {"tool": "terminal", "args": {"command":
  "rm -rf ./projects"}}})`. The human sees the friendly sentence,
  signs it; `pre_tool_call` finds the binding matches and runs the deletion.
  The signature is cryptographically valid and bound to a lie.
- **Fix:** persist the canonical tool_call JSON in the challenge row, render it
  on the approval page in a prominent block ("the exact command you are
  approving"), include it in the `/verify` record, and make the page state
  plainly that the binding, not the prose, is what executes. Ideally derive
  action_text from the tool call when one is supplied instead of letting the
  model write independent prose.

### 2. All trust anchors are agent-writable → full self-approval with no human
- **Where:** `cli.py` `cmd_pin` writes `pinned_owner.pem` (or `pins/<owner>.pem`);
  `cmd_bootstrap` prints a registration link to the terminal the agent owns;
  `gate_core.registration_options/finish` accept any valid WebAuthn ceremony;
  `local_verify.check` trusts whatever the pin file says; `set` writes
  origin/rp_id config.
- **Exploit (entirely implementable today):** the agent runs
  `hermes passkey-gate bootstrap`, completes registration with a *software*
  authenticator (my test suite's `SoftAuthenticator` does exactly this with a
  generated EC key, no browser, no human), runs `hermes passkey-gate pin
  its-own-key.pem`, then mints + approves + verifies any action. Every check
  passes locally because the attacker replaced the trust anchor. The
  documentation's claim "there is no agent-side path to approval" is false in
  any deployment where the agent has terminal + file access, which is the
  normal Hermes configuration.
- **Fix (architectural, not cosmetic):**
  - Registration and pin changes must be impossible through agent-reachable
    channels: bootstrap tokens delivered out-of-band to the human (phone
    notification, physical handoff), never to a terminal the agent reads.
  - Pin store, gate DB, gate code and plugin config must live **outside the
    agent's write reach**: separate OS user/service account, read-only mount,
    or a different host. Verification (`gate_verify`) and the enforcement hook
    must run in a process the agent cannot edit.
  - Re-pinning when a credential already exists must itself require a valid
    signature from the existing pinned key (prevents silent key substitution).
  - Document explicitly: with unrestricted same-user code execution, no
    in-process check can constrain the agent; the gate and verifier must be
    off the agent's control plane.

## HIGH

### 3. Single-use is broken under concurrency — `consume()`'s result is ignored
- **Where:** `tools.hook_verdict` line ~202: `gate_core.consume(row["id"], binding)`
  return value is discarded before `return None` (allow).
- **Exploit:** two identical tool calls racing both find the same approved
  challenge; `consume()` returns True once and False thereafter, but both calls
  are allowed. Also any consume failure (locked DB) still allows.
- **Fix:** `if not gate_core.consume(...): return block`. Consider making
  lookup-and-consume one transaction.

### 4. Approvals never expire for consumption or verification
- **Where:** `gate_core.pending_for_binding` (line ~346) selects approved rows
  regardless of `expires_at`; `consume` doesn't check it either;
  `challenge_status` returns `approved` for any age; `gate_verify` defaults
  `max_age=None`.
- **Exploit:** an approval obtained weeks ago can be consumed today; TTL only
  limits the pending window. Stolen/leaked approvals are valid forever until
  used.
- **Fix:** enforce `expires_at` at consume and at `/verify` (or require an
  explicit `max_age` by default, e.g. challenge TTL).

### 5. SSRF via `parent_approval.base`
- **Where:** `create_challenge` (lines ~255–270) accepts any https URL (plus
  loopback http) and `local_verify.verify_parent_approval` fetches it
  server-side (line ~129).
- **Exploit:** any caller of POST /challenge can make the gate fetch arbitrary
  internal HTTPS endpoints and learn reachability/status from the verdict —
  an internal network oracle on the tailnet host.
- **Fix:** allow parent bases only from a configured allowlist of trusted peer
  gate origins (ideally keyed to the pinned owner), and reject others.

## MEDIUM

### 6. Parent-chain "verified" is not a signature check
- **Where:** `verify_parent_approval` only checks `status == approved` and
  `spki_pem == pinned_pem` (lines ~134–143). It never verifies the parent's
  assertion signature or its binding to the parent action text.
- **Exploit:** a malicious or compromised parent gate can return a fabricated
  record with the correct pinned public key and get `verified`.
- **Fix:** include `action_text` in the `/verify` record (it is already public
  on the approval page, so no new disclosure) and run the full
  `local_verify.check(rec, text, parent_origin, parent_rp_id, pinned_pem)`.

### 7. Enforcement fails open on hook errors and stale config
- **Where:** Hermes skips a hook that raises or times out; `hook_verdict` and
  its callees are not wrapped (`tools.py` 178–204). `cli.apply_config_safe`
  caches once per process and `cmd_set` never invalidates it, so a running
  gateway keeps the old enforcement state after `set`.
- **Exploit:** a locked DB, a non-serializable args object, or a flipped
  setting turns enforcement off silently while the admin believes it is on.
- **Fix:** wrap the verdict in try/except returning block on error when
  `require_passkey` is true; invalidate/reload config on set and on file mtime
  change.

### 8. Audit-chain tamper claim is overstated
- **Where:** `gate_core.audit_verify` recomputes hashes over whatever is in the
  file. Anyone who rewrites the whole log can recompute a self-consistent
  chain and pass it.
- **Fix:** state plainly the chain detects partial edits only relative to a
  trusted head kept elsewhere; periodically notarize `audit_head` to an
  external immutable channel (e.g. append to a second host or a signed daily
  head record).

## LOW

9. `local_verify.check` can raise on malformed/incomplete records
   (`rec["assertion"]`, `rec["credential_public_key"]`), violating the
   handler never-raise contract — wrap and return problems instead (tools.py
   `gate_verify` lines ~94–111).
10. `consume()` overwrites `decided_at`, destroying the original approval
    timestamp; add a separate `consumed_at` column.
11. No rate limit on challenge creation — an agent can fill disk with
    challenges + audit lines; add per-requester throttling.
12. `pin` accepts unparseable PEM; validate it loads as a public key on write.
13. Cloned authenticators with a static sign_count are undetectable by design;
    note it as a limitation rather than a defect.

## What is solid

- WebAuthn verification uses the library correctly: UV required, expected
  challenge/RP/origin checked, sign_count updated on success, single pending
  transition enforced by `rowcount == 1`, replays of an old assertion onto a
  new challenge rejected, unknown ids non-enumerable, wrong sha indistinguishable
  from missing ids.
- The local verifier's core checks are right: sha256 binding of signed text,
  signature over `authenticatorData || sha256(clientDataJSON)`, UP/UV flags,
  pinned-key comparison.
- All user-controlled strings on the page are HTML-escaped; static file serving
  is whitelisted; request body size is capped.

## Recommended order of work

1. Fix #1 (render the bound tool call) and #3 (consume return) — small code,
   huge integrity gain.
2. Fix #4 (expiry) and #5 (parent allowlist).
3. Do #2 properly: move gate + verifier + pins off the agent's control plane,
   make re-pinning require an existing signature, and state the new threat
   model in the README before any public claim that agents cannot self-approve.
4. Then #6–#8 hardening and the low items.

Until #1 and #2 are fixed, the entry should not be presented as "an agent
cannot self-approve" — only as "a tamper-evident record of human approval
when the human actually signed".

---

# Independent reviewer findings (folded in — review now final, 5 Nov 2026)

Both independent full-source reviews have returned. Their verdicts agree with
the adversarial pass above — **not safe to ship as a security plugin** — and
each found issues 1–13 missed. Findings 1–13 are unchanged; the reviewers'
additions are numbered 14–28 below, with severity adjustments noted.

Reviewer notes: Reviewer 1 executed the test suite (`29 passed`) and lists the
coverage gaps at the end. Reviewer 2's environment lacked the `webauthn`
dependency, so its findings come from full source/control-flow reading only.
Neither reviewer modified files.

## Reviewer 1 — verdict: not safe to describe as a strong enforcement boundary

1. **Critical — approval can be reused concurrently.**
   `plugin/tools.py:190-203`, `plugin/gate_core.py:334-343,346-349`.
   `hook_verdict()` selects an approved row, then calls `consume()` and ignores
   the Boolean; check and consume are not one operation, so two concurrent
   identical tool calls can both pass on one approval. Fix: atomic
   claim-and-consume — `UPDATE challenges SET status='consumed' WHERE id=? AND
   status='approved' AND binding_sha256=? AND expires_at >= now RETURNING id`
   — or at minimum honor `consume()`'s return and block on False. (= finding 3)

2. **Critical — human can approve misleading text for a different tool call.**
   `plugin/gate_core.py:223-230,271-287`, `plugin/tools.py:45-46`,
   `plugin/schemas.py:73-82`. `tool_call` is optional and never cross-checked
   against the prose; the hook verifies only `binding_sha256`, never the
   relationship between binding and displayed text. Same issue applies to a
   truthful-looking `why`, requester identity, and parent-approval narrative.
   Fix: for enforced calls require `tool_call`, recompute the canonical call
   server-side, render a description generated from the call, reject
   `require_passkey`-eligible challenges without a binding; ideally one signed
   structured authorization object. (= finding 1)

3. **High — enforcement can be disabled through configuration.**
   `plugin/plugin.yaml:44-53`, `plugin/cli.py:205-221,65-76`.
   `require_passkey` defaults false and `cmd_set()` mutates
   `require_passkey` / `authority_patterns` at runtime with no authentication
   or authorization: the agent runs `hermes passkey-gate set require_passkey
   false` (keeping the CLI path outside its own patterns) and turns the gate
   off before acting. Fix: enforcement policy is operator-owned configuration,
   not agent-mutable state — remove runtime mutation or require independent
   passkey/operator confirmation for changes; audit and reload atomically.

4. **High — configuration-load failures fail open.**
   `plugin/cli.py:93-103`. On any config error `apply_config_safe()` caches
   `{"require_passkey": False, "patterns": []}` and the disabled state
   persists for the process. Fix: configuration failure must produce a block,
   not an empty disabled config; cache a validated immutable policy only after
   successful load; distinguish not-configured from configuration-failed.

5. **High — approval is consumed before the actual tool execution.**
   `plugin/tools.py:187-203`; Hermes applies execution middleware after the
   pre-tool hook, so middleware or another plugin can transform arguments
   (path, command, recipient, payload) after the hook has approved and
   consumed the original ones. Fix: bind and verify the final arguments
   immediately before dispatch, after all transformations; consume the
   authorization at the final dispatch boundary.

6. **High — CLI pinning is not actually first-seen pinning.**
   `plugin/local_verify.py:100-106`. `pin()` unconditionally overwrites
   (`path.write_text(...)`), contradicting the "first seen out of band, then
   trusted" design; any process able to invoke the CLI can replace the owner
   key and then produce locally-verifiable approvals. Fix: refuse to overwrite
   without an explicit, separately authenticated rotation procedure; validate
   the PEM before writing; audit rotation with old/new fingerprints.

7. **High — parent approvals are not locally cryptographically verified.**
   `plugin/local_verify.py:114-143`. Only remote `status == approved` and
   public-key equality are checked — no parent signature, client-data
   challenge, RP ID, origin, UV flags, or action binding. Fix: fetch the full
   parent record and run the complete local verifier against it, including the
   parent action text. (= finding 6, escalated)

8. **High — parent approval can mislead about what was approved.**
   `plugin/gate_core.py:255-270,509-520`, `plugin/local_verify.py:114-143`.
   The child accepts any parent `action_sha256` without requiring equality to
   the child action, so a real approval for an unrelated action is displayed as
   relevant prior context. Fix: require exact parent/child hash equality or
   label parent approvals strictly as unrelated context; always require the
   signer's independent approval of the current action.

9. **Medium — challenge TTL does not constrain approved challenges.**
   `plugin/gate_core.py:311-315,334-349`, `plugin/tools.py:190-203`.
   `pending_for_binding()` and `consume()` select approved rows without
   `expires_at`; an approval minted just before expiry stays usable
   indefinitely. Fix: add expiry to both queries; add a separate
   approval-validity TTL if pending and approved lifetimes differ. (= finding 4)

10. **Medium — regex authority matching is policy-fragile.**
    `plugin/tools.py:167-175`, `plugin/plugin.yaml:49-53`. Unanchored
    `re.search()` over `tool_name + " " + canonical_json` depends on JSON
    spelling/escaping; broad patterns can be evaded via tool aliases,
    connectors, bridges, and type coercions; the raw pattern text is echoed
    into the block message (injection + interpretation manipulation). Fix:
    structured matchers or compile/validate at config time; escape,
    length-cap, and replace displayed patterns with stable rule IDs; test
    aliases/coercions/Unicode/nested args.

11. **Medium — origin/health/verify fetches follow redirects (SSRF family).**
    `plugin/tools.py:143-157`, `plugin/cli.py:263-268`,
    `plugin/local_verify.py:129-133`. `urllib.request.urlopen()` follows
    redirects and the origin is only prefix-checked, so a configured HTTPS
    origin can redirect to internal HTTP services or cloud metadata.
    Fix: parse and pin origins, disable redirects, validate the final host,
    block private networks; same rules for parent bases. (extends finding 5)

12. **Medium — cloudflared timeout can hang indefinitely.**
    `plugin/expose.py:175-197`. `proc.stdout.readline()` blocks when
    cloudflared emits no newline, defeating the deadline, and a stalled tunnel
    process can survive. Fix: nonblocking I/O or a reader thread with queue +
    deadline; always kill and reap the child on timeout and exceptions.

13. **Medium — failed Tailscale HTTPS rules may not be removed.**
    `plugin/expose.py:149-150`. Cleanup runs `tailscale serve --http=<port>
    off` for an HTTPS rule, which may disable a different HTTP rule and leave
    stale exposure. Fix: remove the exact `--https=<port>` rule, then re-read
    the serve map and verify only the intended rule was removed.

14. **Low/Medium — owner pin path collisions.** `plugin/local_verify.py:89-97`.
    Distinct owner labels slug to the same file within 40 chars (e.g.
    `alice@example.com` vs `alice@example!com`), or punctuation-only labels all
    map to one filename — keys can overwrite or be misattributed across peers.
    Fix: collision-resistant filenames (hash of the exact normalized owner),
    store the original label in the pin record.

15. **Low — invalid numeric settings create denial of service.**
    `plugin/cli.py:224-249`, `plugin/gate_core.py:63-77`. Negative
    `challenge_ttl` expires instantly; invalid `port` breaks `serve`; no
    bounded bootstrap TTL. Fix: range-validate; validate `rp_id` as a hostname
    and `origin` as a parsed URL, not string prefixes.

**Reviewer 1's fail-open assessment:** Hermes's current pre_tool_call
dispatcher is documented and implemented to fail closed on timeout/exception
— finding 7's dispatch-level premise is disputed; the plugin's own
configuration path (their #3/#4) is where the real fail-open lives. Test
suite: `29 passed`, but no coverage for concurrent duplicate calls, config
failure, post-hook argument mutation, pin replacement, SSRF redirects, parent
signature verification, or prose/binding mismatches.

## Reviewer 2 — verdict: not safe to ship publicly as a security plugin

1. **Critical — enforcement consume race allows duplicate execution.**
   `plugin/tools.py:190-203`, `plugin/gate_core.py:334-343`. Same mechanism as
   finding 3; graded critical here. Fix: `if not gate_core.consume(row["id"],
   binding): return {"action": "block", "message": "approval already consumed"}`,
   or claim-and-consume in one transaction.

2. **High — local verification does not bind the assertion to the gate's
   recorded challenge.** `plugin/local_verify.py:51-52`,
   `plugin/gate_core.py:322`. The verifier checks only
   `b64u(cd.challenge)[:32].hex() == sha`; the gate's challenge contains
   `sha256(action_text) + random_entropy`, so a valid assertion for action A
   signs only the hash — any other gate record whose action hash matches is
   accepted with a different entropy suffix. The assertion is not
   cryptographically tied to the record presented. Fix: require exact equality
   against `rec["challenge_b64url"]`, compared as decoded bytes. **(new — 14)**

3. **High — `gate_verify` does not verify that the executed action is the
   approved tool call.** `plugin/tools.py:71-113`, `plugin/plugin.yaml:44-53`.
   `gate_verify` checks `challenge_id` + `action_text` only; the tool binding
   is enforced solely by the optional pre-tool hook, which is disabled by
   default (`require_passkey: false`). With enforcement off or outside the
   hook, `verified: true` on text authorizes whatever the agent does next.
   Fix: mandatory enforcement for configured authority tools; pass the actual
   canonical call into `gate_verify` and recompute/compare `binding_sha256`;
   consume atomically at the execution layer. (extends finding 1)

4. **High — parent approval proves only that a pinned key appeared in an
   approved-looking response.** `plugin/local_verify.py:114-143`. No local
   verification of the parent assertion, client data, RP ID, flags, sign
   count, or action binding; a fabricated `{status: approved,
   credential_public_key.spki_pem: <pinned key>}` from a compromised parent
   gate renders "verified". Second variant: a valid approval for an unrelated
   action is accepted because parent `action_sha256` is never compared to the
   child's. Fix: fetch the complete signed record and verify locally against
   parent action text, challenge, origin/RP ID, and pinned key; exact hash
   equality with the child if authorization is intended, otherwise label it
   advisory — never "verified". (= Reviewer 1 #7+#8; resolves with finding 6)

5. **High — parent approval URL is an SSRF primitive.**
   `plugin/gate_core.py:255-270`, `plugin/local_verify.py:128-133`.
   Requester-supplied `parent["base"]` is fetched server-side; adds blind-SSRF
   framing — internal probing and GET side effects, even without response
   disclosure. Fix: explicit allowlist of trusted parent gate origins, strict
   URL parsing, no redirects, resolve-and-block private/loopback/link-local/
   metadata addresses. (= finding 5)

6. **Medium — pin management is overwritable and race/symlink unsafe.**
   `plugin/local_verify.py:100-111`, `plugin/cli.py:158-166`. Beyond
   Reviewer 1 #6: `pin()` follows symlinks, uses neither exclusive-create nor
   atomic rename, the `pins` directory is never chmod'd 0700 nor the data dir
   secured, and no fingerprint is displayed. Fix: refuse overwrite without a
   human-confirmed `--replace`; `O_CREAT|O_EXCL|O_NOFOLLOW`; atomic rename
   from a securely created temp file; 0700 dir / 0600 files; display a
   SHA-256 fingerprint; validate the PEM key type.

7. **Medium — owner-label slug collisions can select the wrong pinned key.**
   `plugin/local_verify.py:89-97`. (= Reviewer 1 #14; suggested fix: hash the
   exact normalized owner, e.g. `slug + "-" + sha256(owner)[:16]`, or keep
   owner + fingerprint in structured storage instead of a lossy filename.)

8. **Medium — independent local verification omits sign-count validation.**
   `plugin/local_verify.py:53-80`. The offline verifier parses no four-byte
   signature counter and keeps no per-credential state, so a cloned
   authenticator or replayed exported record passes if signature + pinned key
   are valid (the online path delegates this to the library). This sharpens
   finding 13 into a concrete correctness gap. Fix: parse and require
   monotonic counter advancement against locally stored credential state, or
   state plainly that offline verification is not replay protection and never
   sole authorization. **(→ 21)**

9. **Medium — registration is socially engineerable and not protected by an
   existing credential.** `plugin/gate_core.py:420-429,432-481`,
   `plugin/cli.py:112-122`. Any CLI caller mints a bootstrap token and
   registration accepts the first valid WebAuthn credential for it — an agent
   can present a registration link as required setup or "repair" and persuade
   its human to register an attacker-controlled passkey. Fix: out-of-band
   human-controlled bootstrap authorization; short code displayed locally and
   entered on the registration page; existing credential required for
   replacement/additional registration; links carry requesting host + key
   fingerprint; explicit revocation and credential inventory. (part of
   finding 2's architectural fix)

10. **Low/Medium — challenge URLs and approval records are bearer-readable.**
    `plugin/gate_core.py:491-536,597-607`. `/a/<id>` exposes the full action
    text to anyone with the ID; `/verify/<id>` exposes the signed assertion,
    public key, requester, timestamps, and audit head. IDs are high entropy,
    but URLs leak into chat logs, proxies, and browser history — action
    disclosure and evidence leaks, though a leaked URL cannot approve by
    itself. Fix: short-lived viewing token, bind page access to an
    authenticated channel, minimize `/verify` output. **(→ 27)**

## Reconciliation (severity changes and additions)

Both reviewers independently found the two headline flaws — approval
confusion (finding 1) and the consume race (finding 3) — and neither disputes
any of 1–13. Severity changes adopted:

- **Finding 3 → CRITICAL.** Both reviewers grade the duplicate-execution
  race critical (Reviewer 1 #1, Reviewer 2 #1).
- **Finding 6 → HIGH.** Both reviewers grade the parent-chain gap high
  (Reviewer 1 #7/#8, Reviewer 2 #4): as shipped, "verified" is not evidence of
  a signed parent action at all, and accepts unrelated actions.
- **Finding 7 refinement.** Reviewer 1 disputes the dispatch-level premise
  (Hermes's pre_tool_call dispatcher is documented and implemented fail-closed
  on timeout/exception); the config-load fail-open stands as the concrete
  fail-open path (their #4, adopted as 17).

New findings not covered by 1–13 (numbering continues):

- **14 (HIGH) — approval replay across gate records:** local verification
  binds the assertion to `sha256(action_text)` only, not to the challenge
  record presented (Reviewer 2 #2). A valid assertion validates any other
  record with the same action hash. Most serious addition.
- **15 (HIGH) — approval consumed before final dispatch:** post-hook
  middleware can transform arguments between approval and execution
  (Reviewer 1 #5).
- **16 (HIGH) — agent-mutable enforcement config:** unauthenticated
  `set require_passkey false` / `set authority_patterns []` (Reviewer 1 #3).
- **17 (HIGH) — config-load failure caches enforcement off** (Reviewer 1 #4).
- **18 (HIGH) — pin replacement with no ceremony, plus symlink/race/perms
  gaps** (Reviewer 1 #6, Reviewer 2 #6). Part of finding 2's architectural
  fix: re-pinning must require the existing owner key's signature.
- **19 (HIGH) — parent approval lacks hash equivalence with the child
  action** (Reviewer 1 #8, Reviewer 2 #4). Folded into finding 6's fix.
- **20 (MEDIUM) — registration social engineering; no existing-credential
  protection on bootstrap** (Reviewer 2 #9).
- **21 (MEDIUM) — sign-count unvalidated in the offline verifier; clones and
  replays undetectable** (Reviewer 2 #8; sharpens finding 13).
- **22 (MEDIUM) — regex authority patterns: unanchored, JSON-spelling
  dependent, raw pattern echoed into the block message** (Reviewer 1 #10).
- **23 (MEDIUM) — redirect-following fetches extend the SSRF family to
  origin/health/verify** (Reviewer 1 #11; extends finding 5).
- **24 (MEDIUM) — cloudflared reader can block past its deadline, tunnel
  survives** (Reviewer 1 #12).
- **25 (MEDIUM) — Tailscale cleanup may remove the wrong serve rule** (Reviewer 1 #13).
- **26 (LOW/MED) — owner-slug collisions on pin filenames** (Reviewer 1 #14,
  Reviewer 2 #7).
- **27 (LOW/MED) — approval URLs and `/verify` records are bearer-readable
  evidence** (Reviewer 2 #10).
- **28 (LOW) — numeric setting ranges** (negative TTL, invalid ports) (Reviewer 1 #15).

## Amended recommended order of work

1. Finding 1 (render the canonical tool call — Reviewer 1 adds: derive the
   description from the call, reject enforced challenges without a binding) +
   finding 3 + finding 14 + block-on-config-failure (17). The consume fix and
   the claim-and-consume transaction carry expiry enforcement by the same
   stroke (finding 4).
2. Finding 5 (parent allowlist, strict URL parsing, no redirects — covers 23)
   and finding 6 (full local verification of the parent record — covers 19).
3. The architectural work for finding 2, before any public claim that agents
   cannot self-approve: move gate + verifier + pins off the agent's control
   plane (covers 16), rotation ceremony for re-pinning (18), bootstrap
   authorization (20), and the amended threat model in the README.
4. Remaining hardening and the new coverage gaps both reviewers flagged:
   findings 7, 8, 22, 24, 25, 26, 27, 28, plus tests for concurrent duplicate
   calls, config failure, post-hook argument mutation, pin replacement,
   redirect/SSRF, parent signature verification, and prose/binding mismatch.
   Reviewer 1 ran the suite (29 passed); none of these paths is currently
   covered.

## Final verdict

Unchanged, now triple-corroborated: **not safe to ship as a security plugin**
until findings 1, 2, 3, 4, 5, 6, 14 and the enforcement-config gaps (16, 17)
are fixed. Until then the entry must be described as "a tamper-evident record
of human approval when the human actually signed" — not "an agent cannot
self-approve".

## Provenance

- Reviewer 1: full-source review, test suite executed (`29 passed`). Raw
  report archived at `docs/security-review/reviewer-1.md`.
- Reviewer 2: full-source + control-flow review; could not run tests (no
  `webauthn` dependency in its environment). Raw report archived at
  `docs/security-review/reviewer-2.md`.
- Folded in by the primary reviewer agent on 5 Nov 2026; findings are the
  reviewers' own text, lightly condensed, with severity reconciled. No code
  changed as part of this fold-in.
