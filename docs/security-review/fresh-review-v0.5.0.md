# Fresh independent security review — passkey-gate v0.5.0

- **Reviewed at:** HEAD `d572e0235aa4009530a4219a5db1c1a7d3bf936d` (v0.5.0, clean tree)
- **Reviewer:** independent subagent, no campaign context (delegation
  `deleg_11029514`, 32 API calls, 629 s; live transcript:
  `~/.hermes/profiles/<profile>/cache/delegation/live/deleg_11029514/task-0.log`)
- **Method:** full source read of plugin/*.py + tests; special attention to
  the diff since `69bcd7e` (the previously reviewed snapshot); six live
  adversarial probes (`probe_freshreview_{replay,misc,dns,audit,audit_child}.py`
  in the profile scratch dir) run against a real software authenticator and a
  real HTTP gate; claims checked against code, not trusted.
- **Suite (independently re-run):** 155 passed in 19.35 s.

## Verdict

**safe-with-residuals** — fit to publish AFTER fixing findings F1 and F2
(both release blockers, both demonstrated by live repro). F3–F7 are hardening
to schedule.

> "I found no path by which an agent or remote party can approve or execute
> without the human's passkey signature. The core WebAuthn ceremony is sound
> and unusually honestly documented — challenge nonces embed
> sha256(action_text)+entropy, approve_finish enforces a real signature with
> UV/UP, exact challenge, rpId and an atomically advancing sign counter,
> consume is a single conditional UPDATE (one signature, one execution on the
> enforced path), the enforcement hook fails closed on every error path
> including unreadable config, SQL is parameterized throughout, subprocess
> calls use argument lists with no shell, the approval page escapes all
> interpolations behind a strict CSP, static serving is not traversable
> (probed), no fetch follows redirects, and the pin ceremony is
> O_EXCL|O_NOFOLLOW."

## Findings

### F1 [HIGH] — Gate-weakening approvals are replayable

`plugin/cli.py:415-445` (`_verify_weakening_approval`), `cli.py:491-567`
(`cmd_set`); `gate_core.consume` is called only from `plugin/tools.py:374`.

The finding-16 ceremony verifies a `--approve` challenge but never consumes
or marks it used, so within challenge_ttl (default 600 s) the same approval
re-authorizes the same weakening any number of times — including after the
operator re-arms the gate.

**Evidence (live repro, real software authenticator, real HTTP gate,
tempdir data):** human signed the phrase "passkey-gate: set
require_passkey=false — confirm this gate-weakening change" ONCE; cmd_set
applied it, the challenge stayed status=approved, the operator set
require_passkey=true (free direction), and the agent replayed the identical
`set require_passkey false --approve <cid>` twice more — enforcement was
disarmed both times with no new signature; challenge_status still reports
"approved". Parent re-ran the reviewer's probe and reproduced it
independently. Probe: `probe_freshreview_replay.py`.

**Recommendation:** burn the approval atomically at apply time (a conditional
UPDATE flipping that challenge to a terminal "consumed" state, mirroring
consume()'s lock discipline), require a fresh challenge per weakening, and
record the consumed challenge id in the config_changed audit entry.

### F2 [HIGH] — Release artifact installs the known-unsafe pre-remediation snapshot

`catalog-entry/passkey-gate.yaml:6` pins sha
`69bcd7e6166908a903362a3a561c3462d4dec528` (the commit the archived
adversarial review judged not shippable — 28 findings incl. two stoppers);
`:14` declares version 0.2.0.

The catalog entry is the file its header says to open a PR with; as shipped
at HEAD it points public installs at v0.4.0-era code while its description
claims v0.5.0 security properties (single-use approvals, hook consumption,
parent re-checks) that the pinned snapshot does not implement.

**Evidence:** read of the file at HEAD vs `docs/security-review.md:1-17` and
`plugin/plugin.yaml:3`; 40 commits of security remediation between 69bcd7e
and d572e02.

**Recommendation:** before any PR/publication, re-pin the sha to the
post-remediation release commit, bump version to 0.5.0, and re-run the
fresh-clone validation the file itself mandates; alternatively drop the file
from the release.

### F3 [MEDIUM] — The hash-chained audit log corrupts itself under normal multi-process use

`plugin/gate_core.py:178` (`_lock = threading.Lock`, process-local),
`gate_core.py:222-244` (`audit()`: read whole file for tail, then append,
holding only the in-process lock).

The gate HTTP service and any CLI command (set/show/bootstrap in the gateway
host's Hermes runtime vs an operator terminal) are separate processes
writing the same audit.jsonl; nothing serializes them, so concurrent appends
fork the chain (two records claim the same prev/seq) and `audit_verify()`
then reports BROKEN with no attacker involved — degrading the plugin's core
evidentiary artifact and handing a real attacker a "race did it" deniability
story.

**Evidence (organic, no patching, two processes × 60 appends each):**
"lines=121 chain_ok=False: chain broken at line 4"; deterministic round with
the read-tail window widened to mirror the real race: "chain broken at line
13". Probes: `probe_freshreview_audit.py` + `probe_freshreview_audit_child.py`.

**Recommendation:** serialize appends cross-process — move the chain tail
into the SQLite DB (already WAL and cross-process safe) or take an
flock/lockfile around read-tail+append; add a multi-process test.

### F4 [LOW] — DNS-rebinding TOCTOU between the parent-fetch SSRF check and the fetch

`plugin/netfetch.py:146-165` (private_network_problem resolves the host),
`netfetch.py:42-44` + `local_verify.py:371-373` (open_no_redirect fetch
re-resolves independently).

The allowlist + private-network verdict is computed from one DNS resolution
and the fetch dials a second, independent resolution, so a rebinding
allowlisted hostname passes the check on a public IP and is fetched at a
loopback/internal IP. Exploitation requires DNS control of a host the
operator deliberately allowlisted, and any fetched record must still pass
pinned-key crypto to matter — the practical gain is an internal
reachability/TLS-probe oracle.

**Evidence (stateful getaddrinfo fake):** check resolution returned
93.184.216.34 (verdict path proceeded); the fetch resolution returned
127.0.0.1 and a loopback listener on the allowlisted port accepted the TCP
connection from the fetch, while verify_parent_approval returned "unverified
(parent gate unreachable)". Probe: `probe_freshreview_dns.py`.

**Recommendation:** resolve once and pin the connection to the validated
address (custom connection factory or connect-to-resolved-IP with SNI/host
header preserved), or re-run the address check on the address urllib
actually dials.

### F5 [LOW] — HTTP gate surface: no per-connection timeout, no request rate limits, wedges on negative Content-Length

`plugin/gate_core.py:833-837` (`_json()`: `int(Content-Length)` then
`rfile.read(n)`; `read(-1)` blocks until client EOF), `gate_core.py:806-931`
(ThreadingHTTPServer, no timeout, unbounded threads), no rate limit on
unauthenticated GET `/a/<id>`, `/verify`, `/health`.

A single raw socket sending "Content-Length: -1" parks a handler thread in
`rfile.read(-1)` forever; an internet-reachable deployment (the advertised
cloudflared quick-tunnel backend) permits unbounded thread/memory exhaustion,
plus unauthenticated /verify mismatch spam appends an fsynced audit line per
request.

**Evidence:** 30 sockets with Content-Length -1 leaked 30 threads
(threading.active_count 2 → 32) while /health stayed 200; each wedged thread
never times out. Probe: `probe_freshreview_misc.py`.

**Recommendation:** reject non-positive/oversized Content-Length, set
Handler.timeout and a max request duration, and rate-limit the
unauthenticated GET endpoints (the challenge-minting path already has one).

### F6 [LOW] — `os_default_rp_id` is dead code (missing import)

`plugin/cli.py:119-130` references `shutil.which` at :122 but shutil is never
imported in cli.py; the NameError is swallowed by the except and the
function always returns 'localhost'.

The documented best-effort default RP ID (tailscale Self.DNSName) never
works, so a fresh install with origin set but rp_id unset gets rp_id
'localhost' and WebAuthn ceremonies fail until the operator sets rp_id
manually — fail-closed, availability/UX only.

**Evidence:** "'shutil' not in vars(cli)"; with a working `tailscale` stub on
PATH returning a DNSName, `cli.os_default_rp_id()` still returned
'localhost'.

**Recommendation:** add the missing `import shutil` (or reuse
expose.fetch_self_dnsname) and add a test that exercises the function with a
stubbed binary.

### F7 [INFO] — `gate_verify` violates the never-raise handler contract on type-abused input

`plugin/tools.py:116`: `int(args.get('wait_seconds') or 0)` raises ValueError
for e.g. `wait_seconds='abc'` before any JSON error shape is produced.

**Evidence:** `tools.gate_verify({'challenge_id': 'A'*24, 'action_text':
'x'*50, 'wait_seconds': 'abc'})` raised ValueError instead of returning a
JSON error string.

**Recommendation:** coerce defensively and return the standard
`{ok: false, error: ...}` shape; add a type-abuse test over all three tool
handlers.

## Claims issues

1. **OVERCLAIM** — `plugin/plugin.yaml:11` and `plugin/schemas.py:24` say
   "approvals are single-use (and consumed on use)"; only the pre_tool_call
   consume path is single-use. Weakening `set --approve` approvals are never
   consumed (replay proven, F1), and text-only (unbound) approvals have no
   consume path at all and verify repeatedly until expires_at. (Accurate
   after F1 for weakening approvals; text-only approvals need a claims
   qualification or a consume-on-verify decision.)
2. **OVERCLAIM** — `CHANGELOG.md:59-62`: "All server-side fetches (parent
   approval, origin, health, verify) go through one shared no-redirect opener
   with strict URL parsing and private-network blocking". Redirect refusal is
   universal, but private-network blocking applies ONLY to parent-gate
   fetches (`netfetch.base_not_fetchable`); the plugin's own-origin fetches
   (`tools.py:228-242`, `cli.py:620`, `expose.py:408`) perform no
   private-network or allowlist check.
3. **INCONSISTENT WITH STATED RULE** — finding 23's remediation says "gate
   URLs are PARSED, never prefix-checked" (`plugin/netfetch.py:56-84`), but
   `tools.py:121` (gate_verify) and `cli.py:421`
   (`_verify_weakening_approval`) still accept the configured origin via a
   bare `startswith('http://'/'https://')` prefix check; `parse_gate_origin`
   is only enforced at cmd_set and parent-approval paths. Operator-controlled
   value, so impact is consistency rather than exploitation.
4. **STALE** — `docs/security-review/threat-model.md:3` states "Applies to:
   passkey-gate v0.4.0" while shipping inside the v0.5.0 release whose
   README/CHANGELOG cite it as the authoritative trust model.
5. **SHIPPING CONTRADICTION** — the catalog entry (F2): pins 69bcd7e and
   declares 0.2.0 while asserting v0.5.0 properties.
6. **VERIFIED ACCURATE (no action)** — the README "Honest limits" and
   "Deployment requirements" sections, plugin.yaml descriptions, and
   threat-model residuals were each checked against the code and are
   accurate: bearer-readable /a and minimized /verify records, no downstream
   execution enforcement, host-control residual, loopback default bind
   (`gate_core.py:926`), audit internal check not being wholesale-rewrite
   evidence, and pin O_EXCL|O_NOFOLLOW all match the implementation. No
   exploitable overclaim of CRITICAL magnitude was found.

## Test gaps

1. No test that a `--approve` weakening challenge is single-use — nothing
   replays the same approved challenge id against cmd_set (F1 probe applies
   the weakening three times off one signature). Existing tests
   (test_gate.py:990-1005) apply the weakening exactly once.
2. All audit-chain tests run in one process; no test exercises two processes
   appending concurrently (the threading.Lock at gate_core.py:178 is
   process-local — the two-process probe breaks the chain organically).
3. No test pins the parent fetch's actual TCP connection target to the
   address the private-network check validated (the rebinding TOCTOU).
4. No test runs os_default_rp_id with a tailscale binary present — the
   unimported-shutil dead code is invisible to the suite.
5. No tests for malformed HTTP framing (negative Content-Length thread
   wedge), handler timeouts, or rate limiting on the unauthenticated GET
   endpoints (/a/<id>, /verify) that an internet-exposed quick tunnel
   exposes.
6. No type-abuse coverage for the tool handlers' never-raise contract
   (gate_verify with wait_seconds='abc' raises ValueError).
