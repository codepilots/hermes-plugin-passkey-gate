# Remediation ledger — passkey-gate security review

Tracks the fix campaign for `docs/security-review.md` (findings 1–28).
Process: one finding (or tightly-coupled finding group) delegated per
subagent, sequentially. Each fix is verified independently by the primary
agent (diff review + full test suite + targeted probe), then committed, then
logged here with evidence. Status legend: ⬜ queued · 🔄 delegated ·
✅ fixed+verified · 📝 addressed-by-documentation (residual limitation
explicitly stated) · ⛔ blocked.

Baseline: commit `efc3bb8` ("docs: catalog entry updated for 0.4.0"),
review as of `bec3b78` (v0.4.0). Test suite baseline: **29 passed**
(`.venv/bin/python -m pytest tests/ -q`, verified 5 Nov 2026).

Coupled findings are fixed in one delegation where the review itself says
they land in the same code path (noted inline). Original low findings 9–13
fold into items below (9→D3, 10→D11, 11→D12, 12→D8, 13→D13).

## Items

| # | Findings | Severity | Status | Evidence |
|---|----------|----------|--------|----------|
| D1 | 1 — approval page never shows the bound tool call | CRITICAL | ✅ | commit `4956b48`; 33 passed; exploit probe green |
| D2 | 3+4 — consume race + approval expiry (atomic claim-and-consume) | CRITICAL+HIGH | ✅ | commit `36a193e`; 39 passed; 8-way race probe green |
| D3 | 14+9 — assertion↔challenge binding; local_verify never-raise | HIGH+LOW | ✅ | commit `dcbdb4a`; 41 passed; replay probe green |
| D4 | 17+7 — config-load failure fail-open; stale config reload | HIGH+MEDIUM | ✅ | commit `f618f0e`; 47 passed; corruption probe green |
| D5 | 5+23 — SSRF: parent allowlist, strict URL parse, no redirects | HIGH+MEDIUM | ✅ | commit `506e8d9`; 61 passed; live SSRF probe green |
| D6 | 6+19 — parent approval: full local signature verify + hash equality | HIGH | ✅ | commit `89d2264`; 66 passed; fabricated-record probe green |
| D7 | 16 — enforcement config agent-mutable | HIGH | ✅ | commit `a5a0cf9`; 78 passed; 19/19 exploit probe green |
| D8 | 18+12 — pin ceremony: no silent overwrite, O_EXCL/no-follow, PEM validation | HIGH | ✅ | commit `a763ad6`; 84 passed; pin probe green |
| D9 | 2+20+15 — threat model, bootstrap hardening, dispatch limitation | CRITICAL (arch) | ✅ (partial, honest) | commit `32805bc`; 87 passed; DB-tamper probe green |
| D10 | 8 — audit chain: honest claim + head notarization | MEDIUM | ✅ | commit `7bfceee`; 102 passed; wholesale-rewrite probe green |
| D11 | 10 — consumed_at column, preserve decided_at | LOW | ✅ | commit `ac5c577`; 107 passed; stamp/migration probe green |
| D12 | 11 — challenge creation rate limit | LOW | ✅ | commit `6ade254`; 114 passed; race probe green |
| D13 | 21+13 — sign-count validation + clone-detection limits | MEDIUM | ✅ | commit `c3e6261`; 120 passed; live-ceremony probe green |
| D14 | 22 — regex pattern validation + safe block-message display | MEDIUM | ✅ | commit `1f51122`; 125 passed; fence/caps probe green |
| D15 | 24 — cloudflared reader deadline | MEDIUM | ✅ | commit `8d9ec70`; 130 passed; grandchild-deadlock probe green after follow-up |
| D16 | 25 — tailscale exact-rule cleanup | MEDIUM | ✅ | commit `a7994bb`; 142 passed; 5-scenario rule probe green after follow-up |
| D17 | 26 — owner-slug collision-resistant pin filenames | LOW/MED | ✅ | commit `0fe4ec7`; 148 passed; independent collision/migration probe green |
| D18 | 27 — bearer-readable verify records: minimize + document | LOW/MED | ✅ partial | commit `e924660`; 149 passed; minimized-record probe green; authenticated channel remains deployment residual |
| D19 | 28 — numeric setting range validation | LOW | ✅ | commit `76f0622`; 155 passed; independent range/legacy/backend/bind probe green |

## Fresh independent review of v0.5.0 — new backlog

A fresh adversarial review (no campaign context) of HEAD `dcc66b7` judged
the release **safe-with-residuals**: the core WebAuthn ceremony is sound, no
path approves or executes without the human's passkey, and the honest-claims
documentation was verified accurate. Two HIGH findings are release blockers
(demonstrated by live repro, independently re-run by the parent); the rest
are hardening. Full report frozen at
[docs/security-review/fresh-review-v0.5.0.md](fresh-review-v0.5.0.md).

| Item | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| F1 | gate-weakening `set --approve` approvals replayable (never consumed) | HIGH | 🔄 | live 3×-replay repro confirmed by parent; probe `probe_freshreview_replay.py` |
| F2 | catalog entry pins pre-remediation `bec3b78`, version 0.2.0 | HIGH | ⬜ after F1 | re-pin needs the final release commit |
| F3 | audit chain self-corrupts under multi-process writes (process-local lock) | MEDIUM | ⬜ | organic 2-process repro, chain broken |
| F4 | DNS-rebinding TOCTOU: SSRF check resolves once, fetch dials again | LOW | ⬜ | stateful getaddrinfo fake, loopback dial demonstrated |
| F5 | HTTP surface: negative Content-Length wedges threads; no GET rate limits | LOW | ⬜ | 30 wedged threads leaked |
| F6 | `os_default_rp_id` dead code — `import shutil` missing | LOW | ⬜ | stub probe returns localhost |
| F7 | `gate_verify` raises on `wait_seconds='abc'` (never-raise contract) | INFO | ⬜ | direct call raises ValueError |
| C1 | "approvals are single-use" overclaim (plugin.yaml:11, schemas.py:24) | claim | with F1 | accurate for weakening approvals after F1 |
| C2 | CHANGELOG "all fetches… private-network blocking" overclaim | claim | with F2 | only parent-gate fetches check |
| C3 | origin accepted via prefix check in gate_verify/_verify_weakening_approval | claim | with F2 | finding-23 rule says parse, never prefix |
| C4 | threat-model.md header still says "Applies to: v0.4.0" | claim | with F2 | stale version |

## Log

### Publication prep — v0.5.0 ✅ (post-campaign, user-approved closing task)

- **Delegated:** version bump 0.4.0 → 0.5.0 (plugin.yaml, pyproject.toml);
  CHANGELOG.md in Keep a Changelog style drawn from this ledger (Security /
  Changed / Added / Known-limitations, findings traceable); README claims
  pass aligning every security claim with the threat model (9 claim
  rewrites: tagline, forged-signature framing, agent-side-path qualification,
  enforcement→verification, diagram, bootstrap operator ceremony,
  gate_verify row, new "Deployment requirements for real boundaries"
  section, extended Honest limits); `.github/workflows/tests.yml` (push +
  PR, least privilege, Python 3.14, pip install -r requirements.txt pytest).
- **Real fix found by the child:** the declared `webauthn>=1.11,<2` pin was
  broken for the repo's own test suite — tests import the webauthn ≥2-only
  `encode_cbor` helper, and the repo venv had silently outrun its declared
  pin (webauthn 3.0.1 installed). Corrected to `>=2,<4` across
  requirements.txt / pyproject.toml / plugin.yaml; verified red under
  1.11.1, green under 2.8.0 and 3.0.1, and CI was proven end-to-end from a
  fresh venv running the workflow's exact commands (155 passed). Same
  failure family as the D16 pyyaml discovery: silently misdeclared
  dependencies riding a stale venv.
- **Parent verification:** full suite independently re-run — 155 passed;
  metadata diffs consistent across all three dependency declarations;
  README diff reviewed hunk-by-hunk against the threat model — all 9
  reported claim changes present and accurate, no drift elsewhere, remaining
  "cannot" uses are legitimate deployment-control statements; static scans
  clean.
- **Standing follow-up (NOT for this release):** `catalog-entry/passkey-gate.yaml`
  is a stale draft — version 0.2.0, pinning `bec3b78` (the pre-remediation
  commit the review graded unsafe), with outdated description language.
  It must be rewritten and repointed at the fresh-review-passed commit
  before any catalog PR; it is deliberately untouched here.

### D19 — finding 28 (LOW): numeric setting range validation ✅

- **Delegated:** persistence validates `port` in `1..65535` and
  `challenge_ttl` in `1..86400`; runtime validates port, challenge TTL, and
  bootstrap TTL (both TTLs `1..86400`), including malformed legacy/config and
  environment values. Invalid expose and HTTP-serve ports refuse before
  backend invocation or socket binding. Ranges are documented in
  `plugin/plugin.yaml`; privileged ports remain allowed because deployment
  did not require rejecting them. No rp_id/origin behavior changed. Child
  reported 155 passed.
- **Parent verification:** full suite independently re-run — 155 passed;
  `git diff --check` and added-line security scans clean. Independent probe
  (`cache/scratch/probe_d19_parent.py`) verified invalid persistence values
  refuse without saving, exact low/high boundaries are accepted, malformed
  runtime state fails closed with explicit range errors, invalid expose ports
  do not invoke a backend, and HTTP serve refuses before binding.
- **Commit:** `76f0622`.

### D18 — finding 27 (LOW/MEDIUM): minimize bearer-readable verify records ✅ partial


- **Delegated:** public approved `/verify` records now retain only the
  action/cryptographic fields required by `verify_parent_approval()` and
  `local_verify.check()`: status, challenge identity/hash, action text,
  approval time, origin/RP, recorded challenge, assertion, and credential
  public key. Removed binding hash, canonical tool call, requester, creation
  time, and audit head. `gate_verify` recovers local binding metadata from
  the local database, preserving its dispatch-binding contract. Parent
  reported 149 passed.
- **Parent verification:** full suite independently re-run — 149 passed;
  `git diff --check` and added-line security scans clean. Independent probe
  (`cache/scratch/probe_d18_parent.py`) fabricated an approved DB row and
  verified the minimized response contains every required crypto/action field,
  omits all removed metadata, and still returns only `{"status": "denied"}`
  for a mismatched action hash.
- **Residual (honest partial):** `/a/<id>` remains bearer-readable, and the
  retained action text and cryptographic evidence remain bearer-readable to
  anyone holding the high-entropy URL inputs. The plugin has no authenticated
  operator channel from which to issue a safe viewing token; deployment must
  provide an authenticated broker/session or equivalent short-lived,
  authenticated token issuance. This is documented in `threat-model.md`.
- **Commit:** `e924660`.

### D17 — finding 26 (LOW/MEDIUM): collision-resistant pin filenames ✅


- **Delegated:** named pin paths now derive from the canonical owner label,
  an uppercase owner fingerprint, and normalized P-256 PEM bytes. The owner
  fingerprint makes lookup exact despite lossy slug collisions; the key
  digest ensures different keys for one owner never share a destination.
  Legacy exact `<slug>.pem` files remain readable. Multiple matching pins
  fail closed with a ValueError naming candidates and instructing the
  operator to keep exactly one. D8's validation-first P-256 and exclusive
  `O_EXCL|O_NOFOLLOW`, mode 0600, fsync ceremony is preserved. Six tests
  added; child reported RED first, then 148 passed.
- **Parent verification:** full suite independently run with the repo venv:
  148 passed. Independent probe
  (`cache/scratch/probe_d17_parent.py`) generated real P-256 keys and
  verified: two slug-colliding owners get distinct files and correct
  attribution; an unpinned slug peer gets no key; same-owner different-key
  ambiguity fails closed naming both files; legacy lookup works and
  legacy/new coexistence fails closed; same-key overwrite is refused.
  `git diff --check` and added-line security scans found no issues.
- **Commit:** `0fe4ec7`.

### D16 — finding 25 (MEDIUM): tailscale exact-rule cleanup ✅ (after follow-up)

- **Delegated (D16):** exact per-gate rule identity (https port + mount +
  proxy target, durably recorded), path-scoped removals verified against a
  fresh serve map, keep-on-rerun, replace-by-handle, foreign ports
  respected. Subagent reported fixed, 140 passed (10 new tests).
- **Environment note:** the parent's full-suite run failed 1 test — the
  pre-existing plugin.yaml drift test imports pyyaml, which was never in
  requirements.txt and silently vanished with Hermes env churn. Installed
  into the repo venv and declared in requirements.txt; unrelated to the diff.
- **Parent verification caught one edge:** with a live recorded rule, an
  explicit target_port held by a foreign service dropped OUR working rule
  before refusing — the refusal was only zero-mutation without a prior rule.
  Follow-up delegation (D16b) reproduced the scenario RED first (the log
  showed the 8445 off issued before the refusal), then gated the replace
  branch behind a claimability pre-check (claimed-minus-our-port
  accounting). 2 new tests, 142 passed.
- **Verification (independent):** full suite re-run — 142 passed; probe
  (`cache/scratch/probe_d16_rules.py`, own from-scratch stateful fake
  tailscale binary, foreign rules seeded on 443 + 8443, every invocation
  logged): first expose sets exactly our rule on the first FREE port;
  re-run KEEPS it with zero serve mutations; a different gate port replaces
  ONLY our rule via the path-scoped off; foreign-held explicit target port
  refused with zero mutations and the live rule + record intact (the
  follow-up edge closed); total failure cleans only this run's partial
  rules, clears the record, foreign rules byte-identical throughout; no
  forbidden command shapes (--http=, bare off, reset) ever issued.
- **Commits:** `a7994bb` (both rounds + requirements.txt).

### D15 — finding 24 (MEDIUM): cloudflared reader deadline ✅ (after follow-up)

- **Delegated (D15):** bound the cloudflared readiness wait with a
  reader-thread + queue and hard monotonic deadline; named failure messages;
  child killed on every failure path. Subagent reported fixed, 128 passed.
- **Parent verification caught a real hole:** the independent probe
  (`cache/scratch/probe_d15_deadline.py`) hung cloudflare_expose FOREVER with
  a stub that forks a pipe-holding grandchild — killing the direct child
  leaves the grandchild holding the pipe, the blocked reader keeps the
  TextIOWrapper buffer lock, and the main thread deadlocks in
  stream.close() (faulthandler stack confirmed: main at expose.py:241
  close(), reader at readline()). The child's own stubs never forked, so its
  suite could not see it.
- **Follow-up delegation (D15b):** reproduce the scenario RED first (it did —
  external timeout exit 124), then kill the process GROUP
  (start_new_session + killpg SIGTERM→SIGKILL, ProcessLookupError-safe) and
  make teardown deadlock-proof (close the RAW fd if the reader somehow
  survives; never close the wrapper while a reader lives). Completed in
  ~467s, 2 new tests, 130 passed.
- **Verification (independent, after follow-up):** full suite re-run — 130
  passed; original probe re-run — ALL scenarios pass: silent hang ends in
  2.0s with the named error and the child dead (no leak), fast-fail reports
  exit code + recent output, success path unchanged, missing binary
  refused. One orphaned probe stub (my pkill pattern artifact, not a plugin
  leak — the success path hands the child back alive by design) killed and
  confirmed clean.
- **Commits:** `8d9ec70` (both rounds, one atomic finding-24 commit).

### D14 — finding 22 (MEDIUM): pattern validation + safe display ✅

- **Delegated:** validate authority_patterns whole at set time (compile
  check, length/count caps, before the finding-16 weakening classification),
  match-time defense in depth for smuggled patterns, block message renders
  the pattern as escaped fenced data. Subagent completed in ~371s, TDD (5
  new tests), left uncommitted.
- **Verification (independent):** full suite re-run — 125 passed; diff review —
  validate_authority_patterns runs before the D7 machinery so a bad list
  cannot hide behind the approval flow and is refused WHOLE; authority_matches
  returns (index, pattern) and skips unusable entries with a logged warning;
  render_pattern caps length, escapes backticks, collapses control chars;
  plugin.yaml description updated. Probe
  (`cache/scratch/probe_d14_patterns.py`): broken regex refused with nothing
  persisted; valid pattern enforced; smuggled broken/non-string patterns
  skipped without crashing while a later good rule still matches with its
  stable index; a pattern carrying hostile backtick + literal newline bytes
  cannot break out of the display fence (backtick escaped, newline
  collapsed); 201-char, 101-pattern, and non-string lists all refused whole.
- **Deviations:** none material (no ReDoS detector invented — compile check
  + caps per the review's ask).
- **Commit:** `1f51122`.

### D13 — findings 21 (MEDIUM) + 13 (MEDIUM): sign-count clone detection ✅

- **Delegated:** validate WebAuthn sign counters on approval (refuse
  counter ≤ stored as clone evidence, atomic update on success,
  counterless 0-after-0 allowed with documented residual), store the
  attestation's initial counter at registration. Subagent completed in
  ~422s, TDD (6 new tests + SoftAuthenticator extended with initial_count
  and chosen-count), left uncommitted.
- **Verification (independent):** full suite re-run — 120 passed (three
  consecutive clean runs by the child, one run by the parent); diff review —
  named clone guard before the crypto call (failure gets its true name), the
  stored counter advances in ONE conditional UPDATE (sign_count=? WHERE
  sign_count<?) before the challenge flip, registration stores v.sign_count,
  local_verify requires the full 37-byte authData header and states the
  offline limitation plainly. Probe
  (`cache/scratch/probe_d13_counter.py`, real HTTP ceremonies on a live
  gate): registration baseline 5 stored; a presented counter BELOW the
  baseline refused as clone evidence; genuine advance to 6 accepted and
  stored; same-counter replay and older-counter signatures refused by name;
  counterless 0-after-0 approved twice; two concurrent approvals presenting
  counter 7 — exactly one approved, the loser refused as clone, stored
  counter atomically 7.
- **Deviations:** none material (guard gives the crypto failure its name
  first; the library call enforces the same rule generically).
- **Commit:** `c3e6261`.

### D12 — finding 11 (LOW): challenge rate limiting ✅

- **Delegated:** per-requester pending cap + global backstop, TOCTOU-safe via
  the existing SQLite write serialization, quota freed by expiry/resolution.
  Subagent completed in ~406s, TDD (7 new tests), left uncommitted.
- **Verification (independent):** full suite re-run — 114 passed; diff review —
  BEGIN IMMEDIATE makes the quota check and the insert one write transaction
  (no overshoot window); only PENDING+unexpired rows hold quota;
  ChallengeLimitError subclasses ValueError so every refusal path surfaces it;
  rejections audited (challenge_rejected); HTTP handler answers 429. Probe
  (`cache/scratch/probe_d12_caps.py`): 11th challenge for the same requester
  refused; different requester unaffected; expired and decided challenges
  each free a slot; 14-way concurrent mint race → exactly 10 succeed, DB
  holds 10, no overshoot; global backstop trips with exactly 100 pending.
- **Deviations accepted:** review named no numbers, so the suggested defaults
  (10 / 100) landed as module constants.
- **Commit:** `6ade254`.

### D11 — finding 10 (LOW): consumed_at column ✅

- **Delegated:** add a consumed_at REAL column (existing alter-table loop),
  stamp it in the SAME atomic conditional UPDATE that claims the row, keep
  decided_at as the human's approval time, migrate old DBs, surface both
  stamps in consumed records. Subagent completed in ~168s, TDD (5 new tests),
  left uncommitted.
- **Verification (independent):** full suite re-run — 107 passed; diff review —
  the old code really did clobber decided_at at consume (`set
  status='consumed', decided_at=?`); now `set status='consumed',
  consumed_at=?` with the WHERE clause byte-identical and the single-statement
  claim intact; consumed records expose approved_at + consumed_at and no
  signature material; gate_verify stops waiting on consumed. Probe
  (`cache/scratch/probe_d11_stamps.py`): old-schema DB migrates in place;
  unconsumed row consumed_at NULL; consume stamps consumed_at while decided_at
  stays exactly the approval time; second claim refused (D2 atomicity
  untouched); record exposes both stamps.
- **Deviations:** none material (migration loop now carries column types).
- **Commit:** `ac5c577`.

### D10 — finding 8 (MEDIUM): audit chain honest claims + head notarization ✅

- **Delegated:** make audit-chain claims honest everywhere; add
  `audit-notarize` (operator-owned anchor file outside the data dir, or
  print for out-of-band storage) and extend `audit-verify` with notary
  comparison (INTACT / GROWN / DIVERGED). Subagent completed in ~388s, TDD
  (15 new tests), left uncommitted.
- **Verification (independent):** full suite re-run — 102 passed; diff review —
  audit_checkpoints() is a read-only walk with audit_verify delegating to it
  (chain computation unchanged, same (ok,msg) semantics); notary file parsed
  strictly; three verdicts with distinct messages; no-notary path says plainly
  "internal chain check only … NOT evidence against a wholesale rewrite";
  README claims corrected; audit_notary_path added to SETTINGS_SPEC but NOT
  SECURITY_KEYS. Probe (`cache/scratch/probe_d10_notary.py`): anchor verifies
  INTACT; growth after anchor reports GROWN with the correct count; THE
  finding-8 scenario — an early entry rewritten and the whole chain
  recomputed so the internal check PASSES — is caught as DIVERGED by the
  notarized head; truncated log DIVERGED; no-notary phrasing honest.
- **Deviations accepted:** audit_notary_path as the default for --to/--notary;
  one shared chain implementation instead of two.
- **Commit:** `7bfceee`.

### D9 — findings 2 (CRITICAL arch) + 20 (MEDIUM) + 15 (HIGH): threat model ✅ (honest partial)

- **Delegated:** write the residual-risk threat model for findings 2/20/15
  with only feasible code mitigations (dispatch-binding contract, no
  auto-registration invariant), explicitly NOT claiming a local plugin defends
  against an agent-controlled process or the final executor. Subagent
  completed in ~170s, self-reported partial, TDD (3 new tests), left
  uncommitted.
- **Verification (independent):** full suite re-run — 87 passed; diff review —
  the hook re-derives the stored canonical payload and checks it against BOTH
  the hook call and the indexed binding before consuming; gate_verify exposes
  approved_tool_call + dispatch_binding and refuses a differing requested
  tool_call; threat-model doc names operator-owned trust anchors, refuses to
  invent an agent-vs-human context signal, and lists concrete deployment
  controls; probe (`cache/scratch/probe_d9_dispatch_fresh.py`, fresh row per
  scenario so each block is attributable): control dispatches and consumes;
  payload/index mismatch refused BY THE CONSISTENCY CHECK (message confirmed);
  a fully self-consistent re-bound hostile payload refused.
- **Residual, accepted deliberately:** findings 2 and 20 are deployment
  requirements (root-owned install, operator-owned pins, no agent-reachable
  bootstrap/pin, out-of-band registration); finding 15 remains unless the
  final executor enforces the same canonical binding hash or a separate
  broker owns that boundary. The threat-model doc records this — no "fully
  fixed" claim for an architectural finding.
- **Commit:** `32805bc`.

### D8 — findings 18 (HIGH) + 12 (MEDIUM): pin ceremony ✅

- **Delegated:** validate P-256 public PEM before any write; create pin files
  exclusively with O_EXCL|O_NOFOLLOW, mode 0600, fsync; refuse replacement
  and report CLI failures clearly. Subagent completed in ~257s, TDD (6 new
  tests), left uncommitted.
- **Verification (independent):** full suite re-run — 84 passed; targeted pin
  tests — 7 passed; diff review — validation occurs before filesystem access,
  final destination is opened directly with exclusive/no-follow flags, bytes
  are fully written and fsynced, and CLI catches read/write/ValueError paths.
  Probe (`cache/scratch/probe_d8_parent_unique.py`): malformed PEM, RSA, and
  wrong-curve keys rejected with no pin; valid pin mode 0600; second pin
  refused with original bytes preserved; symlink destination refused and
  target untouched.
- **Deviations:** none material. The owner-derived filename remains
  predictable by design; collision-resistant naming is explicitly deferred to
  D17.
- **Commit:** `a763ad6`.

### D7 — finding 16 (HIGH): enforcement config agent-mutable ✅

- **Delegated:** classify security-critical setting changes by direction;
  require a passkey approval of an exact server-derived phrase for weakening
  (`require_passkey` off, pattern removal, allowlist addition), leave
  strengthening free, audit every critical change before applying. Subagent
  completed in ~603s, TDD (12 new tests), left uncommitted.
- **Verification (independent):** full suite re-run — 78 passed; static scan
  found no hardcoded secrets, shell injection, eval/exec, or unsafe
  deserialization in added lines; probe
  (`cache/scratch/probe_d7_finding16.py`): 19/19 passed — unauthenticated
  weakening refused and leaves enforcement active; exact phrase and recovery
  URL emitted; approved weakening applies; approval cannot transfer between
  settings; strengthening applies without approval; config_changed audit
  entries contain old/new/approved fields; refused attempts create no audit
  entry; audit chain remains intact.
- **Deviations accepted:** two existing tests were updated because they
  asserted the pre-fix unsafe behavior; one settings test was updated for the
  new fail-closed allowlist policy. The underlying reload contract remains
  covered.
- **Commit:** `a5a0cf9`.

### D6 — findings 6 (HIGH) + 19 (HIGH): parent-chain verification ✅

- **Delegated:** full local crypto verification of fetched parent records
  (call check(), don't modify it), action_text added to the /verify record,
  child/parent hash-equality policy with three verdicts. Subagent completed
  in ~344s, TDD (5 new tests), left uncommitted.
- **Verification (independent):** full suite re-run — 66 passed; diff review —
  verify_parent_approval now requires the claim to match the record (action
  hash AND challenge id), requires action_text/origin/rp_id for local
  verification, runs check() against the pinned key, then applies the
  equality policy; gate_core changes limited to the two allowed (pass child
  sha, add action_text to the record); probe
  (`cache/scratch/probe_d6_parentcheck.py`, live stub parent gate): the
  finding-6 exploit — fabricated record carrying the correct pinned key with
  no assertion — rejected; genuinely-signed record for the SAME action ->
  'verified — the same action was signed on peer's gate'; real approval for a
  DIFFERENT action -> 'context only', never verified; claim/record mismatch
  and garbage-signature records -> unverified.
- **Deviations accepted:** 3 existing tests updated (they encoded the
  pre-fix vulnerable verdicts); challenge_id claim-matching added as an
  in-scope hardening.
- **Commit:** `89d2264`.

### D5 — findings 5 (HIGH) + 23 (MEDIUM): SSRF + redirect fetches ✅

- **Delegated:** parent-gate allowlist (fail-closed default), no-redirect
  fetches everywhere, strict URL parsing, private-network blocking.
  Subagent completed in ~603s, TDD (14 new tests, all RED first), left
  uncommitted. New shared module plugin/netfetch.py.
- **Verification (independent):** full suite re-run — 61 passed; diff review —
  parse_gate_origin (no credentials, host required, https/loopback-http only),
  origin_allowed exact match, private-range blocking with IPv4-mapped handling,
  RedirectBlocked opener used by every fetch; probe
  (`cache/scratch/probe_d5_verify.py`, live stub servers): unlisted parent
  base rejected with ZERO fetches; dead-port base rejected on allowlist
  grounds (no network attempt); allowlisted base fetched and pinned-key
  verified; 302 redirect refused, canary never touched; credential-carrying /
  hostless / ftp parent bases rejected at mint; cmd_set origin parse-validated.
- **Deviations accepted:** tests/test_cross_human.py adapted to allowlist its
  stub parent gate (required by the new fail-closed default); shared
  netfetch.py module instead of duplicating helpers (netfetch is now the one
  fetch path for the whole plugin).
- **Bonus:** the child patched the hermes-plugin-development skill, whose
  origin-validation example was the exact prefix-check anti-pattern finding 23
  proved dangerous.
- **Commit:** `506e8d9`.

### D4 — findings 17 (HIGH) + 7 (MEDIUM, stale-config half): fail-closed config ✅

- **Delegated:** distinguish not-configured from configuration-failed (block on
  the latter), wire a _config_error marker through the hook and gate_challenge,
  invalidate the cache on `set`, reload on settings mtime change. Subagent
  completed in ~390s, TDD (6 new tests), left uncommitted.
- **Discovery beyond the review:** Hermes's own config loader silently serves
  DEFAULTS when config.yaml is unparseable — a naive "load succeeded" check
  would miss the broken-config case entirely. The fix consults the runtime's
  recorded parse-failure state (hermes_cli config_read_errors) and fails closed
  there too.
- **Verification (independent):** full suite re-run — 47 passed; diff review —
  _load_config_state returns require_passkey=True + marker on failure, hook
  blocks on the marker, gate_challenge refuses prose-only challenges while
  patterns can't be evaluated (bound challenges still mint), cmd_set
  invalidates, stamp = path/mtime_ns/size/ino/ctime_ns; probe
  (`cache/scratch/probe_d4_parent.py`): simulated settings-store failure →
  hook blocks with the reason; no-config → default-off preserved, no marker;
  prose-only refused under error; out-of-band settings edit → reloaded on the
  next verdict without restart.
- **Deviations:** none material (register() now seeds via apply_config_safe —
  fail-closed from the first moment).
- **Commit:** `f618f0e`.

### D3 — findings 14 (HIGH) + 9 (LOW): challenge binding + never-raise ✅

- **Delegated:** bind local verification to the exact recorded challenge
  (finding 14) and make local_verify.check() exception-free (finding 9).
  Subagent completed in ~219s, TDD (2 new tests), left uncommitted.
- **Verification (independent):** full suite re-run — 41 passed; diff review —
  signed challenge must equal rec.challenge_b64url as decoded bytes with the
  prefix check kept, per-field guards plus a last-resort blanket; probe
  (`cache/scratch/probe_d3_independent.py`): legit same-nonce record still
  verifies clean; the exploit — same valid signature replayed against a
  different record's nonce with identical action text — rejected with
  'signed challenge does not match the recorded challenge'; 7 hostile record
  shapes (missing assertion, garbage b64, non-dict, int, None, list client
  data) all return problem lists, never raise.
- **Deviations accepted:** non-string action_text gets its own guard message;
  a last-resort except appends 'record malformed' rather than letting
  anything escape. Both strengthen the never-raise contract.
- **Commit:** `dcbdb4a`. **Standing follow-up:** Autumn's personal
  `verify_local.py` (the proved original, outside this repo) needs the same
  two fixes — offer to patch after the campaign.

### D2 — findings 3 (CRITICAL) + 4 (HIGH): atomic claim-and-consume ✅

- **Delegated:** make consume() the atomic adjudicator (one conditional
  UPDATE with expiry), block on False in hook_verdict, enforce expires_at at
  lookup/consume/verify, fail-closed exception wrapping. Subagent completed
  in ~231s, TDD (6 new tests first), left uncommitted.
- **Verification (independent):** full suite re-run by parent — 39 passed;
  diff review — consume() claim is a single UPDATE (rowcount==1 wins),
  challenge_status returns bare 'expired' (no signed payload) for stale
  approvals, hook_verdict try/except blocks on any failure; probe
  (`cache/scratch/probe_d2_independent.py`): 8-way consume race → exactly
  one winner; sequential re-use blocked; stale approval dead at lookup,
  consume, hook, and verify; injected exception → block, never allow.
- **Deviations:** none material. The fail-closed wrap also landed part of
  finding 7's fix here — D4's scope narrowed to config-load caching +
  config reload (no re-wrap needed).
- **Commit:** `36a193e`. **Follow-up outside this repo:** Autumn's personal
  `verify_local.py` (the proved original the plugin's local_verify was
  ported from) shares the finding-14 gap fixed next in D3 — flag for a
  matching patch once D3 lands.

### D1 — finding 1 (CRITICAL): bound tool call now rendered ✅

- **Delegated:** persist the canonical tool_call, render it on the approval
  page, include it in /verify and gate_verify, reject enforced prose without
  a binding. Subagent completed in ~226s, TDD (4 new tests first).
- **Verification (independent):** full suite re-run by parent — 33 passed;
  diff review — migration follows the existing ALTER TABLE pattern, page
  block HTML-escapes the canonical JSON, canonical_binding_json() keeps
  page/verify/hook byte-identical; adversarial probe
  (`cache/scratch/probe_d1_independent.py`) replayed the review's exact
  exploit (prose "List the workshop directory…" bound to
  `rm -rf ./projects`): destructive call visible+escaped on the
  page, page JSON hashes to the enforced binding, enforced prose with no
  binding rejected.
- **Deviations accepted:** /verify carries the canonical call as a byte-exact
  JSON string (hashable against binding_sha256); gate_challenge's pattern
  check matches action_text when no tool_call exists (only signal present).
- **Commit:** `4956b48`. Deferred refinement (not blocking): deriving
  action_text from the tool_call at mint time.

