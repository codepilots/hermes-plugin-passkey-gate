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
| D12 | 11 — challenge creation rate limit | LOW | 🔄 | delegated |
| D13 | 21+13 — sign-count validation + clone-detection limits | MEDIUM | ⬜ | |
| D14 | 22 — regex pattern validation + safe block-message display | MEDIUM | ⬜ | |
| D15 | 24 — cloudflared reader deadline | MEDIUM | ⬜ | |
| D16 | 25 — tailscale exact-rule cleanup | MEDIUM | ⬜ | |
| D17 | 26 — owner-slug collision-resistant pin filenames | LOW/MED | ⬜ | |
| D18 | 27 — bearer-readable verify records: minimize + document | LOW/MED | ⬜ | |
| D19 | 28 — numeric setting range validation | LOW | ⬜ | |

## Log

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

