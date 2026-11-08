# Remediation ledger — passkey-gate security review

Tracks the fix campaign for `docs/security-review.md` (findings 1–28).
Process: one finding (or tightly-coupled finding group) delegated per
subagent, sequentially. Each fix is verified independently by the primary
agent (diff review + full test suite + targeted probe), then committed, then
logged here with evidence. Status legend: ⬜ queued · 🔄 delegated ·
✅ fixed+verified · 📝 addressed-by-documentation (residual limitation
explicitly stated) · ⛔ blocked.

**Reading this ledger:** each row or section is one finding and its fix,
with the evidence that it was verified. Probe scripts cited as
`cache/scratch/probe_*.py` were run outside this repository and are not
committed; the test names cited are in `tests/`.

**Open items (8 Nov 2026):**

- A1–A30: findings of the [v0.7 adversarial review](adversarial-review-v0.7.md); A1, A2, A4–A6, A10 fixed, A3/A11/A15 partly, A9 documented, the rest queued (see the end of this ledger).

- H9: a demo recording for the README.
- D1: deferred refinement — derive `action_text` from the `tool_call` at mint time.
- D2/D3 follow-up outside this repo: apply the same fixes to the original
  `verify_local.py` in the `approval-gate` prototype.
- Residuals that are documented rather than fixed (D9: findings 2, 15, 20;
  D18: finding 27) — see [threat-model.md](threat-model.md).

Baseline: commit `cea3fa4` ("docs: catalog entry updated for 0.4.0"),
review as of `69bcd7e` (v0.4.0). Test suite baseline: **29 passed**
(`.venv/bin/python -m pytest tests/ -q`, verified 5 Nov 2026).

Coupled findings are fixed in one delegation where the review itself says
they land in the same code path (noted inline). Original low findings 9–13
fold into items below (9→D3, 10→D11, 11→D12, 12→D8, 13→D13).

## Items

| # | Findings | Severity | Status | Evidence |
|---|----------|----------|--------|----------|
| D1 | 1 — approval page never shows the bound tool call | CRITICAL | ✅ | commit `c564930`; 33 passed; exploit probe green |
| D2 | 3+4 — consume race + approval expiry (atomic claim-and-consume) | CRITICAL+HIGH | ✅ | commit `4b4ace3`; 39 passed; 8-way race probe green |
| D3 | 14+9 — assertion↔challenge binding; local_verify never-raise | HIGH+LOW | ✅ | commit `61df75e`; 41 passed; replay probe green |
| D4 | 17+7 — config-load failure fail-open; stale config reload | HIGH+MEDIUM | ✅ | commit `ab86055`; 47 passed; corruption probe green |
| D5 | 5+23 — SSRF: parent allowlist, strict URL parse, no redirects | HIGH+MEDIUM | ✅ | commit `970dea6`; 61 passed; live SSRF probe green |
| D6 | 6+19 — parent approval: full local signature verify + hash equality | HIGH | ✅ | commit `1836faa`; 66 passed; fabricated-record probe green |
| D7 | 16 — enforcement config agent-mutable | HIGH | ✅ | commit `8819729`; 78 passed; 19/19 exploit probe green |
| D8 | 18+12 — pin ceremony: no silent overwrite, O_EXCL/no-follow, PEM validation | HIGH | ✅ | commit `823c601`; 84 passed; pin probe green |
| D9 | 2+20+15 — threat model, bootstrap hardening, dispatch limitation | CRITICAL (arch) | ✅ (partial, honest) | commit `74568a1`; 87 passed; DB-tamper probe green |
| D10 | 8 — audit chain: honest claim + head notarization | MEDIUM | ✅ | commit `3503e0d`; 102 passed; wholesale-rewrite probe green |
| D11 | 10 — consumed_at column, preserve decided_at | LOW | ✅ | commit `e2c5b45`; 107 passed; stamp/migration probe green |
| D12 | 11 — challenge creation rate limit | LOW | ✅ | commit `1ec2ae2`; 114 passed; race probe green |
| D13 | 21+13 — sign-count validation + clone-detection limits | MEDIUM | ✅ | commit `23c29d5`; 120 passed; live-ceremony probe green |
| D14 | 22 — regex pattern validation + safe block-message display | MEDIUM | ✅ | commit `64cc439`; 125 passed; fence/caps probe green |
| D15 | 24 — cloudflared reader deadline | MEDIUM | ✅ | commit `32b7eaa`; 130 passed; grandchild-deadlock probe green after follow-up |
| D16 | 25 — tailscale exact-rule cleanup | MEDIUM | ✅ | commit `8122027`; 142 passed; 5-scenario rule probe green after follow-up |
| D17 | 26 — owner-slug collision-resistant pin filenames | LOW/MED | ✅ | commit `be6d632`; 148 passed; independent collision/migration probe green |
| D18 | 27 — bearer-readable verify records: minimize + document | LOW/MED | ✅ partial | commit `180447c`; 149 passed; minimized-record probe green; authenticated channel remains deployment residual |
| D19 | 28 — numeric setting range validation | LOW | ✅ | commit `567d772`; 155 passed; independent range/legacy/backend/bind probe green |

## Fresh independent review of v0.5.0 — new backlog

A fresh adversarial review (no campaign context) of HEAD `d572e02` judged
the release **safe-with-residuals**: the core WebAuthn ceremony is sound, no
path approves or executes without the human's passkey, and the honest-claims
documentation was verified accurate. Two HIGH findings are release blockers
(demonstrated by live repro, independently re-run by the parent); the rest
are hardening. Full report frozen at
[docs/security-review/fresh-review-v0.5.0.md](fresh-review-v0.5.0.md).

| Item | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| F1 | gate-weakening `set --approve` approvals replayable (never consumed) | HIGH | ✅ | commit `1f39755`; 159 passed; reviewer probe re-run + parent 4-process/phrase/expiry probe green |
| F2 | catalog entry pins pre-remediation `69bcd7e`, version 0.2.0 | HIGH | ✅ | code `c2e56f1`, pin `7d6e509`; fresh-clone at the pin: 161 passed; catalog honest |
| F3 | audit chain self-corrupts under multi-process writes (process-local lock) | MEDIUM | ✅ | v0.6.0: flock/msvcrt cross-process lock on appends + chain reads; `test_two_processes_appending_keep_chain_intact` fails pre-fix (chain broken at line 2), passes after |
| F4 | DNS-rebinding TOCTOU: SSRF check resolves once, fetch dials again | LOW | ✅ v0.6.2 | `netfetch.fetch_target` resolves once and returns the checked address; `open_pinned` dials it (TLS verified against the hostname); `test_parent_fetch_dials_the_checked_address_not_a_second_lookup` fails pre-fix |
| F5 | HTTP surface: negative Content-Length wedges threads; no GET rate limits | LOW | ✅ | v0.6.0: negative length → 400, 30 s handler socket timeout. v0.6.2: gate-wide GET cap (300/10 s → 429; per-IP is meaningless behind tailscale serve) + 64-connection ceiling; trade-off documented in CHANGELOG; `test_get_requests_are_capped_gate_wide`, `test_connection_ceiling_closes_extra_connections` |
| F6 | `os_default_rp_id` dead code — `import shutil` missing | LOW | ✅ | v0.6.0; import added + RP ID now defaults to the configured origin's host; `test_cli_default_rp_id_prefers_configured_origin_host` |
| F7 | `gate_verify` raises on `wait_seconds='abc'` (never-raise contract) | INFO | ✅ | v0.6.0: typed refusals in gate_verify/gate_challenge; `test_handlers_never_raise_on_bad_types` |
| C1 | "approvals are single-use" overclaim (plugin.yaml:11, schemas.py:24) | claim | ✅ | accurate "single-use when applied" wording, `c2e56f1` |
| C2 | CHANGELOG "all fetches… private-network blocking" overclaim | claim | ✅ | scoped honestly to parent-gate fetches, `c2e56f1` |
| C3 | origin accepted via prefix check in gate_verify/_verify_weakening_approval | claim | ✅ | parse_gate_origin at both sites, `c2e56f1`; parent probe 7 hostile origins/0 fetches |
| C4 | threat-model.md header still says "Applies to: v0.4.0" | claim | ✅ | bumped to v0.5.0, `c2e56f1` |

## Hackathon-readiness review (8 Nov 2026) — new items

Independent code review + install test against Hermes v0.23.0's plugin
scanner. Fixed items shipped in v0.6.0.

| Item | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| H1 | enforcement hook trusted DB `approved` status without checking the pinned owner key — an agent that registered its own software credential could self-approve enforced calls; a rogue approval could also shadow a genuine one for the same binding | HIGH | ✅ v0.6.0 | hook re-verifies via `local_verify.check` against the pin, falls through to any other approved row that verifies; reviewer PoC now blocked; `test_hook_refuses_approval_from_unpinned_credential`, `test_hook_blocks_when_no_owner_key_pinned`; 169 passed at v0.6.0 |
| H2 | Hermes install scanner verdict `caution` (12 HIGH): cloudflared backend + absolute `rm -rf` doc examples — non-interactive install refused | HIGH (release) | ✅ v0.6.0 | cloudflare quick-tunnel backend removed (tailscale serve + configured origin remain); doc examples relativized; CI pip self-upgrade dropped; scanner verdict `safe` (0 HIGH, 82 medium/low informational) |
| H3 | README install command installs the repo root (no plugin.yaml) | HIGH (release) | ✅ v0.6.0 | now `owner/repo#plugin`; isolated install lands as `passkey-gate` |
| H4 | 46 commits (all of v0.5.0) unpushed; catalog pin `c2e56f1` absent from GitHub; CI never ran; GitHub repo description still says "agent-uncircumventable" | HIGH (release) | ✅ | pushed; tags `v0.6.0` (`ef760bb`, does not load in Hermes — see H12) and `v0.6.1` (`5fbc509`); CI green on GitHub at `5fbc509` (170 passed); fresh GitHub clone at the pin: 170 passed, `hermes plugins install codepilots/hermes-plugin-passkey-gate#plugin --ref 5fbc509…` installs with no scanner prompt, documented `scripts/e2e_hermes.py` run 19/19; catalog pinned to `5fbc509`; repo description updated |
| H5 | tool-call binding not covered by the signature (nonce = sha256(action_text) + entropy; binding lives only in DB) | MEDIUM | ✅ v0.6.0 | nonce = sha256(text) ‖ binding ‖ 16B entropy; hook + gate_verify check it; `test_signature_covers_tool_call_binding` fails pre-fix |
| H6 | unauthenticated `POST /challenge` on exposed origin — arbitrary requester names, can fill global pending cap | MEDIUM | ✅ v0.6.0 | `POST /challenge` needs `Bearer <mint token>` (`mint-token` CLI); `test_http_challenge_requires_mint_token` |
| H7 | `gate_verify` hashes raw action_text but lookup uses stripped text — trailing whitespace never verifies | LOW | ✅ v0.6.0 | verify the stripped text the gate signed; `test_gate_verify_tolerates_surrounding_whitespace` |
| H8 | real tailnet hostname in tests/test_expose.py fixtures (`REAL_HOST`) | LOW (privacy) | ✅ v0.6.0 (working tree) | fixtures use `gate-host.example-tailnet.ts.net`; the old name remained in already-public git history at the time — superseded by H13 (history rewritten 8 Nov 2026) |
| H9 | no end-to-end run inside a real Hermes since v0.5.0 (tests use a mocked ctx); no demo media in README | release | ✅ partial | v0.6.1: `scripts/e2e_hermes.py` — 19/19 PASS through real Hermes v0.23.0 (plugin manager, registry, pre_tool_call dispatch, serve, CLI ceremony; software authenticator). Phone-passkey runs over tailscale done by the operator on 8 Nov 2026 (their feedback became H18); phone screenshots in the README since v0.7.1 docs. Still open: a demo recording |
| H10 | CSRF: `/a/<id>/deny` accepted cross-site `text/plain` posts | LOW | ✅ v0.6.0 | POSTs require application/json (415); `test_cross_site_form_post_to_deny_is_refused` |
| H11 | `challenge_ttl` (up to 24 h), `origin`, `rp_id` changeable without passkey approval | LOW | ✅ v0.6.2 | added to SECURITY_KEYS: raising TTL / moving a set origin or rp_id needs approval, lowering + first-time setup free; `expose` refuses to move an established origin; 3 new tests |
| H12 | plugin FAILED TO LOAD in real Hermes: `register_cli_command(name, fn)` vs Hermes's `(name, help, setup_fn, handler_fn)` — no tools, no hook; hidden by a loose test fake | CRITICAL (release) | ✅ v0.6.1 | found by the real-Hermes smoke run (`Failed to load plugin 'passkey-gate': ... missing 1 required positional argument: 'setup_fn'`); strict fake + `test_cli_registers_with_hermes_signature_and_runs`; e2e 19/19 |
| H13 | PII in git history: real tailnet hostname (test fixtures), a real tailnet IP (test fixtures), home/profile paths (docs), and a full shell-environment dump with Discord user/chat/message IDs, session key, user name and hostname in one commit message (a backticked `set` the shell executed) | MEDIUM (privacy) | ✅ | history rewritten 8 Nov 2026 with git-filter-repo (fixtures → `gate-host.example-tailnet.ts.net` / `100.64.0.10`, paths generalized, message restored to its intended text); every commit hash changed — references in these docs and the catalog pin remapped; tags `v0.6.0`/`v0.6.1` moved to the rewritten commits; full-history re-scan finds none of the strings. GitHub kept the old commits reachable by SHA, so the repository was recreated: the old repo was renamed `hermes-plugin-passkey-gate-old` and made private (pending deletion by the owner), and the clean history pushed to a fresh `codepilots/hermes-plugin-passkey-gate` — old SHAs return 404 there; CI green; fresh-clone tests 170 passed; README install + e2e 19/19 at pin `5fbc509`; note: the trees at tags `v0.6.0`/`v0.6.1` still contain their pre-rewrite catalog pins (`9c22772…`, `90df5e3…`), which no longer exist — only HEAD's pin was remapped |
| H14 | `status` showed a bare `"error": "ValueError"` with no origin set — the first thing a new operator sees | UX | ✅ v0.6.2 | plain-English reason + next step for no origin / refused / timeout / TLS / DNS / redirect; exception name kept as `error_type`; 2 new tests |
| H15 | `docs/scenario.md` named the author's travel plans | privacy | ✅ v0.6.2 (current tree) | sentence removed; earlier public commits still contain it (low sensitivity, past date) |
| H16 | pin step had no real-world path: registration page never showed the public key and nothing exported it (the e2e read it from the HTTP response, hiding the gap) | release | ✅ v0.6.3 | fingerprint on the registration page; `credentials` CLI (fingerprints, flags extra passkeys); `pin --credential <id-prefix>`; 3 tests; e2e now follows the page→credentials→pin flow |
| H17 | `serve` never reloaded settings, so the origin `expose` saved didn't reach a running gate (registration fails its origin check); README listed expose before serve, but expose's TLS probe needs serve running | release | ✅ v0.6.4 | serve re-applies settings on change (cached stat per request); README order fixed; e2e step 'running serve picks up a settings change live' |
| H18 | first-run demo feedback: install took eight manual commands across two terminals; on the phone it was unclear what to provide to confirm the key (a 32-hex fingerprint compared by eye, then a credential-id prefix typed from a different screen); the gate only ran while a terminal stayed open; also the 'Why this ask' / 'Already signed' boxes rendered light-on-light | UX (release) | ✅ v0.7.0 | `setup` wizard (start → HTTPS → register → confirm → optional enforcement; skips finished steps; detects a port held by another program via a new /health `instance` id and moves off it); registration page rewritten around one large 10-char confirmation code (Crockford base32, 50 bits of SHA-256 over the SPKI) that the operator TYPES — `setup` / `pin --code` pin only the passkey that matches, and only among passkeys registered after the QR was shown; `service install|uninstall|start|stop|restart|status|logs` (systemd --user / LaunchAgent, HERMES_HOME pinned, never runs sudo); dark-theme fix; 25 new tests (207 total); e2e OK (23 steps); real-pty wizard run through Hermes with a software phone, including the 8655 port conflict; real systemd install/status/restart/logs/uninstall |
| H19 | v0.7.0 install blocked: scanner verdict `caution` (1 HIGH `sudo_usage`) from the `sudo loginctl enable-linger` hint string in service.py (printed, never run) — found by the fresh-clone pinned install | HIGH (release) | ✅ v0.7.1 | hint reworded ('run this once as an administrator'); scanner verdict `safe` (0 HIGH, 11 medium informational); `test_plugin_code_never_mentions_privilege_escalation`; v0.7.0 tag left as published, catalog never pinned to it; v0.7.1 validated at the pin from a fresh GitHub clone (208 passed, pinned install not blocked, e2e OK) and catalog pinned to `e82f224` |

## Log

### F2 + claims C1-C4 — catalog honest, strict origin parsing ✅

- **Delegated:** catalog entry rewritten for v0.5.0 (honest README-backed
  description; version 0.5.0; sha left as a placeholder for the parent to
  pin). C1: single-use wording in plugin.yaml + schemas.py now states the
  exact truth (consumed at apply time for enforced tool-call and
  gate-weakening approvals; text-only verify until expiry). C2: CHANGELOG
  SSRF bullet scoped honestly (private-network blocking + allowlist are
  parent-gate only). C3: gate_verify and _verify_weakening_approval now
  parse the configured origin via netfetch.parse_gate_origin instead of a
  bare startswith prefix check — credential-carrying, hostless,
  off-loopback-http, and scheme-less origins refused before any fetch;
  loopback-http dev tolerance preserved (it lives in the parser). C4:
  threat-model header bumped to v0.5.0. Two C3 regression tests; child
  reported 161 passed.
- **Parent verification:** suite 161 passed (own run). Independent probe
  (`cache/scratch/probe_f2_parent.py`): all seven hostile origins refused
  at BOTH sites with zero fetches; valid https and both loopback-http forms
  pass the origin gate. Static scans clean (one hit was the new test's
  hostile-input fixture string, not a secret).
- **Pin and validation:** work committed as `c2e56f1` (code-complete
  v0.5.0); catalog sha pinned to
  `c2e56f10f60cf2f253d7698d1912ca2ed5051be2` in `7d6e509`. The catalog's
  mandated fresh-clone validation ran against exactly the pinned commit:
  local clone, clean venv, `pip install -r requirements.txt pytest`,
  161 passed in 20.48 s.
- **Commits:** `c2e56f1` (F2 + C1-C4), `7d6e509` (pin).

### F1 — fresh-review HIGH: gate-weakening approvals single-use ✅

- **Delegated:** cmd_set atomically claims the approval at apply time via a
  new `gate_core.consume_approval(cid, action_sha)` — one conditional UPDATE
  (id + status=approved + exact-phrase sha + unexpired) flipping the row to
  terminal consumed with a `consumed_at` stamp, same lock discipline as
  consume(). Honest deviation: consume() could not be reused — weakening
  approvals are minted text-only (binding_sha256 NULL), which its binding
  match can never claim. Replays/race-losers get a single-use refusal naming
  the spent cid; the verify endpoint reports consumed; config_changed audits
  the consumed cid and the claim emits challenge_consumed. TDD RED first
  (consumption, reviewer's replay scenario, 2-thread race); 4 new tests.
- **Parent verification:** suite 159 passed (own run); reviewer's live probe
  re-run — "replay NOT confirmed (approval was burned)", both replays
  refused, re-arm survives. Independent probe
  (`cache/scratch/probe_f1_parent.py`, direct DB-level attack on the claim
  mechanism): single claim then refusal; a mismatched-phrase claim is
  refused WITHOUT burning the approval; approved-but-expired is
  unclaimable; a real 4-process race produced exactly one WIN with the
  row terminal; exactly one challenge_consumed audit record per burned
  approval and none for refusals.
- **Commit:** `1f39755`.

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
  is a stale draft — version 0.2.0, pinning `69bcd7e` (the pre-remediation
  commit the review graded unsafe), with outdated description language.
  It must be rewritten and repointed at the fresh-review-passed commit
  before any catalog PR; it is deliberately untouched here. **Resolved by F2** (pin `7d6e509`) and every later catalog pin.

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
- **Commit:** `567d772`.

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
- **Commit:** `180447c`.

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
- **Commit:** `be6d632`.

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
- **Commits:** `8122027` (both rounds + requirements.txt).

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
- **Commits:** `32b7eaa` (both rounds, one atomic finding-24 commit).

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
- **Commit:** `64cc439`.

### D13 — findings 21 (MEDIUM) + 13 (LOW): sign-count clone detection ✅

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
- **Commit:** `23c29d5`.

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
- **Commit:** `1ec2ae2`.

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
- **Commit:** `e2c5b45`.

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
- **Commit:** `3503e0d`.

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
- **Commit:** `74568a1`.

### D8 — findings 18 (HIGH) + 12 (LOW): pin ceremony ✅

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
- **Commit:** `823c601`.

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
- **Commit:** `8819729`.

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
- **Commit:** `1836faa`.

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
- **Commit:** `970dea6`.

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
- **Commit:** `ab86055`.

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
- **Commit:** `61df75e`. **Standing follow-up:** Autumn's personal
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
- **Commit:** `4b4ace3`. **Follow-up outside this repo:** Autumn's personal
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
- **Commit:** `c564930`. Deferred refinement (not blocking): deriving
  action_text from the tool_call at mint time.

## Adversarial review of v0.7.1 + unreleased (8 Nov 2026) — A1–A30

Findings from [adversarial-review-v0.7.md](adversarial-review-v0.7.md):
four independent reviewers, MEDIUM-and-above re-verified by the primary
reviewer (M3 reproduced in real Hermes v0.23). Status legend adds 🟡 partially addressed.

| ID | Finding | Severity | Status |
|---|---|---|---|
| A1 | H1: setup pins a port-squatter's key (wizard trusts any 200 at the origin; port move leaves exposure pointing at the squatter) | HIGH | ✅ v0.7.2 — setup never moves a gate that has an address; refuses a link if the address doesn't answer as this gate or the recorded Tailscale rule forwards elsewhere; `set port` warns; threat model corrected; 4 tests |
| A2 | M1: tool-call approval accepted as a settings-weakening approval | MEDIUM | ✅ v0.7.2 — `kind='settings'` set only by the CLI; consume/verify require it and no binding; `hermes-cli` requester reserved; page banner; 3 tests |
| A3 | M2: authority patterns are a trivially evaded deny-list; default presented as protection | MEDIUM | 🟡 v0.7.2 mitigated — decoded-value matching, broader default (+ code execution), strict mode in setup, block message forbids routing around, limits documented; a determined agent can still evade a deny-list (approval-transport idea is the fuller fix); 13 tests |
| A4 | M3: corrupted canary file makes the hook fail open (introduced with the canary) | MEDIUM | ✅ v0.7.2 — any canary read error fails closed; hook body wrapped (any exception blocks); hook registered before settings load; `task_id` optional; verified in real Hermes; 2 tests |
| A5 | M4: `GATE_DATA` override lets a settings approval be replayed | MEDIUM | ✅ v0.7.2 — inside Hermes the data folder is always Hermes's; `GATE_DATA` honoured only outside; verified in real Hermes; 1 test |
| A6 | M5: settings-change phrase hides what is removed | MEDIUM | ✅ v0.7.2 — phrase names the change (REMOVES/ADDS, turns enforcement OFF) and old → new values, so an approval only applies to the state it was granted for; 2 tests |
| A7 | M6: anonymous audit-log flooding | MEDIUM | ⬜ |
| A8 | M7: terminal escape sequences via `show` | MEDIUM | ⬜ |
| A9 | M8: approvals bind command text, not what it depends on | MEDIUM | 📝 v0.7.2 — documented in README known limits and the threat model; not fixed |
| A10 | L1: probe/local_health follow redirects; expose/status don't check instance | LOW | ✅ v0.7.2 — `local_health` uses http.client (no redirects, no proxies, bounded read); `expose`'s TLS probe and setup check the instance; 1 test |
| A11 | L2: request cap per self-declared name; global cap starves the CLI | LOW | 🟡 v0.7.2 partial — settings requests no longer starved by the global cap; per-agent quota is still per self-declared name |
| A12 | L3: GET cap lockout lasts as long as the flood | LOW | ⬜ |
| A13 | L4: slow clients fill connection slots | LOW | ⬜ |
| A14 | L5: no Host check (DNS rebinding) | LOW | ⬜ |
| A15 | L6: bidi/invisible Unicode and page imitation in agent text | LOW | 🟡 v0.7.2 partial — `hermes-cli` requester reserved; bidi/invisible Unicode still rendered |
| A16 | L7: rejected config still applied to runtime settings | LOW | ⬜ |
| A17 | L8: `set rp_id` free while a default RP ID is in effect | LOW | ⬜ |
| A18 | L9: upgraded installs not armed; no upgrade note | LOW | ⬜ |
| A19 | L10: newline injection into the systemd unit | LOW | ⬜ |
| A20 | L11: SSRF filter misses 100.64.0.0/10 | LOW | ⬜ |
| A21 | L12: unbounded fetch reads, no overall deadline | LOW | ⬜ |
| A22 | L13: existing-passkey path drops the after-QR restriction | LOW | ⬜ |
| A23 | L14: deny on non-pending returns 200 "denied" | LOW | ⬜ |
| A24 | L15: free strengthening changes can deny service | LOW | ⬜ |
| A25 | L16: cache freshness depends on `get_config_path` | LOW | ⬜ |
| A26 | INFO: registration/approval expiry edges | INFO | ⬜ |
| A27 | INFO: /health activity signal; bearer can deny | INFO | ⬜ |
| A28 | INFO: symlink-following writes; serve record; notary path unprotected | INFO | ⬜ |
| A29 | INFO: canary arming race; schema; fetched-record trust | INFO | ⬜ |
| A30 | INFO: robustness: torn audit line, non-object tool_call, prose guard | INFO | ⬜ |
