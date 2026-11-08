# Changelog

All notable changes to passkey-gate are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.2] - 2026-11-08

### Security

- **More settings are gate-weakening:** raising `challenge_ttl` (approvals
  stay spendable longer) and changing an `origin` or `rp_id` that is
  already set now need a passkey approval of the exact change, like turning
  enforcement off. Lowering the TTL and first-time setup stay free. `expose`
  no longer overwrites an established origin; it says to use the approved
  `set origin` path. If the current origin is dead, the operator can still
  edit the Hermes config file directly. [H11]
- **DNS rebinding closed on parent-gate fetches:** the host is resolved once,
  every address is checked, and the fetch dials exactly the checked address
  (TLS still verifies the certificate against the hostname). Previously the
  fetch resolved the name a second time, so a DNS answer flipped between the
  check and the connect could steer it to an internal address. [F4]
- **HTTP surface bounded:** a gate-wide cap on non-static GETs (300 per 10 s,
  429 beyond — gate-wide because behind `tailscale serve` every client is
  127.0.0.1), and at most 64 concurrent connections (extra ones are closed
  at once). Trade-off: a flood from inside the tailnet can briefly 429 the
  approval page too, instead of slowing the whole host down. [F5]

### Changed

- `status` / `gate_status` explain an unreachable gate in plain English with
  a next step ("origin not configured — run 'hermes passkey-gate expose'",
  "nothing is listening at … — start 'hermes passkey-gate serve'", TLS,
  DNS, redirect); the exception name moves to `error_type`.
- `docs/scenario.md` no longer mentions the author's travel plans.

## [0.6.1] - 2026-11-08

### Fixed

- **The plugin failed to load in real Hermes (v0.23.0):** `register()`
  called `register_cli_command(name, fn)`, but Hermes's signature is
  `register_cli_command(name, help, setup_fn, handler_fn)`; the TypeError
  aborted the whole plugin — no tools, no enforcement hook, no CLI. The
  test suite's fake context accepted the wrong signature. The command now
  registers with an argparse `setup_fn` + `handler_fn`, a CLI-registration
  failure can no longer take the tools and hook down with it, and the fake
  context matches Hermes's signature exactly. [H12]

### Added

- `scripts/e2e_hermes.py`: end-to-end check through real Hermes (plugin
  manager, tool registry, `pre_tool_call` dispatch, `serve`, CLI ceremony)
  with a software authenticator — 19 steps, all passing against Hermes
  v0.23.0.

## [0.6.0] - 2026-11-08

Hackathon-readiness release: closes the HIGH found by an independent code
review, clears every HIGH finding from Hermes's install-time plugin scanner
(verdict `safe`), and works through the open fresh-review backlog. Ledger:
[docs/security-review/remediation.md](docs/security-review/remediation.md)
(items H1–H9, F3–F7).

### Removed

- **Breaking:** the cloudflared quick-tunnel exposure backend (`expose
  cloudflare`). `expose` now uses `tailscale serve` (tailnet-private HTTPS)
  or validates an HTTPS origin you configure yourself. This also clears the
  scanner's tunnel-service findings, so the plugin installs with a `safe`
  verdict instead of needing confirmation.

### Security

- The `pre_tool_call` enforcement hook re-verifies every approval locally
  against the **pinned owner key** before consuming it, as `gate_verify`
  and `set --approve` already did. Previously an approval signed by any
  registered credential (e.g. one an agent registered itself) satisfied
  the hook. A rogue approval can no longer shadow a genuine approval of the
  same call. [H1]
- **The signature now covers the tool call.** A bound challenge's nonce is
  `sha256(action_text) ‖ binding_sha256 ‖ entropy`; the hook and
  `gate_verify` refuse an approval whose signed nonce does not commit to the
  binding being executed, so rewriting a row's stored call cannot redirect a
  signature. Text-only challenges are unchanged. Bound challenges minted by
  0.5.0 and still pending at upgrade are refused (fail closed; they expire
  within the TTL). [H5]
- **Breaking — HTTP minting needs a token:** `POST /challenge` requires
  `Authorization: Bearer <mint token>` (`hermes passkey-gate mint-token`).
  Anyone who could reach the exposed origin could previously post requests
  under any name or fill the pending cap. In-process `gate_challenge` is
  unaffected. [H6]
- POST endpoints accept `application/json` only (415 otherwise), closing
  cross-site form posts to `/a/<id>/deny`. [reviewer, low]
- Negative `Content-Length` is rejected and handler sockets time out after
  30 s, so one connection cannot pin a server thread. [F5]
- Audit-log appends and chain reads take a cross-process lock (flock on
  POSIX, msvcrt on Windows); the agent and `serve` processes appending
  together no longer break the chain. [F3]

### Fixed

- The default RP ID is the configured origin's hostname when `rp_id` is
  unset (a missing import made it silently fall back to `localhost`). [F6]
- `gate_verify` verifies the stripped action text the gate actually signed,
  so surrounding whitespace no longer fails a genuine approval. [H7]
- `gate_verify` / `gate_challenge` return the error JSON instead of raising
  on non-integer `wait_seconds` or non-string fields. [F7]
- README install command points at the `plugin/` subdirectory
  (`owner/repo#plugin`); test fixtures use a fictional tailnet hostname.

## [0.5.0] - 2026-11-07

Security release. This version closes out the campaign against the
adversarial security review ([docs/security-review.md](docs/security-review.md),
28 findings, finalized 5 Nov 2026): every finding is fixed and independently
verified, or documented as an explicit residual. The per-finding ledger with
evidence is
[docs/security-review/remediation.md](docs/security-review/remediation.md);
the test suite grew from 29 to 155 tests along the way. The minor bump
reflects the changed `/verify` record contract (fields removed) and the
rewritten security posture.

### Changed

- **Breaking — `/verify` record contract:** approved `/verify/<id>` records
  are minimized to the fields needed for parent verification and local
  cryptographic checking (status, challenge id/hash, action text, approval
  time, origin, RP ID, recorded challenge, assertion, credential public key).
  `binding_sha256`, the canonical `tool_call`, `requester`, `created_at`, and
  `audit_head` are no longer exposed; `gate_verify` recovers binding metadata
  from the local database instead. [finding 27]
- Approved challenges now expire at `expires_at` for consumption and
  verification, not only while pending; stale approvals are dead everywhere.
  [finding 4]
- Declared dependency range corrected to `webauthn>=2,<4` (manifest,
  requirements, pyproject) to match the environment the suite is verified
  under; the previous `>=1.11,<2` pin cannot even import the test suite.

### Security

- **The human now signs the exact call that executes.** The canonical tool
  call is persisted with the challenge and rendered verbatim on the approval
  page (the page states plainly that the binding, not the prose, is what
  executes); enforced challenges cannot be minted as prose without a binding;
  the hook re-derives the canonical payload and checks it against both the
  incoming call and the stored binding before consuming, and `gate_verify`
  exposes the approved call and its `dispatch_binding`, refusing a differing
  request. [findings 1, 15]
- **Approvals are single-use under concurrency.** Claim-and-consume is one
  atomic conditional transaction; duplicate concurrent or sequential use is
  refused (verified with an 8-way race probe), and any failure on the consume
  path blocks instead of allowing. [finding 3]
- **Assertions are bound to the exact challenge record.** Local verification
  requires the signed challenge to equal the recorded challenge bytes, so a
  valid signature can no longer be replayed against a different record with
  the same action text; the verifier never raises on malformed input.
  [findings 14, 9]
- **Configuration fails closed.** A settings load failure is distinguished
  from "not configured" and blocks; Hermes's silent serve-the-defaults
  fallback on an unparseable config is detected via the runtime's recorded
  parse-failure state; out-of-band config edits reload without a restart.
  [findings 17, 7]
- **SSRF surface closed.** All server-side fetches (parent approval, origin,
  health, verify) go through one shared no-redirect opener; gate URLs are
  strictly parsed wherever consumed (`set`, `gate_verify`, weakening-approval
  re-checks, parent-approval fetches). Private-network blocking applies to
  parent-gate fetches only, and those must also be on an explicit allowlist,
  empty by default (no fetches at all); the plugin's own-origin fetches do
  no private-network check — that origin is operator-configured and parsed
  when set. [findings 5, 23]
- **Parent approvals are fully verified.** A claimed prior approval is
  fetched and cryptographically verified locally (signature, challenge,
  origin, RP ID, flags) against the pinned peer key, with a child/parent
  hash-equality policy — fabricated records and approvals for unrelated
  actions render as claims, never "verified". [findings 6, 19]
- **Enforcement settings resist the agent.** Weakening `require_passkey`,
  authority patterns, or the parent allowlist requires a passkey approval of
  an exact server-derived phrase; strengthening stays free; every critical
  change is audited before applying. [finding 16]
- **Hardened pin ceremony.** Pin material must parse as a P-256 public key
  before any write; files are created exclusively (`O_EXCL|O_NOFOLLOW`, mode
  0600) and never silently replaced; names are collision-resistant (owner
  fingerprint + key digest), so distinct owners or keys can no longer
  collide on one file. [findings 18, 12, 26]
- **Honest audit chain with external notarization.** Internal chain checks
  are stated to detect partial edits only; `audit-notarize` anchors the chain
  head to an operator-kept file outside the gate data dir, and
  `audit-verify --notary` compares against those anchors (INTACT / GROWN /
  DIVERGED) — that external anchor is what detects a wholesale rewrite.
  [finding 8]
- **Registration is an operator ceremony, never automatic.** Challenge and
  verification paths never create credentials or pin files (covered by
  tests); bootstrap tokens are minted only by the explicit CLI command.
  [findings 2, 20]
- **Clone detection via sign counters.** A presented counter at or below the
  stored baseline is refused as clone evidence; counters advance atomically;
  the offline verifier states plainly that it is not replay protection.
  [findings 21, 13]
- **Authority patterns validated whole at set time** (compile check, length
  and count caps) and rendered safely in block messages (escaped, fenced,
  length-capped), so a smuggled or hostile pattern cannot crash or steer the
  model. [finding 22]
- **Numeric settings are range-validated** at persistence and runtime
  (ports 1–65535, TTLs 1–86400), failing closed on malformed legacy or
  environment values instead of breaking serve or expiring instantly.
  [finding 28]

### Added

- `consumed_at`: consumption time is now recorded without destroying the
  original approval timestamp (`decided_at`); consumed records expose both.
  [finding 10]
- Rate limiting on challenge creation: per-requester pending cap plus a
  global backstop, race-safe. [finding 11]
- `hermes passkey-gate audit-notarize` / `audit-verify --notary` operator
  anchoring (see Security above). [finding 8]
- A concrete deployment threat model stating trust assumptions and residual
  risks: [docs/security-review/threat-model.md](docs/security-review/threat-model.md).
- cloudflared readiness now runs under a hard monotonic deadline with
  process-group teardown — no indefinite hangs, no leaked tunnel processes.
  [finding 24]
- Tailscale `serve` cleanup removes exactly this gate's recorded rule and
  re-reads the serve map to verify foreign rules were untouched. [finding 25]

### Known limitations (residuals, stated honestly)

These are architectural, deliberate, and documented in
[docs/security-review/threat-model.md](docs/security-review/threat-model.md)
— not open findings:

- **An agent that controls the host defeats the boundary.** No process-local
  check can constrain an agent that can edit the plugin code, database,
  config, or pins, or invoke the bootstrap/pin ceremonies itself. Real
  boundaries need the deployment controls in the threat model
  (operator-owned install/data/pins, no agent-reachable bootstrap, separate
  service account or host).
- **Downstream execution is not enforced by the plugin.** The gate verifies
  and binds the approved call and hands the executor a dispatch contract;
  whatever finally executes must itself enforce that exact binding, or a
  separate broker must own that boundary.
- **Approval URLs remain bearer-readable** until a deployment provides an
  authenticated viewing channel. `/verify` records are minimized, but the
  action text and cryptographic evidence are still readable by anyone holding
  the high-entropy URL inputs.
