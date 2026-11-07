# Changelog

All notable changes to passkey-gate are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
