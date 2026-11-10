# Changelog

All notable changes to passkey-gate are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-11-10

### Security

- **Child processes no longer inherit the agent's environment.** Catalog
  review of `f50b315` found that no `subprocess.run` call passed `env=`, so
  every Hermes provider key reached `tailscale`, `systemctl --user` /
  `launchctl` / `journalctl` / `loginctl`, and the regex timing probe. Each
  call now passes an explicit allowlist from the new `plugin/childenv.py`:
  `PATH`, `HOME` and `LANG` for `tailscale` and the probe, plus
  `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` for the service-manager
  commands. Nothing else from the parent environment is passed. A test
  fails if any `subprocess` call in the plugin omits `env=`.

## [0.8.0] - 2026-11-09

### Added

- **Lanes: choose which conversations need a passkey.** Each agent turn is
  placed in one of five lanes: `local` (you at this computer), `owner`
  (your own chat accounts, listed in the new `owner_senders` setting),
  `others` (anyone else, scheduled jobs, webhooks, unknown origins),
  `bots` (senders the chat platform marks as bots) and `agents` (A2A
  sessions and Hermes peer DMs). The new `gated_lanes` setting lists the
  lanes enforcement applies to. It defaults to all five, so existing
  setups behave as before. `setup` asks which lanes to gate when it
  switches enforcement on, with presets for "everything", "when I'm not
  at this computer" and "only other agents and bots".
- The plugin learns each turn's origin from two documented Hermes hooks,
  `post_gateway_admission` (bot flags) and `pre_llm_call` (platform,
  sender, parent session). A session stays in the strictest lane it has
  seen, and subagents inherit their parent's. A turn with no record is
  gated unless Hermes reports a CLI, TUI, Desktop or ACP session.
- Block messages name the lane that caused them.
- README section "Choosing which chats need a passkey", covering how lanes
  are detected and their limits (bot flags depend on the platform,
  messages that steer a running turn aren't attributed, `owner` is only
  as safe as your chat account).

### Security

- Narrowing `gated_lanes` or adding to `owner_senders` is a weakening
  change: once enforcement is on, `set` needs a passkey approval for it.
  `setup` may set both freely only while it is switching enforcement on
  for the first time, and records that in the audit log.

### Security: the rest of the v0.7 review (A7–A30)

- **Audit flooding (M6).** Requests that name no real approval request,
  bad registration tokens and anonymous errors no longer write audit
  lines. Appending reads only the end of the log instead of the whole
  file, and `/health` no longer carries the audit head.
- **Terminal and page spoofing (M7, L6).** Control, bidirectional and
  invisible characters in the action text, requester, owner, reason or
  parent owner are refused when a request is created; `show` escapes any
  it finds. The approval page shows the bound command first and labels
  the requester, description and reason as the agent's own words.
- **HTTP hardening (L3, L4, L5).** Requests must name the gate's own host
  or `localhost` (DNS rebinding is refused with 421). Traffic about a real
  request has its own rate budget, so a flood can't lock you out of an
  approval. Each connection has a 20-second deadline in total.
- **Request caps (L2).** Requests minted over HTTP by remote agents are
  limited to 50 of the 100 open requests.
- **Peer fetches (L11, L12).** The address filter now refuses every
  non-public address, including 100.64.0.0/10 and Tailscale's
  100.100.100.100. A peer gate whose allowlist entry is a `*.ts.net` name
  may still resolve to a tailnet address. Every response the plugin reads
  is size-capped with an overall deadline.
- **Settings (L7, L8, L15, L16, A28, A29).** A config the check rejects is
  no longer applied to the gate's runtime settings. `set rp_id` is judged
  against the RP ID your passkeys actually use. `set` refuses patterns
  that backtrack catastrophically and request lifetimes under 60
  seconds. Settings reload on a timer if the config file can't be
  located. The config check is armed under a lock and declared in the
  config schema. Moving `audit_notary_path` once set needs a passkey
  approval. `set --approve` and `gate_verify` require the fetched record
  to carry the nonce this gate stored.
- **Robustness (L10, L13, L14, A26, A28, A30).** Control characters in
  service paths are refused. Setup refuses an ambiguous code and warns
  against copying codes from `credentials`. Denying a request that isn't
  pending answers 409, not "denied". Registration and approval recheck
  expiry when they complete. The mint token, the config check and the
  Tailscale record are never read or written through a symbolic link. A
  torn last audit line no longer breaks `gate_status` or new entries, and
  `tool_call` must be an object.

### Changed

- **Minimum Hermes version is now 0.23.0** (`requires_hermes` in
  `plugin.yaml` and the catalog entry). 0.23 is the only version the plugin
  is tested on, and the lanes hooks need it.
- README "What it does on your machine" now discloses everything catalog
  rule 13 asks for (hooks and what they record, config writes, the pattern
  timing process, failure behaviour, who can approve and deny), and the
  catalog entry carries a matching disclosure sentence.

### Upgrading from 0.7.1 or earlier

- Hermes 0.23.0 or later is required.

- The config check (added in 0.7.2) isn't armed on upgraded installs until
  you run `hermes passkey-gate setup` or any `set` once. `status` says
  "not armed yet" until then.
- `challenge_ttl` can no longer be set below 60 seconds with `set`.
- The approval page's deny call now answers 409 for a request that is no
  longer pending; the bundled page handles it.

## [0.7.2] - 2026-11-08

### Changed

- README rewritten: a plain-language pitch with phone screenshots
  (`docs/images/`), a quick start built around `setup` with its requirements
  listed (Tailscale on computer and phone, HTTPS certificates enabled), a
  sequence diagram, and reference tables for commands, settings and tools.
  The security model is stated once (what it is, what it isn't, how to make
  it a real boundary, known limits), and a troubleshooting table is new. The
  install section no longer tells you to set `origin`/`rp_id` by hand.
  The old manual "First run" walkthrough is gone; the commands are in the
  Reference table and in `hermes passkey-gate --help` ("Setting up by
  hand"). New sections: what the plugin does on your machine (commands it
  runs, network use, what it stores), and how direct config edits bypass the
  passkey check on settings.
- `docs/scenario.md` rewritten in plain language. It no longer overstates
  what a compromised gate can do, says which approvals are single-use, and
  links to the threat model.
- Plain-language pass over the text people see: the plugin and setting
  descriptions in `plugin.yaml` (shown in the Desktop app), the CLI help,
  and next-step messages, which now point to `setup` / `pin --code` instead
  of `pin <pem-file>`. A plain summary and glossary open the threat model.
- Threat model updated for v0.7: `setup` is listed with `bootstrap`/`pin`
  as an operator-only ceremony; what typed confirmation codes do and don't
  protect against (a compromised gate, a deliberate 50-bit collision, the
  other pin paths); `service install` runs as the operator's user, so it
  doesn't meet the separate-account control (example system unit given);
  the `/health` instance id is an identifier, not authentication.
- The approval page matches the registration page: a "From" card with a
  status pill and countdown, the action under "What it wants to do", and the
  bound command in a framed warning box (its heading is still "THE EXACT
  COMMAND YOU ARE APPROVING"). The hash and request ID move under
  "Technical details". After approving or denying, the page says what happens
  next. The Approve button is disabled while the passkey prompt is open, and
  a cancel says so plainly.

### Security

- Adversarial review of v0.7.1 and these unreleased changes:
  [docs/security-review/adversarial-review-v0.7.md](docs/security-review/adversarial-review-v0.7.md).
  The core verification held; it found 1 HIGH, 8 MEDIUM and 16 LOW issues,
  queued as A1–A30 in the remediation ledger. Fixed in this release:
- **H1: `setup` could pin a port-squatter's key.** It no longer moves a gate
  that already has an HTTPS address, refuses to send a registration link if
  the address doesn't answer as this gate or the recorded Tailscale rule
  forwards to a different port, and `set port` warns that the address
  doesn't follow. Local health checks no longer follow redirects or read
  unbounded responses, and `expose` checks it's talking to this gate. [A1, A10]
- **M3: the enforcement hook could fail open.** A corrupted config-canary
  file made the hook throw, which Hermes treats as "allow". Any error now
  blocks, and the hook is registered before settings load. (Introduced by the
  canary earlier in this release cycle; never shipped.) [A4]
- **M1: a tool-call approval could authorise a settings change.** Only a
  text-only challenge that passkey-gate itself created for a settings change
  counts now, marked server-side; agents can't use the `hermes-cli` name;
  settings requests get their own warning banner and can't be crowded out by
  the global request cap. [A2, A11, A15]
- **M5: the settings phrase now says what changes** (patterns removed or
  added, enforcement turned off) and names the old and new values, so an
  approval only applies to the state it was granted for. The phrase wording
  changed. [A6]
- **M4: `GATE_DATA` can no longer redirect the trust store inside Hermes**,
  which let one settings approval be replayed. [A5]
- **M2: enforcement patterns.** Patterns also match the decoded argument
  values; the `setup` default now covers dangerous command words in any flag
  order, `find -delete` and all code execution; `setup` offers a strict mode
  that gates every terminal, code and file-edit call; the block message tells
  the model that routing around the gate is a violation; and the docs say
  plainly that patterns are a best-effort list. [A3]

### Added

- **Config canary (finding 17).** `set`, `expose` and `setup` write a random
  check value into the plugin's settings and keep a copy in the gate's data
  folder. If the copy exists but the settings don't carry it (a settings
  reset, an edit that removed them, another profile's config), the gate
  fails closed and refuses to write settings, instead of running with
  enforcement silently off. This replaces a private Hermes import (catalog
  rule 9) that could break on any release and couldn't see removed settings
  at all. `status` shows the check. Limit, documented in the threat model: if
  `config.yaml` won't parse and Hermes has no last-known-good copy, Hermes
  doesn't load the plugin at all, so no plugin check can run.
- A short "Historical record" note at the top of each frozen security review,
  saying which version it describes and where current status lives. The
  reviews themselves are unchanged (the two reviewer reports also gained a
  title).
- `plugin/README.md`: the plugin catalog renders the README from the
  plugin's folder, and there wasn't one.
- `setup` offers to use a passkey that's already registered but not yet
  trusted. Before, a phone that had registered without its code being typed
  refused to create a second passkey for the gate, while `setup` only
  accepted new ones, so re-running it could loop forever.
- `gate_verify` declares its optional `tool_call` parameter, so the model
  knows it can check the exact call it's about to run.
- `requires_hermes` in `plugin.yaml` (catalog rule 14), `license` in
  `pyproject.toml`, and compare links in this changelog.

### Fixed

- **An approved call run with one extra argument got an unhelpful block.**
  In a live run the agent had `{command}` signed, then ran it as `{command,
  timeout: 60}`. That is a different call, so the hook rightly blocked it,
  but its message just said to get a new approval, and the human signed
  twice for nothing. When an unused approval for the same tool shares an
  argument with the blocked call, the hook now names each added, missing
  or changed argument and repeats the approved call to retry. Nothing that
  was blocked before is allowed now. `gate_verify` adds a `dispatch_note`
  (run the approved call exactly, nothing added), and the `tool_call`
  description tells agents to include every argument, timeout and workdir
  included.
- **Deny could say "Denied" when nothing was denied.** If the request had
  already been approved (say, in another tab) or had expired, the page still
  reported a denial. It now says nothing changed.
- `expose` saved the gate's address without an audit record; it now writes
  one.
- `gate_verify` always returned `audit_head: null` (the field `/verify` no
  longer serves); it now reports this gate's audit head.
- Catalog entry: `version` said 0.6.4 while pinning v0.7.1; it referred to
  a README section that no longer exists; it claimed Windows support, where
  pinning would fail (`O_NOFOLLOW`); and its description is now readable.
  Screenshots added.
- Consistency fixes across the docs: the CHANGELOG's 0.6.0 ledger range and
  the CSRF item's tag (H10); finding 12 and 13 severities in the ledger; H8
  superseded by H13; the ledger's stale catalog follow-up; an open-items
  list in the ledger; the `gate_verify` parameter name (`wait_seconds`);
  what `gate_status` reports; what the audit log records; that
  `challenge_ttl` also limits how long an approval stays usable.
- In the "Already signed by another human?" box, the verdict was forced onto
  its own line (a CSS rule made every bold word a block), leaving the rest of
  the sentence dangling.

## [0.7.1] - 2026-11-08

### Fixed

- **v0.7.0 could not be installed non-interactively.** Hermes's install
  scanner rated the background-service hint (the `loginctl enable-linger`
  advice, which mentioned `sudo`) HIGH, so the verdict became `caution` and
  `hermes plugins install` refused without a prompt. The hint now says
  "run this once as an administrator". Scanner verdict is `safe` again, and
  a test keeps privilege-escalation wording out of the plugin tree. [H19]

## [0.7.0] - 2026-11-08

### Added

- **`hermes passkey-gate setup`**: a guided first run. It starts the gate
  (offering a background service), publishes the HTTPS address and checks
  it answers, shows the registration QR, waits for the phone, then asks you
  to type the code the phone shows, and pins only the passkey that matches.
  Optionally it switches on enforcement. Re-running skips finished steps; a
  port held by another program (an older approval-gate, another profile) is
  detected and the wizard moves to a free one. [H18]
- **`hermes passkey-gate service install|uninstall|start|stop|restart|status|logs`**:
  run the gate in the background as a per-user systemd unit (Linux) or
  LaunchAgent (macOS), with `HERMES_HOME` pinned to the installing profile.
  It never runs `sudo`; it tells you when `loginctl enable-linger` is
  needed to keep it up after logout. [H18]
- **Confirmation codes**: every registered passkey has a 10-character code
  (`XXXXX-XXXXX`, Crockford base32 of the key's SHA-256, so no I/L/O/U
  look-alikes). `pin --code <code>` pins by it, and `credentials` lists it.
  `pin --credential` and `pin <pem>` still work. [H18]
- `/health` reports `service` and a non-revealing `instance` id so tools can
  tell this gate from another program on the same port.

### Changed

- **The phone registration page is rewritten.** Before you tap, it says what
  will happen in three numbered steps. Afterwards it shows only "Passkey
  created" and the confirmation code in large type, with one instruction:
  type this code into the computer. The fingerprint moves under "Technical
  details". Cancel, timeout, expired link and already-registered errors are
  explained in plain words, and the button works again after a cancel. [H18]
- `bootstrap` and the bare usage text point to `pin --code` and `setup`.
- README First run leads with `setup` and a background-service section; the
  manual steps stay as reference.

### Fixed

- The "Why this ask" and "Already signed" boxes on the approval page had
  light backgrounds under the page's light text, which made them unreadable.

## [0.6.4] - 2026-11-08

### Fixed

- A running `serve` now re-applies settings when the settings file changes
  (one cached stat per request). Before, it kept the settings it started
  with, so the origin saved by `expose` never reached it and passkey
  registration failed its origin check until a restart. [H17]
- README first-run order: `serve` comes before `expose` (expose proves the
  URL with a real TLS `/health` probe, which needs the gate running).

## [0.6.3] - 2026-11-08

### Fixed

- **The pin step had no real-world path.** The registration page only said
  "Registered. Credential abc…" and nothing exported the public key, so an
  operator with a phone passkey had no PEM to hand to `pin`. The page now
  shows the key's fingerprint; `hermes passkey-gate credentials` lists every
  registered passkey with its fingerprint (and flags extra ones you did not
  register); `hermes passkey-gate pin --credential <id-prefix>` pins the
  entry whose fingerprint you matched. `pin <pem-file>` still works.
  `scripts/e2e_hermes.py` now follows this exact flow. [H16]

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
(items H1–H3, H5–H8, H10, F3, F5–F7; H4 and H9 completed with 0.6.1, F4 with 0.6.2).

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
  cross-site form posts to `/a/<id>/deny`. [H10]
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

[Unreleased]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.6.4...v0.7.0
[0.6.4]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/codepilots/hermes-plugin-passkey-gate/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/codepilots/hermes-plugin-passkey-gate/releases/tag/v0.6.0
