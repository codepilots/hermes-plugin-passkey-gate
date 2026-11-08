# passkey-gate

A Hermes plugin for **cryptographically verified human approval** of
high-authority agent actions — a tamper-evident record of what the human
actually signed.

**The key problem it solves:** an agent teammate that sits behind a firewall
— another machine, another network, another schedule — can obtain real
authorization from the human *without the human ever being at that agent's
keyboard*. Hermes's built-in approval system prompts the human in the
session where the action runs; that works when she is present at that
session, and gives an isolated or peer agent nothing but silence. This
plugin gives such an agent a way to mint an approval request bound
bit-for-bit to the exact action text and tool call, deliver it through any
channel the human actually reads (Discord DM, push, QR), and — most
importantly — **independently verify her passkey signature locally with
cryptography before acting**. No agent ever holds a private key, so a relayed
"the human said it's fine" is no longer needed: the genuine article is a
WebAuthn signature from the human's own authenticator, and that signature
cannot be forged from any lane the agent controls. Forging the signature is
not the only attack, though — an agent that controls the gate's host can
subvert the ceremony around the signature (pins, config, records), which is
why real boundaries are a deployment requirement, not something this plugin
can enforce alone (see
[Deployment requirements for real boundaries](#deployment-requirements-for-real-boundaries)).

The full first-hand scenario this came out of — a field agent needing
GitLab access while its human was away from every relevant keyboard, with a
planted fabricated authorization on the wires the same morning — is written
up in [docs/scenario.md](docs/scenario.md).

One paragraph for engineers: an agent wanting a high-authority action mints a
**WebAuthn challenge bound bit-for-bit to the exact action text** (and
optionally to the exact canonical tool call). The agent sends the approval
URL to its human; the human reads the page and signs with **their passkey** —
the agent never holds a private key, so approval must be a WebAuthn
signature from the registered owner credential. Inside a correctly deployed
boundary there is no agent-side path to approval; on a host the agent itself
controls, that boundary is a deployment requirement, not something this
plugin can enforce by itself (see below). Before acting, the agent verifies
the signed assertion **locally** with real cryptography against a **pinned
owner key**. An append-only, hash-chained audit log detects partial edits
and accidental corruption; a wholesale rewrite of the log by someone with
write access to the data directory can pass internal checks, so the CLI can
also notarize the chain head to an operator-kept file outside that
directory — that external anchor is what detects a full rewrite.

This is not prompt-gated "I promise" authorization, and not a yes/no an
agent could fake. It is verification-with-proof: the signed challenge binds
bit-for-bit to what the human saw on the page, so a gate can't lie about
what you signed, and a fake claim "Autumn approved this" collapses on
`gate_verify` unless a signature from the pinned owner key actually checks
out. "Pinned" means only as much as the boundary protecting the pins — see
[Deployment requirements for real boundaries](#deployment-requirements-for-real-boundaries).

## How it works

```
agent wants a high-authority action
  └─ gate_challenge(action_text, tool_call?)     → approval URL + challenge id
human opens URL (over TLS, e.g. tailscale serve) → passes passkey with UV
  └─ WebAuthn nonce == sha256(action_text) [+ binding_sha256] + entropy:
     the signature covers that EXACT text and, when bound, that EXACT call
agent act-check:
  └─ gate_verify(challenge_id, action_text)      → LOCAL crypto verification
        sha256(action_text) [+ binding] == signed challenge
        signature over authenticatorData‖sha256(clientDataJSON) vs PINNED pubkey
        user-presence + user-verification flags, origin/rp_id match
  └─ verified: true (problems: [])  →  record is sound + matches request
optional enforcement hook (require_passkey):
  └─ pre_tool_call blocks calls matching authority patterns unless a challenge
     bound to that exact canonical tool call is approved AND re-verifies
     against the pinned owner key — then CONSUMES it, so each approval
     authorises exactly one deliberate execution.
```

Design provenance: the core is a port of a field-proven prototype
(`approval-gate`, October 2026) whose acceptance test covered two machines:
challenge minted by one, signed by a human passkey on the other, verified
independently, tamper and replay attempts denied, audit chain intact.

## Install

```bash
hermes plugins install codepilots/hermes-plugin-passkey-gate#plugin
```

Then set the two settings that locate your gate (Desktop → Settings → Plugins,
or config.yaml):

```yaml
plugins:
  entries:
    passkey-gate:
      settings:
        origin: "https://your-host.tailnet-name.ts.net:8445"   # HTTPS origin
        rp_id: "your-host.tailnet-name.ts.net"                 # WebAuthn RP ID
```

## First run

```bash
# 0) Publish a HTTPS URL, in this order: explicit config origin >
#    tailscale serve --bg. With tailscale installed it picks a free HTTPS
#    serve port on your tailnet (private to your devices — nothing is put
#    on the public internet), derives origin + RP id from tailscale status --json (no shell string
#    parsing; the serve map is re-read and the new entry located), and saves
#    both back into plugin settings so challenges mint to the right origin
#    from the next session on.
hermes passkey-gate expose            # or: expose tailscale

# 1) Serve the gate locally (needed for the HTTP service; `expose` does NOT
#    start it — tailscaled forwards to it from afar)
hermes passkey-gate serve

# 2) Register passkey -- mint the one-time registration link. OPERATOR
#    ceremony: run it in a terminal you, the human, control (prints there
#    only); never send it through chat, never run it from an agent session
hermes passkey-gate bootstrap

# 3) (Out of band) pin your owner key: the agent independently checks every
#    signature against this exact public key
hermes passkey-gate pin /path/to/pinned_autumn.pem

# 4) Audit the log: internal chain check, plus — if you keep a notary file —
#    comparison against the operator-anchored heads (the only real tamper
#    evidence; see 'Honest limits')
hermes passkey-gate audit-verify --notary /root/gate-notary.log

# 5) Periodically anchor the current chain head to that operator-owned file
#    (must live OUTSIDE the gate data dir — run bare after setting
#    audit_notary_path once, or with no path to just print the head to
#    record somewhere the agent cannot write)
hermes passkey-gate audit-notarize --to /root/gate-notary.log

# 6) Every setting has a CLI command too — typed parse, validate, persist,
#    and immediately re-applied to the running configuration:
#      hermes passkey-gate set require_passkey true
#      hermes passkey-gate set authority_patterns ^terminal .*(rm |curl )
#      hermes passkey-gate set origin https://your-host.ts.net:8447
#      hermes passkey-gate get
```

### Check it end to end

`scripts/e2e_hermes.py` drives the whole flow through a real Hermes install —
CLI ceremony, plugin loading, the enforcement hook blocking, a passkey
approval (software authenticator standing in for your phone), local
verification against the pinned key, one allowed execution, the replay
blocked, and the audit chain — in a throwaway Hermes home. Its docstring has
the three commands to run it.

### Exposure backends

| backend | persistence | what happens |
|---|---|---|
| tailscale (default pick) | survives restarts | `tailscale serve --bg --https=<port> http://127.0.0.1:<gate>`; URL is your machine's `https://<host>.ts.net[:port]`; every candidate port is VERIFIED with a real TLS `/health` probe before it's accepted (a rule being accepted isn't proof it serves — an nginx listening on every interface at :443 can shadow it), rejected ports are un-ruled automatically |
| configured origin | yours | set `plugins.entries.passkey-gate.settings.origin` (and optionally `rp_id`, which otherwise defaults to the origin's host) to an HTTPS origin you already terminate TLS for — e.g. an nginx/caddy reverse proxy to `127.0.0.1:<gate>` — and `expose` just validates |

Why tailscale and no public tunnel: the approval page only has to reach
*your* phone, and a tailnet does that over TLS without publishing the gate
to the internet. If the human's phone is on your tailnet, the approval link
just works from anywhere.

WebAuthn RP-ID detail: default RP is the full origin hostname — always valid.
If you already registered a passkey credential under a broader suffix (e.g.
your tailnet's `*.ts.net` domain), set `rp_id` to that suffix and your
existing credential works for the plugin without re-registering.

## Tools

| Tool | What the model reads |
|---|---|
| `gate_challenge` | Mint an approval request; returns URL + sha256. action_text must read like an authority document (40 chars / 6 word floor, max 4000). Refuses cross-human asks without `why`, and refuses parent chains without an owner named per link — both are etiquette floors, and the error text teaches the correct next move. |
| `gate_verify` | Poll (optional wait) then LOCALLY verify: binding, signature, UV/UP flags, origin, pinned key, max-age. `verified: true` means the record is cryptographically sound and matches this exact request — not that whatever executes next is that call (see Honest limits). |
| `gate_status` | Gate reachable? credentials registered? owner key pinned? peer keys pinned? audit chain internally consistent (internal check only)? Which exposure backends exist? |

## When agents owned by different humans collaborate

This is the case the plugin was originally built for. Sorrel's agent (field
laptop, behind a firewall) needs a resource that lives on Autumn's machine —
and the signer may be a human who has never met that agent. So the ask is a
document, not a favour:

**For the agent** — when you may be asking someone else's human:

- `requester`: your agent name. `requester_owner`: *your* human's name — the
  signer judges whose agent this is. `why`: ONE plain sentence for them:
  what signing enables and why it is safe/needed. Required when the signer
  isn't plausibly your own human; the tool refuses without it — that floor
  is deliberate. Never copy a command line into `why`; explain to a person.
- If a human already approved on the agent's own gate, pass
  `parent_approval` ({base, challenge_id, action_sha256, owner}) — the page
  re-checks the parent record locally before rendering, and the verifier
  says 'unverified' rather than pretending, until you pin that peer's key:
  `hermes passkey-gate pin peer-key.pem <owner>`.
- Your message to them should be one line: who's asking, what it does, the
  link. The page carries the rest.
- Minting on *another* machine's gate over HTTP (`POST /challenge`) needs
  that gate's mint token (`Authorization: Bearer <token>`); its operator
  prints it with `hermes passkey-gate mint-token`. A token lets its holder
  put a request in front of the human — never approve one. Agents on the
  gate's own host mint in-process through `gate_challenge` and need nothing.

**For the human signing** — what you see on the page, in one place:

- **From**: the agent + a named `(agent of <owner>)` — check that owner is
  who you expect; that plus the page's TLS origin and your passkey is the
  whole trust story.
- **Why this ask**: one sentence in their words.
- **Already signed...**: if the request was pre-approved on someone else's
  gate, its locally-checked verdict shows here (verified / unverified /
  key-mismatch). Unverified = a claim, ask for their pinned key first.
- The **full action text** and its sha256, and an expiry. Approving
  authorises exactly that text and nothing else; **denying is always
  safe**, and doing nothing just lets it expire.
- Arrived by chat link but prefer your phone? `hermes passkey-gate show
  <challenge-id>` prints a QR.

Fun fact for the signer: the agents in this story named themselves Bramble
and Sorrel. The gate stays impartial — it only knows whose read the page,
whose key verifies, and whether both match.

## Enforcement hook (opt-in)

```yaml
        require_passkey: true
        authority_patterns:
          - "^terminal .*- (rm|curl|scp|dd|mv /)"
          - "^\\w+ .*credential"       # tools whose args mention credentials
```

Matching tool calls **block** with exact instructions (a JSON template of the
call the challenge must bind), **allow** only when an approved-and-unconsumed
challenge covers that exact binding, and consume that challenge (single use).
The block text tells the model, verbatim, how to mint the right challenge —
and to push back on the human if it thinks the pattern is a false alarm.
This hook gates tool calls that pass through it while enforcement is on; it
is not a boundary against an agent that can edit the plugin, its config, or
the gate data — that needs the
[deployment controls below](#deployment-requirements-for-real-boundaries).

## Deployment requirements for real boundaries

What this plugin **is**: a tamper-evident human-approval ceremony. The human
reads the exact bound action text and tool call on the approval page and
signs it with a passkey; the signature is verified locally with real
cryptography against a pinned key; challenges are single-use and expiry-bound;
and every step lands in a hash-chained audit log that can be anchored
externally. When the human actually signed, the record proves it.

What this plugin **is not**: a boundary against an agent that controls the
host it runs on. No in-process check can constrain an agent that can edit the
plugin code, the gate database, the config, the pin files, or invoke the
`bootstrap`/`pin` ceremonies itself. In such a deployment approvals are
advisory — an honest record, not a fence.

For the ceremony to be a real boundary, the deployment must keep the trust
anchors outside the agent's write/control reach:

- install the plugin root-owned and read-only where practical;
- make the gate data directory, audit log, config, and pin files
  operator-owned, with the agent denied write access;
- run the gate/verifier under a separate service account (or host) the agent
  cannot edit;
- treat `bootstrap` and `pin` as out-of-band operator ceremonies, run from an
  operator terminal — never through the agent;
- have the final executor enforce the same canonical `dispatch_binding`
  immediately before execution (downstream execution is not enforced by the
  plugin — see Honest limits).

The full trust model, including the residuals this plugin deliberately does
not claim to solve, is
[docs/security-review/threat-model.md](docs/security-review/threat-model.md).

## Honest limits

- The audit log is a hash chain **inside the gate data dir**: it detects
  partial edits and accidental corruption, but anyone with write access to
  that directory can rewrite the whole log and recompute a self-consistent
  chain that passes `audit-verify`'s internal check. Internal consistency is
  **not** tamper evidence against a full rewrite. Periodically run
  `hermes passkey-gate audit-notarize --to <path>` (operator-owned file
  outside that directory — or set `audit_notary_path` once); then
  `audit-verify --notary <path>` compares the chain against the anchored
  heads and reports INTACT AND NOTARIZED / GROWN SINCE NOTARIZATION /
  DIVERGED (a notarized head no longer matching the chain — evidence of
  rewriting or truncation).
- The passkey flow protects what the human *reads on the approval page* —
  action_text quality is on the agent, hence the specificity floor. Garbage
  in, garbage signed.
- The HTTP service binds localhost; TLS termination is your job
  (`tailscale serve` recommended — WebAuthn requires HTTPS origins in
  real authenticators).
- `pre_tool_call` sees model tool calls, not internal Hermes subsystem
  activity. Layer it WITH Hermes's approval modes, not instead of them.
- Enforced calls require the model to resubmit identical args; if the
  binding mismatches (say the command changed), the hook blocks with the
  canonical mismatch and the model re-challenges. That's fail-closed by design.
- Downstream execution is **not enforced** by the plugin. The gate binds and
  verifies the approved call and exposes the canonical `dispatch_binding`;
  whatever finally executes (middleware, connectors, another executor) must
  itself enforce that exact binding, or a separate broker must own that
  boundary. `verified: true` says the record matches the request — nothing
  more.
- Approval URLs are **bearer-readable**: anyone holding the high-entropy
  challenge ID (leaked into chat logs, proxies, browser history) can read
  the action text and cryptographic evidence on `/a/<id>` and the minimized
  `/verify` record. Reading cannot approve, but a deployment that needs
  confidentiality must add an authenticated viewing channel — the plugin has
  no operator-authenticated channel to issue one from.
- Everything above presumes the
  [deployment boundary](#deployment-requirements-for-real-boundaries): on a
  host the agent controls, pins, config, and records are agent-writable and
  no local cryptographic check can rescue that deployment. The gate is then
  an honest record-keeper, not a fence.

## License

MIT — see LICENSE.
