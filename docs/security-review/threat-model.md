# Passkey-gate threat model and residual architectural limitations

**Applies to:** passkey-gate v0.6.0, security review dated 5 November 2026
(`69bcd7e6` review context; remediation campaign D9). This document preserves
and qualifies findings **2 (CRITICAL), 15 (HIGH), 20 (MEDIUM) and 27 (LOW/MEDIUM)**. It is a
residual-risk statement, not a claim that those findings are eliminated.

**Updated for v0.7.2 (8 November 2026)** for the v0.7 additions: the `setup` wizard, typed
confirmation codes for pinning, the `service` background runner, and the
`/health` instance id. See [v0.7 additions](#v07-additions-setup-wizard-background-service-gate-identity)
and the v0.7 notes under findings 2 and 20. None of these changes the
boundary described below; two of them sit inside it and are called out so a
deployment doesn't mistake convenience for control.

## In plain terms

- **What passkey-gate proves:** that the person holding the pinned passkey
  read a specific request and signed it. Agents can't produce that
  signature, and every agent can check it.
- **What it relies on:** the agent must not be able to change the gate
  itself: its code, settings, database, or the file holding the trusted
  key. If the agent can, it doesn't need to forge a signature; it can change
  what the gate trusts. In that setup the gate is an honest record, not a
  lock.
- **What it doesn't control:** whatever finally runs the approved action.
  The gate checks that the approval matches the request; the thing that
  executes must check it too.
- **What it leaves visible:** anyone who has an approval link can read the
  request. They can't approve it.

The sections below spell out each of these, with the review findings
they come from.

**Terms used here**

| Term | Meaning |
|---|---|
| Passkey / WebAuthn | The standard that lets a phone or security key sign a challenge after a face, fingerprint or PIN check. |
| Pin, pinned key | The owner's public key, stored once during setup; every signature is checked against it. |
| Bootstrap | Minting the one-time link used to register a passkey. |
| Binding, `dispatch_binding` | A hash of the exact tool call an approval covers. |
| Origin, RP ID | The web address the gate is served on, and the domain a passkey is registered to. |
| Bearer-readable | Readable by anyone who has the link; no login needed. |
| Notary file | A file outside the gate's data folder recording the audit log's head, so a full rewrite of the log is detectable. |

## Security boundary and trust assumptions

Passkey-gate can verify WebAuthn assertions and bind an approval to canonical
text and, when supplied, a canonical structured `tool_call`. That verification
is useful only inside a deployment with a boundary the agent cannot alter.
The following must be operator-owned and outside the agent's write/control
authority:

- trust anchors (pinned owner and peer public keys);
- enforcement configuration, including `require_passkey` and authority
  patterns;
- the plugin code and its dependencies;
- the gate database, audit data, pin files, and other verification data; and
- the final dispatch/executor boundary that turns an approved call into an
  external effect.

If the agent can edit any of those, replace or monkeypatch the plugin, alter the
DB, or invoke the pin/bootstrap path, passkey-gate is **not a security
boundary**. Its approvals are advisory in that deployment. No process-local
cryptographic check can defend against a compromised host or process that can
replace code, monkeypatch modules, alter the database, or bypass the hook.

The `bootstrap`, `pin` and `setup` CLI commands are explicit operator
ceremonies, not automatic registration. (`setup`, added in v0.7, runs
bootstrap and pin as one guided flow, so it has the same status as both.) They must be run by an operator through
an out-of-band procedure. The plugin deliberately does not invent an
agent-vs-human context signal: a caller that can invoke these commands is
already inside the assumed control plane. Verification and challenge creation
must not create credentials or pin files; first registration and first pin are
never implicit side effects.

## Finding 2 — agent-controlled trust anchors (CRITICAL)

The local verifier trusts the configured/pinned key and local process state. It
cannot distinguish an operator's pin from an agent-written replacement when the
agent controls the files, process, or CLI. Remediation D8 (finding 18) prevents silent pin
replacement and validates pin material, but that is not a complete security
boundary against an agent that can edit the installation/data directory or
invoke the ceremony itself. Remediation D7 (finding 16) protects the policy path only within the
same assumption.

Required deployment controls are concrete, not optional documentation:

- install the plugin root-owned and read-only where practical;
- make the data directory and pin files root/operator-owned;
- lock configuration and protect it with restrictive filesystem ACLs;
- run the gate/verifier under a separate service account;
- deny the agent access to the plugin install, DB, audit log, config, and pins;
- provide no agent-reachable `bootstrap`, `pin` or `setup` command — the
  `setup` refusal when stdin is not a terminal is a usability guard, not an
  access control: an agent with a pseudo-terminal passes it;
- do not rely on `hermes passkey-gate service install` for this: it runs the
  gate as the installing user from a unit file in that user's home (see
  [v0.7 additions](#v07-additions-setup-wizard-background-service-gate-identity));
  and
- use a separate host/service or broker when the agent and verifier otherwise
  share an unrestricted process/control plane.

With those controls, the operator can treat the pin and bootstrap ceremonies as
out-of-band setup. Without them, the strongest honest description is a local
tamper-evident record of an assertion, not prevention of self-approval.

## Finding 20 — bootstrap/registration ceremony (MEDIUM)

A bootstrap token is one-time and short-lived, but minting it is still an
explicit CLI operation and the first valid WebAuthn registration is not bound to
an already registered operator credential. An agent can initiate that flow, and
an operator can be socially engineered into registering the wrong authenticator.
The code therefore makes no automatic registration claim and does not add fake
authentication based on an unverifiable caller-context flag.

The operator procedure must deliver bootstrap authorization out of band (for
example, a physical/operator-controlled device or an authenticated operator
channel), use the operator's own authenticator rather than a shared agent vault,
and keep the gate and registration data outside the agent's control. For a
stronger deployment, use an operator-controlled bootstrap code/approval and
require an existing credential for additions or replacement; implement that as
an independently authenticated ceremony or broker, not as an in-process claim.

**v0.6.0 mitigation (hackathon-readiness review H1).** Registration is still
not bound to an existing credential, but a credential registered through a
token the agent minted itself no longer buys anything on its own: the
enforcement hook, `gate_verify`, and `set --approve` all re-verify the signed
assertion against the **pinned** owner key, so approvals signed by any other
credential are refused. The residual is now the pin itself — keep
`pin` an operator ceremony and the pin files outside the agent's write reach.

**v0.7 mitigation: typed confirmation codes.** Each registered credential
has a confirmation code: 10 Crockford-base32 characters (50 bits) of SHA-256
over its SubjectPublicKeyInfo. The registration page shows it after the
phone creates the passkey; the operator types it into `setup` (or
`pin --code`), and only the credential with that code is pinned. `setup`
further restricts the match to credentials registered *after* it printed
the QR code, and warns if more than one appeared. This replaces comparing a
long fingerprint by eye and then typing a credential-id prefix, which was
error-prone and easy to get wrong under social pressure.

What it addresses: the "wrong authenticator" case of this finding. A
credential registered by anyone else, including one racing the operator's
own registration with a separately minted token, has a different code, and
nothing is pinned unless the typed code matches.

What it does not address:

- **A compromised gate.** The code is rendered by the gate's own page. An
  agent that controls the gate process or host can display any code it
  likes; that is finding 2, and the deployment controls above still apply.
- **A deliberate collision.** 50 bits is sized for a human to type, not as an
  offline-secure fingerprint. Substituting a key requires a second preimage
  of the victim's code (about 2^50 key generations), a bootstrap token, and
  completing registration inside the operator's ceremony window. Operators
  who want a 128-bit comparison still have it: the full fingerprint is under
  "Technical details" on the page and in `hermes passkey-gate credentials`.
- **The other pin paths.** `pin --credential <id-prefix>` and
  `pin <pem-file>` are unchanged and carry no code check.
- **Agent-run ceremonies.** If the agent can run `setup` itself, it can
  register its own authenticator and type that authenticator's code.

Pins made through `setup`, `pin --code` and `pin --credential` are recorded
in the audit log as `owner_key_pinned`; `pin <pem-file>` is not.

## Finding 15 — final dispatch substitution (HIGH)

`gate_challenge` stores the canonical tool-call JSON and its
`binding_sha256`. `gate_verify` exposes `approved_tool_call` and
`dispatch_binding` (canonical JSON plus hash), and the pre-tool hook recomputes
the exact canonical call, checks the stored call/hash consistency, and refuses a
mismatch before consuming the approval. A caller that supplies a different
`tool_call` to `gate_verify` receives `verified: false`.

These are local binding checks and an API contract, not control of the final
executor. WebAuthn proves user presence/verification for the signed challenge;
it does **not** prove that the final downstream tool execution matches that
challenge. Parent approvals are context/authorization inputs only when the
full local checks pass; they do not solve dispatch-boundary substitution.

Any middleware, plugin, serializer, connector, shell wrapper, or executor that
changes arguments after the hook can still create a different effect unless
the final boundary rechecks and enforces the exact `dispatch_binding`. The
final executor/dispatcher must therefore enforce the same canonical payload
and hash immediately before execution, consume authorization there, or the
system must use a separate broker that owns this enforcement boundary. Do not
claim that passkey-gate alone controls downstream execution.

## Finding 27 — bearer-readable challenge pages and verification evidence (LOW/MEDIUM)

The gate now minimizes an approved `/verify/<id>?action_sha256=...` response to
only the fields needed by `verify_parent_approval()` and `local_verify.check()`:
`status`, `challenge_id`, `action_sha256`, `action_text`, `approved_at`,
`origin`, `rp_id`, `challenge_b64url`, the signed `assertion`, and the
`credential_public_key`. It no longer returns `binding_sha256`, the canonical
`tool_call`, `requester`, `created_at`, or `audit_head`. Parent verification and
local cryptographic checking continue to use the retained action, nonce,
assertion, key, origin/RP, and approval timestamp fields.

This is minimization, not authentication. The action text and cryptographic
evidence are still bearer-readable to anyone who obtains the high-entropy
identifier and action hash. `/a/<id>` remains unchanged: it still exposes the
approval ceremony to a bearer of the challenge ID. The local plugin has no
independent authenticated operator channel from which to issue a second viewing
token or bind browser access, and replacing the ID with an unauthenticated
viewing token would merely create another bearer secret and could disrupt the
human ceremony. A deployment that needs confidentiality must provide the
missing channel outside this plugin (for example, an operator-authenticated
broker/session or a separately issued, short-lived single-use viewing token
whose issuance is itself authenticated). URLs must still be treated as
sensitive and kept out of logs, history, chat, and monitoring.

## Enforcement patterns are a deny-list (v0.7 review M2)

`authority_patterns` are regular expressions over the text of a tool call.
They decide which calls need an approval; they are not a boundary. An agent
that wants to avoid an approval can often find an equivalent spelling,
flag order, tool or script that no pattern matches. Since v0.7.2 patterns
also run over the decoded argument values, the `setup` default covers the
common dangerous command forms in any flag order plus all code execution,
`setup` offers a strict mode that gates whole tools, and the block message
tells the model that routing around the gate is a violation. Only whole-tool
patterns give certainty, at the cost of approving every call of that tool.
A stronger long-term answer is to let Hermes's own dangerous-command
detection decide what needs approval (an approval transport), with the
passkey as the proof.

**Approvals bind text, not the state it depends on (M8).** The binding
covers `{tool, args}`. A command that runs a script, reads a variable or
depends on the working directory can be changed underneath an approval
within the request lifetime. Approve commands that state exactly what they
do.

## Finding 17 — settings that silently fall back to defaults

If the gate's settings are lost, readers get Hermes's defaults, and the
default is enforcement off. Until v0.7.1 the gate asked a private Hermes
function whether `config.yaml` had failed to parse. That check could break
silently on any Hermes release, and it couldn't see settings that were
removed from a config that still parses.

**Now: a config canary.** Every operator command that writes settings
(`set`, `expose`, `setup`) also writes a random check value,
`config_canary`, into the plugin's settings, and keeps a copy in the gate's
data folder. On every load, if the copy exists but the config's value is
missing or different, the gate fails closed: gated calls are blocked with a
message saying the settings weren't read, and `set`, `expose` and `setup`
refuse to write (writing into a lost config could replace the real settings
and then "match"). With no copy, either the gate was never configured
(default-off is the honest state) or it was upgraded from v0.7.1 or
earlier and hasn't been armed yet; `status` reports "not armed yet" until
the operator runs `setup` or any `set` (v0.7 review L9). A config the check
rejects is not applied to the gate's runtime settings either (L7). It uses
only the public plugin API.

What it catches, checked in Hermes v0.23: the settings block removed or
reset while the YAML still parses, the config replaced by an older or
different file, and the gate reading another profile's config.

What it can't catch: a `config.yaml` that won't parse **and** has no
last-known-good copy. Hermes normally falls back to the last good version
(held in memory, or saved under `backups/config/`), in which case the real
settings, canary included, stay in force. Without one, Hermes runs on
defaults, and because the list of enabled plugins is in the same file, it
**doesn't load this plugin at all**. No check inside the plugin can run, so
enforcement is absent until the file is fixed. Hermes prints a prominent
warning in that case. A deployment that needs the boundary must keep
`config.yaml` operator-owned and change it with care, as the deployment
controls above already require.

Recovery: restore the settings and the gate reloads them. If the config was
replaced on purpose, the operator deletes the `config-canary` file in the
gate's data folder and runs `setup` again. (An agent that can delete files
there is already inside the boundary; see finding 2.)

## v0.7 additions: setup wizard, background service, gate identity

**`hermes passkey-gate service install` is a convenience, not a boundary.**
It writes a per-user systemd unit (`~/.config/systemd/user/passkey-gate.service`)
or LaunchAgent (`~/Library/LaunchAgents/ai.hermes.passkey-gate.plist`) that
runs `hermes passkey-gate serve` as the installing user, with `HERMES_HOME`
pinned in the unit. It adds no network surface (the gate still binds
`127.0.0.1` only) and never escalates privilege. But anything running as
that user — including an agent with the operator's shell — can edit the
unit: point `HERMES_HOME` at another profile's data and pins, change
`ExecStart`, or stop the service. That is the same exposure as running
`serve` in the operator's terminal, and it is why finding 2 requires a
separate service account. A deployment that needs the boundary should
instead install a system unit owned by root that runs as a dedicated
account the agent cannot act as, with the data directory owned by that
account, for example:

```ini
[Service]
User=passkey-gate
Environment=HERMES_HOME=/var/lib/passkey-gate/hermes
ExecStart=/usr/local/bin/hermes passkey-gate serve
Restart=on-failure
```

**`/health` instance id.** `/health` now returns `service: "passkey-gate"`
and `instance`, the first 16 hex characters of SHA-256 over the gate's
resolved data-directory path. `setup` and `service status` use it to tell
this gate from another program on the same port. It is an identifier, not
authentication: the path is guessable, so a local program can compute and
serve the same value, and a bearer of the origin can use it to confirm a
guessed path (low; `/health` already reveals the origin, RP ID, number of
registered passkeys, request lifetime and audit-log head to anyone who can
reach the gate's address). A local
program squatting on the gate's port can impersonate the gate's pages
whether or not it fakes this value; that is a local-host attacker and
outside the boundary.

**Whoever serves the gate's address controls the registration page.** The
[v0.7 adversarial review](adversarial-review-v0.7.md) (H1) showed that an
impostor reachable through the gate's HTTPS address can relay the one-time
registration token to the real gate, register its own key, and show the
phone that key's confirmation code; typing it pins the impostor. (An
earlier version of this section wrongly said such an impostor could not
cause a pin.) An identity check can't fully stop this, because a relaying
impostor passes it by asking the real gate. Since v0.7.2, `setup`:

- never moves a gate that already has an HTTPS address (the H1 path was the
  wizard moving the gate off the port its address forwards to);
- refuses to send a registration link if the address doesn't answer as this
  gate (service name and instance id), or if the recorded Tailscale rule
  forwards to a different port than the gate runs on;
- and `set port` warns that the address doesn't follow the port.

The residual: if the forwarding is changed outside the plugin (a hand-edited
proxy, or `tailscale serve` run by hand) to point at something else, the
code ceremony can't detect it. Keep the forwarding operator-controlled, as
with the rest of the boundary.

**`setup` wizard.** It adds no capability beyond the commands it drives
(`service install`/`restart`, `expose`, `bootstrap`, `pin`, `set`). Its enforcement step only strengthens
settings, and it uses the same `set` path, so a weakening change would still
need a passkey approval. Its "already pinned" detection never replaces an existing pin;
`local_verify.pin` still refuses replacement.

## Residual risk summary

D9 is **partially addressed**:

- no automatic credential registration or pin creation is performed by
  challenge/verification paths, and tests cover that invariant;
- approved results expose the exact canonical tool call and binding contract;
- mismatched requested calls and inconsistent stored bindings are refused; but
- findings 2 and 20 remain architectural deployment requirements, and finding
  15 remains unless the final executor/broker enforces the binding outside the
  agent-controlled process;
- v0.7: typed confirmation codes narrow finding 20's wrong-authenticator
  risk for `setup` / `pin --code`, but do not help against a compromised gate
  or an agent that can run the ceremony itself; `service install` runs as the
  operator's user and does not satisfy finding 2's separate-account control;
  the `/health` instance id is not authentication.

The review's original numbered findings and date/version context remain in
`docs/security-review.md`; this document is the explicit residual limitation
for D9 rather than a "fixed" label.
