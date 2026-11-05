# passkey-gate

A Hermes plugin for **cryptographically provable agent authorization**.

When an agent wants to do something high-authority — grant an access grant to
a teammate, reach the internet from a restricted host, relay a credential,
change a security setting — it mints a **WebAuthn challenge bound bit-for-bit
to the exact action text** (and optionally to the exact canonical tool call).
The agent sends the approval URL to its human; the human reads the page and
signs with **their passkey** — the agent never holds a private key, and there
is no agent-side path to approval. Before acting, the agent verifies the
signed assertion **locally** with real cryptography against a **pinned owner
key**. An append-only, hash-chained audit log makes any tampering detectable.

This is not prompt-gated "I promise" authorization, and not a yes/no an
agent could fake. It is enforcement-with-proof: a gate can't lie about what
you signed, and a fake claim "Autumn approved this" collapses on
`gate_verify` unless the signature actually checks out.

## How it works

```
agent wants a high-authority action
  └─ gate_challenge(action_text, tool_call?)     → approval URL + challenge id
human opens URL (over TLS, e.g. tailscale serve) → passes passkey with UV
  └─ WebAuthn nonce == sha256(action_text) + ent: signed to that EXACT text
agent act-check:
  └─ gate_verify(challenge_id, action_text)      → LOCAL crypto verification
        sha256(action_text) == signed challenge
        signature over authenticatorData‖sha256(clientDataJSON) vs PINNED pubkey
        user-presence + user-verification flags, origin/rp_id match
  └─ verified: true (problems: [])  →  act
optional enforcement hook (require_passkey):
  └─ pre_tool_call blocks calls matching authority patterns unless a challenge
     bound to that exact canonical tool call is approved — and CONSUMES it,
     so each approval authorises exactly one deliberate execution.
```

Design provenance: the core is a port of a field-proven prototype
(`approval-gate`, October 2026) whose acceptance test covered two machines:
challenge minted by one, signed by a human passkey on the other, verified
independently, tamper and replay attempts denied, audit chain intact.

## Install

```bash
hermes plugins install codepilots/hermes-plugin-passkey-gate
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
# 1) Serve the gate locally (terminate TLS outside: tailscale serve, nginx, ...)
hermes passkey-gate serve
# with tailscale:
tailscale serve --bg 8445:8655

# 2) Register passkey -- mint the one-time registration link (prints to
#    THIS terminal only; never send it through chat)
hermes passkey-gate bootstrap

# 3) (Out of band) pin your owner key: the agent independently checks every
#    signature against this exact public key
hermes passkey-gate pin /path/to/pinned_autumn.pem

# 4) Audit the log at any time
hermes passkey-gate audit-verify
```

## Tools

| Tool | What the model reads |
|---|---|
| `gate_challenge` | Mint an approval request; returns URL the agent must send its human + sha256. The action text must read like an authority document (40 chars / 6 word floor, max 4000). |
| `gate_verify` | Poll (optional wait) then LOCALLY verify: binding, signature, UV/UP flags, origin, pinned key, max-age. `verified: true` and no problems = safe to act. |
| `gate_status` | Gate reachable? credentials registered? key pinned? audit chain intact? |

## Enforcement hook (opt-in)

```yaml
        require_passkey: true
        authority_patterns:
          - "^terminal .*- (rm|sudo|curl|scp|dd|mv /)"
          - "^\\w+ .*credential"       # tools whose args mention credentials
```

Matching tool calls **block** with exact instructions (a JSON template of the
call the challenge must bind), **allow** only when an approved-and-unconsumed
challenge covers that exact binding, and consume that challenge (single use).
The block text tells the model, verbatim, how to mint the right challenge —
and to push back on the human if it thinks the pattern is a false alarm.

## Honest limits

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

## License

MIT — see LICENSE.
