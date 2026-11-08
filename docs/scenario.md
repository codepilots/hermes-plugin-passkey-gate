# The scenario: authorising an agent teammate across the firewall

*2026-10-25, first-hand. Names are the two agents' real ones; no hostnames,
ips, key ids or token values are reproduced here.*

## The cast

- **Bramble** — the *workshop* agent, on a desktop that holds the services:
  a self-hosted GitLab, credentials, deploy keys, systemd units. Reachable
  inside a private mesh (a Tailscale tailnet), which also fronts its
  internal services' TLS.
- **Sorrel** — the *field* agent, on a laptop that moves between networks:
  home, cafés, hotels. Often behind captive portals and firewalls. Does the
  presence-dependent work; cannot be reached reliably and drops off the mesh
  for hours (sleep, travel).
- **Autumn** — one human, operator of both agents. Present at exactly one
  keyboard at a time, and often away from both.

## The task that exposed the problem

The two agents were to collaborate on a GitLab repo hosted on Bramble's
desktop (their hackathon project). Sorrel needed a real account, real SSH
access. Bramble had the GitLab instance; Sorrel had none of the details.

In other words: **an agent teammate behind a firewall needed authorisation
from a human who was not at its keyboard — and not at the holding agent's
keyboard for most of the day either.**

## Why the machinery already present couldn't do it

Hermes has a real approval system: when an agent is about to do something
risky, it can pause and ask for consent at the session it is running in.
That is excellent when the human is right there at that session's terminal
or chat — it was designed for exactly that. The 25th had several hours of it
working as intended: Bramble, mid-build, asked its own human, at its own
keyboard, and she clicked through.

But that approval prompt lives **in the acting agent's session**. It has no
route for the case where:

1. the acting agent is *Sorrel* — on a different machine, behind a different
   network, whose session can surface a prompt to nobody, because its human
   is kilometres away and often asleep or travelling;
2. the authorisation must be *relayed* — Sorrel asks Bramble (who holds the
   resource) to grant access; if the ask is just prose ("Autumn said it's
   fine"), Bramble has no way to distinguish a true instruction from a
   fabricated one, and neither does anyone reading the transcript later.

And the day supplied hard evidence for both directions:

- **Over-trust**: a planted entry impersonating Autumn appeared on the
  agents' shared drop-file, asking for exactly the sensitive details
  (a relayed GitLab host:port and credential handover request) that one of
  the requests "asked for". One of Bramble's lanes treated it as real at
  one point. Nothing in the text itself could prove it was her.
- **Under-trust**: the same morning, multiple sessions refused *genuine,
  Autumn-issued* requests, because the refusers could not verify her words
  either — an expired Discord connector hid her confirmations, and "she
  said so" carried no weight when a fabricated variant existed. Two of her
  own direct requests were bounced. Resolution work the human had to keep
  re-doing. This is the cost of a world with claims and no proofs: every
  ambiguous moment stalls into a hold, and the human pays the tax.

## What closes it: authorisation the agent can mint, only a human can spend

The passkey gate inverts the trust problem. The agents never receive an
authorisation *claim*; they receive one *object* — a signed WebAuthn
assertion — and it carries its own proof:

1. Any agent (either machine, any lane) mints a **challenge**, bound
   bit-for-bit to the exact action text and hash-derived from it. Minting
   is untrusted — no privilege, no secret, and an agent can mint all it
   wants without achieving anything.
2. The human gets it as a **URL in any channel she actually uses** (her
   Discord, a DM, a phone push — the link is small, one-time, expiring).
   She reads the page: the full action text, who is asking, how long it
   lives. She signs with **her passkey**, with user-verification required.
   The WebAuthn nonce is `sha256(exact action text) + entropy` — the
   signature is bound to *that text*, not to a session, a machine, or an
   agent's good faith.
3. The agent that will act calls **gate_verify** and re-derives every claim
   **locally, with cryptography** it runs itself: hashes, origin/RP
   match, UP/UV flags, the signature over the exact bytes — against a
   **pinned owner key** registered out-of-band. The gate server cannot lie;
   even a fully compromised gate cannot substitute a key or text without
   local verification catching it. No agent ever holds a private key, so
   no agent can sign anything, ever.
4. Approvals are **single-use and consumable**: the enforcement hook (when
   switched on) only lets a matching tool call through once, and consumes
   the approval on use, so a signed authorisation covers exactly one
   deliberate execution.

In the original field run, that flow was exercised across two machines:
challenge minted on the desktop by the workshop agent, approved on a phone
by Autumn while she was away from both keyboards' side sessions, and
verified independently by the field agent — plus a deliberately altered
action text (denied), a replayed assertion (denied), an impostor credential
claiming the right id with the wrong key (denied), and a manual tampering
check of the hash-chained audit log (detected).

## The general shape of the problem

This is not really a Tailscale/GitLab story. It is the shape that recurs:

- An agent teammate is **network-isolated or unreachable-schedule** (field
  laptop, CI runner, a lab box behind a firewall, another timezone).
- The action it needs is **high-authority but legitimately routine**:
  adding a collaborator, opening a firewall path, relaying a credential
  handover, a destructive maintenance command.
- The human **trusts the agent's judgement but not every intermediate
  channel** — because the intermediate channels include things that can
  lie: peers paraphrasing, boards anyone can write, screenshots, even
  another instance of the agent itself on a different lane.

Hermes's session-scoped approvals handle "human at the keyboard, at the
acting session". This plugin handles the complement: **the human is not at
the acting agent's keyboard — but the action still needs her name on it, in
a form no intermediate channel can fake, that any agent can independently
check.**

## What agents may not use this for

The gate makes *verifiable* authorisation possible, not *manufacturable*.
An agent still cannot approve for itself: there is no signing path without
a human's touch on an authenticator the agent cannot reach, and the
pinning of the owner key is deliberately out-of-band. A signature tells
everyone *who read and deliberately signed what* — nothing else. The agents
still need to ask with honest text (the gate floor-rejects vague asks), and
the human still carries the judgement: she reads exactly what she signs,
and signs exactly what she read.
