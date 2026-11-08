# The scenario: approving an agent's request from somewhere else

*25 October 2026, first-hand. The agents' names are their real ones. No
hostnames, IP addresses, key IDs or tokens appear here.*

This is the day that led to passkey-gate. It explains the problem the
plugin solves, using what actually happened.

## The cast

- **Bramble**, the *workshop* agent. It runs on a desktop that holds the
  services: a self-hosted GitLab, credentials, deploy keys. The desktop is
  on a private Tailscale network (a *tailnet*).
- **Sorrel**, the *field* agent. It runs on a laptop that moves between
  home, cafés and hotels, often behind captive portals and firewalls. It
  drops off the network for hours at a time.
- **Autumn**, the one human who runs both agents. Autumn can only be at one
  keyboard at a time, and is often away from both.

## The task that exposed the problem

The two agents were going to work together on a GitLab repository hosted
on Bramble's desktop: their hackathon project. Sorrel needed a real account
and SSH access. Bramble ran the GitLab server; Sorrel had none of the
details.

So **an agent behind a firewall needed permission from a human who wasn't
at its keyboard, and for most of the day wasn't at the other agent's
keyboard either.**

## Why the existing approvals couldn't help

Hermes already has a good approval system. When an agent is about to do
something risky, it pauses and asks for consent in the session it's running
in. That works well when the human is at that session's terminal or chat,
which is what it was designed for. On the 25th it worked as intended for
hours: Bramble, mid-build, asked Autumn at Bramble's own keyboard, and
Autumn approved.

But that prompt only appears **in the acting agent's own session**. It has
no answer for two cases:

1. **The acting agent is somewhere else.** Sorrel was on a different
   machine and network. Its session could show a prompt to nobody, because
   Autumn was miles away and often asleep or travelling.
2. **The permission has to be relayed.** Sorrel asks Bramble, which holds
   the resource, to grant access. If the request is just words ("Autumn said
   it's fine"), Bramble can't tell a real instruction from a fake one.
   Neither can anyone reading the transcript later.

That day showed both failures:

- **Trusting too much.** A planted message pretending to be Autumn appeared
  in a file the agents shared. It asked for exactly the sensitive details a
  real request had mentioned: the GitLab address and a credential handover.
  At one point, one of Bramble's sessions treated it as genuine. Nothing in
  the text could prove who wrote it.
- **Trusting too little.** The same morning, several sessions refused
  *genuine* requests from Autumn, because they couldn't verify them either.
  An expired Discord connection hid Autumn's confirmations, and "Autumn
  said so" meant nothing once a fake version existed. Two of Autumn's own
  requests were bounced, and Autumn had to keep sorting it out by hand.
  That's the cost of having claims but no proof: every unclear moment
  stalls, and the human pays for it.

## What fixes it: a request any agent can make, that only the human can sign

passkey-gate changes what the agents trust. Instead of a *claim* that the
human approved, they get a *signature* that proves it:

1. **Any agent creates a request.** It's tied to the exact wording of the
   action (and, if given, the exact command to run). Creating a request
   gives no power to approve it: an agent on the gate's own machine creates
   it directly, and an agent elsewhere uses a token that can create requests
   but never approve them. Only a signature counts.
2. **The human gets a link** wherever they'll see it: a chat, a DM, a QR
   code. The page shows the full action, who's asking, and when it expires.
   The human signs with their **passkey**, using a face, fingerprint or
   screen lock. The signature covers a hash of that exact text (and
   command), plus random bytes, so it can't be reused for anything else.
3. **The agent that will act checks the signature itself**, with
   `gate_verify`. It recomputes everything locally: the hashes, the site the
   signature was made for, that a face or PIN was used, and the signature
   itself. It checks all of this against the human's **pinned key**, set up
   once in advance. A reply that merely *says* the request was approved
   proves nothing; only a signature from that key passes. No agent holds a
   private key, so no agent can sign anything.
4. **Approvals for enforced commands work once.** When enforcement is on,
   an approved command runs one time and the approval is then used up. (An
   approval with no command attached stays checkable until it expires.)

In the original field test, this ran across two machines. The workshop
agent created the request on the desktop. Autumn approved it on a phone,
away from both keyboards. The field agent then verified it independently.
The test also tried an altered action text, a replayed signature, and an
impostor passkey with the right ID but the wrong key; all three were
refused. A manual edit to the audit log was detected.

## The general shape of the problem

This isn't really about Tailscale or GitLab. The same pattern keeps coming
up:

- An agent is **hard to reach**: a field laptop, a CI runner, a lab machine
  behind a firewall, another timezone.
- It needs to do something **powerful but routine**: add a collaborator,
  open a firewall port, hand over a credential, run a destructive
  maintenance command.
- The human **trusts the agent, but not every channel in between**, because
  those channels can lie: other agents paraphrasing, shared boards anyone
  can write to, screenshots, even another copy of the same agent.

Hermes's built-in approvals cover "the human is at the keyboard, in the
acting session". This plugin covers the rest: **the human isn't at the
agent's keyboard, but the action still needs the human's sign-off, in a
form no channel can fake and any agent can check.**

## What it doesn't do

passkey-gate makes permission *checkable*, not something an agent can
*produce*. An agent can't approve its own request: signing needs the
human's touch on a device the agent can't reach, and the human's key is
pinned by the operator, not by an agent. A signature proves who read and
deliberately signed what, and nothing more. Agents still have to ask in
honest, specific words (vague requests are rejected), and the judgement
stays with the human, who signs exactly what they read.

This holds as long as the agent can't tamper with the gate itself: its
code, settings or stored keys. How to set that up is covered in the
[threat model](security-review/threat-model.md).
