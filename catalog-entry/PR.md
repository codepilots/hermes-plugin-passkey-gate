Title: Add passkey-gate to the plugin catalog

---

Adds `plugin-catalog/passkey-gate.yaml`, pinned to
[`f50b315`](https://github.com/codepilots/hermes-plugin-passkey-gate/commit/f50b315530beea1f0dc2739049b675ad69f83d26),
version 0.8.0. Its `plugin/` tree is identical to tag
[`v0.8.0`](https://github.com/codepilots/hermes-plugin-passkey-gate/tree/v0.8.0)
(`37a72c4`); the one commit on top only refreshes the approval-page
screenshot. Submitted by the repository owner (codepilots).

## What it does

passkey-gate lets you approve your agents' risky actions with your phone's
passkey, even when you're not at the agent's keyboard.

- An agent asks for approval of an exact action, and optionally the exact
  tool call. You get a link, read the request on your phone and sign it with
  Face ID, a fingerprint or your screen lock.
- The agent then checks your signature against the passkey you pinned during
  setup, on its own machine. A message saying "the human said yes" proves
  nothing; only the signature counts.
- **Optional enforcement:** while it's on, tool calls that match your
  patterns are blocked until you approve them, and each approval runs exactly
  once.
- **Lanes** choose which conversations need a passkey: you at the keyboard,
  your own chat accounts, other people, bots, or other agents (A2A and Hermes
  peer DMs).
- Also included: a guided `setup` wizard, a background service, a
  hash-chained audit log, and approvals between agents owned by different
  people.

This is more than a prompt or skill could do, because the signature comes
from hardware the agent can't reach and is checked locally. The plugin is an
honest approval record by default. It becomes a hard boundary when agents
can't modify the gate; the README's Security model explains how to set that
up.

## Hermes surfaces used

- `ctx.register_tool`: `gate_challenge`, `gate_verify`, `gate_status`
- `ctx.register_hook`:
  - `pre_tool_call` (enforcement)
  - `pre_llm_call` and `post_gateway_admission` (lanes; both observe only
    and return `None`)
- `ctx.register_cli_command`: `hermes passkey-gate …`
- `ctx.get_config` / `ctx.set_config` for its own settings, and
  `ctx.session_surface()`
- Read-only helpers: `plugins.plugin_storage.plugin_data_dir`,
  `hermes_cli.config.get_config_path` (to notice settings edits), and
  `hermes_constants.get_hermes_home` (to pin the service to the profile)

It never patches Hermes. `hermes plugins validate` reports no core override
and no undocumented-module warnings.

## Disclosure (rule 13)

- **Background process:**
  - It runs a small HTTP server on `127.0.0.1` (default port 8655), either in
    a terminal (`hermes passkey-gate serve`) or, if you choose it, as a
    background service that runs as you. The service is a systemd user unit
    or a LaunchAgent, written to your home directory.
  - Your phone reaches the server over HTTPS. By default that is published
    to your own tailnet with `tailscale serve`, which adds a rule to your
    tailnet's serve configuration.
- **Shell commands:** `tailscale status` and `tailscale serve`;
  `systemctl --user`, `journalctl --user`, `loginctl` or `launchctl`; and a
  short Python subprocess that times new authority patterns on long inputs.
  Each runs only when you use the matching feature, and nothing runs with
  elevated privileges. None of them inherits the agent's environment: each
  gets an explicit minimal one (`PATH`, `HOME`, `LANG`, plus
  `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` for `systemctl --user`),
  so provider keys never reach a child process.
- **Network:**
  - It contacts only its own address and any peer gates you list in
    `parent_gate_allowlist`.
  - It follows no redirects, refuses non-public addresses for peers, and caps
    the size and time of every response it reads.
  - No third-party services, no telemetry.
- **Stored data:**
  - It stores passkey public keys, requests, the pinned key, the audit log
    and a remote-minting bearer token in its plugin data folder. No private
    keys are stored anywhere.
  - It writes its settings and a random check value (`config_canary`) into
    its own section of the Hermes config.
  - It writes outside its folder only where you point it: the audit anchor
    file and the service file.
- **Conversation data:** the lanes hooks note each turn's platform, sender id
  and bot flag. These notes stay in memory only (the last 4096 sessions) and
  are never written to disk or added to the model's context.
- **Failure mode:** with enforcement on, any failure (gate unreachable,
  settings unreadable, an error in the hook) blocks the call.
- **Who can act:** only the pinned passkey can approve. Anyone holding an
  approval link can read that request and deny it.
- **Limits:**
  - Authority patterns are a best-effort list over the text of a call, not a
    sandbox. Strict mode gates whole tools for certainty.
  - An approval covers the command text, not the scripts it runs.

## Rules 11 and 12

- **Rule 11 (credentials):** the plugin needs no credentials. Nothing reads
  `.env`, `auth.json` or other credential stores.
- **Rule 12 (approvals and unattended runs):**
  - The plugin adds human approval and never removes it. It doesn't
    auto-approve or disable Hermes guards, and it starts no Hermes or shell
    children.
  - `gate_verify` waits for at most 120 seconds, then returns. In unattended
    runs a gated call is blocked immediately; nothing hangs.

## Validation

All of these were run against v0.8.0 (`plugin/` is identical at the pin), on Hermes v0.23.0:

- `hermes plugins validate --install-deps` passes every check, and the
  security scan is `safe`.
- A pinned install (`--ref 37a72c4…`) is allowed, and the installed files
  are identical to the tag.
- 349 tests pass in a clean virtualenv built from a fresh clone.
- `scripts/e2e_hermes.py` passes 34 of 34 steps against the pinned install.
  It goes through Hermes's own plugin manager, tool registry and hook
  dispatch, using a software authenticator in place of the phone.
- Two adversarial security reviews: findings and fixes are in
  `docs/security-review/`.

## Screenshots

The entry's `screenshots:` show phone registration, the confirmation code,
and the approval page.
