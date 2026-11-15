Title: Update passkey-gate to v0.10.0

---

Updates `plugin-catalog/passkey-gate.yaml` from v0.8.1 to
[`fa737f7`](https://github.com/codepilots/hermes-plugin-passkey-gate/commit/fa737f758519e85434b44045cc865fca9bc06be4),
tag [`v0.10.0`](https://github.com/codepilots/hermes-plugin-passkey-gate/tree/v0.10.0).
Submitted by the repository owner (codepilots).

## What changed since v0.8.1

- **Approval transport (v0.9.0).** The plugin registers a Hermes approval
  transport, `passkey-gate`, which does nothing until the operator selects
  it. A passkey approval for an exact command then also answers Hermes's
  own prompt for that command, once. With `passkey_hermes_prompts` on,
  every command Hermes flags needs the passkey: the plugin posts the
  approval link into the conversation and answers `once` only after
  checking the signature locally. It never answers `session` or `always`.
- **`gate_cancel`.** An agent can withdraw its own request. It only removes
  authority.
- **Error contract.** Every refusal carries an `error_code` and a
  `next_step`, and tools refuse arguments they don't take.
- **Two bundled test skills**, registered where Hermes has `register_skill`.
- **Fail-closed fixes** from a static scan (see Review below): an empty
  config check file, a mistyped `owner_senders` and an unusable authority
  pattern each now gate or block instead of quietly enforcing less.
- The entry's `provides_tools`, `provides_hooks`, description and image
  URLs are updated to match; all images are now pinned to the same commit.

The full list is in the repository's `CHANGELOG.md`.

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
- **Hermes's own prompts:** as Hermes's approval transport, it can require
  the passkey for every command Hermes flags as dangerous.
- Also included: a guided `setup` wizard, a background service, a
  hash-chained audit log, and approvals between agents owned by different
  people.

This is more than a prompt or skill could do, because the signature comes
from hardware the agent can't reach and is checked locally. The plugin is an
honest approval record by default. It becomes a hard boundary when agents
can't modify the gate; the README's Security model explains how to set that
up.

## Hermes surfaces used

- `ctx.register_tool`: `gate_challenge`, `gate_verify`, `gate_cancel`,
  `gate_status`
- `ctx.register_hook`:
  - `pre_tool_call` (enforcement)
  - `pre_llm_call` and `post_gateway_admission` (lanes; both observe only
    and return `None`)
  - `post_tool_call` (drops an unused approve-once cover; returns `None`)
  - `pre_approval_request` and `post_approval_response` (post the approval
    link, then update it with the outcome; observers)
  - `transform_tool_result` (rewords one blocked result, see Disclosure)
- `ctx.register_approval_transport`: `passkey-gate`
- `ctx.register_skill`: the two bundled skills
- `ctx.post_message`: the approval link, in the conversation that asked
- `ctx.register_cli_command`: `hermes passkey-gate …`
- `ctx.get_config` / `ctx.set_config` for its own settings, and
  `ctx.session_surface()`
- Read-only helpers: `plugins.plugin_storage.plugin_data_dir`,
  `hermes_cli.config.get_config_path` (to notice settings edits),
  `hermes_cli.config.load_config_readonly` (to report Hermes's approval
  settings in `status`), `hermes_constants.get_hermes_home` (to pin the
  service to the profile), and `agent.redact.redact_sensitive_text`
- `hermes_cli.config.set_config_value`: only from `setup`, see Disclosure

It never patches Hermes. `hermes plugins validate` reports no core override
and no private-import warnings.

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
- **Messages it posts:** as the approval transport with
  `passkey_hermes_prompts` on, it posts one message into the conversation
  per flagged command, carrying the approval link and the command as Hermes
  displays it (secrets masked), and edits that message with the outcome. If
  it can't set the request up, it posts one line saying so.
- **Hermes settings it changes:** `setup` can set
  `security.approval.transport` and `security.approval.transport_fallback`,
  through Hermes's own `config set` code path, after asking. Nothing else
  outside its own section is written.
- **Tool results it rewrites:** one case. When a passkey request went
  unanswered, Hermes reports "User denied"; the plugin rewords that blocked
  result to say the user did not answer. It never changes a result that
  ran, and never unblocks one.
- **Skills:** two test skills (`approval-layers-test`,
  `malformed-request-test`) that an agent runs only when asked. The first
  runs destructive commands only against decoy files it creates in the
  session's scratch directory.
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
  - As the approval transport it answers only `once` or `deny`, never
    `session` or `always`. No answer, an error or a signature that doesn't
    verify is a `deny`. A prompt it has no passkey request for is handed
    back to Hermes (`transport_fallback` decides). Hermes's hardline blocks,
    deny rules, `approvals.mode` and unattended-run handling all run before
    any transport and are untouched; `status` warns when `approvals.mode`
    isn't `manual`, because flagged commands then may never reach the
    passkey.
  - `gate_verify` waits for at most 300 seconds, then returns; the transport
    waits no longer than Hermes's own `approvals.timeout`. In unattended
    runs a gated call is blocked immediately; nothing hangs.

## Validation

All of these were run against the pin (`fa737f7`, v0.10.0), on Hermes
v0.23.1:

- `hermes plugins validate --install-deps` passes every check, with no
  warnings, and the security scan is `safe`.
- A pinned install (`--ref fa737f7…`) is allowed, and the installed files
  are identical to the tag.
- 493 tests pass in a clean virtualenv built from a fresh clone; CI is
  green on the pinned commit (Python 3.11 to 3.14).
- `scripts/e2e_hermes.py` passes 53 of 53 steps against the pinned install.
  It goes through Hermes's own plugin manager, tool registry, hook dispatch
  and approval engine, using a software authenticator in place of the phone.
- `scripts/validate_plugin_catalog.py` accepts the entry.

**Hermes version.** Tested on v0.23.1 only. Every Hermes API the plugin
uses is present at the v0.23.0 tag (checked by reading the source, not by
running it); the optional ones are registered defensively.

## Review

- v0.8.1 and earlier had two adversarial security reviews; findings and
  fixes are in `docs/security-review/`.
- The code added since (the approval transport, `gate_cancel`, the reword
  hook, argument checking) has **not** had an independent adversarial
  review. It is self-reviewed, with `docs/security-review/threat-model.md`
  as the account of its limits.
- An automated static scan of the tree was run on 15 November 2026: 0
  critical or high, 2 medium, 8 low, dependency check clean. It executed
  nothing and reports its own coverage as incomplete. Seven findings are
  fixed in v0.10.0; the rest are listed with reasons in
  `docs/proposals/2026-11-15-catalog-resubmission-readiness.md`.

## Known limits of the new parts

- **Not yet exercised live in Hermes:** a deny on the phone, the no-answer
  timeout, and the TUI and Desktop surfaces. They are covered by unit tests
  and `scripts/failure_paths.py`.
- **The reworded "did not answer" result depends on Hermes's exact refusal
  text.** If that text changes, the rewording silently stops and the agent
  sees Hermes's "User denied" again; nothing is unblocked either way. A
  distinct "no answer" result from a transport would remove this.
- **The passkey signs what Hermes shows**, which is the redacted command.
  Two commands differing only in a masked secret look identical.
- The classic terminal client can't show a posted link in time, so there
  Hermes's own prompt is used.

## Screenshots

The entry's `screenshots:` show phone registration, the confirmation code,
and the approval page.
