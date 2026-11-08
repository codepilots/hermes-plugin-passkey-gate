"""passkey-gate plugin — registration.

What this plugin is, in one paragraph for future maintainers:

  An agent wanting to do something high-authority mints a WebAuthn challenge
  bound bit-for-bit to the exact action text (and optionally to the exact
  canonical tool call). The agent sends the approval URL to its human — or,
  when agents owned by different humans collaborate, to the peer's human,
  with requester_owner + `why` so a stranger can judge the ask. The human
  reads the page and signs with THEIR passkey — the agent never holds a
  private key, and no agent-side path can approve. Before acting, the agent
  calls gate_verify, which re-derives every claim locally (sha256 binding,
  signature over authenticatorData||sha256(clientDataJSON), user-verification
  flags, origin/rp_id) against a PINNED owner key. An optional pre_tool_call
  hook hard-enforces the flow: calls matching configured authority patterns
  are blocked unless an approved, unconsumed challenge covers that exact
  canonical binding, and consume it on use — so each enforced approval
  authorises exactly one execution (text-only approvals, with no bound call,
  stay verifiable until they expire).

Design provenance: the WebAuthn server core and the local verifier are ports
of Autumn's `approval-gate` service and `verify_local.py` (the protocol draft lives in that prototype's repository, not here), which
passed a full field acceptance test on 2026-10-25: challenge minted by one
machine, approved by the human's passkey, verified independently on two
machines, tamper/attempts denied, audit chain intact.

The full first-hand scenario behind this plugin: docs/scenario.md.
"""
import argparse
import logging

from . import cli, gate_core, schemas, tools

logger = logging.getLogger(__name__)


def _on_pre_tool_call(tool_name: str, args: dict = None, task_id: str = "", **kwargs):
    # Hermes drops exceptions raised by hooks and lets the call proceed, so
    # an exception here would be a fail-OPEN. Anything unexpected blocks
    # (v0.7 adversarial review M3 / A4).
    try:
        return _pre_tool_call_verdict(tool_name, args if isinstance(args, dict) else {})
    except Exception as exc:
        logger.exception("passkey-gate: pre_tool_call failed; blocking")
        return {"action": "block", "message": (
            f"Passkey gate: an internal error stopped the safety check ({type(exc).__name__}: "
            f"{exc}) — failing closed, this call is blocked. Tell the human; "
            "'hermes passkey-gate status' shows what the gate sees.")}


def _pre_tool_call_verdict(tool_name, args):
    cfg = cli.apply_config_safe()
    if cfg.get("_config_error"):
        # Finding 17: a config that is PRESENT but failed to load must fail
        # CLOSED. The authority patterns are exactly what could not be read,
        # so no call can be judged low-authority — block until the settings
        # load, and tell the human the config is the problem (not a missing
        # approval, not a pattern miss).
        return {"action": "block", "message": (
            "Passkey gate: the gate's configuration failed to load "
            f"({cfg['_config_error']}) — failing closed, this call is blocked. "
            "The gate cannot tell which calls need a passkey until its settings "
            "read, so nothing runs unenforced. Tell the human to fix the "
            "passkey-gate settings (`hermes passkey-gate get` shows them; they "
            "live in the Hermes config file). Once they parse, the gate reloads "
            "them automatically and this call can be retried.")}
    return tools.hook_verdict(tool_name, args, cfg["patterns"], cfg["require_passkey"])


def _setup_cli(parser):
    parser.add_argument("argv", nargs=argparse.REMAINDER,
                        help="subcommand and its arguments, e.g. 'status' or "
                             "'set require_passkey true'")


def _run_cli(ctx, args) -> int:
    out = cli.dispatch(ctx, " ".join(getattr(args, "argv", None) or []))
    if out:
        print(out)
    return 2 if isinstance(out, str) and out.startswith("usage:") else 0


def register(ctx):
    cli._ctx_ref = ctx
    cli.invalidate_config_cache()
    # The hook goes in FIRST: a register() that died while loading settings
    # would leave no hook at all, the one fail-open path worse than a block.
    # Settings that won't load make the hook block every call with the reason.
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    try:
        cfg = cli.apply_config_safe()
    except Exception as exc:
        logger.exception("passkey-gate: settings failed to load at registration")
        cfg = {"require_passkey": True, "_config_error": f"{type(exc).__name__}: {exc}"}

    ctx.register_tool(name="gate_challenge", toolset="passkey-gate",
                      schema=schemas.GATE_CHALLENGE, handler=tools.gate_challenge)
    ctx.register_tool(name="gate_verify", toolset="passkey-gate",
                      schema=schemas.GATE_VERIFY, handler=tools.gate_verify)
    ctx.register_tool(name="gate_status", toolset="passkey-gate",
                      schema=schemas.GATE_STATUS, handler=tools.gate_status)

    try:
        # Hermes API: register_cli_command(name, help, setup_fn(subparser),
        # handler_fn(args) -> exit code). A failure here must never take the
        # tools and the enforcement hook down with it.
        ctx.register_cli_command(
            name="passkey-gate",
            help="Passkey approval gate: setup (start here), service, serve, pin, status, ...",
            setup_fn=_setup_cli,
            handler_fn=lambda args: _run_cli(ctx, args),
            description=cli.__doc__ or "",
        )
    except Exception:
        logger.exception("passkey-gate: CLI command registration failed; "
                         "tools and the pre_tool_call hook remain registered")

    creds = None
    try:
        creds = gate_core.credential_count()
    except Exception:
        pass
    logger.info("passkey-gate registered; passkey credentials on file: %s; enforcement on: %s%s",
                creds, cfg["require_passkey"],
                f" — CONFIG ERROR, failing closed: {cfg['_config_error']}"
                if cfg.get("_config_error") else "")
