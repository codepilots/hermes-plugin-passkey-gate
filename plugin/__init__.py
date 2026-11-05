"""passkey-gate plugin — registration.

What this plugin is, in one paragraph for future maintainers:

  An agent wanting to do something high-authority mints a WebAuthn challenge
  bound bit-for-bit to the exact action text (and optionally to the exact
  canonical tool call). The agent sends the approval URL to its human; the
  human reads the page and signs with THEIR passkey — the agent never holds
  a private key, and no agent-side path can approve. Before acting, the
  agent calls gate_verify, which re-derives every claim locally (sha256
  binding, signature over authenticatorData||sha256(clientDataJSON),
  user-verification flags, origin/rp_id) against a PINNED owner key. An
  optional pre_tool_call hook hard-enforces the flow: calls matching
  configured authority patterns are blocked unless an approved, unconsumed
  challenge covers that exact canonical binding — signatures are consumed,
  so each approval authorises exactly one deliberate action.

Design provenance: the WebAuthn server core and the local verifier are ports
of Autumn's `approval-gate` service and `verify_local.py` (protocol draft
docs/protocol-v1.1-authority-verification-DRAFT.md in that project), which
passed a full field acceptance test on 2026-10-25: challenge minted by one
machine, approved by the human's passkey, verified independently on two
machines, tamper/attempts denied, audit chain intact.
"""
import logging
import re
import shutil
from pathlib import Path

from . import gate_core, local_verify, schemas, tools

logger = logging.getLogger(__name__)


def _apply_config(ctx):
    origin = (ctx.get_config("origin", default="") or "").strip()
    rp_id = (ctx.get_config("rp_id", default="") or "").strip()
    port = ctx.get_config("port", default=8655)
    ttl = ctx.get_config("challenge_ttl", default=600)
    data_dir = _plugin_data(ctx)
    gate_core.configure(data_dir=str(data_dir),
                        rp_id=rp_id or os_default_rp_id(),
                        origin=origin or None,
                        port=port)
    return {"require_passkey": bool(ctx.get_config("require_passkey", default=False)),
            "patterns": ctx.get_config("authority_patterns", default=[]) or []}


def _plugin_data(ctx):
    try:
        from plugins.plugin_storage import plugin_data_dir
        return plugin_data_dir("passkey-gate")
    except Exception:
        # outside Hermes (tests, manual runs)
        return Path(__file__).resolve().parent / ".gate-data"


def os_default_rp_id():
    # best-effort default from tailscale magicdns if present
    try:
        out = shutil.which("tailscale") and __import__("subprocess").run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=5)
        if out and out.returncode == 0:
            import json as _json
            host = (_json.loads(out.stdout).get("Self") or {}).get("DNSName", "")
            if host:
                return host.rstrip(".")
    except Exception:
        pass
    return "localhost"


def _on_pre_tool_call(tool_name: str, args: dict, task_id: str, **kwargs):
    cfg = _apply_config_safe()
    return tools.hook_verdict(tool_name, args, cfg["patterns"], cfg["require_passkey"])


_cfg_cache = None
_ctx_ref = None


def _apply_config_safe():
    global _cfg_cache
    if _cfg_cache is None:
        _cfg_cache = {"require_passkey": False, "patterns": []}
        try:
            if _ctx_ref is not None:
                _cfg_cache = _apply_config(_ctx_ref)
        except Exception:
            logger.exception("passkey-gate: config apply failed; enforcement off (fail-open for loading, fail-closed per-call)")
    return _cfg_cache


def _cmd_cli(ctx, args_str: str):
    """hermes passkey-gate <serve|bootstrap|audit-verify|pin> [args]"""
    parts = args_str.strip().split()
    cmd = parts[0] if parts else ""
    data_dir = _plugin_data(ctx) if ctx is not None else Path(__file__).resolve().parent / ".gate-data"
    _apply_config(ctx) if ctx is not None else None
    if cmd == "serve":
        gate_core.serve()
        return "serve returned"
    if cmd == "bootstrap":
        url = gate_core.mint_bootstrap_token()
        # one-time registration link: printed to THIS terminal only, not to chat
        try:
            import qrcode
            q = qrcode.QRCode(border=1)
            q.add_data(url)
            q.print_ascii(invert=True)
        except Exception:
            pass
        return f"One-time registration link ({gate_core.bootstrap_ttl() // 60} min, single use). Do not paste it anywhere:\n\n{url}"
    if cmd == "audit-verify":
        ok, msg = gate_core.audit_verify()
        return ("OK " if ok else "BROKEN ") + msg
    if cmd == "pin":
        if len(parts) < 2:
            return "usage: hermes passkey-gate pin <pem-file>"
        pem = Path(parts[1]).read_text()
        path = local_verify.pin(data_dir, pem)
        return f"pinned owner key to {path}. The agent can now verify approvals against it independently."
    return "usage: hermes passkey-gate <serve|bootstrap|audit-verify|pin> [args]"


def register(ctx):
    global _ctx_ref, _cfg_cache
    _ctx_ref = ctx
    _cfg_cache = None
    cfg = _apply_config(ctx)
    _cfg_cache = cfg

    ctx.register_tool(name="gate_challenge", toolset="passkey-gate",
                      schema=schemas.GATE_CHALLENGE, handler=tools.gate_challenge)
    ctx.register_tool(name="gate_verify", toolset="passkey-gate",
                      schema=schemas.GATE_VERIFY, handler=tools.gate_verify)
    ctx.register_tool(name="gate_status", toolset="passkey-gate",
                      schema=schemas.GATE_STATUS, handler=tools.gate_status)

    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_cli_command("passkey-gate", lambda args: _cmd_cli(ctx, args))

    creds = None
    try:
        creds = gate_core.credential_count()
    except Exception:
        pass
    logger.info("passkey-gate registered (verify-only mode); passkey credentials on file: %s; enforcement on: %s",
                creds, cfg["require_passkey"])
