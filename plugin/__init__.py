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
import json
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
    """hermes passkey-gate <serve|bootstrap|audit-verify|pin|expose|set|get> [args]"""
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
    if cmd == "expose":
        return _cmd_expose(ctx, parts[1:], data_dir)
    if cmd == "set":
        return _cmd_set(ctx, parts[1:]) if ctx is not None else "no hermes context to write settings to (run inside hermes)"
    if cmd in ("get", "show"):
        return _cmd_show(ctx) if ctx is not None else "no hermes context to read settings from (run inside hermes)"
    return "usage: hermes passkey-gate <serve|bootstrap|audit-verify|pin|expose|set|get> [args]"


# keys exactly as declared in plugin.yaml config_schema
_SETTINGS_SPEC = {
    "origin": {"type": "str", "webauthn_note": "must be https:// (except localhost)"},
    "rp_id": {"type": "str"},
    "port": {"type": "int"},
    "challenge_ttl": {"type": "int"},
    "require_passkey": {"type": "bool"},
    "authority_patterns": {"type": "list"},
}


def _parse_setting(key, raw: str):
    """Parse a CLI value per the setting's declared type. Returns (value, error)."""
    spec = _SETTINGS_SPEC[key]
    typ = spec["type"]
    raw = raw.strip()
    try:
        if typ == "bool":
            low = raw.lower()
            if low in ("true", "yes", "on", "1"):
                return True, None
            if low in ("false", "no", "off", "0"):
                return False, None
            return None, f"{key} wants true/false, got {raw!r}"
        if typ == "int":
            return int(raw), None
        if typ == "list":
            stripped = raw
            try:
                val = json.loads(stripped)
                if not isinstance(val, list):
                    raise ValueError("not a list")
                return val, None
            except (json.JSONDecodeError, ValueError):
                # comma fallback so people don't need to remember JSON quoting
                return [x.strip() for x in stripped.split(",") if x.strip()], None
        return raw, None
    except ValueError as exc:
        return None, f"{key}: {exc}"


def _cmd_set(ctx, rest):
    if not rest:
        return "usage: hermes passkey-gate set <key> <value> — keys: " + ", ".join(_SETTINGS_SPEC)
    key, raw = rest[0], " ".join(rest[1:])
    if key not in _SETTINGS_SPEC:
        return f"unknown setting {key!r}. Keys: " + ", ".join(_SETTINGS_SPEC)
    value, err = _parse_setting(key, raw)
    if err:
        return err
    if key == "origin" and value:
        # WebAuthn: https everywhere except loopback dev origins
        if not (value.startswith("https://") or value.startswith("http://127.0.0.1")
                or value.startswith("http://localhost")):
            return "origin must be https:// (loopback http is tolerated for dev) — webauthn requirement"
    ctx.set_config(key, value)
    _apply_config(ctx)
    return f"{key} = {json.dumps(value)}\n" + _cmd_show(ctx)


def _cmd_show(ctx):
    rows = []
    for key in _SETTINGS_SPEC:
        cur = ctx.get_config(key, default=_DEFAULTS.get(key))
        rows.append(f"  {key} = {json.dumps(cur)}")
    return "passkey-gate settings (plugins.entries.passkey-gate.settings.*):\n" + "\n".join(rows)


_DEFAULTS = {
    "origin": "",
    "rp_id": "",
    "port": 8655,
    "challenge_ttl": 600,
    "require_passkey": False,
    "authority_patterns": [],
}


def _cmd_expose(ctx, args, data_dir):
    """Set up public HTTPS exposure per what the user has installed:
    configured origin > tailscale serve --bg > cloudflared quick tunnel > help."""
    from . import expose

    backend = args[0].strip().lower() if args else "auto"
    if backend not in ("auto", "tailscale", "cloudflare", "none"):
        return "usage: hermes passkey-gate expose [auto|tailscale|cloudflare|none]"
    origin_cfg = (ctx.get_config("origin", default="") or "").strip() if ctx is not None else ""
    rp_cfg = (ctx.get_config("rp_id", default="") or "").strip() if ctx is not None else ""
    gate_port = int(ctx.get_config("port", default=8655)) if ctx is not None else 8655

    if backend == "auto":
        result = expose.auto_expose(gate_port, origin_cfg, rp_cfg)
    elif backend == "tailscale":
        result = expose.tailscale_expose(gate_port)
    elif backend == "cloudflare":
        result = expose.cloudflare_expose(gate_port)
    else:
        result = {"ok": False, "backend": "none",
                  "error": "none requested: set plugins.entries.passkey-gate.settings.origin to your HTTPS origin"}
    if not result.get("ok"):
        return json_dumps(result)

    url, rp_id = result["url"], result["rp_id"]
    lines = [f"exposure ready: {url} (rp_id {rp_id})", result.get("note", "")]
    if result.get("persistent") and ctx is not None:
        # persist so future sessions mint challenges to the same origin without
        # re-running expose (tailscale keeps serving; config is the record)
        ctx.set_config("origin", url)
        ctx.set_config("rp_id", rp_id)
        gate_core.configure(rp_id=rp_id, origin=url)
        lines.append("saved origin + rp_id to plugin settings")
    if backend == "cloudflare":
        lines.append("holding the quick-tunnel process open — Ctrl+C stops the public URL")
        proc = result.get("process")
        if proc is not None:
            try:
                proc.wait()
            except KeyboardInterrupt:
                pass
    return "\n".join(_nonempty(lines))


def _nonempty(lines):
    return [line for line in lines if line]


def json_dumps(obj):
    import json as _json
    return _json.dumps(obj, indent=2)


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
