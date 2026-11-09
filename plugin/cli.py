"""Commands under `hermes passkey-gate <command>`.

Getting started
  setup              guided first run: starts the gate, gives it an HTTPS
                     address, registers your phone's passkey and pins it
                     when you type the code the phone shows. Safe to re-run.
  service <action>   run the gate in the background (install, status, logs,
                     start, stop, restart, uninstall). Uses a systemd user
                     unit on Linux or a LaunchAgent on macOS.
  serve              run the gate in this terminal instead.
  status             is the gate reachable, is your key pinned, is
                     enforcement on?

Setting up by hand (what `setup` does)
  expose [auto|tailscale]
                     give the gate an HTTPS address (Tailscale, or check the
                     origin you configured) and save it.
  bootstrap          print a one-time registration link and QR code for your
                     phone (15 minutes, single use). Show it only on your own
                     screen; never send it through a chat.
  credentials        list registered passkeys with their confirmation codes.
  pin --code <XXXXX-XXXXX>
                     trust the passkey whose code your phone showed.
  pin --credential <id-prefix>  |  pin <pem-file> [owner]
                     trust a passkey by id, or a public key file (name an
                     owner to trust another person's key for shared
                     approvals).

Day to day
  show <challenge-id>
                     print a pending request's link and QR code.
  set <key> <value> [--approve <challenge-id>]
                     change a setting; applies to a running gate at once.
                     Changes that make the gate weaker (turning enforcement
                     off, removing a pattern, trusting another gate, a longer
                     request lifetime, moving the address) need your passkey:
                     the refusal prints a link and the --approve command.
  get                show all settings.
  mint-token         print the token another machine's agent needs to send
                     requests to this gate. It can create requests, never
                     approve them.

Audit log
  audit-verify [--notary <file>]
                     check the log's hash chain and, if you keep an anchor
                     file, compare against it (INTACT AND NOTARIZED, GROWN
                     SINCE NOTARIZATION, or DIVERGED).
  audit-notarize [--to <file>]
                     record the log's current head in an anchor file outside
                     the gate's data folder. The chain alone can't detect the
                     whole log being rewritten; the anchor can.

Run setup, bootstrap and pin yourself, never through an agent: they decide
which key is trusted.
"""
import json
import logging
import os
import secrets
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import gate_core, expose, lanes, local_verify, netfetch, service, tools

logger = logging.getLogger(__name__)

USAGE = ("usage: hermes passkey-gate "
         "<setup|service|serve|bootstrap|expose|credentials|pin|show|set|get|status|mint-token|"
         "audit-verify|audit-notarize> [args]\n"
         "new here? run: hermes passkey-gate setup")

# keys exactly as declared in plugin.yaml config_schema (drift-tested)
SETTINGS_SPEC = {
    "origin": {"type": "str"},
    "rp_id": {"type": "str"},
    "port": {"type": "int", "min": gate_core.PORT_MIN, "max": gate_core.PORT_MAX},
    "challenge_ttl": {"type": "int", "min": gate_core.CHALLENGE_TTL_MIN, "max": gate_core.CHALLENGE_TTL_MAX},
    "require_passkey": {"type": "bool"},
    "authority_patterns": {"type": "list"},
    "parent_gate_allowlist": {"type": "list"},
    "audit_notary_path": {"type": "str"},
    "gated_lanes": {"type": "list"},
    "owner_senders": {"type": "list"},
}

DEFAULTS = {
    "origin": "",
    "rp_id": "",
    "port": 8655,
    "challenge_ttl": 600,
    "require_passkey": False,
    "authority_patterns": [],
    "parent_gate_allowlist": [],
    "audit_notary_path": "",
    "gated_lanes": list(lanes.LANES),
    "owner_senders": [],
}

# finding 16: the settings that define what the gate enforces. An agent with
# terminal access could disarm any of them with one unauthenticated `set`, so
# weakening one requires a passkey approval of an exact server-derived
# phrase; strengthening is free; every change is audited.
SECURITY_KEYS = ("require_passkey", "authority_patterns", "parent_gate_allowlist",
                 # H11: a longer TTL keeps signed approvals spendable longer,
                 # and moving origin/rp_id re-points where approvals are
                 # minted and what they are verified against
                 "challenge_ttl", "origin", "rp_id",
                 # v0.8 lanes: ungating a lane, or naming a sender as the
                 # owner, takes those conversations out of enforcement
                 "gated_lanes", "owner_senders")

_ctx_ref = None
_cfg_cache = None
_cfg_stamp = None  # settings-source signature the cache was built from


# ---------------------------------------------------------------- ctx plumbing
def plugin_data(ctx):
    try:
        from plugins.plugin_storage import plugin_data_dir
        return plugin_data_dir("passkey-gate")
    except Exception:
        # outside Hermes (tests, manual runs): keep it out of the install tree
        return Path(__file__).resolve().parent / ".gate-data"


def apply_config(ctx):
    origin = (ctx.get_config("origin", default="") or "").strip()
    rp_id_c = (ctx.get_config("rp_id", default="") or "").strip()
    port = ctx.get_config("port", default=8655)
    ttl = ctx.get_config("challenge_ttl", default=600)
    allow = ctx.get_config("parent_gate_allowlist", default=[]) or []
    if not isinstance(allow, list):  # fail closed on unexpected typing
        allow = []
    gate_core.configure(data_dir=str(plugin_data(ctx)),
                        rp_id=rp_id_c or os_default_rp_id(origin),
                        origin=origin or None,
                        port=int(port),
                        challenge_ttl=int(ttl),
                        parent_allowlist=allow)
    owners = ctx.get_config("owner_senders", default=[]) or []
    return {"require_passkey": bool(ctx.get_config("require_passkey", default=False)),
            "patterns": ctx.get_config("authority_patterns", default=[]) or [],
            # normalize_lanes fails closed on a malformed value (all lanes)
            "gated_lanes": ctx.get_config("gated_lanes", default=list(lanes.LANES)),
            "owner_senders": owners if isinstance(owners, list) else []}


def os_default_rp_id(origin: str = ""):
    """Best-effort RP ID when none is configured: the configured origin's own
    hostname (always a valid RP ID for that origin), else this machine's
    tailscale DNS name, else localhost."""
    host = expose.rp_id_from_origin(origin)
    if host:
        return host
    try:
        out = shutil.which("tailscale") and subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=5)
        if out and out.returncode == 0:
            host = (json.loads(out.stdout).get("Self") or {}).get("DNSName", "")
            if host:
                return host.rstrip(".")
    except Exception:
        pass
    return "localhost"


def _settings_source():
    """The file the gate's settings are read through (the Hermes profile's
    config.yaml); None outside a Hermes runtime."""
    try:
        from hermes_cli.config import get_config_path
        return get_config_path()
    except Exception:
        return None


def _settings_stamp():
    """One cheap stat of the settings source per verdict, so out-of-band
    edits (a config form, a second CLI process, an editor) take effect
    without a process restart. Mirrors Hermes's own config-cache signature."""
    path = _settings_source()
    if path is None:
        return None
    try:
        st = path.stat()
        return (str(path), st.st_mtime_ns, st.st_size, st.st_ino, st.st_ctime_ns)
    except OSError:
        return ("unreadable", str(path))


# ------------------------------------------------------------ config canary
# Finding 17: if the gate's settings are lost — a settings reset, an edit
# that removed them, another profile's config, or a config.yaml that won't
# parse with no last-known-good copy to fall back on — readers get silent
# DEFAULTS, and the default here is "enforcement off". To tell "the operator chose these settings" from "the
# loader fell back", every operator command that writes settings also writes
# a random check value into them (CANARY_KEY), and keeps a copy in the gate's
# data dir — which a broken config.yaml cannot take with it. On every load:
#   no copy            -> never configured: default-off is the honest state
#   copy == config     -> the config was read
#   copy, config lacks -> fall back / wrong profile / replaced: FAIL CLOSED
# Only public plugin API (ctx.get_config / set_config) is involved. The
# canary is never written on load: writing into a config the loader just
# failed to parse could overwrite the operator's real settings.
CANARY_KEY = "config_canary"


def _canary_file() -> Path:
    return gate_core.data_dir() / "config-canary"


def _expected_canary():
    """The check value this gate expects in its config, or None if the gate
    was never configured. An unreadable copy raises (the caller fails closed)."""
    try:
        return _canary_file().read_text().strip() or None
    except FileNotFoundError:
        return None


def config_canary_problem(ctx):
    """None when the settings were demonstrably read (or the gate was never
    configured); otherwise a plain explanation with the way out."""
    if ctx is None:
        return None
    try:
        expected = _expected_canary()
    except Exception as exc:  # unreadable OR undecodable: fail closed (A4)
        return (f"the gate's config check file {_canary_file()} can't be read "
                f"({type(exc).__name__}: {exc})")
    if expected is None:
        return None
    try:
        got = ctx.get_config(CANARY_KEY, default=None)
    except Exception as exc:
        return f"the Hermes config can't be read ({type(exc).__name__}: {exc})"
    if got == expected:
        return None
    return (f"the Hermes config wasn't read as expected: passkey-gate's check value "
            f"({CANARY_KEY}) is {'missing' if got is None else 'different'}, so its settings "
            "were lost or replaced (a settings reset, an edit that removed them, a "
            "broken config.yaml, or another Hermes profile's config). Restore them and "
            "the gate picks them up automatically. If you replaced "
            f"the config on purpose, delete {_canary_file()} and run "
            "'hermes passkey-gate setup'.")


def _expected_canary_safe():
    try:
        return _expected_canary()
    except Exception:
        return None


def stamp_config_canary(ctx):
    """Arm the check after an operator command wrote settings successfully.
    Config first, then the copy: if writing the config fails, the check is
    simply not armed yet (never a fail-closed caused by our own write)."""
    if ctx is None or config_canary_problem(ctx):
        return
    expected = _expected_canary()
    if expected is not None:
        return  # already armed, and the config matches
    value = secrets.token_hex(8)
    ctx.set_config(CANARY_KEY, value)
    path = _canary_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    os.replace(tmp, path)


def invalidate_config_cache():
    """Drop the cached config so the next verdict reloads it (after `set`,
    or any other change to the settings)."""
    global _cfg_cache
    _cfg_cache = None


def _load_config_state():
    """Read the enforcement config once, failing CLOSED (finding 17).

    Only 'no config source at all' (no Hermes runtime) keeps the legitimate
    default-off behavior. A config that is PRESENT but fails to load — a
    malformed setting, a storage failure, or an unparseable settings file
    the loader silently replaced with defaults — yields require_passkey
    True plus a ``_config_error`` marker, and the pre_tool_call hook blocks
    on the marker instead of guessing which calls are high-authority.
    """
    if _ctx_ref is None:
        # never registered: nothing has been configured, so default-off is
        # the honest state, not a failure
        return {"require_passkey": False, "patterns": []}
    try:
        cfg = apply_config(_ctx_ref)
    except Exception as exc:
        logger.exception("passkey-gate: config load failed; failing closed until it loads")
        return {"require_passkey": True, "patterns": [],
                "_config_error": f"{type(exc).__name__}: {exc}"}
    problem = config_canary_problem(_ctx_ref)
    if problem:
        logger.error("passkey-gate: %s; failing closed", problem)
        return {"require_passkey": True, "patterns": [], "_config_error": problem}
    return cfg


def apply_config_safe():
    global _cfg_cache, _cfg_stamp
    stamp = _settings_stamp()
    if _cfg_cache is None or stamp != _cfg_stamp:
        _cfg_cache = _load_config_state()
        _cfg_stamp = stamp
    return _cfg_cache


# ---------------------------------------------------------------- commands
def cmd_serve(ctx, rest):
    # settings changed by `expose` / `set` in another terminal apply live
    gate_core._config_refresh = apply_config_safe
    gate_core.serve()
    return "serve returned"


def cmd_mint_token(ctx, rest):
    tok = gate_core.mint_api_token()
    return ("Gate mint token — HTTP POST /challenge requires it as "
            "'Authorization: Bearer <token>'. Give it only to remote agents that "
            "must mint approval requests on THIS gate (a token lets its holder put "
            "requests in front of the human, never approve them). Local agents "
            "mint in-process via gate_challenge and do not need it.\n\n" + tok)


def qr_text(data: str) -> str:
    """Terminal QR code for `data` ('' when qrcode is unavailable)."""
    try:
        import io
        import qrcode
        q = qrcode.QRCode(border=1)
        q.add_data(data)
        buf = io.StringIO()
        q.print_ascii(out=buf, invert=True)
        return buf.getvalue()
    except Exception:
        return ""


def cmd_bootstrap(ctx, rest):
    url = gate_core.mint_bootstrap_token()
    print(qr_text(url), flush=True)
    return (f"One-time registration link ({gate_core.bootstrap_ttl() // 60} min, single use). "
            f"Do not paste it anywhere — the QR above is enough for your phone.\n"
            f"After you create the passkey, the phone shows a 10-character code; pin it with:\n"
            f"  hermes passkey-gate pin --code <that code>\n\n{url}")


def cmd_setup(ctx, rest):
    from . import setup_wizard
    return setup_wizard.cmd_setup(ctx, rest)


SERVICE_USAGE = ("usage: hermes passkey-gate service "
                 "<install|uninstall|start|stop|restart|status|logs>")


def cmd_service(ctx, rest):
    action = rest[0].strip().lower() if rest else "status"
    try:
        port = gate_core.validate_port(ctx.get_config("port", default=8655) if ctx is not None else 8655)
    except ValueError as exc:
        return f"REFUSED: {exc}"
    if action == "install":
        _, text = service.install(port)
    elif action == "uninstall":
        _, text = service.uninstall()
    elif action in ("start", "stop", "restart"):
        _, text = service.control(action)
    elif action == "status":
        _, text = service.status(port)
    elif action == "logs":
        _, text = service.logs()
    else:
        return SERVICE_USAGE
    return text


def cmd_expose(ctx, rest):
    backend = rest[0].strip().lower() if rest else "auto"
    if backend not in ("auto", "tailscale", "none"):
        return "usage: hermes passkey-gate expose [auto|tailscale|none]"
    problem = config_canary_problem(ctx)
    if problem:
        return f"REFUSED: {problem}"
    origin_cfg = (ctx.get_config("origin", default="") or "").strip() if ctx is not None else ""
    rp_cfg = (ctx.get_config("rp_id", default="") or "").strip() if ctx is not None else ""
    try:
        gate_port = gate_core.validate_port(ctx.get_config("port", default=8655) if ctx is not None else 8655)
    except ValueError as exc:
        return f"REFUSED: {exc}; exposure was not started"
    if backend == "auto":
        result = expose.auto_expose(gate_port, origin_cfg, rp_cfg)
    elif backend == "tailscale":
        result = expose.tailscale_expose(gate_port)
    else:
        result = {"ok": False, "backend": "none",
                  "error": "none requested: set plugins.entries.passkey-gate.settings.origin to your HTTPS origin"}
    if not result.get("ok"):
        return json.dumps(result, indent=2)
    url, rp_id = result["url"], result["rp_id"]
    lines = [f"exposure ready: {url} (rp_id {rp_id})", result.get("note", "")]
    if (result.get("persistent") and ctx is not None and
            ((origin_cfg and url != origin_cfg) or (rp_cfg and rp_id != rp_cfg))):
        # H11: moving an established origin/rp_id is a gate-weakening change
        # — expose sets things up, it does not bypass the approval rule
        lines.append(f"NOT saved: an origin is already configured ({origin_cfg}, rp_id "
                     f"{rp_cfg or '(default)'}). Moving it needs a passkey approval — run "
                     f"'hermes passkey-gate set origin {url}' and follow its instructions.")
    elif result.get("persistent") and ctx is not None:
        try:  # first-time origin setup is free, but it is still recorded
            _ensure_data_dir()
            gate_core.audit("config_changed", key="origin", old=_jsonable(origin_cfg),
                            new=url, weakened=False, approved=None, via="expose")
            gate_core.audit("config_changed", key="rp_id", old=_jsonable(rp_cfg),
                            new=rp_id, weakened=False, approved=None, via="expose")
        except Exception:
            logger.exception("passkey-gate: could not audit the origin saved by expose")
        ctx.set_config("origin", url)
        ctx.set_config("rp_id", rp_id)
        stamp_config_canary(ctx)
        gate_core.configure(rp_id=rp_id, origin=url)
        lines.append("saved origin + rp_id to plugin settings (persists across sessions)")
    return "\n".join(x for x in lines if x)


def cmd_credentials(ctx, rest):
    """List registered passkeys with their key fingerprints, so the operator
    can pin the one whose code their phone showed after registering."""
    creds = gate_core.list_credentials()
    if not creds:
        return ("no passkeys registered yet — run 'hermes passkey-gate setup' "
                "and register on your phone first")
    try:
        pinned_pem = local_verify.pinned(gate_core.data_dir())
    except ValueError:
        pinned_pem = None
    lines = []
    for c in creds:
        when = datetime.fromtimestamp(c["registered_at"], timezone.utc).isoformat(timespec="seconds")
        mark = "  [PINNED owner key]" if pinned_pem and pinned_pem.strip() == c["spki_pem"].strip() else ""
        lines.append(f"code {c['code']}  registered {when}  id {c['credential_id'][:12]}…  "
                     f"fingerprint {c['fingerprint']}{mark}")
    lines += ["", "pin the one whose code your phone showed after registering:",
              "  hermes passkey-gate pin --code <the code from your phone>"]
    if len(creds) > 1:
        lines += ["", f"NOTE: {len(creds)} passkeys are registered. If you only registered one, "
                  "the others are not yours — never pin a key you did not just see on your own phone."]
    return "\n".join(lines)


def _pin_credential(c):
    try:
        path = local_verify.pin(gate_core.data_dir(), c["spki_pem"], None)
    except (OSError, ValueError) as exc:
        return f"REFUSED: pin ceremony failed: {exc}"
    try:
        gate_core.audit("owner_key_pinned", via="cli", credential_id=c["credential_id"],
                        fingerprint=c["fingerprint"])
    except Exception:
        pass
    return (f"pinned owner key, code {c['code']} (fingerprint {c['fingerprint']}, credential "
            f"{c['credential_id'][:12]}…) to {path}. Check this code is the one your phone "
            "showed. Approvals are now verified against it locally.")


def cmd_pin(ctx, rest):
    if not rest:
        return ("usage: hermes passkey-gate pin --code <code your phone showed>\n"
                "   or: hermes passkey-gate pin --credential <id-prefix>  "
                "(see 'hermes passkey-gate credentials')\n"
                "   or: hermes passkey-gate pin <pem-file> [owner-label]")
    if rest[0] == "--code":
        code = gate_core.normalize_confirmation_code(" ".join(rest[1:]))
        if not code:
            return ("usage: hermes passkey-gate pin --code <XXXXX-XXXXX> — the 10-character "
                    "code your phone showed after creating the passkey")
        matches = [c for c in gate_core.list_credentials() if c["code"] == code]
        if len(matches) != 1:
            return (f"REFUSED: {len(matches) or 'no'} registered passkey(s) have code {code}. "
                    "Check the code on your phone (see 'hermes passkey-gate credentials'); "
                    "if it isn't listed, that passkey did not register on this gate.")
        return _pin_credential(matches[0])
    if rest[0] == "--credential":
        if len(rest) < 2 or len(rest[1]) < 6:
            return "usage: hermes passkey-gate pin --credential <at least 6 characters of the id>"
        matches = [c for c in gate_core.list_credentials() if c["credential_id"].startswith(rest[1])]
        if len(matches) != 1:
            return (f"REFUSED: {len(matches)} registered passkeys match {rest[1]!r} — give enough "
                    "of the id to pick exactly one (see 'hermes passkey-gate credentials')")
        return _pin_credential(matches[0])
    try:
        pem = Path(rest[0]).read_text()
    except OSError as exc:
        return f"REFUSED: could not read PEM file {rest[0]!r}: {exc}"
    owner = rest[1] if len(rest) > 1 else None
    try:
        path = local_verify.pin(gate_core.data_dir(), pem, owner)
    except (OSError, ValueError) as exc:
        return f"REFUSED: pin ceremony failed: {exc}"
    label = f" ({owner})" if owner else ""
    return (f"pinned owner key{label} to {path}. Approvals can now be verified "
            f"independently against it locally.")


def cmd_show(ctx, rest):
    """Print approval URL + QR for a pending challenge — the human can open or
    scan it straight away, regardless of which channel the ask arrived in."""
    if not rest:
        return "usage: hermes passkey-gate show <challenge-id>"
    cid = rest[0].strip()
    if not gate_core.ID_RE.match(cid):
        return "not a valid challenge id"
    row = gate_core.db().execute("select * from challenges where id=?", (cid,)).fetchone()
    if row is None:
        return "no such challenge"
    st = row["status"] if row["status"] != "pending" or time_left(row) > 0 else "expired"
    lines = [f"challenge: {cid}", f"status: {st}",
             f"requester: {row['requester']}" +
             (f" (agent of {row['requester_owner']})" if row["requester_owner"] else "")]
    if row["why"]:
        lines.append(f"why: {row['why']}")
    if gate_core.origin():
        url = f"{gate_core.origin()}/a/{cid}"
        lines.append(f"url: {url}")
        try:
            import qrcode
            q = qrcode.QRCode(border=1)
            q.add_data(url)
            q.print_ascii(invert=True)
        except Exception:
            pass
    else:
        lines.append("gate origin not configured — run: hermes passkey-gate expose")
    return "\n".join(lines)


def time_left(row):
    return row["expires_at"] - time.time()


# ------------------------------------------------- finding 16: gated `set`
def _split_approve_flag(rest):
    """Pull `--approve <challenge-id>` off a set command's args.
    Returns (positional_args, challenge_id_or_None, error_or_None)."""
    args = list(rest)
    if "--approve" not in args:
        return args, None, None
    i = args.index("--approve")
    if i + 1 >= len(args):
        return (args, None,
                "--approve needs the challenge id of the passkey approval, e.g.: "
                "hermes passkey-gate set require_passkey false --approve <challenge-id>")
    cid = args[i + 1].strip()
    del args[i:i + 2]
    return args, cid, None


def _canonical_value(value):
    """Canonical JSON spelling of a setting value — the exact form embedded in
    the server-derived approval phrase, so what the human reads and signs is
    byte-identical to what cmd_set re-derives at verification time."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _quoted(items):
    return ", ".join(json.dumps(str(x)) for x in items)


def _change_description(key, old, new):
    """What a gate-weakening change does, in words the signer can judge
    (v0.7 review M5: showing only the new value let a near-identical edit
    that disables a pattern look like the existing rule)."""
    if key == "require_passkey":
        return "turns enforcement OFF (require_passkey true → false)"
    if key == "gated_lanes":
        old_l = sorted(lanes.normalize_lanes(old), key=lanes.LANES.index)
        new_l = sorted(lanes.normalize_lanes(new), key=lanes.LANES.index)
        removed = [x for x in old_l if x not in new_l]
        return ("stops requiring a passkey in lane(s) "
                + ", ".join(f"{x} ({lanes.LANE_WORDS[x]})" for x in removed)
                if removed else f"gated_lanes: {_quoted(old_l)} → {_quoted(new_l)}")
    if key in ("authority_patterns", "parent_gate_allowlist", "owner_senders"):
        old_l = [str(x) for x in (old or [])] if isinstance(old, (list, tuple)) else []
        new_l = [str(x) for x in (new or [])] if isinstance(new, (list, tuple)) else []
        removed = [x for x in old_l if x not in new_l]
        added = [x for x in new_l if x not in old_l]
        noun = {"authority_patterns": "pattern", "parent_gate_allowlist": "trusted peer gate",
                "owner_senders": "owner sender"}[key]
        parts = []
        if removed:
            parts.append(f"REMOVES {len(removed)} {noun}(s): {_quoted(removed)}")
        if added:
            parts.append(f"ADDS {len(added)} {noun}(s): {_quoted(added)}")
        if not parts:
            parts.append(f"shrinks the list from {len(old_l)} to {len(new_l)} entries")
        return f"{key}: " + "; ".join(parts)
    if key == "challenge_ttl":
        return f"lengthens the request lifetime from {old} to {new} seconds"
    if key == "origin":
        return f"moves the gate's address from {old!r} to {new!r}"
    if key == "rp_id":
        return f"moves the passkey domain (RP ID) from {old!r} to {new!r}"
    return f"{key}: {_canonical_value(old)} → {_canonical_value(new)}"


def weakening_phrase(key, new_value, old_value=None):
    """The EXACT server-derived action text a passkey must sign to authorize
    this gate-weakening change (finding 16). One derivation serves both the
    mint and the verification, so the two can never drift apart. It names
    the old value as well as the new one, so an approval only applies to the
    state it was granted against (v0.7 review M5)."""
    return (f"passkey-gate settings change: {_change_description(key, old_value, new_value)}. "
            f"Exact change: {key} from {_canonical_value(old_value)} to "
            f"{_canonical_value(new_value)}. This weakens the gate; approve only if you "
            "asked for it.")


def _normalize_typed(key, value):
    """Coerce a stored setting to its declared type for direction comparison.
    None means 'so malformed the direction cannot be judged' (fail closed)."""
    typ = SETTINGS_SPEC[key]["type"]
    if typ == "bool":
        return bool(value)
    if typ == "list":
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(x) for x in value]
        return None
    return value


def _change_weakens(key, old, new):
    """True when a change makes the gate easier to bypass (finding 16):
    turning require_passkey off, removing any authority pattern (or
    shrinking/emptying the list), or adding a parent-gate allowlist entry.
    The reverse directions are free; a change whose direction cannot be
    judged counts as weakening."""
    old_n, new_n = _normalize_typed(key, old), _normalize_typed(key, new)
    if old_n is None or new_n is None:
        return True  # cannot judge the direction -> fail closed
    if key == "require_passkey":
        return bool(old_n) and not bool(new_n)
    if key == "authority_patterns":
        if not (isinstance(old_n, list) and isinstance(new_n, list)):
            return True  # a non-list in a list slot cannot be judged -> fail closed
        removed = set(old_n) - set(new_n)
        return bool(removed) or len(new_n) < len(old_n)
    if key in ("parent_gate_allowlist", "owner_senders"):
        if not (isinstance(old_n, list) and isinstance(new_n, list)):
            return True
        return bool(set(new_n) - set(old_n))
    if key == "gated_lanes":
        if not (isinstance(old_n, list) and isinstance(new_n, list)):
            return True
        return bool(lanes.normalize_lanes(old_n) - lanes.normalize_lanes(new_n))
    if key == "challenge_ttl":
        # raising the TTL keeps approvals live longer; lowering is free
        try:
            return int(new_n) > int(old_n if old_n is not None else DEFAULTS["challenge_ttl"])
        except (TypeError, ValueError):
            return True
    if key in ("origin", "rp_id"):
        # first-time setup (nothing configured yet) is free; moving an
        # established origin/RP ID is not
        old_s = (old_n or "").strip() if isinstance(old_n, str) or old_n is None else None
        if old_s is None or not isinstance(new_n, str):
            return True
        return bool(old_s) and new_n.strip() != old_s
    return False


def _jsonable(value):
    """Audit-safe representation: JSON values pass through, anything exotic
    degrades to its repr instead of letting audit() raise."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)


def _ensure_data_dir():
    """gate_core.audit() assumes the data dir already exists (db() normally
    creates it); a `set` can run before anything else has touched a fresh
    install, so create it here — the same mkdir+chmod db() itself does."""
    try:
        d = gate_core.data_dir()
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    except Exception:
        pass


def _verify_weakening_approval(cid, phrase):
    """Problems list for a --approve challenge; empty == a passkey owned by
    the pinned human signed this exact phrase. Uses gate_verify's fetch path
    (same origin/redirect rules, same seams), then re-derives every claim
    LOCALLY — the gate's yes/no is never trusted on its own."""
    base = tools._base_url()
    # Claims issue 3 (finding 23's rule): gate URLs are PARSED, never
    # prefix-checked — the same rule cmd_set enforces; the old
    # startswith(('http://', 'https://')) check accepted credential-carrying
    # and hostless origins.
    try:
        netfetch.parse_gate_origin(base)
    except ValueError:
        return ["the gate origin is not configured or is not a valid gate origin "
                "(https; loopback http tolerated for dev) — set "
                "plugins.entries.passkey-gate.settings.origin (or run "
                "'hermes passkey-gate expose') so the approval can be checked "
                "against the gate"]
    sha = tools.hashlib_sha256(phrase)
    rec = tools._fetch_verify(base, cid, sha)
    if not isinstance(rec, dict):
        return [f"the gate returned {rec!r} instead of an approval record"]
    status = rec.get("status")
    if status != "approved":
        detail = f" ({rec['error']})" if isinstance(rec.get("error"), str) else ""
        return [f"the approval challenge status is {status!r}, not approved{detail} — "
                "the human has not signed this exact change (or the approval is "
                "expired or already consumed)"]
    if rec.get("action_sha256") != sha:
        return ["the approval was signed for different action text than this "
                "change requires"]
    # v0.7 review M1: only a challenge the gate's own CLI minted for a
    # settings change counts — never an agent's request, even one whose text
    # is the same phrase, and never one with a bound tool call (the page
    # would have told the human to judge the command, not this text)
    row = gate_core.db().execute(
        "select kind, binding_sha256, tool_call, action_sha256 from challenges where id=?",
        (cid,)).fetchone()
    if (row is None or row["kind"] != gate_core.SETTINGS_KIND or row["binding_sha256"]
            or row["tool_call"] or row["action_sha256"] != sha):
        return ["this approval wasn't created by passkey-gate for a settings change, so it "
                "can't authorise one — re-run the change without --approve to get the right "
                "approval link"]
    pinned = local_verify.pinned(gate_core.data_dir())
    if pinned is None:
        return ["no owner key is pinned — run 'hermes passkey-gate setup' (or 'hermes passkey-gate pin --code <code from your phone>') before any gate-weakening "
                "change can be approved"]
    return [f"local verification failed: {p}" for p in
            local_verify.check(rec, phrase, tools._origin(), gate_core.rp_id(), pinned)]


def _weakening_needs_approval(key, new_value, raw, old_value=None):
    """Refusal that carries its own recovery (finding 16): mint the approval
    challenge for the EXACT server-derived phrase and hand back the URL, the
    challenge id, and the --approve re-run — the human decides, not the agent
    this setting is meant to constrain."""
    phrase = weakening_phrase(key, new_value, old_value)
    lines = [f"REFUSED: set {key} weakens the passkey gate — enforcement settings "
             "are operator-owned, and a gate-weakening change needs a passkey "
             "approval signed by your human first.",
             "",
             "approval phrase (the human signs EXACTLY this):",
             f"  {phrase}"]
    try:
        c = gate_core.create_challenge(phrase, "hermes-cli", _kind=gate_core.SETTINGS_KIND)
    except Exception as exc:
        c = None
        lines.append(f"  (no approval challenge could be created — {type(exc).__name__}: "
                     f"{exc}; fix that and re-run this command)")
    if c:
        if c.get("url"):
            lines += ["", "approval URL — send it to your human; they read the page "
                      "and sign with their passkey:", f"  {c['url']}"]
        else:
            lines += ["", "the gate origin is not configured, so there is no approval "
                      "URL yet — run 'hermes passkey-gate expose' (or set origin), "
                      "then re-run this command"]
        lines += ["", "once they approve, re-run the same change with:",
                  f"  hermes passkey-gate set {key} {raw} --approve {c['challenge_id']}"]
    if key in ("origin", "rp_id"):
        lines += ["", "if the CURRENT origin no longer works (so no approval can be "
                  "signed on it), the operator can change it out of band by editing "
                  "plugins.entries.passkey-gate.settings in the Hermes config file "
                  "directly — then re-register the passkey, since credentials are "
                  "bound to the RP ID"]
    return "\n".join(lines)


def _weakening_approval_failed(key, new_value, problems, old_value=None):
    """Refusal for a --approve that did not verify, with the reasons."""
    return "\n".join(
        [f"REFUSED: set {key} weakens the passkey gate, and the supplied approval "
         "did not verify for this exact change:"] +
        [f"  - {p}" for p in problems] +
        ["", "approval phrase this change requires (the human must sign exactly this):",
         f"  {weakening_phrase(key, new_value, old_value)}",
         "re-run without --approve to mint a fresh approval challenge, send its URL "
         "to your human, and re-run with --approve once they have signed it."])


def _weakening_approval_used(key, cid):
    """F1 refusal for a REPLAYED approval: the challenge was already consumed
    by an application (or this application lost the atomic claim to a
    concurrent one). One human signature authorises exactly one
    gate-weakening change — re-arming does not revive a spent approval."""
    return "\n".join(
        [f"REFUSED: set {key} weakens the passkey gate, and its approval challenge "
         f"{cid} has already been used.",
         "",
         "A passkey approval is single-use: one human signature authorises exactly "
         "ONE application of one gate-weakening change, and it is consumed at apply "
         "time — re-arming the gate does not revive it.",
         "",
         "Re-run the same change WITHOUT --approve to mint a fresh approval "
         "challenge, send its URL to your human, and re-run with --approve once "
         "they have signed it."])


# Settings the setup wizard may narrow without a passkey, but only BEFORE it
# turns enforcement on: with require_passkey off nothing is enforced yet, so
# choosing the lanes is part of switching enforcement on, not a weakening.
SETUP_FREE_WHILE_OFF = ("gated_lanes", "owner_senders")


def cmd_set(ctx, rest, *, _setup_enforcement_off=False):
    if not rest:
        return ("usage: hermes passkey-gate set <key> <value> [--approve <challenge-id>] — keys: "
                + ", ".join(SETTINGS_SPEC))
    rest, approve_cid, flag_err = _split_approve_flag(rest)
    if flag_err:
        return flag_err
    key, raw = rest[0], " ".join(rest[1:])
    if key not in SETTINGS_SPEC:
        return f"unknown setting {key!r}. Keys: " + ", ".join(SETTINGS_SPEC)
    problem = config_canary_problem(ctx)
    if problem:
        # writing into a config Hermes couldn't read could replace the
        # operator's real settings — and would then "match" the canary
        return f"REFUSED: {problem} Nothing was saved."
    value, err = parse_setting(key, raw)
    if err:
        return err
    if key == "origin" and value:
        # WebAuthn: https everywhere except loopback dev origins. PARSE the
        # URL (finding 23): a prefix check accepts credential-carrying,
        # hostless, and unparseable origins.
        try:
            netfetch.parse_gate_origin(value)
        except ValueError as exc:
            return f"origin rejected: {exc} — WebAuthn needs https (loopback http tolerated for dev)"
    if key == "authority_patterns":
        # finding 22: a pattern list is validated whole BEFORE anything else
        # — before the weakening classification, so an invalid pattern can
        # never hide behind (or trip) the finding-16 approval machinery —
        # and refused whole: nothing from an unsound list is persisted.
        problems = tools.validate_authority_patterns(value)
        if problems:
            return ("REFUSED: authority_patterns rejected — nothing was saved. Every "
                    f"pattern must be a string, a regex that compiles, at most "
                    f"{tools.MAX_PATTERN_LEN} chars, with at most "
                    f"{tools.MAX_PATTERN_COUNT} patterns in the list:\n  - "
                    + "\n  - ".join(problems)
                    + "\nFix the pattern(s) and re-run the same command.")
    if key == "gated_lanes":
        problems = lanes.validate(value)
        if problems:
            return "REFUSED: gated_lanes rejected — nothing was saved:\n  - " + "\n  - ".join(problems)
        value = sorted({str(v).strip().lower() for v in value}, key=lanes.LANES.index)
    if key == "owner_senders":
        problems = lanes.validate_owner_senders(value)
        if problems:
            return "REFUSED: owner_senders rejected — nothing was saved:\n  - " + "\n  - ".join(problems)
        value = [str(v).strip() for v in value]
    _ensure_data_dir()  # audit() needs the data dir; db() may never have run
    if key in SECURITY_KEYS:
        # finding 16: enforcement policy is operator-owned, not agent-mutable.
        # A WEAKENING change is refused unless --approve names a passkey
        # approval of the exact server-derived phrase; strengthening applies
        # free; both directions are audited.
        try:
            old = ctx.get_config(key, default=DEFAULTS.get(key))
        except Exception as exc:
            return (f"REFUSED: the current {key} cannot be read to tell whether this "
                    f"change weakens the gate ({type(exc).__name__}: {exc}) — a "
                    "security-critical setting is never changed while its current "
                    "value is unreadable")
        weakens = _change_weakens(key, old, value)
        setup_free = (weakens and _setup_enforcement_off and key in SETUP_FREE_WHILE_OFF
                      and not bool(ctx.get_config("require_passkey", default=False)))
        if setup_free:
            weakens = False
        if weakens:
            if approve_cid is None:
                return _weakening_needs_approval(key, value, raw, old)
            phrase = weakening_phrase(key, value, old)
            problems = _verify_weakening_approval(approve_cid, phrase)
            if problems:
                # F1: an approval already spent on an application replays
                # as status 'consumed' — route that to the single-use
                # refusal so the operator learns the rule, not just a
                # failed check (the verification itself is unchanged).
                if gate_core.challenge_consumed(approve_cid):
                    return _weakening_approval_used(key, approve_cid)
                return _weakening_approval_failed(key, value, problems, old)
            # F1: burn the approval ATOMICALLY, before anything is applied
            # or audited — the claim is one conditional UPDATE in the same
            # discipline as gate_core.consume(), so concurrent
            # applications of the same --approve challenge cannot both
            # win: exactly one applies, every replay and race loser is
            # refused below.
            if not gate_core.consume_approval(approve_cid, tools.hashlib_sha256(phrase)):
                return _weakening_approval_used(key, approve_cid)
        # audit BEFORE applying: a security-critical change that cannot be
        # audited does not happen
        try:
            gate_core.audit("config_changed", key=key, old=_jsonable(old), new=_jsonable(value),
                            weakened=weakens,
                            **({"via": "setup, before enforcement was on"} if setup_free else {}),
                            approved=approve_cid if weakens else None,
                            consumed=approve_cid if weakens else None)
        except Exception as exc:
            return (f"REFUSED: this change could not be recorded in the audit log "
                    f"({type(exc).__name__}: {exc}) — a security-critical change that "
                    f"cannot be audited does not happen. Fix the gate's data directory "
                    f"({gate_core.data_dir()}) and re-run.")
    else:
        try:  # non-security keys keep today's behavior; the audit is best-effort
            gate_core.audit("config_changed", key=key,
                            old=_jsonable(ctx.get_config(key, default=DEFAULTS.get(key))),
                            new=_jsonable(value), weakened=False, approved=None)
        except Exception:
            pass
    ctx.set_config(key, value)
    stamp_config_canary(ctx)
    # finding 7: a running gateway must see this change on the NEXT hook
    # call — drop the cache before re-applying so no verdict serves stale state
    invalidate_config_cache()
    apply_config(ctx)
    note = ""
    if key == "port" and (ctx.get_config("origin", default="") or "").strip():
        # v0.7 review H1: the HTTPS address doesn't follow the port
        note = ("NOTE: your HTTPS address still forwards to the old port. Until it's "
                "updated, whatever listens there answers your phone instead of the gate. "
                "Update the forwarding (for Tailscale: run 'hermes passkey-gate expose').\n")
    return f"{key} = {json.dumps(value)}\n" + note + cmd_show_settings(ctx)


def parse_setting(key, raw: str):
    """Parse a CLI value per the setting's declared type. Returns (value, error)."""
    typ = SETTINGS_SPEC[key]["type"]
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
            value = int(raw)
            minimum, maximum = SETTINGS_SPEC[key]["min"], SETTINGS_SPEC[key]["max"]
            if not minimum <= value <= maximum:
                return None, (f"REFUSED: {key} must be an integer in the allowed range "
                              f"{minimum}..{maximum}; nothing was saved")
            return value, None
        if typ == "list":
            try:
                val = json.loads(raw)
                if not isinstance(val, list):
                    raise ValueError("not a list")
                return val, None
            except (json.JSONDecodeError, ValueError):
                # comma fallback so people don't need to remember JSON quoting
                return [x.strip() for x in raw.split(",") if x.strip()], None
        return raw, None
    except ValueError as exc:
        if typ == "int":
            minimum, maximum = SETTINGS_SPEC[key]["min"], SETTINGS_SPEC[key]["max"]
            return None, (f"REFUSED: invalid {key}; it must be an integer in the allowed range "
                          f"{minimum}..{maximum}; got {raw!r}; nothing was saved")
        return None, f"{key}: {exc}"


def cmd_show_settings(ctx, rest=None):
    rows = []
    for key in SETTINGS_SPEC:
        cur = ctx.get_config(key, default=DEFAULTS.get(key))
        rows.append(f"  {key} = {json.dumps(cur)}")
    return "passkey-gate settings (plugins.entries.passkey-gate.settings.*):\n" + "\n".join(rows)


def cmd_status(ctx, rest):
    """One-screen answer to 'can I rely on this gate right now?'"""
    out = {"gate": {"reachable": False}}
    base = ((ctx.get_config("origin", default="") or "").strip()).rstrip("/") if ctx is not None else ""
    if not base:
        out["gate"] = {"reachable": False, **tools.gate_unreachable_reason(base)}
    else:
        try:
            with netfetch.open_no_redirect(f"{base}/health", timeout=8) as r:
                out["gate"] = {**json.loads(r.read()), "reachable": r.status == 200}
        except Exception as exc:
            out["gate"] = {"reachable": False, **tools.gate_unreachable_reason(base, exc)}
    out["origin_configured"] = bool(base)
    out["backends_detected"] = expose.detect_backends()
    out["owner_key_pinned"] = local_verify.pinned(gate_core.data_dir()) is not None
    pins_dir = gate_core.data_dir() / "pins"
    out["peer_keys_pinned"] = sorted(p.name[:-4] for p in pins_dir.glob("*.pem")) if pins_dir.exists() else []
    problem = config_canary_problem(ctx)
    out["config_check"] = (f"FAILING: {problem}" if problem else
                           "ok" if _expected_canary_safe() else
                           "not armed yet (run 'hermes passkey-gate setup')")
    out["enforcement"] = {**apply_config_safe(),
                          "note": "patterns are regexes matched against tool_name + canonical args JSON"}
    return json.dumps(out, indent=2)


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _notary_file(ctx, override):
    """Resolve the operator's notary file: explicit flag wins, else the
    configured audit_notary_path (non-security key — it only names where
    anchors are kept, not what the gate enforces), else None."""
    if override:
        return Path(override).expanduser()
    if ctx is not None:
        configured = (ctx.get_config("audit_notary_path", default="") or "").strip()
        if configured:
            return Path(configured).expanduser()
    return None


def _read_notary(p):
    """Parse the operator's notary file: lines of '<ISO timestamp> <head
    hash>' as written by audit-notarize (or pasted by hand from its output).
    Returns (records, problem); records is [(ts, head), ...]."""
    records = []
    for i, line in enumerate(p.read_text().splitlines()):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if (len(parts) != 2 or len(parts[1]) != 64
                or set(parts[1]) > set("0123456789abcdef")):
            return None, (f"notary file line {i + 1} is malformed "
                          "(expected '<timestamp> <head hash>')")
        records.append((parts[0], parts[1]))
    return records, None


def _notary_verdict(records):
    """Finding 8: compare notarized heads against the chain checkpoints.
    Notarizations happen in chronological order against an append-only log,
    so each notarized head must be a chain checkpoint at or after the
    previous match (a prefix of the chain's history, not scattered). Returns
    (verdict, detail), verdict in {'intact', 'grown', 'diverged'}."""
    ok, msg, heads = gate_core.audit_checkpoints()
    pos = 0
    last = None
    for ts, head in records:
        try:
            idx = heads.index(head, pos)
        except ValueError:
            if head in heads:
                return "diverged", (
                    f"notarized head {head[:12]}… ({ts}) matches the chain only "
                    "BEFORE the previous notarized position — the log was "
                    "rewritten or reordered")
            return "diverged", (
                f"notarized head {head[:12]}… ({ts}) is not a checkpoint of "
                "the current chain — the log was truncated or wholesale-"
                "rewritten after it was recorded")
        last = (ts, head, idx)
        pos = idx
    if last is None:  # empty notary file — the caller reports this plainly
        return "diverged", "the notary file contains no records"
    ts, head, idx = last
    new = len(heads) - (idx + 1)
    if new:
        return "grown", (
            f"{new} new audit entries since the last notarized head "
            f"{head[:12]}… ({ts}) — normal for an append-only log; notarize "
            "again to re-anchor the new head")
    return "intact", (
        f"the last notarized head {head[:12]}… ({ts}) is the current chain "
        f"head; 0 new entries since notarization")


def cmd_audit_verify(ctx, rest):
    """(1) internal chain check — semantics unchanged, backward-compatible
    OK/BROKEN prefix — then (2) the notary comparison when an anchor file
    exists. Finding 8: the internal check alone is NOT tamper evidence; only
    the external anchor detects a wholesale rewrite."""
    args = list(rest or [])
    notary = None
    if "--notary" in args:
        i = args.index("--notary")
        if i + 1 >= len(args):
            return "error: --notary needs a path"
        notary, args = args[i + 1], args[:i] + args[i + 2:]
    if args:
        return "error: unknown arguments: " + " ".join(args)
    ok, msg = gate_core.audit_verify()
    base = ("OK " if ok else "BROKEN ") + msg
    p = _notary_file(ctx, notary)
    if p is None:
        return (base + "\n"
                "internal chain check only — no notary file, so this is NOT "
                "evidence against a wholesale rewrite of the log (finding 8): "
                "anyone with write access to the gate data dir can recompute "
                "a self-consistent chain. Anchor the head out of band with "
                "`hermes passkey-gate audit-notarize [--to <path>]`, then "
                "verify with `audit-verify --notary <path>`.")
    if not ok:
        return base + "\nnotary comparison skipped — the internal chain is already broken"
    if not p.exists():
        return (base + "\n"
                f"internal chain check only — notary file {p} does not exist, "
                "so there is no external evidence against a wholesale rewrite. "
                f"Create the anchor with `hermes passkey-gate audit-notarize --to {p}`.")
    records, problem = _read_notary(p)
    if problem:
        return ("DIVERGED (notary unusable): " + problem + f" — treat {p} as "
                "compromised or fix it by hand; the internal chain check "
                "alone is not tamper evidence")
    if not records:
        return (base + "\n"
                f"notary file {p} is empty — no external evidence recorded "
                f"yet; run `audit-notarize --to {p}` to anchor the current head")
    verdict, detail = _notary_verdict(records)
    if verdict == "intact":
        return base + "\nINTACT AND NOTARIZED — " + detail
    if verdict == "grown":
        return base + "\nGROWN SINCE NOTARIZATION — " + detail
    return ("DIVERGED — the internal chain is self-consistent BUT " + detail
            + ". Internal consistency alone must not be trusted here (finding 8)")


def cmd_audit_notarize(ctx, rest):
    """Finding 8 operator ceremony (same philosophy as bootstrap/pin: trust
    lives outside the agent's write surface): record the current chain head
    where the log's attacker cannot also rewrite it."""
    args = list(rest or [])
    to = None
    if "--to" in args:
        i = args.index("--to")
        if i + 1 >= len(args):
            return "error: --to needs a path"
        to, args = args[i + 1], args[:i] + args[i + 2:]
    if args:
        return "error: unknown arguments: " + " ".join(args)
    head = gate_core.audit_head()
    if not head:
        return "nothing to notarize: the audit log is empty"
    p = _notary_file(ctx, to)
    if p is None:
        stamp = _utc_now()
        return (f"audit head to record OUT OF BAND — the hash chain lives in "
                f"the gate data dir, where an attacker with write access can "
                f"rewrite the whole log and recompute a self-consistent chain "
                f"(finding 8); its head is only evidence if recorded outside "
                f"that directory:\n\n  {stamp}  {head}\n\n"
                "store this line where the agent cannot write it (a note in "
                "your password manager, a file on another host, a signed "
                "message to yourself). To have the gate append it to a notary "
                "file for you: `hermes passkey-gate audit-notarize --to "
                "<path>` (or set `audit_notary_path` once and run it bare).")
    # an anchor kept inside the log's own directory is no anchor at all
    data_dir = gate_core.data_dir().resolve()
    resolved = p.resolve()
    if resolved == data_dir or data_dir in resolved.parents:
        return (f"refusing: the notary file must live OUTSIDE the gate data "
                f"dir ({data_dir}) — an attacker who can rewrite the audit "
                f"log could rewrite a notary kept beside it")
    if not p.parent.exists():
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return f"error: cannot create notary directory {p.parent}: {exc}"
    stamp = _utc_now()
    try:
        # O_APPEND keeps concurrent notarizations from clobbering each other;
        # O_NOFOLLOW refuses a symlink planted at the anchor path
        fd = os.open(p, os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        return f"error: cannot open notary file {p} safely: {exc}"
    with os.fdopen(fd, "a") as f:
        f.write(f"{stamp} {head}\n")
        f.flush()
        os.fsync(f.fileno())
    return (f"notarized: appended '{stamp} {head}' to {p}\n"
            "keep that file operator-owned and outside the agent's write "
            f"reach — it is the external anchor `audit-verify --notary {p}` "
            "checks against a wholesale rewrite of the audit log")


_COMMANDS = {
    "setup": cmd_setup,
    "service": cmd_service,
    "serve": cmd_serve,
    "bootstrap": cmd_bootstrap,
    "expose": cmd_expose,
    "pin": cmd_pin,
    "credentials": cmd_credentials,
    "show": cmd_show,
    "set": cmd_set,
    "get": cmd_show_settings,
    "show-settings": cmd_show_settings,
    "status": cmd_status,
    "audit-verify": cmd_audit_verify,
    "audit-notarize": cmd_audit_notarize,
    "mint-token": cmd_mint_token,
}


def dispatch(ctx, args_str: str):
    parts = args_str.strip().split()
    cmd = parts[0] if parts else ""
    fn = _COMMANDS.get(cmd)
    if fn is None:
        return USAGE
    if cmd in ("set", "get", "show-settings", "status", "setup") and ctx is None:
        return "that command needs a hermes runtime context — run inside hermes"
    return fn(ctx, parts[1:])
