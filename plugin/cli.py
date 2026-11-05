"""CLI commands — everything under `hermes passkey-gate <cmd> [args]`.

  serve              run the HTTP gate service (binds 127.0.0.1:<port>; TLS is
                     terminated by tailscale serve / cloudflared / nginx)
  bootstrap          mint the one-time passkey registration link (QR + link
                     printed only to THIS terminal; never send it through chat)
  expose [backend]   auto-set up public HTTPS exposure (tailscale > cloudflared
                     > your configured origin > honest instructions) and persist
                     origin + rp_id into plugin settings
  pin <pem> [owner]  pin an owner public key locally (out-of-band first sight);
                     name the owner to pin PEER keys for parent-approval chains
  show <challenge>   print a pending challenge's URL + QR — the human-lifts-
                     her-phone path when the URL arrived in a chat she's on
  set <key> <value> [--approve <challenge-id>]
                     configure a setting (typed parse + validate + persist +
                     re-apply immediately; same namespace the Desktop form
                     uses). Weakening a security-critical setting — turning
                     require_passkey off, removing an authority pattern,
                     adding a parent-gate allowlist entry — is REFUSED unless
                     --approve names a passkey approval of the exact
                     server-derived phrase; strengthening is free; both are
                     audited (finding 16).
  get                show all settings
  audit-verify       check the append-only audit chain intact
"""
import json
import logging
import os
import time
from pathlib import Path

from . import gate_core, expose, local_verify, netfetch, tools

logger = logging.getLogger(__name__)

USAGE = ("usage: hermes passkey-gate "
         "<serve|bootstrap|expose|pin|show|set|get|status|audit-verify> [args]")

# keys exactly as declared in plugin.yaml config_schema (drift-tested)
SETTINGS_SPEC = {
    "origin": {"type": "str"},
    "rp_id": {"type": "str"},
    "port": {"type": "int"},
    "challenge_ttl": {"type": "int"},
    "require_passkey": {"type": "bool"},
    "authority_patterns": {"type": "list"},
    "parent_gate_allowlist": {"type": "list"},
}

DEFAULTS = {
    "origin": "",
    "rp_id": "",
    "port": 8655,
    "challenge_ttl": 600,
    "require_passkey": False,
    "authority_patterns": [],
    "parent_gate_allowlist": [],
}

# finding 16: the settings that define what the gate enforces. An agent with
# terminal access could disarm any of them with one unauthenticated `set`, so
# weakening one requires a passkey approval of an exact server-derived
# phrase; strengthening is free; every change is audited.
SECURITY_KEYS = ("require_passkey", "authority_patterns", "parent_gate_allowlist")

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
                        rp_id=rp_id_c or os_default_rp_id(),
                        origin=origin or None,
                        port=int(port),
                        challenge_ttl=int(ttl),
                        parent_allowlist=allow)
    return {"require_passkey": bool(ctx.get_config("require_passkey", default=False)),
            "patterns": ctx.get_config("authority_patterns", default=[]) or []}


def os_default_rp_id():
    """Best-effort default for hosts that never ran `expose`."""
    try:
        out = shutil.which("tailscale") and __import__("subprocess").run(
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


def _active_settings_error():
    """A config.yaml that exists but will not read/parse is served to
    readers as silent DEFAULTS by the Hermes config loader; this returns the
    loader's recorded parse failure while the file on disk is still the
    broken one, so the gate can tell 'the admin chose this' from 'the
    loader fell back'. None outside Hermes."""
    try:
        from hermes_cli.config_read_errors import get_active_config_parse_failure
        return get_active_config_parse_failure() or None
    except Exception:
        return None


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
    parse_failure = _active_settings_error()
    if parse_failure:
        logger.error("passkey-gate: settings source unreadable (%s); failing closed",
                     parse_failure)
        return {"require_passkey": True, "patterns": [],
                "_config_error": f"settings source unreadable: {parse_failure}"}
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
    gate_core.serve()
    return "serve returned"


def cmd_bootstrap(ctx, rest):
    url = gate_core.mint_bootstrap_token()
    try:
        import qrcode
        q = qrcode.QRCode(border=1)
        q.add_data(url)
        q.print_ascii(invert=True)
    except Exception:
        pass
    return (f"One-time registration link ({gate_core.bootstrap_ttl() // 60} min, single use). "
            f"Do not paste it anywhere — the QR above is enough for your phone:\n\n{url}")


def cmd_expose(ctx, rest):
    backend = rest[0].strip().lower() if rest else "auto"
    if backend not in ("auto", "tailscale", "cloudflare", "none"):
        return "usage: hermes passkey-gate expose [auto|tailscale|cloudflare|none]"
    origin_cfg = (ctx.get_config("origin", default="") or "").strip() if ctx is not None else ""
    rp_cfg = (ctx.get_config("rp_id", default="") or "").strip() if ctx is not None else ""
    gate_port = int(ctx.get_config("port", default=8655))
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
        return json.dumps(result, indent=2)
    url, rp_id = result["url"], result["rp_id"]
    lines = [f"exposure ready: {url} (rp_id {rp_id})", result.get("note", "")]
    if result.get("persistent") and ctx is not None:
        ctx.set_config("origin", url)
        ctx.set_config("rp_id", rp_id)
        gate_core.configure(rp_id=rp_id, origin=url)
        lines.append("saved origin + rp_id to plugin settings (persists across sessions)")
    if backend == "cloudflare":
        lines.append("holding the quick-tunnel process open — Ctrl+C stops the public URL")
        proc = result.get("process")
        if proc is not None:
            proc.wait()
    return "\n".join(x for x in lines if x)


def cmd_pin(ctx, rest):
    if not rest:
        return "usage: hermes passkey-gate pin <pem-file> [owner-label]"
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


def weakening_phrase(key, new_value):
    """The EXACT server-derived action text a passkey must sign to authorize
    this gate-weakening change (finding 16). One derivation serves both the
    mint and the verification, so the two can never drift apart."""
    return (f"passkey-gate: set {key}={_canonical_value(new_value)} — "
            "confirm this gate-weakening change")


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
    if key == "parent_gate_allowlist":
        if not (isinstance(old_n, list) and isinstance(new_n, list)):
            return True
        return bool(set(new_n) - set(old_n))
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
    if not base.startswith(("http://", "https://")):
        return ["the gate origin is not configured — set "
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
    pinned = local_verify.pinned(gate_core.data_dir())
    if pinned is None:
        return ["no owner key is pinned — pin the human's public key out of band "
                "with 'hermes passkey-gate pin <pem-file>' before any gate-weakening "
                "change can be approved"]
    return [f"local verification failed: {p}" for p in
            local_verify.check(rec, phrase, tools._origin(), gate_core.rp_id(), pinned)]


def _weakening_needs_approval(key, new_value, raw):
    """Refusal that carries its own recovery (finding 16): mint the approval
    challenge for the EXACT server-derived phrase and hand back the URL, the
    challenge id, and the --approve re-run — the human decides, not the agent
    this setting is meant to constrain."""
    phrase = weakening_phrase(key, new_value)
    lines = [f"REFUSED: set {key} weakens the passkey gate — enforcement settings "
             "are operator-owned, and a gate-weakening change needs a passkey "
             "approval signed by your human first.",
             "",
             "approval phrase (the human signs EXACTLY this):",
             f"  {phrase}"]
    try:
        c = gate_core.create_challenge(phrase, "hermes-cli")
    except Exception as exc:
        c = None
        lines.append(f"  (no approval challenge could be minted here — {type(exc).__name__}: "
                     f"{exc}; mint one with the gate_challenge tool using the phrase above)")
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
    return "\n".join(lines)


def _weakening_approval_failed(key, new_value, problems):
    """Refusal for a --approve that did not verify, with the reasons."""
    return "\n".join(
        [f"REFUSED: set {key} weakens the passkey gate, and the supplied approval "
         "did not verify for this exact change:"] +
        [f"  - {p}" for p in problems] +
        ["", "approval phrase this change requires (the human must sign exactly this):",
         f"  {weakening_phrase(key, new_value)}",
         "re-run without --approve to mint a fresh approval challenge, send its URL "
         "to your human, and re-run with --approve once they have signed it."])


def cmd_set(ctx, rest):
    if not rest:
        return ("usage: hermes passkey-gate set <key> <value> [--approve <challenge-id>] — keys: "
                + ", ".join(SETTINGS_SPEC))
    rest, approve_cid, flag_err = _split_approve_flag(rest)
    if flag_err:
        return flag_err
    key, raw = rest[0], " ".join(rest[1:])
    if key not in SETTINGS_SPEC:
        return f"unknown setting {key!r}. Keys: " + ", ".join(SETTINGS_SPEC)
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
        if weakens:
            if approve_cid is None:
                return _weakening_needs_approval(key, value, raw)
            problems = _verify_weakening_approval(approve_cid, weakening_phrase(key, value))
            if problems:
                return _weakening_approval_failed(key, value, problems)
        # audit BEFORE applying: a security-critical change that cannot be
        # audited does not happen
        try:
            gate_core.audit("config_changed", key=key, old=_jsonable(old), new=_jsonable(value),
                            weakened=weakens, approved=approve_cid if weakens else None)
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
    # finding 7: a running gateway must see this change on the NEXT hook
    # call — drop the cache before re-applying so no verdict serves stale state
    invalidate_config_cache()
    apply_config(ctx)
    return f"{key} = {json.dumps(value)}\n" + cmd_show_settings(ctx)


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
            return int(raw), None
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
    try:
        with netfetch.open_no_redirect(f"{base}/health", timeout=8) as r:
            out["gate"] = {**json.loads(r.read()), "reachable": r.status == 200}
    except Exception as exc:
        out["gate"] = {"reachable": False, "error": f"{type(exc).__name__}"}
    out["origin_configured"] = bool(base)
    out["backends_detected"] = expose.detect_backends()
    out["owner_key_pinned"] = local_verify.pinned(gate_core.data_dir()) is not None
    pins_dir = gate_core.data_dir() / "pins"
    out["peer_keys_pinned"] = sorted(p.name[:-4] for p in pins_dir.glob("*.pem")) if pins_dir.exists() else []
    out["enforcement"] = {**apply_config_safe(),
                          "note": "patterns are regexes matched against tool_name + canonical args JSON"}
    return json.dumps(out, indent=2)


def cmd_audit_verify(ctx, rest):
    ok, msg = gate_core.audit_verify()
    return ("OK " if ok else "BROKEN ") + msg


_COMMANDS = {
    "serve": cmd_serve,
    "bootstrap": cmd_bootstrap,
    "expose": cmd_expose,
    "pin": cmd_pin,
    "show": cmd_show,
    "set": cmd_set,
    "get": cmd_show_settings,
    "show-settings": cmd_show_settings,
    "status": cmd_status,
    "audit-verify": cmd_audit_verify,
}


def dispatch(ctx, args_str: str):
    parts = args_str.strip().split()
    cmd = parts[0] if parts else ""
    fn = _COMMANDS.get(cmd)
    if fn is None:
        return USAGE
    if cmd in ("set", "get", "show-settings", "status") and ctx is None:
        return "that command needs a hermes runtime context — run inside hermes"
    return fn(ctx, parts[1:])
