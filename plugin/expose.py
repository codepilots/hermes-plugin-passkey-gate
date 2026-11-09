"""Public exposure for the gate — pick-and-remember, per the user's own setup.

WebAuthn needs HTTPS, so the gate has to sit behind a TLS terminator the user
already runs. This module auto-detects what's available and sets it up:

  tailscale   — `tailscale serve --bg --https=<port> --set-path=/ <target>`;
                tailscaled keeps serving after this process exits, so setup
                can print the URL and return. Origin + RP id are derived from
                `tailscale status --json` (Self.DNSName), parsed WITHOUT
                trusting the CLI: the serve status map is re-read and the new
                entry located in it. The gate's serve rule is identified by
                an EXACT handle — (https listen port, mount path, proxy
                target) — recorded durably per gate instance, so re-runs,
                replacements and cleanup touch only THIS plugin's rule,
                never other services' rules on the same tailnet host
                (finding 25).
  none        — localhost only; instruct the user to set `origin` manually.

RP ID default: the FULL hostname of the origin (always a valid registrable
suffix of itself). `rp_id` config can pin a parent/other suffix to reuse an
existing passkey credential registered under it — credentials only match
origins sharing their RP ID suffix.
"""
import json
import re
import os
import shutil
import subprocess
from pathlib import Path

from . import netfetch

# Ports tried, in order, for tailscale HTTPS serving (443 = clean URL)
TAILSCALE_PORTS = [443, 8443, 8445, 8446, 8447, 8448, 8480, 8500, 8600, 8661]

# Finding 25 — the EXACT handle of this gate's serve rule. Every create, check
# and cleanup operation matches all three components: the https listen port,
# the mount path, and the proxy target (derived from the gate port). The
# handle is recorded durably (SERVE_RECORD_NAME in the plugin data dir) so a
# later run can still recognize its own rule after the gate port changed —
# and can prove a rule belongs to someone else by the same test.
SERVE_MOUNT = "/"
SERVE_RECORD_NAME = "tailscale-serve.json"


def _which(name: str):
    return shutil.which(name)


def detect_backends() -> dict:
    return {"tailscale": _which("tailscale") is not None}


def fetch_status_json(binpath: str = "tailscale", timeout: int = 15) -> dict | None:
    try:
        out = subprocess.run([binpath, "serve", "status", "--json"],
                             capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0 and out.stdout.strip().startswith("{"):
            return json.loads(out.stdout)
    except Exception:
        pass
    return None


def fetch_self_dnsname(binpath: str = "tailscale", timeout: int = 15) -> str | None:
    try:
        out = subprocess.run([binpath, "status", "--json"], capture_output=True,
                             text=True, timeout=timeout)
        if out.returncode == 0:
            dns = (json.loads(out.stdout).get("Self") or {}).get("DNSName") or ""
            return dns.rstrip(".") or None
    except Exception:
        pass
    return None


def _claimed_ports(status: dict) -> set[int]:
    claimed = set()
    if not isinstance(status, dict):
        return claimed
    for key in (str(p) for p in (status.get("TCP") or {})):
        try:
            claimed.add(int(key))
        except ValueError:
            continue
    for host_entry in (status.get("Web") or {}):
        try:
            claimed.add(int(str(host_entry).rsplit(":", 1)[-1]))
        except ValueError:
            continue
    return claimed


def pick_https_port(status: dict) -> int | None:
    """First preferred HTTPS port not already claimed by another serve rule."""
    for p in TAILSCALE_PORTS:
        if p not in _claimed_ports(status):
            return p
    return None


def origin_from_host(host: str, https_port: int) -> str:
    base = f"https://{host}"
    return base if https_port == 443 else f"{base}:{https_port}"


def _record_path():
    """Durable record of our own serve rule, kept in the plugin data dir. Lazy
    import keeps this module usable without the gate engine (then there is no
    record, and rules are still managed exactly within a single run)."""
    try:
        from . import gate_core
        return Path(gate_core.data_dir()) / SERVE_RECORD_NAME
    except Exception:
        return None


def _load_record(path) -> dict | None:
    if not path:
        return None
    try:
        rec = json.loads(Path(path).read_text())
        if isinstance(rec, dict) and "port" in rec and "target" in rec:
            return rec
    except Exception:
        pass
    return None


def _save_record(path, record) -> None:
    if not path:
        return
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        try:
            tmp.unlink()  # v0.7 review A28: never write through a planted link
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(record, indent=2))
        os.replace(tmp, p)
    except Exception:
        pass


def _clear_record(path) -> None:
    if not path:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


def _handlers(status) -> dict:
    """Flat map of every serve rule in the status map: {(host:port, mount): proxy}."""
    flat = {}
    for hostport, entry in ((status or {}).get("Web") or {}).items():
        for mount, handler in ((entry or {}).get("Handlers") or {}).items():
            proxy = (handler or {}).get("Proxy")
            if proxy:
                flat[(str(hostport), str(mount))] = str(proxy)
    return flat


def _port_of_hostport(hostport) -> int | None:
    try:
        return int(str(hostport).rsplit(":", 1)[-1])
    except ValueError:
        return None


def _rule_matching(status, port, mount, target) -> dict | None:
    """The live serve rule with EXACTLY this handle (https port, mount path,
    proxy target) — the identity check behind every rule operation here."""
    for (hostport, m), proxy in _handlers(status).items():
        if _port_of_hostport(hostport) == port and m == mount and proxy == target:
            return {"hostport": hostport, "port": port, "mount": mount, "target": target}
    return None


def _recorded_rule_live(status, record) -> dict | None:
    """The live rule matching our recorded handle exactly — or None when the
    rule is gone or something else now serves there. Either way it is then
    NOT ours and must never be removed."""
    if not record:
        return None
    try:
        port = int(record["port"])
    except (KeyError, TypeError, ValueError):
        return None
    return _rule_matching(status, port, str(record.get("mount") or SERVE_MOUNT),
                         str(record["target"]))


def _unserve(binpath, port, mount=SERVE_MOUNT, timeout=30) -> None:
    """Remove the serve rule at EXACTLY (https port, mount): the same flags
    the create used, plus path-scoped `off` (finding 25 — the old cleanup ran
    `--http=<port> off` against an HTTPS rule, targeting a different
    protocol's rule; and bare `--https=<port> off` can tear down every mount
    on the port). `off` on a mount that is not served just errors, removing
    nothing — it cannot take someone else's rule."""
    try:
        subprocess.run([binpath, "serve", "--bg", f"--https={port}", f"--set-path={mount}", "off"],
                       capture_output=True, text=True, timeout=timeout)
    except Exception:
        pass


def _drop_rule(binpath, rule, before_status) -> list[str]:
    """Remove our rule by exact handle and — as the review requires — re-read
    the serve map to verify that ONLY that rule disappeared. Returns warnings
    (empty when the removal was surgical)."""
    before = _handlers(before_status)
    _unserve(binpath, rule["port"], rule["mount"])
    after = _handlers(fetch_status_json(binpath=binpath) or {})
    key = (rule["hostport"], rule["mount"])
    warnings = [f"tailscale removed more than our rule: {k[0]} mount {k[1]} vanished"
                for k in sorted(set(before) - set(after)) if k != key]
    if key in after:
        warnings.append(f"our serve rule on https port {rule['port']} could not be "
                        f"removed and is still active")
    return warnings


def _refuse_foreign_port(status, port) -> dict:
    """The zero-mutation refusal for an explicitly requested port that another
    service already serves (finding 25): names the rule it refuses to touch.
    One wording shared by every refusal site, so callers cannot tell which
    check fired — only that nothing was mutated."""
    detail = "; ".join(f"{hp} mount {mount} -> {proxy}"
                       for (hp, mount), proxy in _handlers(status).items()
                       if _port_of_hostport(hp) == port)
    return {"ok": False, "backend": "tailscale",
            "error": (f"refusing to overwrite another service's serve rule on "
                      f"port {port} ({detail})")}


def tailscale_expose(gate_port: int, target_port: int | None = None,
                     binpath: str = "tailscale", record_path=None) -> dict:
    """Serve the gate under the host's tailscale HTTPS URL. tailscaled owns the
    forwarding, so after setup this process can exit.

    Finding 25 — EXACT rule identity. This gate's rule is the triple (https
    listen port, mount path, proxy target http://127.0.0.1:<gate_port>), and
    that handle is recorded durably, so create/check/cleanup operations target
    precisely this gate's rule and never another service's on the same
    tailnet host: every removal is the path-scoped off of the exact handle,
    verified against a fresh serve map afterwards. A re-run with the same
    gate port KEEPS a working rule with zero mutations; a rule left by a
    previous run for a DIFFERENT gate port is replaced remove-then-set and
    the result says so; that stale port counts as free for this run, while
    other services' ports stay claimed exactly as the serve status reports.
    An explicit target_port that another service already holds is refused
    with ZERO mutations even then — claimability is checked BEFORE our live
    rule is dropped, so a refused request never destroys the working serve rule.

    A serve rule being ACCEPTED is not proof it WORKS: a local service bound to
    0.0.0.0:<port> (e.g. nginx on 443) can hold the port first, so tailnet
    connections fall through to that service's own TLS instead of tailscale's
    proxy. Every candidate is therefore verified with a real TLS GET of
    /health (cert chain verified, no -k) and rejected ports are un-ruled
    before the next candidate is tried."""
    if not _which(binpath):
        return {"ok": False, "backend": "tailscale", "error": "tailscale CLI not found"}
    host = fetch_self_dnsname(binpath=binpath)
    if not host:
        return {"ok": False, "backend": "tailscale", "error": "tailscale status unavailable (tailscaled down?)"}
    target = f"http://127.0.0.1:{gate_port}"
    rpath = Path(record_path) if record_path is not None else _record_path()
    record = _load_record(rpath)
    status = fetch_status_json(binpath=binpath) or {}
    our_rule = _recorded_rule_live(status, record)
    warnings: list[str] = []
    removed: list[dict] = []
    notes: list[str] = []

    if our_rule is not None:
        keep_it = (our_rule["target"] == target
                   and (target_port is None or target_port == our_rule["port"]))
        if keep_it:
            # correct rule already live: verify it works and KEEP it untouched
            url = origin_from_host(host, our_rule["port"])
            located = _locate_url(status, host, our_rule["port"])
            if located:
                url = located.replace(":443", "")
            ok, why = _tls_probe(f"{url}/health")
            if ok:
                new_record = {"host": host, "port": our_rule["port"], "mount": our_rule["mount"],
                              "target": target, "url": url}
                _save_record(rpath, new_record)
                return {"ok": True, "backend": "tailscale", "url": url,
                        "rp_id": url.split("//", 1)[-1].rsplit(":", 1)[0], "persistent": True,
                        "note": (f"existing serve rule kept: tailscaled forwards {url} -> "
                                 f"127.0.0.1:{gate_port}; survives restarts of this process"),
                        "serve_rule": new_record}
            warnings += _drop_rule(binpath, our_rule, status)
            removed.append({"port": our_rule["port"], "mount": our_rule["mount"],
                            "target": our_rule["target"], "reason": f"unreachable ({why})"})
            notes.append(f"removed previous serve rule on port {our_rule['port']} (unreachable: {why})")
        else:
            # a previous run's rule for a DIFFERENT gate port (or a different
            # requested port): replace it — remove-then-set, exact handle.
            # D16: an explicit target_port that another service holds must
            # refuse BEFORE our live rule is dropped — a refusal that arrives
            # after the drop destroys the working serve rule and dangles the
            # record. Claimability uses the same accounting as below: every
            # port the serve map claims minus OUR own recorded port.
            if (target_port is not None and target_port != our_rule["port"]
                    and target_port in _claimed_ports(status) - {our_rule["port"]}):
                return _refuse_foreign_port(status, target_port)
            warnings += _drop_rule(binpath, our_rule, status)
            removed.append({"port": our_rule["port"], "mount": our_rule["mount"],
                            "target": our_rule["target"],
                            "reason": "superseded by this run (different gate port)"})
            notes.append(f"replaced previous passkey-gate serve rule on port {our_rule['port']} "
                         f"(was forwarding to {our_rule['target']})")
        status = fetch_status_json(binpath=binpath) or {}
    elif record is not None:
        notes.append("previous passkey-gate serve rule no longer matches the record — left untouched")

    # claimed ports: other services' rules exactly as the serve status reports
    # them, minus THIS plugin's own rule — its port frees up because this run
    # replaces or re-creates the rule there itself (finding 25)
    ours_ports = {our_rule["port"]} if our_rule is not None else set()
    claimed = _claimed_ports(status) - ours_ports
    if target_port is not None:
        if target_port in claimed:
            return _refuse_foreign_port(status, target_port)
        candidates = [target_port]
    else:
        candidates = [p for p in TAILSCALE_PORTS if p not in claimed]
    last_error = None
    for port in candidates:
        out = subprocess.run([binpath, "serve", "--bg", f"--https={port}", f"--set-path={SERVE_MOUNT}", target],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            last_error = f"tailscale serve {target} failed: {(out.stderr or out.stdout).strip()[:300]}"
            continue
        status_after = fetch_status_json(binpath=binpath) or {}
        rule = _rule_matching(status_after, port, SERVE_MOUNT, target)
        if rule is None:
            # accepted but not identifiable as ours in the map: clean the exact
            # slot (a no-op error if nothing is served there) and move on
            last_error = f"port {port} accepted the rule but the exact serve rule is not in the map"
            _unserve(binpath, port, SERVE_MOUNT)
            continue
        url = origin_from_host(host, port)
        located = _locate_url(status_after, host, port)
        if located:
            url = located.replace(":443", "")
        probe = _tls_probe(f"{url}/health")
        if probe[0]:
            new_record = {"host": host, "port": port, "mount": SERVE_MOUNT,
                          "target": target, "url": url}
            _save_record(rpath, new_record)
            note = f"tailscaled forwards {url} -> 127.0.0.1:{gate_port}; survives restarts of this process"
            if notes:
                note = "; ".join(notes) + "; " + note
            if warnings:
                note += " — WARNING: " + "; ".join(warnings)
            result = {"ok": True, "backend": "tailscale", "url": url,
                      "rp_id": url.split("//", 1)[-1].rsplit(":", 1)[0], "persistent": True,
                      "note": note, "serve_rule": new_record}
            if removed:
                result["removed"] = removed
            return result
        last_error = f"port {port} did not serve our TLS origin ({probe[1]})"
        # un-rule the dead candidate by its EXACT handle — never anyone else's
        warnings += _drop_rule(binpath, rule, status_after)
        removed.append({"port": port, "mount": SERVE_MOUNT, "target": target,
                        "reason": f"cleaned after failed probe ({probe[1]})"})
        notes.append(f"cleaned partial rule on port {port} after failed probe")
    if record is not None:
        # the rule our record pointed at is gone now (dropped above, or no
        # longer ours) — never leave a record for a rule that does not exist
        _clear_record(rpath)
    error = f"no working HTTPS port found. Last issue: {last_error}"
    if notes:
        error += ". " + "; ".join(notes)
    result = {"ok": False, "backend": "tailscale", "error": error}
    if removed:
        result["removed"] = removed
    if warnings:
        result["warnings"] = warnings
    return result


def is_this_gate(health) -> bool:
    """A /health answer that comes from THIS gate (same data dir), not just
    anything saying "ok". The instance id can be computed by anyone who can
    guess the data-dir path, so this catches misconfiguration and lazy
    impostors, not a relaying man in the middle — see recorded_target_port()
    for that (v0.7 review H1 / A1)."""
    try:
        from . import gate_core
        return (isinstance(health, dict) and health.get("status") == "ok"
                and health.get("service") == "passkey-gate"
                and health.get("instance") == gate_core.instance_id())
    except Exception:
        return False


def recorded_target_port() -> int | None:
    """The local port our recorded tailscale serve rule forwards to, or None
    when there is no record (no tailscale exposure, or a configured origin)."""
    rec = _load_record(_record_path())
    if not rec:
        return None
    m = re.fullmatch(r"http://127\.0\.0\.1:(\d{1,5})/?", str(rec.get("target", "")))
    return int(m.group(1)) if m else None


def _tls_probe(url: str, timeout: int = 12) -> tuple[bool, str]:
    try:
        with netfetch.open_no_redirect(url, timeout=timeout) as r:
            body = r.read(4096)
            if r.status != 200:
                return False, f"unexpected response {r.status}"
            try:
                health = json.loads(body)
            except ValueError:
                return False, "unexpected body"
            if not is_this_gate(health):
                return False, "answered, but not as this passkey-gate (another service or another gate)"
            return True, "health ok"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:140]}"


def _locate_url(status: dict, host: str, port: int) -> str | None:
    for key in (status.get("Web") or {}):
        k = str(key)
        if host in k and k.endswith(f":{port}"):
            return f"https://{k}" if not k.startswith("http") else k
    return None


def rp_id_from_origin(origin: str) -> str | None:
    """The hostname of an https origin — the default WebAuthn RP ID for it."""
    from urllib.parse import urlparse
    try:
        host = urlparse((origin or "").strip()).hostname
    except ValueError:
        return None
    return host or None


def auto_expose(gate_port: int, gate_origin_cfg: str = "", gate_rp_id_cfg: str = "") -> dict:
    """Selection logic, called by the `expose` CLI command:
    explicit config origin > tailscale > instructions to configure an origin."""
    if gate_origin_cfg.strip():
        return {"ok": True, "backend": "configured",
                "url": gate_origin_cfg.strip(),
                "rp_id": (gate_rp_id_cfg.strip() or rp_id_from_origin(gate_origin_cfg)
                          or "localhost"),
                "persistent": True, "note": "using manually configured origin"}
    b = detect_backends()
    if b["tailscale"]:
        return tailscale_expose(gate_port)
    return {"ok": False, "backend": "none",
            "error": ("no HTTPS path found: install tailscale (https://tailscale.com/download), "
                      "or set plugins.entries.passkey-gate.settings.origin to an HTTPS origin "
                      "you already terminate TLS for (e.g. an nginx/caddy reverse proxy)")}
