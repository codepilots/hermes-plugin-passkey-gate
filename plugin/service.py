"""Run the gate in the background — `hermes passkey-gate service <action>`.

  install     write a per-user service that runs `hermes passkey-gate serve`,
              start it now and at every login (systemd --user on Linux, a
              LaunchAgent on macOS)
  uninstall   stop it and remove the service file
  start | stop | restart
  status      is the service running, and does the gate answer locally?
  logs        the service's recent output

The service runs as YOU, with HERMES_HOME pinned to the Hermes home this
command ran under, so it serves the same profile, settings and data as the
terminal you set it up from. It binds 127.0.0.1 only, exactly like `serve`.
Nothing here needs root; on Linux, keeping it running while you are logged
out needs lingering (`loginctl enable-linger $USER`, run once as an
administrator), which this module reports but never runs for you.
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from . import childenv

UNIT_NAME = "passkey-gate.service"
LAUNCHD_LABEL = "ai.hermes.passkey-gate"


def _run(cmd, timeout=30):
    """Run a command, never raising: (returncode, combined output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=childenv.systemd_user_env())
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(cmd)}: timed out"


# test seams
run = _run
platform = sys.platform


def manager():
    """'systemd', 'launchd', or None when neither is usable here."""
    if platform == "darwin" and shutil.which("launchctl"):
        return "launchd"
    if platform.startswith("linux") and shutil.which("systemctl"):
        rc, _ = run(["systemctl", "--user", "show-environment"], timeout=10)
        if rc == 0:
            return "systemd"
    return None


def hermes_executable():
    """Absolute path of the `hermes` launcher the service should start."""
    found = shutil.which("hermes")
    if found:
        return str(Path(found).absolute())
    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if argv0 and argv0.name == "hermes" and argv0.exists():
        return str(argv0.absolute())
    return None


def hermes_home():
    """The Hermes home this process serves — pinned into the service so it
    reads the same profile, not whatever the default happens to be."""
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        env = os.environ.get("HERMES_HOME", "").strip()
        return env or None


def unit_path():
    base = os.environ.get("XDG_CONFIG_HOME", "").strip() or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user" / UNIT_NAME


def plist_path():
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def launchd_log_path():
    return Path.home() / "Library" / "Logs" / "passkey-gate.log"


def _systemd_quote(arg: str) -> str:
    # systemd unit syntax: double-quoted words, backslash escapes, and % is
    # a specifier character that must be doubled
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def _path_problem(name, value):
    """v0.7 review L10: a control character (a newline above all) in a path
    would add lines to the unit file or plist."""
    if value is not None and any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in str(value)):
        raise ValueError(f"{name} contains a control character (such as a newline), "
                         "so it can't be written into a service file safely")


def unit_text(exe: str, home: str | None) -> str:
    _path_problem("the hermes executable path", exe)
    _path_problem("HERMES_HOME", home)
    env = f"Environment={_systemd_quote('HERMES_HOME=' + home)}\n" if home else ""
    return ("[Unit]\n"
            "Description=passkey-gate: Hermes passkey approval gate (127.0.0.1 only)\n"
            "After=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={_systemd_quote(exe)} passkey-gate serve\n"
            f"{env}"
            "Environment=PYTHONUNBUFFERED=1\n"
            "Restart=on-failure\n"
            "RestartSec=3\n\n"
            "[Install]\n"
            "WantedBy=default.target\n")


def plist_text(exe: str, home: str | None) -> str:
    _path_problem("the hermes executable path", exe)
    _path_problem("HERMES_HOME", home)
    from xml.sax.saxutils import escape
    env = {"PYTHONUNBUFFERED": "1", **({"HERMES_HOME": home} if home else {})}
    env_xml = "".join(f"<key>{escape(k)}</key><string>{escape(v)}</string>" for k, v in env.items())
    log = escape(str(launchd_log_path()))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f"<key>Label</key><string>{LAUNCHD_LABEL}</string>\n"
            "<key>ProgramArguments</key><array>"
            f"<string>{escape(exe)}</string><string>passkey-gate</string><string>serve</string>"
            "</array>\n"
            f"<key>EnvironmentVariables</key><dict>{env_xml}</dict>\n"
            "<key>RunAtLoad</key><true/>\n"
            "<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n"
            f"<key>StandardOutPath</key><string>{log}</string>\n"
            f"<key>StandardErrorPath</key><string>{log}</string>\n"
            "</dict></plist>\n")


def local_health(port: int, timeout: float = 2.0):
    """The gate's /health on 127.0.0.1:<port> as a dict, or None if nothing
    that looks like passkey-gate answers there."""
    # http.client, not urlopen: no redirects (a squatter could bounce the
    # check to a forged answer elsewhere), no proxy settings from the
    # environment, and a bounded read (v0.7 review L1 / A10)
    import http.client
    conn = None
    try:
        conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
        conn.request("GET", "/health")
        r = conn.getresponse()
        if r.status != 200:
            return None
        body = json.loads(r.read(65536))
        return body if isinstance(body, dict) and body.get("status") == "ok" else None
    except Exception:
        return None
    finally:
        if conn is not None:
            conn.close()


def probe(port: int) -> str:
    """What is on 127.0.0.1:<port>: 'ours' (this gate — same data dir),
    'other' (something else is listening: an older approval-gate, another
    profile's gate, any other program), or 'free'."""
    import socket
    health = local_health(port)
    if health is not None:
        try:
            from . import gate_core
            if health.get("instance") == gate_core.instance_id():
                return "ours"
        except Exception:
            pass
        return "other"
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=1):
            return "other"
    except OSError:
        return "free"


def _no_manager_text(exe):
    cmd = shlex.quote(exe or "hermes") + " passkey-gate serve"
    return ("No supported service manager found here (systemd --user on Linux, launchd on "
            "macOS). To keep the gate running without a terminal, start it detached:\n"
            f"  nohup {cmd} >~/passkey-gate.log 2>&1 &\n"
            "or run it under whatever supervisor you already use (tmux, supervisord, a "
            "container restart policy).")


def _linger_note():
    user = os.environ.get("USER") or ""
    rc, out = run(["loginctl", "show-user", user, "--property=Linger"], timeout=10) if user else (1, "")
    if rc == 0 and out.strip().endswith("=yes"):
        return None
    return ("note: it runs while you are logged in. To keep it running after you log out "
            f"(and start it at boot), run this once as an administrator: "
            f"loginctl enable-linger {user or '$USER'}")


def install(port: int):
    """Write the service file, start it, enable it at login. Returns
    (ok, text)."""
    mgr = manager()
    exe = hermes_executable()
    if exe is None:
        return False, ("could not find the 'hermes' command on PATH, so there is nothing for "
                       "the service to run. Make sure 'hermes' works in this terminal, then retry.")
    if mgr is None:
        return False, _no_manager_text(exe)
    home = hermes_home()
    lines = []
    state = probe(port)
    if state == "ours":
        lines.append(f"note: this gate is already running on 127.0.0.1:{port} (probably 'serve' in "
                     "another terminal). Stop that one with Ctrl-C; the service keeps retrying "
                     "and takes over within a few seconds.")
    elif state == "other":
        lines.append(f"WARNING: another program is using port {port}, so the service can't start "
                     "there. Pick a free port: hermes passkey-gate set port <n> — then "
                     "hermes passkey-gate service restart")
    if mgr == "systemd":
        path = unit_path()
        replaced = path.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            text = unit_text(exe, home)
        except ValueError as exc:
            return False, f"not installed: {exc}"
        path.write_text(text)
        for cmd in (["systemctl", "--user", "daemon-reload"],
                    ["systemctl", "--user", "enable", UNIT_NAME],
                    ["systemctl", "--user", "restart", UNIT_NAME]):
            rc, out = run(cmd)
            if rc != 0:
                return False, f"{' '.join(cmd)} failed: {out}"
        lines.insert(0, f"{'updated' if replaced else 'installed'} {path}")
        lines.insert(1, "started passkey-gate in the background; it starts again at every login "
                        "and restarts if it crashes")
        note = _linger_note()
        if note:
            lines.append(note)
        lines.append("check it: hermes passkey-gate service status   ·   "
                     "output: hermes passkey-gate service logs")
        return True, "\n".join(lines)
    # launchd
    path = plist_path()
    replaced = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    launchd_log_path().parent.mkdir(parents=True, exist_ok=True)
    domain = f"gui/{os.getuid()}"
    if replaced:
        run(["launchctl", "bootout", f"{domain}/{LAUNCHD_LABEL}"])
    try:
        text = plist_text(exe, home)
    except ValueError as exc:
        return False, f"not installed: {exc}"
    path.write_text(text)
    rc, out = run(["launchctl", "bootstrap", domain, str(path)])
    if rc != 0:
        return False, f"launchctl bootstrap failed: {out}"
    lines[0:0] = [f"{'updated' if replaced else 'installed'} {path}",
                  "started passkey-gate in the background; it starts again at every login "
                  "and restarts if it crashes",
                  f"output goes to {launchd_log_path()}"]
    return True, "\n".join(lines)


def uninstall():
    mgr = manager()
    if mgr == "systemd":
        path = unit_path()
        if not path.exists():
            return True, "no passkey-gate service is installed"
        run(["systemctl", "--user", "disable", "--now", UNIT_NAME])
        path.unlink()
        run(["systemctl", "--user", "daemon-reload"])
        return True, f"stopped the service and removed {path}"
    if mgr == "launchd":
        path = plist_path()
        if not path.exists():
            return True, "no passkey-gate service is installed"
        run(["launchctl", "bootout", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"])
        path.unlink()
        return True, f"stopped the service and removed {path}"
    return False, _no_manager_text(hermes_executable())


def installed() -> bool:
    mgr = manager()
    if mgr == "systemd":
        return unit_path().exists()
    if mgr == "launchd":
        return plist_path().exists()
    return False


def control(action: str):
    """start / stop / restart an installed service."""
    mgr = manager()
    if mgr is None:
        return False, _no_manager_text(hermes_executable())
    if not installed():
        return False, "the service is not installed — run: hermes passkey-gate service install"
    if mgr == "systemd":
        rc, out = run(["systemctl", "--user", action, UNIT_NAME])
    else:
        target = f"gui/{os.getuid()}/{LAUNCHD_LABEL}"
        if action == "stop":
            rc, out = run(["launchctl", "bootout", target])
        elif action == "start":
            rc, out = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path())])
        else:
            rc, out = run(["launchctl", "kickstart", "-k", target])
    if rc != 0:
        return False, f"{action} failed: {out}"
    return True, {"start": "started", "stop": "stopped", "restart": "restarted"}[action]


def status(port: int):
    mgr = manager()
    health = local_health(port)
    lines = []
    if mgr is None:
        lines.append("service manager: none found (systemd --user / launchd)")
    elif not installed():
        lines.append("background service: not installed (hermes passkey-gate service install)")
    elif mgr == "systemd":
        _, state = run(["systemctl", "--user", "is-active", UNIT_NAME])
        _, enabled = run(["systemctl", "--user", "is-enabled", UNIT_NAME])
        lines.append(f"background service: {state or 'unknown'} ({enabled or 'unknown'} at login) "
                     f"— {unit_path()}")
    else:
        rc, _ = run(["launchctl", "print", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"])
        lines.append(f"background service: {'loaded' if rc == 0 else 'not loaded'} — {plist_path()}")
    state = probe(port)
    if state == "ours":
        lines.append(f"gate on 127.0.0.1:{port}: answering (origin {health.get('origin') or 'not set'}, "
                     f"{health.get('credentials', 0)} passkey(s) registered)")
    elif state == "other":
        lines.append(f"port {port}: in use by something that is NOT this gate (another program, an "
                     "older approval-gate, or another profile's gate) — pick a free port with "
                     "hermes passkey-gate set port <n>")
    else:
        lines.append(f"gate on 127.0.0.1:{port}: not answering")
    return state == "ours", "\n".join(lines)


def logs(lines: int = 60):
    mgr = manager()
    if mgr == "systemd":
        rc, out = run(["journalctl", "--user", "-u", UNIT_NAME, "-n", str(lines), "--no-pager"])
        return rc == 0, out or "(no output yet)"
    if mgr == "launchd":
        p = launchd_log_path()
        if not p.exists():
            return True, "(no output yet)"
        return True, "\n".join(p.read_text(errors="replace").splitlines()[-lines:])
    return False, _no_manager_text(hermes_executable())
