"""Minimal environments for the child processes the gate starts.

The gate runs inside the Hermes agent process, whose environment holds every
provider API key. A child process started without `env=` inherits all of it,
so every `subprocess.run` here passes one of these explicit allowlists
instead. Only the named variables are copied, and only when they are set;
nothing else in the parent environment ever reaches a child.
"""
import os

# PATH to find binaries, HOME for per-user state, LANG for output encoding.
BASE_KEYS = ("PATH", "HOME", "LANG")

# `systemctl --user` (and `journalctl --user`, `loginctl`) find the user's
# service manager through these two.
SYSTEMD_USER_KEYS = BASE_KEYS + ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")


def _pick(keys) -> dict:
    env = {k: os.environ[k] for k in keys if os.environ.get(k)}
    env.setdefault("PATH", os.defpath)
    return env


def base_env() -> dict:
    """For `tailscale` and the regex timing probe."""
    return _pick(BASE_KEYS)


def systemd_user_env() -> dict:
    """For `systemctl --user` / `launchctl` and friends."""
    return _pick(SYSTEMD_USER_KEYS)
