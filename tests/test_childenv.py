"""Catalog review (f50b315): no child process may inherit the agent's
environment. Every subprocess.run in the plugin passes an explicit minimal
env, and a provider key set in the parent never reaches the child."""
import ast
import subprocess
import sys
from pathlib import Path

from passkey_gate import childenv, cli, expose, service, tools

PLUGIN = Path(__file__).resolve().parent.parent / "plugin"
SECRET = "sk-should-never-leak"


def test_every_subprocess_call_passes_env():
    missing = []
    for path in sorted(PLUGIN.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
                    and not any(k.arg == "env" for k in node.keywords)):
                missing.append(f"{path.name}:{node.lineno}")
    assert missing == []


def test_envs_are_allowlists(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", SECRET)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    assert set(childenv.base_env()) <= {"PATH", "HOME", "LANG"}
    assert "XDG_RUNTIME_DIR" not in childenv.base_env()
    sysd = childenv.systemd_user_env()
    assert set(sysd) <= set(childenv.SYSTEMD_USER_KEYS)
    assert sysd["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert sysd["DBUS_SESSION_BUS_ADDRESS"].startswith("unix:")
    for env in (childenv.base_env(), sysd):
        assert SECRET not in env.values()


def test_path_always_present(monkeypatch):
    monkeypatch.delenv("PATH", raising=False)
    assert childenv.base_env()["PATH"]


def _capture(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(kw.get("env"))
        return subprocess.CompletedProcess(cmd, 1, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


def test_call_sites_send_minimal_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    seen = _capture(monkeypatch)
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/usr/bin/" + n)
    expose.fetch_status_json()
    expose.fetch_self_dnsname()
    cli.os_default_rp_id("")
    service._run(["systemctl", "--user", "is-active", "x"])
    tools.slow_patterns([r"a+"])
    assert len(seen) == 5
    for env in seen:
        assert env is not None and SECRET not in env.values()
        assert "ANTHROPIC_API_KEY" not in env


def test_probe_really_runs_without_secret(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    out = subprocess.run([sys.executable, "-I", "-c", "import os,sys; sys.stdout.write(repr(dict(os.environ)))"],
                         capture_output=True, text=True, env=childenv.base_env(), timeout=10)
    assert SECRET not in out.stdout
    assert tools.slow_patterns([r"a+b"]) == []
