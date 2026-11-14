"""A passkey approval also answers Hermes's own prompt for that exact command
(transport.py), and nothing else."""
import hashlib
import json
from dataclasses import dataclass

import pytest

from passkey_gate import transport


@dataclass(frozen=True)
class FakeRequest:
    """Shape of hermes_cli.approval_transport.ApprovalRequest that present() uses."""
    command: str
    allowed_choices: tuple = ("once", "session", "always", "deny")
    request_id: str = "r1"
    digest: str = "d1"

    def respond(self, choice):
        return ("decision", self.request_id, self.digest, choice)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    transport.clear()
    monkeypatch.setattr(transport, "_redact", lambda text: text.replace("SECRET", "***"))
    yield
    transport.clear()


CMD = "rm -rf /srv/data/old-backups"


def test_covered_command_is_answered_once_and_only_once():
    transport.note_covered("terminal", {"command": CMD})
    assert transport.present(FakeRequest(CMD)) == ("decision", "r1", "d1", "once")
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD))


def test_uncovered_command_falls_back_to_hermes_prompt():
    transport.note_covered("terminal", {"command": CMD})
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD + " /etc"))
    # the real cover is untouched by the miss
    assert transport.present(FakeRequest(CMD))[3] == "once"


def test_never_answers_with_a_wider_scope_or_when_once_is_not_offered():
    transport.note_covered("terminal", {"command": CMD})
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD, allowed_choices=("deny",)))


def test_finished_call_discards_its_unused_cover():
    transport.note_covered("terminal", {"command": CMD})
    transport.discard("terminal", {"command": CMD})
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD))


def test_cover_expires(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    transport.note_covered("terminal", {"command": CMD})
    now[0] += transport.CREDIT_TTL_SECONDS + 1
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD))


def test_two_approvals_give_two_covers():
    transport.note_covered("terminal", {"command": CMD})
    transport.note_covered("terminal", {"command": CMD})
    transport.present(FakeRequest(CMD))
    transport.present(FakeRequest(CMD))
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD))


def test_command_that_redaction_alters_gets_no_cover():
    """Hermes only shows redacted text, so two commands differing only in a
    secret would look identical: such commands keep Hermes's own prompt."""
    cmd = "curl -H 'Authorization: SECRET' https://x"
    transport.note_covered("terminal", {"command": cmd})
    for shown in (cmd, cmd.replace("SECRET", "***")):
        with pytest.raises(transport.NotCovered):
            transport.present(FakeRequest(shown))


def test_no_cover_when_hermes_redaction_is_unavailable(monkeypatch):
    monkeypatch.setattr(transport, "_redact", lambda text: None)
    transport.note_covered("terminal", {"command": CMD})
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD))


def test_execute_code_cover_matches_hermes_prompt_text():
    code = "import shutil\nshutil.rmtree('/srv/x')"
    transport.note_covered("execute_code", {"code": code})
    assert transport.present(FakeRequest(f"execute_code <<'PY'\n{code}\nPY"))[3] == "once"


def test_other_tools_never_get_a_cover():
    transport.note_covered("write_file", {"path": "/x", "content": CMD})
    transport.note_covered("terminal", {"command": "   "})
    transport.note_covered("terminal", None)
    assert transport._credits == {}


def test_hook_records_cover_only_when_it_consumes_an_approval(monkeypatch):
    from passkey_gate import gate_core, tools
    call = {"tool": "terminal", "args": {"command": CMD}}
    canonical = gate_core.canonical_binding_json(call)
    binding = hashlib.sha256(canonical.encode()).hexdigest()
    row = {"id": "c1", "tool_call": json.dumps(call), "binding_sha256": binding}
    monkeypatch.setattr(gate_core, "pending_for_binding", lambda b: row if b == binding else None)
    monkeypatch.setattr(tools, "_pinned_owner_problems", lambda r: None)
    monkeypatch.setattr(tools, "near_miss_hint", lambda *a: None)
    consumed = []
    monkeypatch.setattr(gate_core, "consume", lambda cid, b: not consumed and not consumed.append(cid))

    assert tools.hook_verdict("terminal", {"command": CMD}, [r"rm -rf"], True) is None
    assert transport.present(FakeRequest(CMD))[3] == "once"
    # a second run: approval already spent -> blocked, and no new cover
    v = tools.hook_verdict("terminal", {"command": CMD}, [r"rm -rf"], True)
    assert v["action"] == "block"
    with pytest.raises(transport.NotCovered):
        transport.present(FakeRequest(CMD))
    # unmatched (ungated) calls never earn a cover
    assert tools.hook_verdict("terminal", {"command": "ls"}, [r"rm -rf"], True) is None
    assert transport._credits == {}


def test_register_offers_transport_and_post_tool_call(monkeypatch):
    import passkey_gate
    from passkey_gate import cli
    monkeypatch.setattr(cli, "_ctx_ref", None)
    monkeypatch.setattr(cli, "_cfg_cache", None)
    seen = {"hooks": [], "transports": []}

    class Ctx:
        def get_config(self, key, default=None):
            return default

        def set_config(self, key, value):
            pass

        def register_tool(self, **kw):
            pass

        def register_hook(self, name, fn):
            seen["hooks"].append(name)

        def register_cli_command(self, **kw):
            pass

        def register_approval_transport(self, name, fn):
            seen["transports"].append((name, fn))

    passkey_gate.register(Ctx())
    assert seen["transports"] == [("passkey-gate", transport.present)]
    assert "post_tool_call" in seen["hooks"] and "pre_tool_call" in seen["hooks"]

    class OldHermes(Ctx):
        register_approval_transport = None

    passkey_gate.register(OldHermes())  # no transport API: still registers fine


def test_set_hermes_cover_writes_through_hermes_config(monkeypatch):
    import sys
    import types
    written, cfg = [], {}

    def set_config_value(key, value):
        written.append((key, value))
        cfg[key.rsplit(".", 1)[1]] = value
    fake = types.ModuleType("hermes_cli.config")
    fake.set_config_value = set_config_value
    fake.load_config_readonly = lambda: {"security": {"approval": dict(cfg)}}
    monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)

    ok, note = transport.set_hermes_cover(True)
    assert ok and note.startswith("on")
    assert written == [("security.approval.transport_fallback", "builtin"),
                       ("security.approval.transport", "passkey-gate")]
    ok, note = transport.set_hermes_cover(False)
    assert ok and cfg["transport"] == "builtin"

    def refuse(key, value):
        print("✗ managed install")
        raise SystemExit(1)
    fake.set_config_value = refuse
    ok, note = transport.set_hermes_cover(True)
    assert not ok and "managed install" in note


def test_set_hermes_cover_outside_hermes():
    ok, note = transport.set_hermes_cover(True)
    assert not ok and "by hand" in note


# ------------------------------------------------ pre_approval_request hook
@pytest.fixture
def approval_hook(monkeypatch):
    """The plugin's pre_approval_request hook with config, surface and
    begin_ask faked: returns (call, asked) where asked lists begin_ask calls."""
    import passkey_gate
    from passkey_gate import cli, lanes
    cfg = {"require_passkey": True, "passkey_hermes_prompts": True, "patterns": [],
           "gated_lanes": list(lanes.LANES), "owner_senders": []}
    state = {"surface": "discord"}
    asked = []
    monkeypatch.setattr(cli, "apply_config_safe", lambda: cfg)
    monkeypatch.setattr(passkey_gate, "_session_surface", lambda: state["surface"])
    monkeypatch.setattr(cli, "_ctx_ref", type("Ctx", (), {"post_message": staticmethod(lambda t: None)})())
    monkeypatch.setattr(transport, "begin_ask", lambda rid, cmd, why, post: asked.append((rid, cmd)) or "asked")
    lanes.reset()

    def fire(surface="transport:passkey-gate", **kw):
        return passkey_gate._on_pre_approval_request(
            surface=surface, request_id="r1", command=CMD, description="recursive delete", **kw)
    return fire, asked, cfg, state


def test_hook_asks_for_a_passkey_on_a_gated_chat(approval_hook):
    fire, asked, cfg, state = approval_hook
    assert fire() is None and asked == [("r1", CMD)]


@pytest.mark.parametrize("change", [
    {"passkey_hermes_prompts": False}, {"require_passkey": False}, {"_config_error": "broken"}])
def test_hook_stays_out_unless_the_setting_and_enforcement_are_on(approval_hook, change):
    fire, asked, cfg, state = approval_hook
    cfg.update(change)
    fire()
    assert asked == []


def test_hook_ignores_other_approval_surfaces(approval_hook):
    fire, asked, cfg, state = approval_hook
    for surface in ("gateway", "cli", "smart", "transport:someone-else"):
        fire(surface=surface)
    assert asked == []


def test_hook_leaves_the_classic_terminal_and_ungated_lanes_to_hermes(approval_hook):
    fire, asked, cfg, state = approval_hook
    state["surface"] = "cli"                      # can't show the link in time
    fire()
    state["surface"] = "tui"                      # local lane, not gated here
    cfg["gated_lanes"] = ["others", "bots", "agents"]
    fire()
    assert asked == []
    state["surface"] = "discord"                  # unknown origin counts as gated
    fire()
    assert asked == [("r1", CMD)]


def test_hook_never_raises(approval_hook, monkeypatch):
    fire, asked, cfg, state = approval_hook
    monkeypatch.setattr(transport, "begin_ask", lambda *a: 1 / 0)
    assert fire() is None


def test_status_warns_when_hermes_can_approve_without_asking(monkeypatch):
    import sys
    import types
    cfg = {"security": {"approval": {"transport": "passkey-gate", "transport_fallback": "builtin"}},
           "approvals": {"mode": "smart"}}
    fake = types.ModuleType("hermes_cli.config")
    fake.load_config_readonly = lambda: cfg
    monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    out = transport.hermes_selection(every_prompt=True)
    assert out["every_flagged_command"] and "approvals.mode manual" in out["warning"]
    cfg["approvals"]["mode"] = "manual"
    out = transport.hermes_selection(every_prompt=True)
    assert "warning" not in out and out["note"].startswith("on: every command Hermes flags")
    cfg["security"]["approval"]["transport"] = "builtin"
    assert transport.hermes_selection(every_prompt=True)["note"].startswith("WARNING")
    assert "every_flagged_command" in transport.hermes_selection()


@pytest.mark.parametrize("hermes_timeout, ttl, expect", [
    (300, 600, None),
    (600, 600, None),
    (900, 600, "expires after 600s"),
    (60, 600, "short for a phone"),
    ("junk", 600, None),
])
def test_wait_warning(hermes_timeout, ttl, expect):
    out = transport.wait_warning(hermes_timeout, ttl)
    assert (out is None) if expect is None else (expect in out)


def test_status_warns_about_timers(monkeypatch):
    import sys
    import types
    cfg = {"security": {"approval": {"transport": "passkey-gate", "transport_fallback": "builtin"}},
           "approvals": {"mode": "manual", "timeout": 60}}
    fake = types.ModuleType("hermes_cli.config")
    fake.load_config_readonly = lambda: cfg
    monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake)
    out = transport.hermes_selection(every_prompt=True, request_ttl=600)
    assert out["waits_seconds"] == 60 and "short for a phone" in out["warning"]
    cfg["approvals"]["timeout"] = 300
    assert "warning" not in transport.hermes_selection(every_prompt=True, request_ttl=600)
