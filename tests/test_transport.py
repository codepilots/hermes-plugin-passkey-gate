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
