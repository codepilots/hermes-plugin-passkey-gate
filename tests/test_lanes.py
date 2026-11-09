"""Lanes (v0.8): which conversations enforcement applies to.

Covers turn classification, sticky origins, subagent inheritance, the
fail-closed fallbacks, the hook wiring, and the settings rules (narrowing
lanes or adding an owner sender is a weakening change)."""

import pytest

import passkey_gate
from passkey_gate import cli, lanes, tools
from test_settings import FakeCtx, _cli

PATTERNS = [r"^terminal .*\brm\b"]
RISKY = {"command": "rm -rf build"}
SAFE = {"command": "ls"}


@pytest.fixture(autouse=True)
def _fresh():
    lanes.reset()
    yield
    lanes.reset()


@pytest.fixture
def cfg(monkeypatch):
    """Enforcement on with the given lanes; hook_verdict stubbed to 'blocked'
    so these tests only exercise the lane decision."""
    state = {"require_passkey": True, "patterns": PATTERNS,
             "gated_lanes": list(lanes.LANES), "owner_senders": []}
    monkeypatch.setattr(cli, "apply_config_safe", lambda: state)
    monkeypatch.setattr(tools, "hook_verdict",
                        lambda name, args, patterns, on: {"action": "block", "message": "blocked"})
    monkeypatch.setattr(passkey_gate, "_session_surface", lambda: "")
    return state


def verdict(task_id="t1", session_id="s1"):
    return passkey_gate._pre_tool_call_verdict("terminal", RISKY, task_id=task_id,
                                               session_id=session_id)


def turn(platform, sender="", session_id="s1", task_id="t1", parent=""):
    passkey_gate._on_pre_llm_call(session_id=session_id, task_id=task_id, platform=platform,
                                  sender_id=sender, parent_session_id=parent,
                                  user_message="hi", conversation_history=[])


# ------------------------------------------------------------ classification
@pytest.mark.parametrize("platform,sender,lane", [
    ("cli", "", "local"), ("tui", "", "local"), ("desktop", "", "local"), ("acp", "", "local"),
    ("local", "uid:1000", "local"),
    ("a2a", "sorrel", "agents"),
    ("local", "api-peer", "agents"),          # hermes peer dm Bot Chat
    ("api_server", "api-peer", "agents"),
    ("telegram", "42", "others"),
    ("cron", "", "others"), ("webhook", "", "others"), ("", "", "others"),
])
def test_classify(platform, sender, lane):
    assert lanes.classify(platform, sender) == lane


def test_owner_sender_and_bot_flag():
    assert lanes.classify("telegram", "42", ["telegram:42"]) == "owner"
    assert lanes.classify("discord", "42", ["telegram:42"]) == "others"  # platform matters
    passkey_gate._on_post_gateway_admission(session_key="k", platform="discord",
                                            source={"platform": "discord", "user_id": "99",
                                                    "is_bot": True})
    assert lanes.classify("discord", "99") == "bots"
    # a bot flag beats an owner listing: a flagged sender is never "you"
    assert lanes.classify("discord", "99", ["discord:99"]) == "bots"


def test_admission_without_bot_flag_records_nothing():
    lanes.note_admission(platform="discord", source={"user_id": "7", "is_bot": "yes"})
    assert lanes.classify("discord", "7") == "others"


# ------------------------------------------------------------ the hook
def test_default_lanes_gate_everything_like_before(cfg):
    turn("cli")
    assert verdict()["action"] == "block"


def test_ungated_local_lane_lets_the_keyboard_through(cfg):
    cfg["gated_lanes"] = ["owner", "others", "bots", "agents"]
    turn("cli")
    assert verdict() is None


def test_agent_turn_is_gated_and_named_in_the_message(cfg):
    cfg["gated_lanes"] = ["agents"]
    turn("a2a", "sorrel")
    v = verdict()
    assert v["action"] == "block" and "Gated lane: agents" in v["message"]
    turn("telegram", "42", session_id="s2", task_id="t2")
    assert verdict("t2", "s2") is None


def test_peer_dm_is_agents_not_local(cfg):
    cfg["gated_lanes"] = ["agents"]
    turn("local", "api-peer")
    assert verdict()["action"] == "block"


def test_bots_lane_is_separate_from_other_people(cfg):
    cfg["gated_lanes"] = ["bots"]
    lanes.note_admission(platform="discord", source={"user_id": "99", "is_bot": True})
    turn("discord", "99")
    assert verdict()["action"] == "block"
    turn("discord", "12", session_id="s2", task_id="t2")   # a person, not gated
    assert verdict("t2", "s2") is None


def test_origin_is_sticky_for_the_session(cfg):
    """Once an agent has spoken in a session, a later turn from you in the
    same session is still gated (it may be acting on the agent's words)."""
    cfg["gated_lanes"] = ["agents"]
    turn("a2a", "sorrel")
    turn("a2a", "", task_id="t9")             # same session, next turn
    assert verdict("t9", "s1")["action"] == "block"


def test_subagent_inherits_parent_origin(cfg):
    cfg["gated_lanes"] = ["agents"]
    turn("a2a", "sorrel", session_id="parent", task_id="tp")
    turn("cli", "", session_id="child", task_id="tc", parent="parent")
    assert verdict("tc", "child")["action"] == "block"


def test_lookup_falls_back_to_session_id(cfg):
    cfg["gated_lanes"] = ["agents"]
    turn("a2a", "sorrel", task_id="")
    assert verdict(task_id="other", session_id="s1")["action"] == "block"


def test_unknown_origin_is_gated_when_any_remote_lane_is(cfg, monkeypatch):
    cfg["gated_lanes"] = ["agents"]
    assert verdict("never-seen", "never-seen")["action"] == "block"
    v = verdict("never-seen", "never-seen")
    assert "could not be determined" in v["message"]
    # Hermes says it's the CLI: local, not gated here
    monkeypatch.setattr(passkey_gate, "_session_surface", lambda: "cli")
    assert verdict("never-seen", "never-seen") is None
    # Hermes says A2A: agents
    monkeypatch.setattr(passkey_gate, "_session_surface", lambda: "a2a")
    assert verdict("never-seen", "never-seen")["action"] == "block"
    # the gateway's "local" platform also carries peer Bot Chats: not trusted as local
    monkeypatch.setattr(passkey_gate, "_session_surface", lambda: "local")
    assert verdict("never-seen", "never-seen")["action"] == "block"


def test_unknown_origin_passes_only_when_just_local_is_gated(cfg):
    cfg["gated_lanes"] = ["local"]
    assert verdict("never-seen", "never-seen") is None


def test_enforcement_off_ignores_lanes(cfg):
    cfg["require_passkey"] = False
    turn("a2a", "sorrel")
    assert verdict() is None


def test_eviction_falls_back_to_unknown(cfg, monkeypatch):
    monkeypatch.setattr(lanes, "MAX_TRACKED", 2)
    cfg["gated_lanes"] = ["agents"]
    turn("cli", session_id="a", task_id="a")
    turn("cli", session_id="b", task_id="b")
    turn("cli", session_id="c", task_id="c")
    assert verdict("a", "a")["action"] == "block"   # evicted -> unknown -> gated


@pytest.mark.parametrize("bad", ["agents", None, 5, ["nonsense"]])
def test_malformed_lanes_config_gates_everything(bad):
    assert lanes.normalize_lanes(bad) == set(lanes.LANES)


def test_empty_lanes_list_gates_nothing():
    assert lanes.normalize_lanes([]) == set()


def test_observer_hooks_return_none_and_never_raise():
    assert passkey_gate._on_pre_llm_call(session_id=object(), platform=["x"]) is None
    assert passkey_gate._on_post_gateway_admission(source="junk") is None


def test_real_hook_path_with_real_verdict(monkeypatch):
    """No stubs: the real hook_verdict blocks an unapproved risky call in a
    gated lane and lets it through in an ungated one."""
    state = {"require_passkey": True, "patterns": PATTERNS,
             "gated_lanes": ["agents"], "owner_senders": []}
    monkeypatch.setattr(cli, "apply_config_safe", lambda: state)
    monkeypatch.setattr(passkey_gate, "_session_surface", lambda: "")
    turn("a2a", "sorrel")
    v = passkey_gate._on_pre_tool_call("terminal", RISKY, task_id="t1", session_id="s1")
    assert v["action"] == "block" and "no approved passkey challenge" in v["message"]
    assert passkey_gate._on_pre_tool_call("terminal", SAFE, task_id="t1", session_id="s1") is None
    turn("cli", session_id="s2", task_id="t2")
    assert passkey_gate._on_pre_tool_call("terminal", RISKY, task_id="t2", session_id="s2") is None


# ------------------------------------------------------------ settings
def test_narrowing_lanes_needs_approval_widening_is_free():
    ctx = FakeCtx()
    out = _cli(ctx, "set gated_lanes agents,bots")
    assert "REFUSED" in out and "weakens" in out and "local" in out
    assert "gated_lanes" not in ctx.store
    ctx.store["gated_lanes"] = ["agents"]
    out = _cli(ctx, "set gated_lanes agents,bots")
    assert ctx.store["gated_lanes"] == ["bots", "agents"], out


def test_lanes_are_validated_and_normalized():
    ctx = FakeCtx()
    out = _cli(ctx, "set gated_lanes agents,robots")
    assert "REFUSED" in out and "unknown lane 'robots'" in out
    out = _cli(ctx, "set gated_lanes AGENTS, local , bots, others, owner")
    assert ctx.store["gated_lanes"] == ["local", "owner", "others", "bots", "agents"], out


def test_adding_an_owner_sender_needs_approval_removing_is_free():
    ctx = FakeCtx()
    out = _cli(ctx, "set owner_senders telegram:42")
    assert "REFUSED" in out and "weakens" in out and "ADDS 1 owner sender" in out
    ctx.store["owner_senders"] = ["telegram:42", "discord:7"]
    out = _cli(ctx, "set owner_senders telegram:42")
    assert ctx.store["owner_senders"] == ["telegram:42"], out


@pytest.mark.parametrize("bad", ["telegram", ":42", "a2a:sorrel", "local:api-peer", "cli:me"])
def test_owner_senders_must_be_chat_accounts(bad):
    ctx = FakeCtx()
    ctx.store["owner_senders"] = []
    out = _cli(ctx, f"set owner_senders {bad}")
    assert "REFUSED: owner_senders rejected" in out


def test_setup_may_narrow_lanes_only_while_enforcement_is_off():
    ctx = FakeCtx()
    out = cli.cmd_set(ctx, ["gated_lanes", "agents"], _setup_enforcement_off=True)
    assert ctx.store["gated_lanes"] == ["agents"], out
    ctx.store["require_passkey"] = True
    out = cli.cmd_set(ctx, ["gated_lanes", "[]"], _setup_enforcement_off=True)
    assert "REFUSED" in out and ctx.store["gated_lanes"] == ["agents"]
    # and never for the other security settings
    ctx.store["require_passkey"] = False
    ctx.store["authority_patterns"] = ["x"]
    out = cli.cmd_set(ctx, ["authority_patterns", "[]"], _setup_enforcement_off=True)
    assert "REFUSED" in out


def test_setup_flag_is_not_reachable_from_the_command_line():
    ctx = FakeCtx()
    out = _cli(ctx, "set gated_lanes agents _setup_enforcement_off=True")
    assert "REFUSED" in out
