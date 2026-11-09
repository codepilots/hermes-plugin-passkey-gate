"""Lanes: which conversations the enforcement hook applies to.

Every agent turn starts in one of five lanes, and the operator picks which
lanes need a passkey (`gated_lanes`, default all five, which is the
pre-0.8 behaviour of gating everything):

  local   you at this computer: CLI, TUI, Desktop, ACP editor
  owner   a chat message from a sender listed in `owner_senders`
          ("platform:user_id", e.g. "telegram:123456789")
  others  a chat message from anyone else, plus scheduled jobs, webhooks,
          API runs and anything whose origin can't be told
  bots    a chat message whose sender the chat platform marks as a bot
          (Discord's bot flag, or a platform's `bot_users` list)
  agents  another agent talking to this one directly: an A2A session
          (platform `a2a`) or a Hermes peer DM (`hermes peer dm`, sender
          `api-peer`)

How a turn's lane is learned, using documented Hermes plugin hooks only:

  * `post_gateway_admission` sees every admitted chat message with its
    sender; senders flagged `is_bot` are remembered as bots.
  * `pre_llm_call` fires once per turn with the session id, platform,
    sender and parent session; the origin is recorded against the session
    (and its task id), and a delegated subagent inherits its parent's.
  * `pre_tool_call` looks the record up and gates the call if ANY origin
    recorded for that session is in a gated lane. Origins are sticky for
    the life of the session: once an agent has spoken in a chat, the chat
    stays in the agents lane.

Fail closed: when there is no record (the turn hook never ran, the record
was evicted, an older Hermes), only a session Hermes itself reports as
CLI/TUI/Desktop/ACP counts as local; A2A counts as agents; anything else is
treated as gated whenever any non-local lane is gated.

Limits are written up for operators in the README ("Choosing which chats
need a passkey"). Nothing here can approve a call: it only decides whether
the authority patterns are checked for this turn at all.
"""
import threading
from collections import OrderedDict

LANES = ("local", "owner", "others", "bots", "agents")
LANE_WORDS = {
    "local": "you at this computer",
    "owner": "a chat from you (an owner sender)",
    "others": "a chat from someone else, a scheduled job, or an unknown origin",
    "bots": "a chat message from a sender the platform marks as a bot",
    "agents": "another agent (A2A or a Hermes peer DM)",
}
# Hermes session surfaces that are a person at this computer. "local" is
# NOT here: the gateway's local platform also carries peer Bot Chats.
LOCAL_SURFACES = frozenset({"cli", "tui", "desktop", "acp"})
# the platform that is a local session when the sender is a local OS user
LOCAL_PLATFORM = "local"
# Hermes's subject for a peer agent's Bot Chat (hermes peer dm / peer run)
PEER_SENDERS = frozenset({"api-peer"})
AGENT_PLATFORMS = frozenset({"a2a"})
MAX_TRACKED = 4096

_lock = threading.Lock()
_bot_senders: "OrderedDict[tuple[str, str], bool]" = OrderedDict()
_origins: "OrderedDict[str, frozenset]" = OrderedDict()


def _remember(store, key, value):
    store[key] = value
    store.move_to_end(key)
    while len(store) > MAX_TRACKED:
        store.popitem(last=False)


def _norm(value) -> str:
    return str(value or "").strip()


def reset():
    """Forget everything (tests)."""
    with _lock:
        _bot_senders.clear()
        _origins.clear()


# ---------------------------------------------------------------- hooks
def note_admission(session_key=None, platform=None, source=None, **_):
    """post_gateway_admission observer: remember senders the chat platform
    marks as bots. Always returns None (never consumes the message)."""
    try:
        src = source if isinstance(source, dict) else {}
        if src.get("is_bot") is True:
            plat = _norm(platform or src.get("platform")).lower()
            uid = _norm(src.get("user_id"))
            if plat and uid:
                with _lock:
                    _remember(_bot_senders, (plat, uid), True)
    except Exception:
        pass
    return None


def note_turn(session_id=None, task_id=None, platform=None, sender_id=None,
              parent_session_id=None, **_):
    """pre_llm_call observer: record where this turn came from. Returns None
    (a string would be injected into the model's context)."""
    try:
        origin = (_norm(platform).lower(), _norm(sender_id))
        with _lock:
            origins = {origin}
            for key in (_norm(session_id), _norm(parent_session_id)):
                if key and key in _origins:
                    origins |= _origins[key]
            frozen = frozenset(origins)
            for key in (_norm(session_id), _norm(task_id)):
                if key:
                    _remember(_origins, key, frozen)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- verdict
def classify(platform, sender_id, owner_senders=()) -> str:
    plat, sender = _norm(platform).lower(), _norm(sender_id)
    if plat in AGENT_PLATFORMS or sender in PEER_SENDERS:
        return "agents"
    if plat in LOCAL_SURFACES:
        return "local"
    with _lock:
        is_bot = bool(sender) and (plat, sender) in _bot_senders
    if is_bot:
        return "bots"
    if plat == LOCAL_PLATFORM and sender.startswith("uid:"):
        return "local"
    owners = {_norm(o).lower() for o in owner_senders or ()}
    if sender and f"{plat}:{sender}".lower() in owners:
        return "owner"
    return "others"


def turn_lanes(task_id="", session_id="", surface="", owner_senders=()):
    """The lanes this tool call's session has been in, or None when unknown."""
    with _lock:
        origins = None
        for key in (_norm(task_id), _norm(session_id)):
            if key and key in _origins:
                origins = _origins[key]
                break
    if origins is not None:
        return {classify(p, s, owner_senders) for p, s in origins}
    surf = _norm(surface).lower()
    if surf in LOCAL_SURFACES:
        return {"local"}
    if surf in AGENT_PLATFORMS:
        return {"agents"}
    return None


def normalize_lanes(value):
    """The configured gated lanes as a set. Fails closed: a value that isn't
    a list, or a non-empty list with no valid lane in it, gates every lane."""
    if not isinstance(value, (list, tuple)):
        return set(LANES)
    lanes = {_norm(v).lower() for v in value} & set(LANES)
    if value and not lanes:
        return set(LANES)
    return lanes


def gate_decision(gated, lanes):
    """(gated?, lane words for the block message)."""
    if lanes is None:
        if gated - {"local"}:
            return True, "this turn's origin could not be determined, so it is treated as gated"
        return False, ""
    hit = sorted(lanes & gated, key=LANES.index)
    if not hit:
        return False, ""
    return True, "; ".join(f"{lane} — {LANE_WORDS[lane]}" for lane in hit)


def validate(value):
    """Problems with a gated_lanes value (empty list = fine)."""
    if not isinstance(value, list):
        return ["gated_lanes must be a list"]
    bad = [v for v in value if _norm(v).lower() not in LANES]
    return [f"unknown lane {v!r} (lanes: {', '.join(LANES)})" for v in bad]


def validate_owner_senders(value):
    if not isinstance(value, list):
        return ["owner_senders must be a list"]
    out = []
    for v in value:
        plat, _, uid = _norm(v).partition(":")
        if not plat or not uid:
            out.append(f"{v!r} is not platform:user_id (e.g. telegram:123456789)")
        elif plat.lower() in AGENT_PLATFORMS or uid in PEER_SENDERS or plat.lower() in LOCAL_SURFACES:
            out.append(f"{v!r} is not a chat sender: agents and local sessions have their own lanes")
    return out


def normalize_lanes_ordered(value):
    return sorted(normalize_lanes(value), key=LANES.index)
