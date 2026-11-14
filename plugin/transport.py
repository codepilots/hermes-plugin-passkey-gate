"""Approval transport: a passkey approval also answers Hermes's own prompt.

Without this, a command the gate already passkey-approved can still hit
Hermes's built-in dangerous-command prompt straight afterwards, so the human
approves the same thing twice. Hermes lets a plugin register an *approval
transport* (where its approval prompts are answered). Ours answers exactly
one case, and passes everything else back to Hermes's normal prompt:

  1. The pre_tool_call hook consumes a passkey approval for an exact call
     and calls ``note_covered`` for it. That records a credit for the text
     Hermes will show in its prompt.
  2. If Hermes then asks for approval of that same text, ``present`` spends
     the credit and answers ``once``. Never ``session`` or ``always``: one
     signature still authorises one execution.
  3. Anything else raises ``NotCovered``. With ``transport_fallback:
     builtin`` Hermes then shows its normal prompt on the usual surface.
     Without it, Hermes denies (its fail-closed default), which is why
     ``status`` warns about that setting.

Credits are single use, expire after a few seconds, and are thrown away when
the tool call that earned them finishes (``discard``, from post_tool_call),
so an unused credit can't cover a later call. Hermes's prompt only ever
receives redacted text, so a credit is only recorded when redaction leaves
the command unchanged: two different commands can never share one credit.
Hermes still owns hardline blocks, deny rules and the rest of its guards;
those run before any transport is asked.

Operator opt-in (Hermes config.yaml):

    security:
      approval:
        transport: passkey-gate
        transport_fallback: builtin

Passkey for every command Hermes flags (setting passkey_hermes_prompts)
-----------------------------------------------------------------------
The cover above only helps commands the operator's patterns already caught.
With passkey_hermes_prompts on, Hermes's own detector decides what needs
approval and the passkey proves the human said yes:

  1. Just before Hermes calls the transport it fires pre_approval_request,
     in the session's own context. ``begin_ask`` mints a challenge (kind
     HERMES_KIND, text-only, created by the gate, never by an agent) over
     the text Hermes would have shown, and posts the approval link into
     that same conversation with ctx.post_message. No agent is involved in
     delivering it.
  2. ``present`` (on Hermes's worker thread) waits for that challenge. A
     signature is verified here, locally, against the pinned owner key,
     then consumed: answer ``once``. Denied on the phone, no answer in
     time, or a signature that doesn't verify: answer ``deny``.
  3. When Hermes stops waiting, post_approval_response calls ``end_ask``,
     which updates the chat message with the outcome, cancels a wait that
     is still running and withdraws the challenge, so a late signature
     leaves nothing spendable behind.

Hermes's transport worker thread has lost the session's profile and
conversation: there, the gate's data folder would resolve to the DEFAULT
profile's, and posted messages can't be edited. So ``begin_ask`` records
the data folder while it has the session's context and ``present`` pins
its thread to it (gate_core.using_data_dir), and the message is only ever
edited from ``end_ask``, which runs in the session's context again.

If the link can't be minted or delivered (the classic terminal client only
shows posted messages at the end of the turn; no owner key pinned; no gate
address; text the approval page refuses), nothing is recorded and
``present`` raises NotCovered as before: Hermes's transport_fallback
decides, ``builtin`` meaning its ordinary prompt and anything else a denial.
"""
import logging
import threading
import time

from . import gate_core, local_verify

logger = logging.getLogger(__name__)

TRANSPORT_NAME = "passkey-gate"
CREDIT_TTL_SECONDS = 30.0
ASK_MARGIN_SECONDS = 5.0   # answer this long before Hermes's own timeout
ASK_POLL_SECONDS = 1.0
ASK_KEEP_SECONDS = 3600.0  # forget a request whose end never arrived
DISPLAY_CHARS = 600

_lock = threading.Lock()
_credits: dict[str, list[float]] = {}  # prompt text -> expiry times, one per credit
_asks: dict = {}  # Hermes request id -> _Ask


class NotCovered(Exception):
    """No passkey approval covers this prompt; Hermes's own prompt decides."""


def _redact(text: str) -> str | None:
    try:
        from agent.redact import redact_approval_display
    except Exception:
        return None
    try:
        return redact_approval_display(text, force=True)
    except Exception:
        return None


def prompt_text(tool_name: str, args) -> str | None:
    """The text Hermes's approval prompt carries for this call, or None when
    the call can't be matched safely (unknown tool, or redaction would alter
    the text, which could make two different commands look identical)."""
    if not isinstance(args, dict):
        return None
    if tool_name == "terminal" and isinstance(args.get("command"), str):
        raw = args["command"]
    elif tool_name == "execute_code" and isinstance(args.get("code"), str):
        raw = f"execute_code <<'PY'\n{args['code']}\nPY"
    else:
        return None
    if not raw.strip() or _redact(raw) != raw:
        return None
    return raw


def _prune(now: float) -> None:
    for key in [k for k, exp in _credits.items() if not any(e > now for e in exp)]:
        del _credits[key]
    for key, exp in _credits.items():
        exp[:] = [e for e in exp if e > now]


def note_covered(tool_name: str, args) -> None:
    """Called by the hook right after it consumes a passkey approval for this call."""
    text = prompt_text(tool_name, args)
    if text is None:
        return
    now = time.monotonic()
    with _lock:
        _prune(now)
        _credits.setdefault(text, []).append(now + CREDIT_TTL_SECONDS)


def discard(tool_name: str, args) -> None:
    """The call has finished: any credit it didn't use must not outlive it."""
    text = prompt_text(tool_name, args)
    if text is None:
        return
    with _lock:
        exp = _credits.get(text)
        if exp:
            exp.pop(0)
            if not exp:
                del _credits[text]


def _take(text: str) -> bool:
    now = time.monotonic()
    with _lock:
        _prune(now)
        exp = _credits.get(text)
        if not exp:
            return False
        exp.pop(0)
        if not exp:
            del _credits[text]
        return True


def has_cover(command) -> bool:
    """Is there an unspent cover for this prompt text? (Reads only.)"""
    now = time.monotonic()
    with _lock:
        return any(e > now for e in _credits.get(command, ()))


# ------------------------------------------------ passkey for Hermes's prompts
class _Ask:
    """One Hermes approval request waiting on a passkey signature."""

    def __init__(self, cid, sha, text, command, handle, data_dir):
        self.cid, self.sha, self.text, self.command, self.handle = cid, sha, text, command, handle
        self.data_dir = data_dir       # resolved in the session's context
        self.cancelled = threading.Event()
        self.started = False           # present() picked it up
        self.line = None               # outcome for the chat message, once decided
        self.closed = False            # end_ask already updated the message
        self.created = time.monotonic()


def ask_text(command: str, description: str) -> str:
    """The exact text the human signs for a Hermes-flagged command."""
    return (f"Run this command, which Hermes flagged as: {(description or 'dangerous').strip()}"
            f"\n\n{command}")


def _shown(command: str) -> str:
    return command if len(command) <= DISPLAY_CHARS else (
        command[:DISPLAY_CHARS] + " … (the approval page shows all of it)")


def _hermes_approvals() -> dict:
    try:
        from hermes_cli.config import load_config_readonly
        cfg = (load_config_readonly() or {}).get("approvals") or {}
        return cfg if isinstance(cfg, dict) else {}
    except Exception:
        return {}


def _wait_words() -> str:
    try:
        minutes = max(1, int(float(_hermes_approvals().get("timeout") or 0)) // 60)
    except (TypeError, ValueError):
        minutes = 0
    return f"within {minutes} min" if minutes else "in time"


def begin_ask(request_id, command, description, post) -> str:
    """pre_approval_request, in the session's context: mint the challenge and
    post its link into this conversation. Returns what happened, for the log.
    Never raises; anything short of "asked" leaves no trace, so present()
    falls back to Hermes's own handling."""
    cid = None
    try:
        if not request_id or not isinstance(command, str) or not command.strip():
            return "not asked: no request to sign"
        if has_cover(command):
            return "covered: a passkey approval for this exact call was just used"
        if local_verify.pinned(gate_core.data_dir()) is None:
            return "not asked: no owner key is pinned"
        text = ask_text(command, description if isinstance(description, str) else "")
        c = gate_core.create_challenge(text, gate_core.HERMES_REQUESTER, _kind=gate_core.HERMES_KIND)
        cid = c["challenge_id"]
        if not c.get("url"):
            gate_core.withdraw_challenge(cid, "no gate address configured")
            return "not asked: the gate has no address (origin) yet"
        handle = post("🔐 Passkey approval needed\n"
                      f"Hermes flagged this command ({(description or 'dangerous').strip()}):\n"
                      f"{_shown(command)}\n\n"
                      f"Approve or deny with your passkey: {c['url']}\n"
                      f"No answer {_wait_words()} means it does not run.")
        if not getattr(handle, "ok", False):
            gate_core.withdraw_challenge(cid, "the link could not be posted")
            return f"not asked: the link could not be posted ({getattr(handle, 'error', None)})"
        now = time.monotonic()
        with _lock:
            for old in [k for k, a in _asks.items() if now - a.created > ASK_KEEP_SECONDS]:
                del _asks[old]  # an end_ask that never came
            _asks[str(request_id)] = _Ask(cid, c["action_sha256"], text, command, handle,
                                          gate_core.data_dir())
        return "asked"
    except Exception as exc:
        if cid:
            try:
                gate_core.withdraw_challenge(cid, "request setup failed")
            except Exception:
                pass
        return f"not asked: {type(exc).__name__}: {exc}"


def _verify(ask) -> list:
    """Problems list; empty means the pinned owner's passkey signed exactly
    this text for exactly this challenge. Every claim is re-derived here."""
    rec = gate_core.challenge_status(ask.cid, ask.sha)
    if not isinstance(rec, dict) or rec.get("status") != "approved":
        return [f"the request is {rec.get('status') if isinstance(rec, dict) else rec!r}, not approved"]
    if rec.get("action_sha256") != ask.sha:
        return ["the approval was signed for different text"]
    row = gate_core.db().execute(
        "select kind, binding_sha256, tool_call, action_sha256, challenge from challenges where id=?",
        (ask.cid,)).fetchone()
    if (row is None or row["kind"] != gate_core.HERMES_KIND or row["binding_sha256"]
            or row["tool_call"] or row["action_sha256"] != ask.sha
            or not gate_core.record_matches_local_challenge(rec, row["challenge"])):
        return ["this isn't the request passkey-gate created for this command"]
    pinned = local_verify.pinned(gate_core.data_dir())
    if pinned is None:
        return ["no owner key is pinned"]
    return list(local_verify.check(rec, ask.text, gate_core.origin(), gate_core.rp_id(), pinned))


def _finish(ask, line: str) -> None:
    """Record the outcome line; end_ask writes it to the chat."""
    ask.line = line


def _update_message(ask, line: str) -> None:
    try:
        result = ask.handle.edit(f"{line}\n{_shown(ask.command)}")
        if isinstance(result, dict) and not result.get("ok"):
            logger.info("passkey-gate: the approval message was not updated: %s", result.get("error"))
    except Exception:
        logger.info("passkey-gate: could not update the approval message", exc_info=True)


def _decide(ask, timeout_seconds: float) -> bool:
    """Wait for the human, then verify. True only for a verified, consumed
    passkey approval; every other path (and any error) is a refusal."""
    try:
        deadline = time.monotonic() + max(1.0, timeout_seconds - ASK_MARGIN_SECONDS)
        while True:
            state = gate_core.challenge_state(ask.cid)
            if state != "pending" or ask.cancelled.is_set() or time.monotonic() >= deadline:
                break
            ask.cancelled.wait(ASK_POLL_SECONDS)
        if state == "approved" and not ask.cancelled.is_set():
            problems = _verify(ask)
            if not problems and gate_core.consume_approval(
                    ask.cid, ask.sha, kind=gate_core.HERMES_KIND,
                    consumed_by="hermes approval transport"):
                _finish(ask, "✓ Approved with your passkey. Running it once:")
                return True
            logger.warning("passkey-gate: approval for a Hermes prompt did not verify: %s",
                           "; ".join(problems) or "already used")
            gate_core.withdraw_challenge(ask.cid, "approval did not verify")
            _finish(ask, "✗ That approval didn't verify against your pinned passkey. Not run:")
            return False
        if state == "denied":
            _finish(ask, "✗ Denied. Not run:")
            return False
        gate_core.withdraw_challenge(
            ask.cid, "Hermes stopped waiting" if ask.cancelled.is_set() else "no answer in time")
        _finish(ask, "⌛ No passkey approval in time. Not run:")
        return False
    except Exception:
        logger.exception("passkey-gate: waiting for a passkey approval failed; refusing")
        try:
            gate_core.withdraw_challenge(ask.cid, "wait failed")
        except Exception:
            pass
        return False


def present(request):
    """Hermes approval-transport callback."""
    once_allowed = "once" in getattr(request, "allowed_choices", ())
    if once_allowed and _take(request.command):
        return request.respond("once")
    rid = str(getattr(request, "request_id", "") or "")
    with _lock:
        ask = _asks.get(rid)
        if ask is not None:
            ask.started = True
    if ask is None:
        raise NotCovered("no passkey approval covers this command; using Hermes's own prompt")
    approved = False
    try:
        # this worker thread has lost the session's profile: use the data
        # folder begin_ask resolved, not whatever resolves here
        with gate_core.using_data_dir(ask.data_dir):
            if once_allowed:
                approved = _decide(ask, float(getattr(request, "timeout_seconds", 300) or 300))
            else:  # nothing a signature could grant: don't leave the request open
                gate_core.withdraw_challenge(ask.cid, "Hermes did not offer a single-use approval")
                _finish(ask, "✗ Hermes didn't offer a one-off approval for this. Not run:")
    finally:
        with _lock:
            if ask.line is None:
                ask.line = "✗ Not run:"
            if ask.closed:  # Hermes gave up earlier and end_ask already ran
                _asks.pop(rid, None)
    return request.respond("once" if approved else "deny")


def end_ask(request_id) -> None:
    """post_approval_response: Hermes has stopped waiting on this request.
    A wait still running is cancelled; a request present() never picked up
    is withdrawn here."""
    rid = str(request_id or "")
    with _lock:
        ask = _asks.get(rid)
        if ask is None:
            return
        line, waiting = ask.line, ask.started and ask.line is None
        ask.cancelled.set()
        ask.closed = True
        if not waiting:
            _asks.pop(rid, None)
    if line is None:
        line = "⌛ Hermes stopped waiting. Not run:"
        if not waiting:  # present() never picked it up: withdraw it here
            try:
                with gate_core.using_data_dir(ask.data_dir):
                    gate_core.withdraw_challenge(ask.cid, "Hermes never waited on it")
            except Exception:
                pass
    _update_message(ask, line)


def clear() -> None:
    with _lock:
        _credits.clear()
        _asks.clear()


def set_hermes_cover(on: bool) -> tuple[bool, str]:
    """Select (or deselect) this transport in the active Hermes profile's
    config, through Hermes's own `hermes config set` code path. Turning it
    on always sets transport_fallback: builtin too, since without it Hermes
    would deny every prompt the passkey didn't cover."""
    try:
        import contextlib
        import io
        from hermes_cli.config import set_config_value
    except Exception:
        return False, "this Hermes can't be configured from here; edit config.yaml by hand"
    changes = ([("security.approval.transport_fallback", "builtin"),
                ("security.approval.transport", TRANSPORT_NAME)] if on else
               [("security.approval.transport", "builtin")])
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            for key, value in changes:
                set_config_value(key, value)
    except SystemExit:
        return False, "Hermes refused the change: " + (out.getvalue().strip() or "no reason given")
    except Exception as exc:
        return False, f"could not write the Hermes config ({type(exc).__name__}: {exc})"
    state = hermes_selection()
    if bool(state.get("selected")) != on:
        return False, "the Hermes config didn't take the change: " + state.get("note", "")
    return True, state.get("note", "")


def hermes_selection(every_prompt: bool = False) -> dict:
    """What Hermes's config says about approval transports, for `status`.
    ``every_prompt`` is the gate's own passkey_hermes_prompts setting."""
    try:
        from hermes_cli.config import load_config_readonly
        cfg = ((load_config_readonly() or {}).get("security") or {}).get("approval") or {}
    except Exception:
        return {"selected": None, "note": "Hermes config not readable from here"}
    selected = str(cfg.get("transport") or "builtin").strip().lower()
    fallback = str(cfg.get("transport_fallback") or "").strip().lower()
    out = {"selected": selected == TRANSPORT_NAME, "transport": selected,
           "transport_fallback": fallback or "deny"}
    if selected != TRANSPORT_NAME:
        out["note"] = ("off: a passkey-approved command may still get Hermes's own prompt. "
                       f"Set security.approval.transport: {TRANSPORT_NAME} and "
                       "transport_fallback: builtin to turn it on")
    elif fallback != "builtin":
        out["note"] = ("WARNING: transport_fallback is not 'builtin', so every Hermes "
                       "approval prompt the passkey didn't cover is DENIED instead of shown")
    else:
        out["note"] = "on: a passkey approval also answers Hermes's prompt for that exact command"
    out["every_flagged_command"] = bool(every_prompt)
    if every_prompt:
        mode = str(_hermes_approvals().get("mode") or "").strip().lower()
        out["approvals_mode"] = mode or "unknown"
        if selected != TRANSPORT_NAME:
            out["note"] = ("WARNING: passkey_hermes_prompts is on, but passkey-gate isn't Hermes's "
                           "approval transport, so it has no effect. Set security.approval.transport: "
                           f"{TRANSPORT_NAME} (or run setup)")
        else:
            out["note"] = ("on: every command Hermes flags needs your passkey; the link is posted in "
                           "the chat. " + ("Where it can't be delivered (the classic terminal client), "
                                           "Hermes's own prompt is used." if fallback == "builtin" else
                                           "Where it can't be delivered, the command is denied."))
            if mode != "manual":
                out["warning"] = (f"Hermes approvals.mode is {mode or 'unset'!r}, not 'manual': Hermes can "
                                  "approve or skip flagged commands without asking you, and those never "
                                  "reach your passkey. Run: hermes config set approvals.mode manual")
    return out
