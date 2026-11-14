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
"""
import threading
import time

TRANSPORT_NAME = "passkey-gate"
CREDIT_TTL_SECONDS = 30.0

_lock = threading.Lock()
_credits: dict[str, list[float]] = {}  # prompt text -> expiry times, one per credit


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


def present(request):
    """Hermes approval-transport callback."""
    if "once" in getattr(request, "allowed_choices", ()) and _take(request.command):
        return request.respond("once")
    raise NotCovered("no passkey approval covers this command; using Hermes's own prompt")


def clear() -> None:
    with _lock:
        _credits.clear()


def hermes_selection() -> dict:
    """What Hermes's config says about approval transports, for `status`."""
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
    return out
