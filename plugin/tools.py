"""Tool handlers + enforcement logic.

Handlers follow Hermes plugin rules: (args: dict, **kwargs) -> JSON string,
never raise, same JSON shape on error. The enforcement pieces
(`authority_matches`, `hook_verdict`) are shared with the pre_tool_call hook
in __init__.py and tested directly.
"""
import json
import re
import time
import urllib.request

from . import gate_core, local_verify

# Where gate_core keeps its mutable module-level configuration


def _origin() -> str:
    return gate_core.origin()


def _base_url() -> str:
    return _origin().rstrip("/")


def gate_challenge(args: dict, **kwargs) -> str:
    text = args.get("action_text")
    requester = args.get("requester") or "unknown"
    tool_call = args.get("tool_call") or None
    owner = args.get("requester_owner")
    why = args.get("why")
    parent = args.get("parent_approval")
    cross_human = bool(owner) and owner.strip().lower() != requester.strip().lower()
    parent = parent if isinstance(parent, dict) else None
    if parent and not str(parent.get("owner") or "").strip():
        return json.dumps({"ok": False, "error":
                           "parent_approval needs an `owner`: which human signed the prior "
                           "approval — a chain without a name on each link is just a claim"})
    if cross_human and not why:
        return json.dumps({"ok": False, "error":
                           f"you named a different owner ({owner!r}), so the signer may be a "
                           "stranger to your project: write `why` — one plain sentence for THEM "
                           "saying what signing enables and why it is safe"})
    if not tool_call:
        # Approval-confusion fix: with enforcement on, prose that matches an
        # authority pattern must not be signable without the exact call it
        # covers — the human approves the bound tool call, not the prose.
        try:
            from . import cli  # same config cache path the pre_tool_call hook uses
            cfg = cli.apply_config_safe()
        except Exception:
            cfg = {}
        if cfg.get("require_passkey"):
            for pat in cfg.get("patterns") or []:
                try:
                    if re.search(pat, text or ""):
                        return json.dumps({"ok": False, "error": (
                            f"enforcement is on and this action matches an authority "
                            f"pattern ({pat!r}), but no tool_call was supplied. Pass the "
                            "exact tool_call you intend to run, shaped "
                            "{'tool': <name>, 'args': <the same args object>}: the human "
                            "approves, and the hook enforces, the bound tool call — "
                            "not the prose.")})
                except re.error:
                    continue
    try:
        c = gate_core.create_challenge(text, requester, tool_call,
                                       requester_owner=owner, why=why,
                                       parent_approval=parent)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc)})
    out = {"ok": True, **c}
    if cross_human:
        out["instructions"] = (
            "You are asking ANOTHER HUMAN (not your own). Send the approval URL to them "
            "via their channel with: who you are and who your human is (" + (owner or "?") +
            "), the plain-English `why`, and what it costs/changes. The page shows all of "
            "this; your message adds one line, not the whole spec. If another human already "
            "signed, say so with their name. Then gate_verify with challenge_id and the "
            "same action_text before acting — verified:true or nothing."
        )
    else:
        out["instructions"] = (
            "Send the human the approval URL and one line saying what it approves. "
            "They see the full action text on the page before signing. Then "
            "gate_verify with challenge_id and the same action_text before acting."
        )
    if c.get("url") is None:
        out["error_hint"] = "gate origin is not configured — set plugins.entries.passkey-gate.settings.origin"
    return json.dumps(out)


def gate_verify(args: dict, **kwargs) -> str:
    cid = args.get("challenge_id") or ""
    text = args.get("action_text") or ""
    wait_s = min(max(int(args.get("wait_seconds") or 0), 0), 120)
    max_age = args.get("max_age")

    if not cid or not text:
        return json.dumps({"ok": False, "error": "challenge_id and action_text required"})
    if not (_base_url().startswith("https://") or _base_url().startswith("http://")):
        return json.dumps({"ok": False,
                           "error": "gate origin not configured — set plugins.entries.passkey-gate.settings.origin"})

    base = _base_url()
    sha = hashlib_sha256(text)
    deadline = time.time() + wait_s
    last: dict = {"status": "no-gate"}
    while True:
        rec = _fetch_verify(base, cid, sha)
        last = rec if isinstance(rec, dict) else {"status": "error"}
        st = last.get("status")
        if st in ("approved", "denied", "expired") or time.time() >= deadline:
            break
        time.sleep(2)
    if last.get("status") == "approved":
        rec = last
        pinned = local_verify.pinned(gate_core.data_dir())
        problems = local_verify.check(rec, text, _origin(), gate_core.rp_id(), pinned, max_age)
        if pinned is None:
            problems.append(
                "no owner key pinned yet — pin it out of band with "
                "'hermes passkey-gate pin <pem-file>' before trusting approvals"
            )
        binding_note = None
        if rec.get("binding_sha256"):
            binding_note = "challenge is bound to a specific canonical tool call"
        out = {"ok": True, "verified": not problems, "problems": problems,
               "challenge_id": cid, "action_sha256": rec.get("action_sha256"),
               "approved_at": rec.get("approved_at"),
               "binding_sha256": rec.get("binding_sha256"),
               "binding_note": binding_note,
               "audit_head": rec.get("audit_head")}
        if rec.get("tool_call"):
            # tell the caller exactly what the approval covers, so it can
            # confirm the call it is about to make is the one that was bound
            try:
                out["bound_tool_call"] = json.loads(rec["tool_call"])
            except (TypeError, ValueError):
                out["bound_tool_call"] = rec["tool_call"]
        return json.dumps(out)
    return json.dumps({"ok": True, "verified": False, "status": last.get("status", "error"),
                       "challenge_id": cid})


def gate_status(args: dict, **kwargs) -> str:
    out = {"ok": True}
    base = _base_url()
    out["gate"] = _fetch_health(base)
    out["rp_id"] = gate_core.rp_id()
    out["origin_configured"] = bool(_origin())
    out["backends_detected"] = _detect_backends()
    out["owner_key_pinned"] = local_verify.pinned(gate_core.data_dir()) is not None
    if args.get("audit_check", True):
        out["audit"] = gate_core.audit_verify()
    return json.dumps(out)


def _detect_backends():
    try:
        from . import expose
        return expose.detect_backends()
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------- helpers
def hashlib_sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


def _fetch_verify(base: str, cid: str, sha: str):
    url = f"{base}/verify/{cid}?action_sha256={sha}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read())
    except Exception as exc:
        return {"status": "error", "error": f"gate not reachable: {type(exc).__name__}"}


def _fetch_health(base: str):
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=8) as r:
            return json.loads(r.read())
    except Exception as exc:
        return {"status": "unreachable", "error": f"{type(exc).__name__}"}


# ---------------------------------------------------------------- enforcement
def canonical_for_hook(tool_name: str, args) -> str:
    """The exact string the challenge binding hashes. Deterministic key order,
    compact separators — both the challenge minter and this hook call IT."""
    return json.dumps({"tool": tool_name, "args": args}, sort_keys=True, separators=(",", ":"))


def authority_matches(patterns, tool_name: str, args) -> re.Match | None:
    subject = tool_name + " " + canonical_for_hook(tool_name, args)
    for pat in patterns or []:
        try:
            if re.search(pat, subject):
                return pat
        except re.error:
            continue
    return None


def hook_verdict(tool_name: str, args, patterns, require_passkey: bool) -> dict | None:
    """pre_tool_call directive: block until this exact call is passkey-approved.

    Never approves anything itself — fail closed. Returns None when no
    pattern matches (or enforcement is off), letting Hermes's own approval
    system do whatever it would do anyway.
    """
    if not require_passkey:
        return None
    matched = authority_matches(patterns, tool_name, args)
    if matched is None:
        return None
    binding = gate_core.sha256_hex(canonical_for_hook(tool_name, args))
    row = gate_core.pending_for_binding(binding)
    if row is None:
        return {"action": "block", "message": (
            "Passkey gate: this tool call matches an authority pattern, but no "
            f"approved passkey challenge covers it (pattern: {matched}). "
            "Call gate_challenge first with action_text describing EXACTLY this "
            f"action and tool_call set to {json.dumps({'tool': tool_name, 'args': args})}, "
            "send the human the approval URL, wait for their passkey signature, "
            "then retry this identical tool call verbatim. If you disagree that "
            "this requires an approval, say so instead of trying to retry it."
        )}
    gate_core.consume(row["id"], binding)
    # allow = no block directive; the challenge is consumed and audited
    return None
