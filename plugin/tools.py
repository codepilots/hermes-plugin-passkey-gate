"""Tool handlers + enforcement logic.

Handlers follow Hermes plugin rules: (args: dict, **kwargs) -> JSON string,
never raise, same JSON shape on error. The enforcement pieces
(`authority_matches`, `hook_verdict`) are shared with the pre_tool_call hook
in __init__.py and tested directly.
"""
import json
import logging
import re
import time

from . import gate_core, local_verify, netfetch

logger = logging.getLogger(__name__)

# Where gate_core keeps its mutable module-level configuration


def _origin() -> str:
    return gate_core.origin()


def _base_url() -> str:
    return _origin().rstrip("/")


def _pinned_owner_problems(row) -> str | None:
    """None when the approved challenge row verifies locally against the
    pinned owner key; otherwise a short reason. Never raises."""
    try:
        pinned = local_verify.pinned(gate_core.data_dir())
        if pinned is None:
            return ("no owner key is pinned — run 'hermes passkey-gate setup' (or 'hermes passkey-gate pin --code <code from your phone>')")
        rec = gate_core.challenge_status(row["id"], row["action_sha256"])
        problems = local_verify.check(dict(rec), row["action_text"], gate_core.origin(),
                                      gate_core.rp_id(), pinned)
        # check() proved the signature covers row["challenge"]; the nonce
        # must in turn commit to the binding being executed
        if row["binding_sha256"] and not gate_core.challenge_covers_binding(
                row["challenge"], row["binding_sha256"]):
            problems.append("the signed challenge does not cover this tool-call binding")
        return "; ".join(problems) if problems else None
    except Exception as exc:
        return f"local verification failed ({type(exc).__name__})"


def _stored_call_matches(row, tool_name, args, binding) -> bool:
    """The row's stored canonical call re-hashes to binding and equals this call."""
    try:
        stored = gate_core.canonical_binding_json(json.loads(row["tool_call"]))
    except (TypeError, ValueError, KeyError):
        return False
    return stored == canonical_for_hook(tool_name, args) and gate_core.sha256_hex(stored) == binding


def gate_challenge(args: dict, **kwargs) -> str:
    text = args.get("action_text")
    requester = args.get("requester") or "unknown"
    tool_call = args.get("tool_call") or None
    owner = args.get("requester_owner")
    why = args.get("why")
    parent = args.get("parent_approval")
    bad = [k for k, v in (("requester", requester), ("requester_owner", owner), ("why", why))
           if v is not None and not isinstance(v, str)]
    if bad:
        return json.dumps({"ok": False, "error": f"{', '.join(bad)} must be a string"})
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
        if cfg.get("_config_error"):
            # finding 17: with the config unreadable the gate cannot judge
            # pattern matches, so it will not mint a signable prose-only
            # challenge that enforcement cannot evaluate
            return json.dumps({"ok": False, "error": (
                f"passkey-gate configuration failed to load ({cfg['_config_error']}) — "
                "the gate cannot tell whether this action matches an authority "
                "pattern, so it will not mint a prose-only challenge. Tell the "
                "human to fix the passkey-gate settings; the gate reloads them "
                "automatically once they parse. A challenge bound to an exact "
                "tool_call can still be minted.")})
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
                except (re.error, TypeError):
                    # finding 22: same defense in depth as authority_matches —
                    # a pattern smuggled past cmd_set's validation is skipped
                    # as non-matching and logged; the handler answers, never
                    # raises, whatever sits in the pattern list
                    logger.warning("passkey-gate: authority pattern %r is unusable "
                                   "(out-of-band edit past cmd_set's validation?) — "
                                   "treating it as non-matching", pat)
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
        out["error_hint"] = ("the gate has no HTTPS address yet, so this request has no link — "
                             "ask the human to run 'hermes passkey-gate setup'")
    return json.dumps(out)


def _local_audit_head():
    try:
        return gate_core.audit_head()
    except Exception:
        return None


def gate_verify(args: dict, **kwargs) -> str:
    cid = args.get("challenge_id") or ""
    text = args.get("action_text") or ""
    if not isinstance(cid, str) or not isinstance(text, str):
        return json.dumps({"ok": False, "error": "challenge_id and action_text must be strings"})
    # the gate signs the STRIPPED text (create_challenge strips it), so verify
    # the same bytes — a trailing newline must not fail a genuine approval
    text = text.strip()
    try:
        wait_s = min(max(int(args.get("wait_seconds") or 0), 0), 120)
    except (TypeError, ValueError):
        return json.dumps({"ok": False, "error": "wait_seconds must be an integer (0-120)"})
    max_age = args.get("max_age")

    if not cid or not text:
        return json.dumps({"ok": False, "error": "challenge_id and action_text required"})
    # Claims issue 3 (finding 23's rule): gate URLs are PARSED, never
    # prefix-checked — the same rule cmd_set enforces. The old
    # startswith('http://'/'https://') check let credential-carrying,
    # hostless, and non-https origins through to a fetch.
    try:
        netfetch.parse_gate_origin(_base_url())
    except ValueError:
        return json.dumps({"ok": False,
                           "error": "gate origin is not configured or is not a valid gate origin "
                           "(https; loopback http tolerated for dev) — set "
                           "plugins.entries.passkey-gate.settings.origin"})

    base = _base_url()
    sha = hashlib_sha256(text)
    deadline = time.time() + wait_s
    last: dict = {"status": "no-gate"}
    while True:
        rec = _fetch_verify(base, cid, sha)
        last = rec if isinstance(rec, dict) else {"status": "error"}
        st = last.get("status")
        if st in ("approved", "consumed", "denied", "expired") or time.time() >= deadline:
            break
        time.sleep(2)
    if last.get("status") == "approved":
        rec = last
        pinned = local_verify.pinned(gate_core.data_dir())
        problems = local_verify.check(rec, text, _origin(), gate_core.rp_id(), pinned, max_age)
        if pinned is None:
            problems.append(
                "no owner key is pinned yet — run 'hermes passkey-gate setup' (or 'hermes passkey-gate pin --code <code from your phone>') before trusting approvals"
            )
        binding_note = None
        approved_tool_call = None
        canonical_tool_call = None
        # /verify deliberately omits binding metadata (finding 27). For the
        # local gate's own agent-facing helper, recover the bound call from the
        # local DB instead of widening the public parent-record contract.
        local_row = gate_core.db().execute(
            "select binding_sha256, tool_call, challenge from challenges "
            "where id=? and action_sha256=? and status='approved'",
            (cid, rec.get("action_sha256"))).fetchone()
        if local_row is not None and not gate_core.record_matches_local_challenge(
                rec, local_row["challenge"]):
            # v0.7 review A29: the record must carry the nonce stored here
            problems.append("the approval record's challenge differs from the one this gate issued")
        if local_row is not None and local_row["tool_call"]:
            binding_note = "challenge is bound to a specific canonical tool call"
            try:
                approved_tool_call = json.loads(local_row["tool_call"])
                canonical_tool_call = gate_core.canonical_binding_json(approved_tool_call)
            except (TypeError, ValueError):
                problems.append("approved tool call record is malformed")
        approved_binding = local_row["binding_sha256"] if local_row is not None else None
        if approved_binding:
            signed = local_verify._b64u_or_none(rec.get("challenge_b64url"))
            if not gate_core.challenge_covers_binding(signed, approved_binding):
                problems.append("the signed challenge does not cover the bound tool call")
        requested_tool_call = args.get("tool_call")
        if requested_tool_call is not None:
            if not isinstance(requested_tool_call, dict):
                problems.append("requested tool_call must be an object")
            elif approved_tool_call is None:
                problems.append("approval has no bound tool call")
            else:
                requested_canonical = gate_core.canonical_binding_json(requested_tool_call)
                if (requested_canonical != canonical_tool_call or
                        gate_core.sha256_hex(requested_canonical) != approved_binding):
                    problems.append("requested tool call does not match the approved tool call")
        out = {"ok": True, "verified": not problems, "problems": problems,
               "challenge_id": cid, "action_sha256": rec.get("action_sha256"),
               "approved_at": rec.get("approved_at"),
               "binding_sha256": approved_binding,
               "binding_note": binding_note,
               # /verify no longer returns the head (finding 27 minimization);
               # report this gate's own audit head instead of a constant null
               "audit_head": _local_audit_head(),
               # Contract for callers and for a downstream dispatcher: this is
               # the exact canonical payload whose hash was approved. The
               # plugin cannot enforce that a later executor uses it.
               "approved_tool_call": approved_tool_call,
               "dispatch_binding": ({"canonical_tool_call": canonical_tool_call,
                                     "binding_sha256": approved_binding}
                                    if canonical_tool_call is not None else None)}
        if approved_tool_call is not None:
            # Keep the legacy name for compatibility with existing callers.
            out["bound_tool_call"] = approved_tool_call
            out["dispatch_note"] = (
                "Run approved_tool_call exactly: the same tool and the same args, "
                "nothing added or removed (not even a timeout or working directory). "
                "Any difference is a different call, and the gate will block it.")
        return json.dumps(out)
    out = {"ok": True, "verified": False, "status": last.get("status", "error"),
           "challenge_id": cid}
    if last.get("status") == "consumed":
        # finding 10: a spent approval reports BOTH stamps — when the human
        # approved it and when the execution consumed it
        out["approved_at"] = last.get("approved_at")
        out["consumed_at"] = last.get("consumed_at")
    return json.dumps(out)


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
        with netfetch.open_no_redirect(url, timeout=10) as r:
            return json.loads(netfetch.read_capped(r))
    except Exception as exc:
        return {"status": "error", "error": f"gate not reachable: {type(exc).__name__}"}


def gate_unreachable_reason(base: str, exc: Exception | None = None) -> dict:
    """Plain-English reason the gate could not be reached, plus the next
    step — what a first-time operator (or a judge) sees from `status`."""
    if not base:
        return {"error": "origin not configured",
                "next_step": "run 'hermes passkey-gate expose' (tailscale) or "
                             "'hermes passkey-gate set origin https://<your-host>'"}
    out = _unreachable_text(base, exc)
    if exc is not None:
        out["error_type"] = type(exc).__name__
    return out


def _unreachable_text(base: str, exc) -> dict:
    import socket
    import ssl
    import urllib.error
    reason = getattr(exc, "reason", exc)
    if isinstance(exc, netfetch.RedirectBlocked):
        return {"error": f"the gate at {base} tried to redirect, and redirects are refused",
                "next_step": "point the origin straight at passkey-gate (no redirecting proxy)"}
    if isinstance(exc, urllib.error.HTTPError):
        return {"error": f"the gate at {base} answered HTTP {exc.code}",
                "next_step": "check that the origin points at passkey-gate, not another service"}
    if isinstance(reason, ConnectionRefusedError):
        return {"error": f"nothing is listening at {base}",
                "next_step": ("start the gate: 'hermes passkey-gate service start' (or "
                              "'service install' / 'serve' if it isn't set up yet)")}
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return {"error": f"timed out reaching {base}",
                "next_step": "check the gate is running and the tailscale serve rule exists"}
    if isinstance(reason, ssl.SSLError):
        return {"error": f"TLS failed for {base} ({reason})",
                "next_step": "check the HTTPS terminator (tailscale serve) for this origin"}
    if isinstance(reason, socket.gaierror):
        return {"error": f"cannot resolve the host in {base}",
                "next_step": "check the origin's hostname (is this machine on the tailnet?)"}
    if isinstance(exc, ValueError):
        return {"error": f"origin {base!r} is not a valid gate origin ({exc})",
                "next_step": "set an https origin: 'hermes passkey-gate set origin https://<host>'"}
    return {"error": f"could not reach {base} ({type(exc).__name__}: {reason})",
            "next_step": "check 'hermes passkey-gate serve' is running and the origin is right"}


def _fetch_health(base: str):
    try:
        with netfetch.open_no_redirect(f"{base}/health", timeout=8) as r:
            return json.loads(netfetch.read_capped(r, 65536))
    except Exception as exc:
        return {"status": "unreachable", **gate_unreachable_reason(base, exc)}


# ---------------------------------------------------------------- enforcement
# Finding 22: bounds on operator authority patterns. A pattern that cannot
# compile, is not a string, or is enormous has no business in the match path:
# it either throws at match time (fail-closed but opaque), silently matches
# far more than intended, or widens the catastrophic-backtracking (ReDoS)
# surface. Per the review this is deliberately a compile check plus caps,
# NOT a ReDoS detector: nested-quantifier shapes (e.g. `(a+)+$`) are the
# operator's own responsibility — the caps bound what a persisted pattern
# can cost to compile and how much of it the hook ever echoes.
MAX_PATTERN_LEN = 200        # chars per authority pattern
MAX_PATTERN_COUNT = 100      # patterns in the list
PATTERN_DISPLAY_CAP = 120    # chars of a pattern echoed into a block message


def validate_authority_patterns(patterns):
    """Finding 22: every reason an authority_patterns value must not be
    persisted; an empty list means the value is sound. Runs at `set` time
    BEFORE the finding-16 weakening classification — so an invalid pattern
    can never hide behind (or trip) the approval machinery — and a bad list
    is refused WHOLE: a list is only ever stored complete and sound."""
    if not isinstance(patterns, (list, tuple)):
        return [f"authority_patterns must be a list, got {type(patterns).__name__}"]
    problems = []
    if len(patterns) > MAX_PATTERN_COUNT:
        problems.append(f"the list has {len(patterns)} patterns; the cap is {MAX_PATTERN_COUNT}")
    for i, pat in enumerate(patterns):
        if not isinstance(pat, str):
            problems.append(f"patterns[{i}] is not a string but {type(pat).__name__}")
            continue
        if len(pat) > MAX_PATTERN_LEN:
            problems.append(f"patterns[{i}] is {len(pat)} chars; the cap is {MAX_PATTERN_LEN}")
            continue
        try:
            re.compile(pat)
        except re.error as exc:
            problems.append(f"patterns[{i}] does not compile as a regex: {exc}")
    return problems


# v0.7 review L15: Python's re has no timeout, so a catastrophically
# backtracking pattern would stall the hook. At `set` time each pattern is run
# against long, awkward inputs in a separate process that is killed if it
# takes too long.
SLOW_PATTERN_LIMIT_S = 2.0
_PROBE_SCRIPT = r"""
import json, re, sys
pats = json.load(sys.stdin)
bases = ["a" * 2000 + "!", " " * 2000 + "!", "a " * 1000 + "!", "x-" * 1000 + "!",
         "\\" * 2000 + "!", "/" * 2000 + "!", "." * 2000 + "!",
         '{"command":"' + "a" * 2000 + '"}!', "x" * 2000 + "!", "0" * 2000 + "!"]
probes = bases + ["terminal " + b for b in bases]
for i, p in enumerate(pats):
    rx = re.compile(p)
    for s in probes:
        rx.search(s)
    print(i, flush=True)
"""


def slow_patterns(patterns) -> list:
    """Patterns that take too long on long inputs (with their index)."""
    import subprocess
    import sys
    if not isinstance(patterns, (list, tuple)) or not patterns:
        return []
    try:
        r = subprocess.run([sys.executable, "-I", "-c", _PROBE_SCRIPT], input=json.dumps(list(patterns)),
                           capture_output=True, text=True, timeout=SLOW_PATTERN_LIMIT_S)
        return [] if r.returncode == 0 else [f"could not be checked ({r.stderr.strip()[-200:]})"]
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        done = len((out.decode() if isinstance(out, bytes) else out).split())
        i = min(done, len(patterns) - 1)
        return [f"patterns[{i}] {patterns[i]!r}"]


def render_pattern(pat, index: int) -> str:
    """Finding 22: the ONLY way a matched authority pattern may appear in a
    block message — a stable rule ID (its position in the configured list,
    the reference `hermes passkey-gate get` shows) plus the pattern itself
    as length-capped, backtick-fenced DATA, never free prose. The pattern is
    operator config, but config can be edited out of band, so the fence
    cannot be broken open: backticks are escaped and control characters
    collapsed, so nothing in the echo can read as an instruction aimed at
    the agent, and the cap keeps a huge pattern from flooding the message."""
    text = str(pat)
    if len(text) > PATTERN_DISPLAY_CAP:
        text = text[:PATTERN_DISPLAY_CAP] + "…"
    text = (text.replace("\\", "\\\\").replace("`", "\\`")
            .replace("\r", " ").replace("\n", " ").replace("\t", " "))
    return f"rule authority_patterns[{index}]: `{text}`"


def canonical_for_hook(tool_name: str, args) -> str:
    """The exact string the challenge binding hashes. Deterministic key order,
    compact separators — both the challenge minter and this hook call IT."""
    return json.dumps({"tool": tool_name, "args": args}, sort_keys=True, separators=(",", ":"))


def _string_values(value, depth=0):
    """Every string inside a tool call's arguments, in a stable order."""
    if depth > 20:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k in sorted(value, key=str) for s in _string_values(value[k], depth + 1)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _string_values(v, depth + 1)]
    return []


def authority_matches(patterns, tool_name: str, args) -> tuple[int, str] | None:
    """First authority pattern matching this exact call, as (rule_index,
    pattern) — the index is the stable rule ID the block message shows.
    Finding 22: a pattern that reached config without cmd_set's set-time
    validation (an out-of-band edit) must neither crash the hook nor turn
    into an opaque block: it is skipped as non-matching and logged."""
    subject = tool_name + " " + canonical_for_hook(tool_name, args)
    # v0.7 review M2: patterns also run over the DECODED argument values
    # (real newlines and tabs, unescaped quotes and non-ASCII), so `\b`,
    # `\s` and literal quotes behave as operators expect. This can only add
    # matches, never remove one the JSON form would have made.
    decoded = tool_name + " " + " ".join(_string_values(args))
    for i, pat in enumerate(patterns or []):
        try:
            if re.search(pat, subject) or re.search(pat, decoded):
                return i, pat
        except (re.error, TypeError):
            logger.warning("passkey-gate: authority pattern %r (rule %d) is unusable "
                           "(out-of-band edit past cmd_set's validation?) — "
                           "treating it as non-matching", pat, i)
            continue
    return None


HINT_VALUE_CAP = 80


def _short(value) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return text if len(text) <= HINT_VALUE_CAP else text[:HINT_VALUE_CAP] + "…"


def near_miss_hint(tool_name: str, args) -> str | None:
    """Explain a block when the agent HOLDS an approval for this tool whose
    arguments differ from the call it just made — e.g. the model added
    `timeout: 60` when running a command it got signed without one, so the
    binding hash differs and nothing covers the call (8 Nov field incident).

    Purely diagnostic: names the differing top-level arguments and repeats the
    approved call so the agent can retry it verbatim. Never allows anything.
    Only offered when the approval shares at least one identical argument with
    this call (otherwise it is a different action, not a near miss). Never
    raises."""
    try:
        if not isinstance(args, dict):
            return None
        best = None
        for row in gate_core.approved_unconsumed_tool_calls():
            try:
                approved = json.loads(row["tool_call"])
            except (TypeError, ValueError):
                continue
            if not isinstance(approved, dict) or approved.get("tool") != tool_name:
                continue
            a_args = approved.get("args")
            if not isinstance(a_args, dict):
                continue
            keys = set(a_args) | set(args)
            differing = sorted((k for k in keys if a_args.get(k, ...) != args.get(k, ...)), key=str)
            same = [k for k in keys if k in a_args and k in args and a_args[k] == args[k]]
            if not differing or not same:
                continue
            if best is None or len(differing) < len(best[1]):
                best = (approved, differing)
        if best is None:
            return None
        approved, differing = best
        a_args = approved["args"]
        parts = []
        for k in differing:
            if k not in a_args:
                parts.append(f"adds `{k}` = {_short(args[k])}")
            elif k not in args:
                parts.append(f"leaves out `{k}` = {_short(a_args[k])}")
            else:
                parts.append(f"changes `{k}` (approved: {_short(a_args[k])}, this call: {_short(args[k])})")
        return (
            "Passkey gate: you hold a passkey approval for a `" + tool_name + "` call, but "
            "this call is not the one the human signed — it " + "; ".join(parts) + ". "
            "The approval covers only the exact arguments signed; any added, missing or "
            "changed argument (even a timeout or working directory) is a different call. "
            "Retry with exactly the approved call, nothing added or removed: "
            f"{json.dumps(approved, ensure_ascii=False)}. "
            "If you really need the different arguments, request a fresh approval via "
            "gate_challenge with tool_call set to exactly the call you will run.")
    except Exception:
        return None


def hook_verdict(tool_name: str, args, patterns, require_passkey: bool) -> dict | None:
    """pre_tool_call directive: block until this exact call is passkey-approved.

    Never approves anything itself — fail closed: if anything in the verdict
    path raises, the call is BLOCKED, never allowed. Returns None only when
    enforcement is off, no pattern matches, or THIS call atomically won the
    claim on an approved, unconsumed, unexpired challenge (single use).
    """
    if not require_passkey:
        return None
    try:
        matched = authority_matches(patterns, tool_name, args)
        if matched is None:
            return None
        rule_index, matched_pattern = matched
        binding = gate_core.sha256_hex(canonical_for_hook(tool_name, args))
        row = gate_core.pending_for_binding(binding)
        if row is None:
            hint = near_miss_hint(tool_name, args)
            if hint:
                return {"action": "block", "message": hint}
            return {"action": "block", "message": (
                "Passkey gate: this tool call matches an authority pattern, but no "
                "approved passkey challenge covers it (matched "
                f"{render_pattern(matched_pattern, rule_index)}). "
                "Call gate_challenge first with action_text describing EXACTLY this "
                f"action and tool_call set to {json.dumps({'tool': tool_name, 'args': args})}, "
                "send the human the approval URL, wait for their passkey signature, "
                "then retry this identical tool call verbatim. Do NOT reach the same "
                "effect another way (a reworded command, different flags, another tool, "
                "a script): that is a policy violation, whether or not the gate notices. "
                "If you disagree that this requires an approval, say so to the human."
            )}
        # Do not trust the indexed binding alone: the stored canonical payload
        # must itself hash to that binding. This catches a tampered/malformed
        # record before consumption and makes the hook's exact-call contract
        # explicit. Final dispatch still has to enforce the same contract.
        try:
            stored_call = json.loads(row["tool_call"])
            stored_canonical = gate_core.canonical_binding_json(stored_call)
            if (stored_canonical != canonical_for_hook(tool_name, args) or
                    gate_core.sha256_hex(stored_canonical) != binding or
                    row["binding_sha256"] != binding):
                return {"action": "block", "message": (
                    "Passkey gate: the approved bound tool call does not match this "
                    "exact call or its binding hash; refusing dispatch. Request a "
                    "fresh approval for the exact canonical tool call."
                )}
        except (TypeError, ValueError, KeyError):
            return {"action": "block", "message": (
                "Passkey gate: the approved bound tool call is malformed; refusing "
                "dispatch. Request a fresh approval."
            )}
        # The DB saying 'approved' is not proof: any credential registered on
        # this gate could have produced it. Re-verify the stored assertion
        # locally against the PINNED owner key — the same check gate_verify
        # and `set --approve` run — so an approval signed by an unpinned
        # (e.g. agent-registered software) credential never executes. A
        # failing row must not shadow a genuine one for the same call either:
        # fall through to any other approved row that does verify.
        pin_problem = _pinned_owner_problems(row)
        if pin_problem:
            for alt in gate_core.approved_for_binding(binding):
                if (alt["id"] != row["id"] and alt["binding_sha256"] == binding
                        and _stored_call_matches(alt, tool_name, args, binding)
                        and _pinned_owner_problems(alt) is None):
                    row, pin_problem = alt, None
                    break
        if pin_problem:
            return {"action": "block", "message": (
                "Passkey gate: this tool call has an approval on record, but it did "
                f"not verify against the pinned owner key ({pin_problem}); refusing "
                "dispatch. Only an approval signed by the human's pinned passkey can "
                "authorise this call — tell the human; do not retry.")}
        if not gate_core.consume(row["id"], binding):
            # Lost the claim race to an identical tool call, or the approval
            # aged past expires_at between lookup and claim. Either way this
            # call must not execute: one signature, one execution.
            return {"action": "block", "message": (
                "Passkey gate: the approval covering this exact tool call was "
                "already consumed or expired — request a fresh approval via "
                "gate_challenge and have the human sign it before retrying. "
                "A single signature authorises exactly one execution."
            )}
        # allow = no block directive; the challenge is consumed and audited
        return None
    except Exception as exc:
        return {"action": "block", "message": (
            f"Passkey gate: enforcement check failed ({type(exc).__name__}) — "
            "failing closed, the call is blocked. If this action is genuinely "
            "intended, request a fresh approval via gate_challenge."
        )}
