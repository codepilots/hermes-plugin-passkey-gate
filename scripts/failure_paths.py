"""Show what the gate says on each failure path an agent can hit.

Runs every path for real against a throwaway gate in a temporary folder,
with a software authenticator standing in for your phone. It never touches
your Hermes profile, your pinned key or the running gate service, and it
needs no phone and no network.

    python3 scripts/failure_paths.py            # every path
    python3 scripts/failure_paths.py verify     # only paths whose name contains "verify"
    python3 scripts/failure_paths.py --list

Any Python will do to start it: if that one lacks the project's packages,
the script carries on under the project's .venv.

Each path prints what was sent and exactly what the agent (or the chat)
gets back. Exits non-zero if a path did not produce the expected reply.
"""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
try:
    import pytest  # noqa: F401  (the test helpers below need it)
    import webauthn  # noqa: F401
except ModuleNotFoundError as exc:
    # Started with a Python that lacks the project's packages (plain
    # `python3`): carry on under the project's own environment if it exists.
    if VENV_PYTHON.exists() and Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]])
    sys.exit(f"{exc.name} is not installed for this Python. Set the project up first:\n"
             "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest\n"
             "then run: .venv/bin/python scripts/failure_paths.py")
sys.path.insert(0, str(ROOT / "tests"))
import conftest  # noqa: E402,F401  (loads the plugin as the package "passkey_gate")
import test_gate as t  # noqa: E402  (software authenticator and HTTP helpers)

os.environ["GATE_CHALLENGE_TTL"] = "600"

import passkey_gate  # noqa: E402
from passkey_gate import cli, gate_core, lanes, tools, transport  # noqa: E402

ACTION = t.ACTION
TOOL_CALL = t.TOOL_CALL
CMD = "rm -rf /srv/scratch-build"
BOLD, DIM, RED, GREEN, OFF = ("\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[0m") \
    if sys.stdout.isatty() else ("", "", "", "", "")
failed = []
PATHS = []


def path(name, title):
    def wrap(fn):
        PATHS.append((name, title, fn))
        return fn
    return wrap


def show(label, value):
    text = value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False)
    print(f"  {DIM}{label}{OFF}")
    for line in text.splitlines() or [""]:
        print(f"    {line}")


def reply(raw, keep=("ok", "verified", "status", "problems", "error", "error_code", "denied_reason",
                     "text_only_note", "parent_note", "wait_seconds_clamped_to", "next_step")):
    """The fields that matter, from a tool's JSON reply."""
    out = json.loads(raw) if isinstance(raw, str) else raw
    return {k: out[k] for k in keep if k in out}


def expect(condition, what):
    print(f"  {GREEN}✓{OFF} {what}" if condition else f"  {RED}✗ expected: {what}{OFF}")
    if not condition:
        failed.append(what)


def post(base, route, body: bytes, headers):
    req = urllib.request.Request(base + route, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# ------------------------------------------------------------------ the paths
@path("bridge-json", "The agent sends Hermes's tool_call bridge a mis-quoted `calls` string")
def bridge_json(base, phone):
    calls = ('[{"name": "gate_challenge", "arguments": {"action_text": "...", "tool_call": '
             '{"tool": "terminal", "args": {"command": "git commit -m "Add tracking""}}}}]')
    show("agent sent (calls, as a string)", calls)
    try:
        json.loads(calls)
        error = None
    except json.JSONDecodeError as e:
        error = f"tool_call 'calls' is not valid JSON: {e}"
    show("Hermes answers, before the gate is ever called", {"error": error})
    expect(error is not None, "Hermes rejects it; the gate's guidance is what steers the retry")
    desc = passkey_gate.schemas.GATE_CHALLENGE["parameters"]["properties"]["tool_call"]["description"]
    show("guidance the agent now reads in the gate_challenge schema", desc[desc.index("Pass a JSON object"):])


@path("text-only-mint", "The agent drops tool_call, you sign, and the approval can't run the call")
def text_only(base, phone):
    minted = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "bramble"}))
    show("gate_challenge without tool_call", reply(minted))
    expect("text_only_note" in minted, "the mint itself warns it is text-only")
    t.approve(base, phone, minted["challenge_id"])
    out = tools.gate_verify({"challenge_id": minted["challenge_id"], "action_text": ACTION,
                             "tool_call": TOOL_CALL})
    show("after you sign: gate_verify with the tool call", reply(out))
    expect("text-only" in json.loads(out).get("next_step", ""), "verify explains it and says to mint again")


@path("bad-binding", "The agent binds a tool_call no real call could match")
def bad_binding(base, phone):
    for bad in ({"tool": "terminal"}, {"tool": "terminal", "args": {"command": CMD}, "extra": True}):
        out = tools.gate_challenge({"action_text": ACTION, "requester": "bramble", "tool_call": bad})
        show(f"gate_challenge with tool_call {json.dumps(bad)}", reply(out))
        expect(json.loads(out).get("error_code") == "invalid_tool_call", "refused before anything is minted")


@path("mint-wording", "The agent's action text is too thin, or its parent approval is malformed or unlisted")
def mint_wording(base, phone):
    out = tools.gate_challenge({"action_text": "delete stuff", "requester": "bramble"})
    show("gate_challenge with action_text 'delete stuff'", reply(out))
    expect("until when" in json.loads(out).get("error", ""), "says what the text must contain")
    parent = {"base": "https://peer.example.ts.net", "owner": "Sorrel",
              "challenge_id": "A" * 32, "action_sha256": "0" * 64}
    out = tools.gate_challenge({"action_text": ACTION, "requester": "bramble",
                                "parent_approval": {**parent, "action_sha256": "abc"}})
    show("parent_approval with a malformed action_sha256", reply(out))
    expect("parent_approval.action_sha256" in json.loads(out).get("error", ""), "names the field and its format")
    out = tools.gate_challenge({"action_text": ACTION, "requester": "bramble", "parent_approval": parent})
    show("parent_approval from a gate that isn't on the allowlist", reply(out))
    expect("parent_note" in json.loads(out), "minted, with a note that it will show as unverified")


@path("missing-why", "The agent names its owner but gives no `why`")
def missing_why(base, phone):
    out = tools.gate_challenge({"action_text": ACTION, "requester": "bramble", "requester_owner": "Autumn"})
    show("gate_challenge", reply(out))
    expect(json.loads(out).get("error_code") == "why_required", "why_required, and nothing was minted")


@path("verify-wrong-text", "The agent rewords action_text when verifying")
def wrong_text(base, phone):
    c = t.new_challenge(base, tool_call=TOOL_CALL)
    t.approve(base, phone, c["challenge_id"])
    out = tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION + " Thanks."})
    show("gate_verify with slightly different text", reply(out))
    expect(json.loads(out).get("denied_reason") == "action_text_mismatch", "told it was the text, not a refusal")
    out = tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION})
    show("gate_verify with the minted text", reply(out))
    expect(json.loads(out).get("verified") is True, "the same approval still verifies")


@path("verify-unknown-id", "The agent verifies an id this gate never issued")
def unknown_id(base, phone):
    out = tools.gate_verify({"challenge_id": "A" * 32, "action_text": ACTION, "wait_seconds": 500})
    show("gate_verify with a made-up challenge_id and wait_seconds 500", reply(out))
    expect(json.loads(out).get("denied_reason") == "unknown_challenge", "told there is no such request")
    expect(json.loads(out).get("wait_seconds_clamped_to") == tools.MAX_WAIT_SECONDS, "told the wait was shortened")


@path("verify-refused", "You tap Deny on the approval page")
def refused(base, phone):
    c = t.new_challenge(base)
    t.call(base, f"/a/{c['challenge_id']}/deny", {})
    out = tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION})
    show("gate_verify", reply(out))
    expect(json.loads(out).get("denied_reason") == "refused", "reported as a real refusal")


@path("verify-bad-arguments", "gate_verify is called with missing or wrong arguments")
def bad_arguments(base, phone):
    for args in ({}, {"challenge_id": "abc", "action_text": ACTION, "wait_seconds": "a while"},
                 {"challenge_id": "abc", "action_text": ACTION, "max_age": -1}):
        out = tools.gate_verify(args)
        show(f"gate_verify({json.dumps(args)[:70]})", reply(out))
        expect(bool(json.loads(out).get("error_code")) and bool(json.loads(out).get("next_step")),
               "has an error_code and a next_step")


@path("hook-block", "The agent runs a command your patterns gate, with no approval")
def hook_block(base, phone):
    verdict = tools.hook_verdict("terminal", {"command": CMD}, [r"^terminal .*rm -rf"], True)
    show(f"pre_tool_call hook on: {CMD}", verdict)
    expect(verdict and verdict.get("action") == "block", "the call is blocked, with how to ask properly")


@path("hook-block-waiting", "The agent re-runs the command while its request is still unsigned")
def hook_block_waiting(base, phone):
    args = {"command": "rm -rf /srv/still-waiting"}
    c = t.new_challenge(base, tool_call={"tool": "terminal", "args": args})
    verdict = tools.hook_verdict("terminal", args, [r"^terminal .*rm -rf"], True)
    show("pre_tool_call hook, with a matching request pending", verdict)
    expect(c["challenge_id"] in verdict["message"] and "Do not mint again" in verdict["message"],
           "points at the waiting request instead of asking for another")


@path("http-mint", "A remote agent mints over HTTP and gets it wrong")
def http_mint(base, phone):
    good = {"Content-Type": "application/json", "Authorization": "Bearer " + gate_core.mint_api_token()}
    for label, body, headers, code in (
            ("no mint token", b"{}", {"Content-Type": "application/json"}, "invalid_mint_token"),
            ("a form post", b"action_text=x", {**good, "Content-Type": "text/plain"}, "unsupported_content_type"),
            ("prose around the JSON", b'Here you go:\n{"action_text": "x"}', good, "invalid_json"),
            ("a JSON array", b'["x"]', good, "invalid_json_shape"),
            ("vague action text", json.dumps({"action_text": "grant access", "requester": "r"}).encode(),
             good, "invalid_request")):
        status, out = post(base, "/challenge", body, headers)
        show(f"POST /challenge with {label} → HTTP {status}", out)
        expect(out.get("error_code") == code, code)


@path("transport-no-answer", "Hermes flags a command and nobody answers the passkey link in time")
def transport_no_answer(base, phone):
    hermes_says = json.dumps({"output": "", "exit_code": -1, "status": "blocked", "error": (
        "BLOCKED: User denied this command through the selected approval transport. The user "
        "has NOT consented to this action. Do NOT retry or attempt the same outcome through "
        "another route.")})
    c = gate_core.create_challenge(transport.ask_text(CMD, "recursive delete"), gate_core.HERMES_REQUESTER,
                                   _kind=gate_core.HERMES_KIND)
    ask = transport._Ask(c["challenge_id"], c["action_sha256"], "text", CMD, None, gate_core.data_dir())
    print(f"  {DIM}waiting about a second for an answer that never comes…{OFF}")
    approved = transport._decide(ask, transport.ASK_MARGIN_SECONDS + 1)
    show("the chat message is updated to", ask.line + "\n" + CMD)
    show("what Hermes tells the agent", json.loads(hermes_says)["error"])
    out = passkey_gate._on_transform_tool_result(tool_name="terminal", args={"command": CMD}, result=hermes_says)
    show("what the agent reads after the gate's transform_tool_result hook", json.loads(out or hermes_says)["error"])
    expect(not approved and out and "did NOT deny" in out, "not run, and not reported as a refusal")


@path("transport-denied", "Hermes flags a command and you tap Deny")
def transport_denied(base, phone):
    hermes_says = json.dumps({"error": "BLOCKED: User denied this command through the selected approval "
                                       "transport. The user has NOT consented to this action."})
    c = gate_core.create_challenge(transport.ask_text(CMD, "recursive delete"), gate_core.HERMES_REQUESTER,
                                   _kind=gate_core.HERMES_KIND)
    t.call(base, f"/a/{c['challenge_id']}/deny", {})
    ask = transport._Ask(c["challenge_id"], c["action_sha256"], "text", CMD, None, gate_core.data_dir())
    approved = transport._decide(ask, 10)
    show("the chat message is updated to", ask.line + "\n" + CMD)
    out = passkey_gate._on_transform_tool_result(tool_name="terminal", args={"command": CMD}, result=hermes_says)
    show("what the agent reads", json.loads(out or hermes_says)["error"])
    expect(not approved and out is None, "a real denial is passed through unchanged")


@path("transport-setup-failure", "Hermes flags a command but the gate can't create the link")
def transport_setup_failure(base, phone):
    posts = []
    saved = (cli.apply_config_safe, passkey_gate._session_surface, cli._ctx_ref,
             transport.begin_ask, transport.hermes_selection)
    cli.apply_config_safe = lambda: {"require_passkey": True, "passkey_hermes_prompts": True, "patterns": [],
                                     "gated_lanes": list(lanes.LANES), "owner_senders": []}
    passkey_gate._session_surface = lambda: "discord"
    cli._ctx_ref = type("Ctx", (), {"post_message": staticmethod(posts.append)})()
    try:
        for outcome, fallback in (("not asked: no owner key is pinned", "builtin"),
                                  ("not asked: the gate has no address (origin) yet", "deny")):
            transport.begin_ask = lambda *a, _o=outcome: _o
            transport.hermes_selection = lambda _f=fallback: {"transport_fallback": _f}
            passkey_gate._on_pre_approval_request(surface="transport:passkey-gate", request_id="r1",
                                                  command=CMD, description="recursive delete")
            show(f"{outcome!r}, transport_fallback: {fallback} → posted in the chat", posts[-1])
    finally:
        (cli.apply_config_safe, passkey_gate._session_surface, cli._ctx_ref,
         transport.begin_ask, transport.hermes_selection) = saved
    expect(len(posts) == 2 and "own approval prompt" in posts[0] and "refuse the command" in posts[1],
           "the chat says why, and what Hermes will do next")


def main(argv):
    if "--list" in argv:
        for name, title, _ in PATHS:
            print(f"{name:26} {title}")
        return 0
    wanted = [a for a in argv if not a.startswith("-")]
    chosen = [p for p in PATHS if not wanted or any(w in p[0] for w in wanted)]
    if not chosen:
        print("no path matches; try --list")
        return 2
    srv = gate_core.ThreadingHTTPServer(("127.0.0.1", 0), gate_core.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    tools._base_url = lambda: base
    # register the software passkey and pin it, as setup does with your phone
    phone = t.SoftAuthenticator()
    token = t.mint_token()
    _, opts = t.call(base, "/register/options", {"token": token})
    _, reg = t.call(base, "/register/finish", {"token": token, "session_id": opts["session_id"],
                                               "credential": phone.create(opts)})
    t.pin_once(gate_core.data_dir(), reg["spki_pem"])
    print(f"{DIM}throwaway gate at {base}, data in {gate_core.data_dir()}{OFF}")
    for name, title, fn in chosen:
        print(f"\n{BOLD}{name}{OFF}  {title}")
        try:
            fn(base, phone)
        except Exception as exc:
            expect(False, f"{name} ran without raising ({type(exc).__name__}: {exc})")
    srv.shutdown()
    print(f"\n{len(chosen)} path(s) shown, {len(failed)} unexpected.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
