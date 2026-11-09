"""v0.7 review backlog (Proposal 3): M6, M7 and the LOW/INFO items A11–A30.

Each test names the finding it closes. Servers here are real
BoundedHTTPServer instances on 127.0.0.1; the data folder is a fresh temp
dir per test (GATE_DATA)."""
import hashlib
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from passkey_gate import cli, gate_core, netfetch, service, tools
from test_settings import FakeCtx, _cli

ACTION = ("Delete the local build cache directory ./build-cache so the next "
          "build starts from a clean state")
ORIGIN = "https://gate.example.ts.net"


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setenv("GATE_DATA", str(tmp_path))
    gate_core.configure(origin=ORIGIN, rp_id="gate.example.ts.net", challenge_ttl=600,
                        port=8655, bootstrap_ttl=900)
    monkeypatch.setattr(gate_core, "_budgets", {"other": gate_core._Budget(300),
                                                "approval": gate_core._Budget(300)})
    return tmp_path


@pytest.fixture
def server(data):
    srv = gate_core.BoundedHTTPServer(("127.0.0.1", 0), gate_core.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def req(base, path, body=None, host=None, auth=False):
    headers = {"Content-Type": "application/json"}
    if host:
        headers["Host"] = host
    if auth:
        headers["Authorization"] = "Bearer " + gate_core.mint_api_token()
    r = urllib.request.Request(base + path, method="POST" if body is not None else "GET",
                               data=json.dumps(body).encode() if body is not None else None,
                               headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read()
            ctype = resp.headers.get_content_type()
            return resp.status, json.loads(raw) if ctype == "application/json" else raw.decode()
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode()


def audit_lines(data):
    p = data / "audit.jsonl"
    return p.read_text().splitlines() if p.exists() else []


# ------------------------------------------------------- M7 / L6 (A8, A15)
@pytest.mark.parametrize("field", ["requester", "requester_owner", "why", "action_text"])
@pytest.mark.parametrize("bad", ["\x1b[2K", "‮", "​", "\x07", " "])
def test_control_bidi_and_invisible_characters_are_refused(data, field, bad):
    kw = {"action_text": ACTION, "requester": "bramble", "requester_owner": "Robin",
          "why": "So the next build does not reuse stale objects from the cache."}
    kw[field] = kw[field][:3] + bad + kw[field][3:]
    with pytest.raises(ValueError, match="control, bidirectional or invisible"):
        gate_core.create_challenge(kw.pop("action_text"), kw.pop("requester"), **kw)


def test_newlines_and_tabs_stay_allowed_in_action_text(data):
    c = gate_core.create_challenge(ACTION + "\n\tthen run the build again", "bramble")
    assert c["challenge_id"]


def test_show_escapes_terminal_sequences_already_in_the_db(data):
    c = gate_core.create_challenge(ACTION, "bramble")
    gate_core.db().execute("update challenges set requester=?, why=? where id=?",
                           ("evil\x1b]52;c;aGk=\x07", "ok‮evil", c["challenge_id"]))
    out = cli.cmd_show(FakeCtx(), [c["challenge_id"]])
    assert "\x1b" not in out and "‮" not in out and "\x07" not in out
    assert "\\x1b" in out and "\\u202e" in out


def test_page_puts_the_bound_command_before_the_agents_prose(data):
    c = gate_core.create_challenge(ACTION, "bramble",
                                   {"tool": "terminal", "args": {"command": "rm -rf ./build-cache"}})
    row = gate_core.db().execute("select * from challenges where id=?", (c["challenge_id"],)).fetchone()
    page = gate_core.approval_page(row)
    assert page.index("THE EXACT COMMAND") < page.index("What it says it wants to do")
    assert "(the name the agent gave)" in page and "(written by the agent)" in page


# ------------------------------------------------------- A30
@pytest.mark.parametrize("bad", ["rm -rf /", ["terminal"], {"tool": 5}, {"tool": "t", "args": "x"}])
def test_tool_call_must_be_an_object(data, bad):
    with pytest.raises(ValueError, match="tool_call must be an object"):
        gate_core.create_challenge(ACTION, "bramble", bad)


def test_torn_last_audit_line_is_tolerated(data):
    gate_core.audit("one")
    with open(data / "audit.jsonl", "a") as f:
        f.write('{"seq": 1, "hash": "trunc')        # a crash mid-write
    h = gate_core.audit("two")                       # no exception
    assert gate_core.audit_head() == h
    ok, msg = gate_core.audit_verify()
    assert not ok and "line 1" in msg                # still reported
    st = json.loads(tools.gate_status({}))           # A30: gate_status no longer raises
    assert isinstance(st, dict)


def test_audit_append_reads_only_the_tail(data, monkeypatch):
    for i in range(50):
        gate_core.audit("e", i=i)
    gate_core._tail_cache.clear()
    opened = []
    real_read = type(data).read_text
    monkeypatch.setattr(type(data), "read_text",
                        lambda self, *a, **k: opened.append(self) or real_read(self, *a, **k))
    gate_core.audit("after")
    gate_core.audit_head()
    assert not [p for p in opened if p.name == "audit.jsonl"]
    assert gate_core.audit_verify()[0]


def test_tail_cache_notices_another_writer(data):
    gate_core.audit("a")
    # a second process appends: simulate by dropping our cache key's validity
    with open(data / "audit.jsonl") as f:
        last = json.loads(f.read().splitlines()[-1])
    rec = {"seq": last["seq"] + 1, "ts": 1, "event": "other-process", "prev": last["hash"]}
    rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with open(data / "audit.jsonl", "a") as f:
        f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
    gate_core.audit("b")
    assert gate_core.audit_verify()[0]


# ------------------------------------------------------- M6 (A7)
def test_anonymous_junk_writes_no_audit_lines(server, data):
    before = len(audit_lines(data))
    fake = "x" * 32
    for path, body in ((f"/a/{fake}/finish", {"id": "x"}), (f"/a/{fake}/options", {}),
                       (f"/a/{fake}/deny", {}), ("/register/options", {"token": "y" * 40}),
                       ("/register/finish", {"token": "y" * 40, "session_id": "nope"}),
                       (f"/a/{fake}/finish", None)):
        req(server, path, body if body is not None else {})
    assert len(audit_lines(data)) == before


def test_real_requests_are_still_audited(server, data):
    c = gate_core.create_challenge(ACTION, "bramble")
    before = len(audit_lines(data))
    s, _ = req(server, f"/a/{c['challenge_id']}/deny", {})
    assert s == 200
    assert json.loads(audit_lines(data)[-1])["event"] == "challenge_denied"
    assert len(audit_lines(data)) == before + 1


def test_health_no_longer_carries_the_audit_head(server):
    s, r = req(server, "/health")
    assert s == 200 and "audit_head" not in r


# ------------------------------------------------------- L3 (A12)
def test_junk_flood_does_not_lock_the_human_out_of_a_real_request(server, data, monkeypatch):
    monkeypatch.setattr(gate_core, "_budgets", {"other": gate_core._Budget(3),
                                                "approval": gate_core._Budget(300)})
    c = gate_core.create_challenge(ACTION, "bramble")
    codes = [req(server, f"/a/{'z' * 30}")[0] for _ in range(5)]
    assert codes[-1] == 429
    s, page = req(server, f"/a/{c['challenge_id']}")
    assert s == 200 and "Approval request" in page
    assert req(server, "/register")[0] == 200


# ------------------------------------------------------- L4 (A13)
def test_slow_client_is_cut_off_at_the_request_deadline(server, monkeypatch):
    monkeypatch.setattr(gate_core, "REQUEST_DEADLINE_S", 1)
    host, port = server.split("//")[1].split(":")
    with socket.create_connection((host, int(port)), timeout=5) as s:
        start = time.monotonic()
        s.sendall(b"GET /health HTTP/1.1\r\n")      # never finishes the headers
        s.settimeout(5)
        try:
            data = s.recv(100)
        except (ConnectionResetError, socket.timeout):
            data = b""
        assert data == b"" and time.monotonic() - start < 4


# ------------------------------------------------------- L5 (A14)
def test_dns_rebinding_host_is_refused(server):
    s, r = req(server, "/health", host="attacker.example:8655")
    assert s == 421
    assert req(server, "/health", host="localhost:8655")[0] == 200
    assert req(server, "/health", host="gate.example.ts.net")[0] == 200
    s, _ = req(server, f"/a/{'q' * 30}/deny", {}, host="attacker.example")
    assert s == 421


# ------------------------------------------------------- L14 (A23)
def test_deny_on_a_request_that_is_not_pending_is_409(server, data):
    c = gate_core.create_challenge(ACTION, "bramble")
    gate_core.db().execute("update challenges set status='approved' where id=?", (c["challenge_id"],))
    s, r = req(server, f"/a/{c['challenge_id']}/deny", {})
    assert s == 409 and r.get("status") != "denied"
    st = gate_core.db().execute("select status from challenges where id=?",
                                (c["challenge_id"],)).fetchone()[0]
    assert st == "approved"


# ------------------------------------------------------- L2 (A11)
def test_remote_minting_has_its_own_share_of_the_cap(server, data, monkeypatch):
    monkeypatch.setattr(gate_core, "MAX_PENDING_CHALLENGES_HTTP", 2)
    for i in range(2):
        s, _ = req(server, "/challenge", {"action_text": ACTION, "requester": f"remote{i}"}, auth=True)
        assert s == 201
    s, r = req(server, "/challenge", {"action_text": ACTION, "requester": "remote9"}, auth=True)
    assert s == 429 and "remote agents" in r["error"]
    assert gate_core.create_challenge(ACTION, "local-agent")["challenge_id"]   # local still fine


# ------------------------------------------------------- L11 / L12 (A20, A21)
@pytest.mark.parametrize("addr", ["100.64.0.1", "100.100.100.100", "198.18.0.1", "192.0.0.8"])
def test_non_public_addresses_are_refused(addr):
    assert netfetch._address_problem(addr)


def test_tailnet_peer_by_ts_net_name_is_allowed_but_not_the_service_address():
    fake = lambda ip: (lambda host, _: [(0, 0, 0, "", (ip, 0))])
    assert netfetch._resolve_checked("peer.example.ts.net", "peer.example.ts.net",
                                     fake("100.101.2.3"))[0] is None
    assert netfetch._resolve_checked("peer.example.ts.net", "peer.example.ts.net",
                                     fake("100.100.100.100"))[0]
    assert netfetch._resolve_checked("gate.example.com", "gate.example.com",
                                     fake("100.101.2.3"))[0]


def test_response_reads_are_capped():
    import io
    with pytest.raises(netfetch.ResponseTooLarge):
        netfetch.read_capped(io.BytesIO(b"x" * 5000), limit=1000)
    assert netfetch.read_capped(io.BytesIO(b"ok"), limit=1000) == b"ok"


# ------------------------------------------------------- L7 (A16)
def test_rejected_config_is_not_applied(data, monkeypatch):
    ctx = FakeCtx()
    cli._canary_file().write_text("expected-value")
    ctx.store.update(challenge_ttl=86400, origin="https://evil.example", config_canary="other")
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    gate_core.configure(origin=ORIGIN, challenge_ttl=600, port=8655, bootstrap_ttl=900)
    state = cli._load_config_state()
    assert state.get("_config_error")
    assert gate_core.challenge_ttl() != 86400 and gate_core.origin() != "https://evil.example"


# ------------------------------------------------------- L16 (A25)
def test_settings_reload_on_a_timer_when_the_file_cannot_be_stamped(monkeypatch):
    ctx = FakeCtx()
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    monkeypatch.setattr(cli, "_settings_stamp", lambda: None)
    cli.invalidate_config_cache()
    clock = [1000.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    assert cli.apply_config_safe()["require_passkey"] is False
    ctx.store["require_passkey"] = True
    clock[0] += cli.CONFIG_RECHECK_S + 0.1
    assert cli.apply_config_safe()["require_passkey"] is True
    cli.invalidate_config_cache()


# ------------------------------------------------------- L8 (A17)
def test_rp_id_change_is_judged_against_the_default_in_use(data, monkeypatch):
    ctx = FakeCtx()
    monkeypatch.setattr(gate_core, "credential_count", lambda: 1)
    monkeypatch.setattr(gate_core, "rp_id", lambda: "gate.example.ts.net")
    out = _cli(ctx, "set rp_id other.example.com")
    assert "REFUSED" in out and "rp_id" not in ctx.store
    monkeypatch.setattr(gate_core, "credential_count", lambda: 0)
    out = _cli(ctx, "set rp_id other.example.com")      # nothing registered: first-time setup
    assert ctx.store["rp_id"] == "other.example.com", out


# ------------------------------------------------------- L15 (A24)
def test_catastrophic_pattern_is_refused():
    ctx = FakeCtx()
    out = _cli(ctx, 'set authority_patterns ["^terminal (a+)+$"]')
    assert "REFUSED" in out and "too long" in out
    assert "authority_patterns" not in ctx.store
    out = _cli(ctx, 'set authority_patterns ["^terminal .*\\\\brm\\\\b"]')
    assert "REFUSED" not in out, out


def test_tiny_challenge_ttl_is_refused():
    ctx = FakeCtx()
    ctx.store["challenge_ttl"] = 600
    out = _cli(ctx, "set challenge_ttl 1")
    assert "REFUSED" in out and "at least 60" in out and ctx.store["challenge_ttl"] == 600


# ------------------------------------------------------- L10 (A19)
@pytest.mark.parametrize("home", ["/home/me\nExecStartPre=/bin/evil", "/home/\rme"])
def test_control_characters_never_reach_the_service_file(home):
    with pytest.raises(ValueError, match="control character"):
        service.unit_text("/usr/bin/hermes", home)
    with pytest.raises(ValueError, match="control character"):
        service.plist_text("/usr/bin/hermes", home)


# ------------------------------------------------------- A26
def test_registration_cannot_finish_after_the_token_expired(data, monkeypatch):
    tok = gate_core.mint_bootstrap_token().rsplit("#", 1)[-1]
    opts = gate_core.registration_options(tok)
    assert opts
    gate_core.db().execute("update bootstrap_tokens set expires_at=?", (time.time() - 1,))
    monkeypatch.setattr(gate_core, "verify_registration_response",
                        lambda **kw: type("V", (), {"credential_id": b"c" * 16,
                                                    "credential_public_key": b"k",
                                                    "sign_count": 0})())
    r = gate_core.registration_finish(tok, opts["session_id"], {})
    assert r.get("error") and gate_core.credential_count() == 0


# ------------------------------------------------------- A28 / A29
def test_mint_token_is_not_read_through_a_symlink(data, tmp_path_factory):
    secret = tmp_path_factory.mktemp("elsewhere") / "secret"
    secret.write_text("not-the-token")
    os.symlink(secret, data / gate_core.MINT_TOKEN_NAME)
    assert gate_core.mint_token_ok("Bearer not-the-token") is False


def test_fetched_record_must_carry_the_locally_stored_nonce(data):
    c = gate_core.create_challenge(ACTION, "bramble")
    stored = gate_core.db().execute("select challenge from challenges where id=?",
                                    (c["challenge_id"],)).fetchone()[0]
    good = {"challenge_b64url": gate_core.bytes_to_base64url(stored)}
    assert gate_core.record_matches_local_challenge(good, stored)
    assert not gate_core.record_matches_local_challenge({"challenge_b64url": "AAAA"}, stored)
    assert not gate_core.record_matches_local_challenge({}, stored)


def test_canary_arming_is_serialised(data):
    ctx = FakeCtx()
    threads = [threading.Thread(target=cli.stamp_config_canary, args=(ctx,)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert cli._canary_file().read_text() == ctx.store["config_canary"]
    assert cli.config_canary_problem(ctx) is None
