"""Finding 11 (LOW): challenge creation is rate-limited.

Pre-fix, anything that can reach the gate — the gate_challenge tool, POST
/challenge, the CLI's --approve mint — could mint unlimited challenges:
each lands in the DB, renders an approval page, and can be pushed at the
human as a social-engineering flood, with unbounded DB + audit growth.

Post-fix creation is capped per requester with a global backstop, and the
quota counts only PENDING, UNEXPIRED challenges: an expired or decided
challenge frees its slot, so the throttle never outlives the TTL. The
count and the insert are one BEGIN IMMEDIATE write transaction, so
concurrent minters cannot each see "room for one more" and overshoot the
cap — SQLite serializes them exactly like the consume() claim.

Exceeding a cap is a refusal with a clear message (a ChallengeLimitError,
which subclasses ValueError so every existing caller already treats it as
a clean refusal), surfaced by the HTTP handler as 429 with the same
{"error": ...} body the other refusals use.
"""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from passkey_gate import cli, gate_core, tools

ACTION = ("Grant GitLab user sorrel Developer access to project autumn/meta-hackathon "
          "on 100.64.0.10:5080, expiring 2026-11-08.")


def _reset_cli(monkeypatch):
    """Neutral config plumbing (mirrors test_ssrf_allowlist): no runtime ctx,
    a clean default-off cache, and an empty gate_core settings dict, so the
    tools handler mints without tripping over (or inheriting) whatever cli
    state earlier test modules left behind."""
    monkeypatch.setattr(cli, "_ctx_ref", None)
    monkeypatch.setattr(cli, "_cfg_cache", {"require_passkey": False, "patterns": []})
    monkeypatch.setattr(cli, "_cfg_stamp", None, raising=False)
    monkeypatch.setattr(cli, "_settings_source", lambda: None, raising=False)
    monkeypatch.setattr(gate_core, "_settings", {})


@pytest.fixture
def gate_env(tmp_path, monkeypatch):
    """An isolated gate: fresh data dir, a TTL long enough that pending
    challenges stay pending for the test's whole run (expiry is simulated
    directly in the DB, never by sleeping)."""
    _reset_cli(monkeypatch)
    monkeypatch.setenv("GATE_DATA", str(tmp_path))
    monkeypatch.setenv("GATE_CHALLENGE_TTL", "600")
    monkeypatch.setenv("GATE_ORIGIN", "https://gate.example.ts.net:8445")
    monkeypatch.setenv("GATE_RP_ID", "gate.example.ts.net")
    monkeypatch.delenv("GATE_PARENT_ALLOWLIST", raising=False)
    return tmp_path


def mint(requester, text=ACTION):
    """Create a challenge through the tools handler (the agent-facing path)."""
    return json.loads(tools.gate_challenge({"action_text": text, "requester": requester}))


def pending_count(requester=None):
    """The quota the gate counts: PENDING, UNEXPIRED rows only."""
    q = "select count(*) from challenges where status='pending' and expires_at>=?"
    args = [time.time()]
    if requester is not None:
        q += " and requester=?"
        args.append(requester)
    return gate_core.db().execute(q, args).fetchone()[0]


# ----------------------------------------------- the per-requester cap
def test_minting_up_to_the_per_requester_limit_works(gate_env):
    cap = gate_core.MAX_PENDING_CHALLENGES_PER_REQUESTER
    for i in range(cap):
        out = mint("flood-agent")
        assert out["ok"] is True, (i, out)
    assert pending_count("flood-agent") == cap


def test_mint_past_the_per_requester_limit_is_refused(gate_env):
    cap = gate_core.MAX_PENDING_CHALLENGES_PER_REQUESTER
    for _ in range(cap):
        assert mint("flood-agent")["ok"] is True
    out = mint("flood-agent")
    assert out["ok"] is False
    assert "challenge limit" in out["error"], out["error"]
    assert "flood-agent" in out["error"], out["error"]
    assert pending_count("flood-agent") == cap  # nothing snuck into the DB
    # the engine call raises the same refusal for callers that skip the tool
    with pytest.raises(gate_core.ChallengeLimitError) as caught:
        gate_core.create_challenge(ACTION, "flood-agent")
    assert "challenge limit" in str(caught.value)
    assert pending_count("flood-agent") == cap
    # the refusal is tamper-evident, like every other rejection
    rejected = [json.loads(line) for line in
                (gate_core.data_dir() / "audit.jsonl").read_text().splitlines()
                if json.loads(line)["event"] == "challenge_rejected"]
    assert rejected and "challenge limit" in rejected[-1]["reason"]
    assert rejected[-1]["requester"] == "flood-agent"


def test_the_cap_is_per_requester_not_global(gate_env):
    cap = gate_core.MAX_PENDING_CHALLENGES_PER_REQUESTER
    for _ in range(cap):
        assert mint("flood-agent")["ok"] is True
    assert mint("flood-agent")["ok"] is False  # A is at its cap
    for i in range(3):  # a different requester has its own quota
        out = mint("other-agent")
        assert out["ok"] is True, (i, out)
    assert pending_count("flood-agent") == cap
    assert pending_count("other-agent") == 3


# ----------------------- expiry and resolution free the quota
def test_expired_and_decided_challenges_free_the_quota(gate_env):
    cap = gate_core.MAX_PENDING_CHALLENGES_PER_REQUESTER
    for _ in range(cap):
        assert mint("flood-agent")["ok"] is True
    assert mint("flood-agent")["ok"] is False  # full
    # expire one pending challenge directly in the DB: its slot frees
    cid = gate_core.db().execute("select id from challenges where requester=? and"
                                 " status='pending'", ("flood-agent",)).fetchone()["id"]
    gate_core.db().execute("update challenges set expires_at=? where id=?",
                           (time.time() - 1.0, cid))
    assert mint("flood-agent")["ok"] is True  # the expired slot was reused
    # a human DECISION frees a slot too (denied here; approved/consumed count
    # the same way — only pending rows hold quota). The row picked must be
    # one that actually holds quota — an expired row is still status
    # 'pending' but no longer counts.
    cid = gate_core.db().execute("select id from challenges where requester=? and"
                                 " status='pending' and expires_at>=?",
                                 ("flood-agent", time.time())).fetchone()["id"]
    gate_core.db().execute("update challenges set status='denied', decided_at=? where id=?",
                           (time.time(), cid))
    assert mint("flood-agent")["ok"] is True
    assert pending_count("flood-agent") == cap


# ------------------------------------------- the global backstop
def test_global_backstop_triggers_even_with_distinct_requesters(gate_env):
    """No single requester anywhere near its own cap — the flood is spread
    across distinct identities — yet the gate's total pending budget is
    finite: the 101st distinct requester is refused."""
    total = gate_core.MAX_PENDING_CHALLENGES_TOTAL
    for i in range(total):
        out = mint(f"agent-{i}")
        assert out["ok"] is True, (i, out)
    assert pending_count() == total
    out = mint("brand-new-agent")  # empty per-requester quota, full gate
    assert out["ok"] is False
    assert "challenge limit" in out["error"], out["error"]
    assert pending_count() == total  # the DB did not grow
    # the quota is about PENDING challenges only: deciding one frees a slot
    gate_core.db().execute("update challenges set status='denied', decided_at=?"
                           " where status='pending' and requester='agent-0'", (time.time(),))
    assert mint("brand-new-agent")["ok"] is True


# --------------------------------------------------- TOCTOU safety
def test_concurrent_minters_cannot_overshoot_the_cap(gate_env):
    """The count and the insert must be one serialized transaction: sixteen
    racers mint for the same requester at the same instant, and the cap
    still holds exactly — no check-then-insert window to slip through."""
    cap = gate_core.MAX_PENDING_CHALLENGES_PER_REQUESTER
    racers = cap + 6
    bar = threading.Barrier(racers, timeout=15)
    results = []

    def racer():
        bar.wait()
        results.append(mint("racer")["ok"])

    threads = [threading.Thread(target=racer) for _ in range(racers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == cap, results  # exactly the cap succeeded, no more
    assert pending_count("racer") == cap


# ------------------------------------------ the HTTP endpoint shape
def _post(base, body):
    req = urllib.request.Request(base + "/challenge", method="POST",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + gate_core.mint_api_token()})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_http_challenge_endpoint_throttles_with_429(gate_env):
    """Anything that can reach the gate's HTTP endpoint gets the same
    throttle: the cap is enforced in the engine, and the endpoint answers
    an over-cap mint with 429 in the existing {"error": ...} shape — a
    clean refusal, not a crash and not a silent 500."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), gate_core.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        cap = gate_core.MAX_PENDING_CHALLENGES_PER_REQUESTER
        for i in range(cap):
            s, r = _post(base, {"action_text": ACTION, "requester": "http-flood"})
            assert s == 201, (i, r)
        s, r = _post(base, {"action_text": ACTION, "requester": "http-flood"})
        assert s == 429, (s, r)
        assert "challenge limit" in r["error"], r
        # a different requester is not collateral damage
        s, r = _post(base, {"action_text": ACTION, "requester": "http-other"})
        assert s == 201, r
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------- fresh-review F5: GET cap + connection ceiling
def test_get_requests_are_capped_gate_wide(monkeypatch):
    monkeypatch.setattr(gate_core, "GET_RATE_MAX", 3)
    monkeypatch.setattr(gate_core, "_get_hits", __import__("collections").deque())
    srv = gate_core.BoundedHTTPServer(("127.0.0.1", 0), gate_core.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        codes = []
        for _ in range(5):
            try:
                with urllib.request.urlopen(base + "/verify/x?action_sha256=0", timeout=5) as r:
                    codes.append(r.status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429], codes
        with urllib.request.urlopen(base + "/static/app.js", timeout=5) as r:
            assert r.status == 200  # static assets are not counted
    finally:
        srv.shutdown()


def test_connection_ceiling_closes_extra_connections():
    import socket
    srv = gate_core.BoundedHTTPServer(("127.0.0.1", 0), gate_core.Handler, max_connections=1)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        addr = srv.server_address
        hog = socket.create_connection(addr, timeout=5)   # holds the only slot, sends nothing
        time.sleep(0.3)
        extra = socket.create_connection(addr, timeout=5)
        extra.settimeout(5)
        assert extra.recv(10) == b""                     # closed at once, no thread spent
        extra.close()
        hog.close()
        time.sleep(0.5)                                  # slot released when the hog goes
        with urllib.request.urlopen(f"http://{addr[0]}:{addr[1]}/health", timeout=5) as r:
            assert r.status == 200
    finally:
        srv.shutdown()
