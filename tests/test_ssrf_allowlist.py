"""Findings 5 + 23: the parent-base SSRF oracle, redirect-following fetches,
and prefix-based origin validation.

The chain under test: any caller can mint a challenge naming a
parent_approval.base; pre-fix the gate fetched that base server-side and
rendered what it learned — an internal-network oracle on the tailnet host.
Post-fix the base must be allowlisted (exact scheme+host+port origin match,
default empty = NO parent fetch at all), parse-validated, and resolved to a
non-internal address — all BEFORE any network I/O — and every server-side
fetch (parent verify, gate verify/health, status, TLS probe) treats a 3xx
redirect as the error it is instead of following it.
"""
import json
import socket as socket_mod
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkey_gate import cli, expose, gate_core, local_verify, tools

TMP = tempfile.mkdtemp()
ACTION = ("Grant GitLab user sorrel Developer access to project autumn/meta-hackathon "
          "on 100.64.0.10:5080, expiring 2026-11-08.")

# a fixed peer-owner key the stub parent gate's record will present
PEER_KEY = ec.generate_private_key(ec.SECP256R1())
PEER_PEM = PEER_KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _parent(base):
    return {"base": base, "challenge_id": "A" * 24, "action_sha256": "f" * 64, "owner": "bob"}


# ---------------------------------------------------------------- stub servers
class _StubGate(BaseHTTPRequestHandler):
    """Parent-gate stand-in: serves /verify/* from a fixed approved record."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path.startswith("/verify/"):
            body = json.dumps(self.server.record).encode()
        else:
            body = json.dumps({"status": "denied"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Redirector(BaseHTTPRequestHandler):
    """Answers everything with 302 -> the canary (an 'internal' service)."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        self.send_response(302)
        self.send_header("Location", self.server.location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _Canary(BaseHTTPRequestHandler):
    """The internal endpoint a followed redirect would land on."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        body = json.dumps({"status": "internal-service",
                           "secret": "metadata-credential"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler, **attrs):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    for k, v in attrs.items():
        setattr(srv, k, v)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def pinned_dir():
    local_verify.pin(TMP, PEER_PEM, "bob")
    return TMP


@pytest.fixture(scope="module")
def parent_stub():
    srv = _serve(_StubGate, hits=[], record={
        "status": "approved", "challenge_id": "A" * 24, "action_sha256": "f" * 64,
        "credential_public_key": {"spki_pem": PEER_PEM}})
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv
    srv.shutdown()


@pytest.fixture(scope="module")
def canary():
    srv = _serve(_Canary, hits=[])
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv
    srv.shutdown()


@pytest.fixture(scope="module")
def redirector(canary):
    canary_url, _ = canary
    srv = _serve(_Redirector, hits=[], location=canary_url + "/internal")
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv
    srv.shutdown()


def _reset_cli(monkeypatch):
    """Neutral config plumbing for end-to-end calls: no runtime ctx, a clean
    default-off cache, and an empty gate_core settings dict (module state can
    carry an allowlist pushed by earlier test modules' real apply_config
    calls — settings legitimately win over env, so tests that drive the env
    path must start from a clean slate), so gate_challenge mints without
    touching (or tripping over) whatever cli state earlier test modules left
    behind."""
    monkeypatch.setattr(cli, "_ctx_ref", None)
    monkeypatch.setattr(cli, "_cfg_cache", {"require_passkey": False, "patterns": []})
    monkeypatch.setattr(cli, "_cfg_stamp", None, raising=False)
    monkeypatch.setattr(cli, "_settings_source", lambda: None, raising=False)
    monkeypatch.setattr(gate_core, "_settings", {})


def _dead_port_base():
    """http://127.0.0.1:<port> where nothing listens — a fetch would fail
    fast, so the ONLY way this resolves quickly is by not fetching at all."""
    s = socket_mod.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


# ------------------------------------------------ finding 5: the allowlist gate
def test_unlisted_parent_base_is_never_fetched(parent_stub, pinned_dir):
    """An unlisted base yields its verdict BEFORE any network I/O — a
    reachable, responding internal endpoint must not become an oracle. No
    allowlist is configured at all (the default), so nothing may be fetched."""
    base, srv = parent_stub
    before = len(srv.hits)
    verdict = local_verify.verify_parent_approval(_parent(base), pinned_dir)
    assert verdict == "unverified (parent gate not on allowlist)", verdict
    assert len(srv.hits) == before  # the fetch never happened
    # an explicitly empty allowlist is the same fail-closed state
    verdict = local_verify.verify_parent_approval(_parent(base), pinned_dir, allowlist=[])
    assert verdict == "unverified (parent gate not on allowlist)"
    # a listed ORIGIN does not cover a different origin, even the same host:
    # the match is on scheme+host+port, exactly
    verdict = local_verify.verify_parent_approval(
        _parent(base), pinned_dir, allowlist=[f"https://127.0.0.1:{srv.server_address[1]}"])
    assert verdict == "unverified (parent gate not on allowlist)"
    assert len(srv.hits) == before
    # a base pointing at a port nothing listens on: instant verdict, no fetch
    verdict = local_verify.verify_parent_approval(_parent(_dead_port_base()), pinned_dir)
    assert verdict == "unverified (parent gate not on allowlist)"


def test_unlisted_parent_verdict_is_visible_on_the_page(monkeypatch, parent_stub, pinned_dir):
    """The rejection must be visible to the human signer: create_challenge
    persists the verdict and the approval page renders it."""
    base, _ = parent_stub
    _reset_cli(monkeypatch)
    monkeypatch.setenv("GATE_DATA", pinned_dir)
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "bramble",
                                           "parent_approval": _parent(base)}))
    assert out["ok"] is True, out
    row = gate_core.db().execute("select * from challenges where id=?",
                                 (out["challenge_id"],)).fetchone()
    assert row["parent_verified"] == "unverified (parent gate not on allowlist)"
    assert "not on allowlist" in gate_core.approval_page(row)


def test_allowlisted_parent_gate_is_fetched_and_verifies(parent_stub, pinned_dir):
    """The legitimate path survives the fix: an allowlisted stub parent gate
    is fetched exactly as before and verifies against the pinned peer key."""
    base, srv = parent_stub
    before = len(srv.hits)
    verdict = local_verify.verify_parent_approval(_parent(base), pinned_dir, allowlist=[base])
    assert verdict == "verified against pinned key for bob", verdict
    assert len(srv.hits) == before + 1  # the fetch happened
    # trailing-slash and default-port spellings name the same origin
    verdict = local_verify.verify_parent_approval(
        _parent(base + "/"), pinned_dir, allowlist=[base])
    assert verdict == "verified against pinned key for bob", verdict


def test_allowlisted_parent_gate_end_to_end(monkeypatch, parent_stub, pinned_dir):
    """Config plumbing end to end: the allowlist read from settings reaches
    the verifier, so an allowlisted peer gate still verifies through the
    normal gate_challenge path."""
    base, _ = parent_stub
    _reset_cli(monkeypatch)
    monkeypatch.setenv("GATE_DATA", pinned_dir)
    monkeypatch.setenv("GATE_PARENT_ALLOWLIST", json.dumps([base]))
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "bramble",
                                           "parent_approval": _parent(base)}))
    assert out["ok"] is True, out
    row = gate_core.db().execute("select parent_verified from challenges where id=?",
                                 (out["challenge_id"],)).fetchone()
    assert row["parent_verified"] == "verified against pinned key for bob"
    # and without the env allowlist it would have refused (no fetch state leak)
    monkeypatch.setenv("GATE_PARENT_ALLOWLIST", "[]")
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "bramble",
                                           "parent_approval": _parent(base)}))
    row = gate_core.db().execute("select parent_verified from challenges where id=?",
                                 (out["challenge_id"],)).fetchone()
    assert row["parent_verified"] == "unverified (parent gate not on allowlist)"


def test_parent_allowlist_setting_reaches_gate_core(monkeypatch):
    """apply_config pushes parent_gate_allowlist into gate_core.configure, and
    parent_allowlist() fail-closes on absent/garbled config."""
    seen = {}
    monkeypatch.setattr(gate_core, "configure", lambda **kw: seen.update(kw))
    # module settings may already hold an allowlist pushed by earlier test
    # modules' real apply_config calls; settings win over env, so clear them
    monkeypatch.setattr(gate_core, "_settings", {})

    class Ctx:
        def get_config(self, key, default=None):
            return {"origin": "https://h.example.ts.net", "rp_id": "h.example.ts.net",
                    "port": 8655, "challenge_ttl": 600,
                    "parent_gate_allowlist": ["https://peer.example.ts.net:8445"]}.get(key, default)

    cli.apply_config(Ctx())
    assert seen["parent_allowlist"] == ["https://peer.example.ts.net:8445"]
    monkeypatch.setenv("GATE_PARENT_ALLOWLIST", json.dumps(["https://a.example.ts.net"]))
    assert gate_core.parent_allowlist() == ["https://a.example.ts.net"]
    monkeypatch.setenv("GATE_PARENT_ALLOWLIST", "not json at all")
    assert gate_core.parent_allowlist() == []  # fail closed on garbage
    monkeypatch.setenv("GATE_PARENT_ALLOWLIST", json.dumps({"not": "a list"}))
    assert gate_core.parent_allowlist() == []
    monkeypatch.delenv("GATE_PARENT_ALLOWLIST", raising=False)
    assert gate_core.parent_allowlist() == []  # default: NO parent fetches at all


# --------------------------------------------- finding 23: no redirect anywhere
def test_parent_fetch_never_follows_redirects(redirector, canary, pinned_dir):
    """A redirect answer from the parent gate is an error, never followed —
    the fetch must not land on the internal service the redirect names."""
    rbase, _ = redirector
    _, csrv = canary
    before = len(csrv.hits)
    verdict = local_verify.verify_parent_approval(_parent(rbase), pinned_dir, allowlist=[rbase])
    assert verdict.startswith("unverified"), verdict
    assert "redirect" in verdict
    assert len(csrv.hits) == before  # the Location was never fetched


def test_verify_and_health_fetches_never_follow_redirects(redirector, canary):
    rbase, _ = redirector
    _, csrv = canary
    before = len(csrv.hits)
    rec = tools._fetch_verify(rbase, "A" * 24, "f" * 64)
    assert rec.get("status") == "error", rec
    assert "RedirectBlocked" in rec.get("error", ""), rec
    health = tools._fetch_health(rbase)
    assert health.get("status") == "unreachable", health
    assert health.get("error") == "RedirectBlocked", health
    assert len(csrv.hits) == before


def test_status_and_tls_probe_never_follow_redirects(redirector, canary):
    rbase, _ = redirector
    _, csrv = canary
    before = len(csrv.hits)

    class Ctx:
        def get_config(self, key, default=None):
            return {"origin": rbase}.get(key, default)

    out = json.loads(cli.cmd_status(Ctx(), None))
    assert out["gate"].get("reachable") is False, out["gate"]
    assert out["gate"].get("error") == "RedirectBlocked", out["gate"]
    ok, note = expose._tls_probe(f"{rbase}/health")
    assert ok is False and "RedirectBlocked" in note
    assert len(csrv.hits) == before


def test_open_no_redirect_semantics(parent_stub, redirector, canary):
    """The shared helper directly: 200 passes through; a 3xx raises with the
    status code and the refused target; the target is never contacted."""
    from passkey_gate import netfetch
    base, _ = parent_stub
    rbase, _ = redirector
    _, csrv = canary
    before = len(csrv.hits)
    with netfetch.open_no_redirect(f"{base}/verify/x?action_sha256=0") as r:
        assert r.status == 200
    with pytest.raises(netfetch.RedirectBlocked) as caught:
        netfetch.open_no_redirect(f"{rbase}/health")
    assert caught.value.code in (301, 302, 303, 307, 308)
    assert caught.value.location  # names where it refused to go
    assert len(csrv.hits) == before


# ----------------------------------- findings 5+23: strict parse of the base
def test_parent_base_is_parsed_not_prefix_checked(monkeypatch, pinned_dir):
    """https://-prefix-looking URLs that are not valid gate origins
    (credential-carrying, hostless) must be refused at mint time — the old
    startswith('https://') check let them through to a server-side fetch."""
    _reset_cli(monkeypatch)
    monkeypatch.setenv("GATE_DATA", pinned_dir)
    rejected = ("https://user:secret@host.example.ts.net",  # credentials ride along
                "https://",                                 # no host at all
                "https://:8445",                            # port without a host
                "http://192.168.1.9:8655",                  # http off loopback
                "ftp://host.example.ts.net")
    for bad in rejected:
        out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "bramble",
                                               "parent_approval": _parent(bad)}))
        assert out["ok"] is False, bad
        assert "parent_approval" in out["error"], (bad, out["error"])
    # the verifier says the same thing on a direct call, still with no fetch
    verdict = local_verify.verify_parent_approval(
        _parent("https://user:pw@h.example.ts.net"), pinned_dir)
    assert "not a valid gate origin" in verdict, verdict


def test_allowlisted_host_resolving_internal_is_rejected(monkeypatch, pinned_dir):
    """Finding 5 hardening: an allowlisted DNS name that resolves into
    private/loopback space — or not at all — is rejected before the fetch,
    so a re-pointed DNS record cannot pivot the parent fetch internal."""
    base = "https://peer-gate.example.test"
    allowlist = [base]

    def gaierror(host, port):
        raise socket_mod.gaierror("no such host")

    monkeypatch.setattr(socket_mod, "getaddrinfo", gaierror)
    verdict = local_verify.verify_parent_approval(_parent(base), pinned_dir, allowlist=allowlist)
    assert "does not resolve" in verdict, verdict

    monkeypatch.setattr(socket_mod, "getaddrinfo",
                        lambda host, port: [(socket_mod.AF_INET, 1, 6, "", ("10.9.9.9", 443))])
    verdict = local_verify.verify_parent_approval(_parent(base), pinned_dir, allowlist=allowlist)
    assert "resolves to a private address" in verdict, verdict

    # IPv4-mapped IPv6 is judged as its IPv4 self, not passed through
    monkeypatch.setattr(socket_mod, "getaddrinfo",
                        lambda host, port: [(socket_mod.AF_INET6, 1, 6, "", ("::ffff:127.0.0.1", 0))])
    verdict = local_verify.verify_parent_approval(_parent(base), pinned_dir, allowlist=allowlist)
    assert "resolves to a loopback address" in verdict, verdict


def test_private_network_problem_rules():
    """The resolution rule in isolation: internal addresses are rejected for
    DNS-named entries, but an allowlist entry that names the literal internal
    host (or localhost) is the admin's deliberate choice and stands."""
    from passkey_gate import netfetch

    def resolver_from(*addrs):
        infos = [(socket_mod.AF_INET6 if ":" in a else socket_mod.AF_INET, 1, 6, "", (a, 0))
                 for a in addrs]
        return lambda host, port: infos

    host = "gate.example.test"
    for addr, word in (("10.0.0.5", "private"), ("192.168.1.9", "private"),
                       ("172.20.1.5", "private"), ("127.0.0.2", "loopback"),
                       ("169.254.9.9", "link-local"), ("fd00::5", "private"),
                       ("fe80::1", "link-local"), ("::ffff:10.0.0.5", "private")):
        problem = netfetch.private_network_problem(host, host, resolver=resolver_from(addr))
        assert problem and word in problem, (addr, problem)
    # a public resolution is fine (mixed families, all addresses checked)
    assert netfetch.private_network_problem(
        host, host, resolver=resolver_from("8.8.8.8", "2606:4700::1111")) is None
    # literal internal host named BY THE ENTRY itself -> deliberate, allowed
    assert netfetch.private_network_problem("10.1.2.3", "10.1.2.3",
                                            resolver=resolver_from("10.1.2.3")) is None
    assert netfetch.private_network_problem("127.0.0.1", "127.0.0.1",
                                            resolver=resolver_from("127.0.0.1")) is None
    assert netfetch.private_network_problem("localhost", "localhost",
                                            resolver=resolver_from("127.0.0.1")) is None

    def boom(host, port):
        raise socket_mod.gaierror("dns gone")

    assert "does not resolve" in netfetch.private_network_problem(host, host, resolver=boom)
