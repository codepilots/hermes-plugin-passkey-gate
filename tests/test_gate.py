"""End-to-end tests with a software authenticator (real WebAuthn crypto, no browser).

Ported to the plugin package from the original `approval-gate` test suite
(that suite covered Sorrel's field DoD: health 200; approve -> verify approved
with matching sha256 and locally-checkable assertion; replayed/mismatched
sha256 -> denied; >TTL -> expired; no approval without a valid assertion;
single-use; bootstrap token single-use; specificity floor; non-enumerable
verify; audit chain integrity), keeping the same cases verbatim where the
crypto contract is involved, plus new plugin-contract tests: canonical
binding is stable across minter/hook, hook verdicts fail closed, consumption
is exactly-once.
"""
import base64
import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

TMP = tempfile.mkdtemp()
ORIGIN = "https://yourhost.example.ts.net:8445"
RP_ID = "yourhost.example.ts.net"
os.environ.update(GATE_DATA=TMP, GATE_CHALLENGE_TTL="2", GATE_ORIGIN=ORIGIN, GATE_RP_ID=RP_ID)

PLUGIN_DIR = Path(__file__).resolve().parents[1]  # repo root

# conftest.py at the project root loads the dash-named plugin as a proper
# package ("passkey_gate"); plain imports from here.
from passkey_gate import gate_core, local_verify, tools  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from webauthn.helpers import encode_cbor  # noqa: E402

ACTION = ("Grant GitLab user sorrel Developer access to project autumn/meta-hackathon "
          "on 100.64.0.10:5080, expiring 2026-11-08.")

TOOL_CALL = {"tool": "terminal", "args": {"command": "ssh git@100.64.0.10 -p 2222 grant-sorrel"}}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    def __init__(self, origin=ORIGIN, rp_id=RP_ID):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.count = 0
        self.pem = None  # the SPKI PEM the gate returns at registration
        self.origin, self.rp_id = origin, rp_id

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return encode_cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _cd(self, typ, challenge_b64u):
        return json.dumps({"type": typ, "challenge": challenge_b64u, "origin": self.origin,
                           "crossOrigin": False}).encode()

    def create(self, opts, initial_count=0):
        """Registration ceremony. `initial_count` sets the attestation's
        signature counter (findings 21+13: registration must store exactly
        what the attestation reports, not a hardcoded 0)."""
        rp_hash = hashlib.sha256(opts["rp"]["id"].encode()).digest()
        auth = rp_hash + bytes([0x45]) + struct.pack(">I", initial_count) + b"\0" * 16 \
            + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        att = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(self._cd("webauthn.create", opts["challenge"])),
                             "attestationObject": b64u(att), "transports": ["internal"]}}

    def get(self, opts, flags=0x05, count=None):
        """Assertion ceremony. `count` presents a CHOSEN signature counter:
        the clone/replay shapes of finding 21 replay a counter the gate has
        already seen (or present an older one) instead of advancing to the
        next; None advances monotonically like a genuine authenticator."""
        self.count = self.count + 1 if count is None else count
        auth = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.count)
        cd = self._cd("webauthn.get", opts["challenge"])
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "clientExtensionResults": {},
                "response": {"authenticatorData": b64u(auth), "clientDataJSON": b64u(cd),
                             "signature": b64u(sig), "userHandle": None}}


@pytest.fixture(scope="module")
def base():
    os.environ.update(GATE_DATA=TMP, GATE_CHALLENGE_TTL="2", GATE_PORT="0",
                      GATE_ORIGIN=ORIGIN, GATE_RP_ID=RP_ID)
    srv = gate_core.ThreadingHTTPServer(("127.0.0.1", 0), gate_core.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def call(base, path, body=None):
    headers = {"Content-Type": "application/json"}
    if path == "/challenge":
        headers["Authorization"] = "Bearer " + gate_core.mint_api_token()
    req = urllib.request.Request(base + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if r.headers.get_content_type() == "application/json" else raw.decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def mint_token():
    tok = secrets.token_urlsafe(32)
    gate_core.db().execute("insert into bootstrap_tokens values(?,?,?,NULL)",
                           (hashlib.sha256(tok.encode()).hexdigest(), time.time(), time.time() + 900))
    return tok


@pytest.fixture(scope="module")
def autumn(base):
    a = SoftAuthenticator()
    tok = mint_token()
    s, opts = call(base, "/register/options", {"token": tok})
    assert s == 200 and opts["rp"]["id"] == RP_ID
    s, r = call(base, "/register/finish", {"token": tok, "session_id": opts["session_id"], "credential": a.create(opts)})
    assert s == 200, r
    a.pem = r["spki_pem"]
    # the phone shows this code; the operator types it into setup / pin --code
    assert r["code"] == gate_core.key_confirmation_code(a.pem)
    assert any(c["code"] == r["code"] for c in gate_core.list_credentials())
    # token is single use
    s, _ = call(base, "/register/options", {"token": tok})
    assert s == 403
    return a


def new_challenge(base, text=ACTION, tool_call=None, requester="sorrel"):
    s, r = call(base, "/challenge", {"action_text": text, "requester": requester,
                                     "tool_call": tool_call} if tool_call else
                {"action_text": text, "requester": requester})
    assert s == 201, r
    return r


def approve(base, a, cid, **kw):
    s, opts = call(base, f"/a/{cid}/options", {})
    assert s == 200, opts
    return call(base, f"/a/{cid}/finish", a.get(opts, **kw))


def test_health(base):
    s, r = call(base, "/health")
    assert s == 200 and r["status"] == "ok" and r["rp_id"] == RP_ID


def test_specificity_floor(base):
    s, r = call(base, "/challenge", {"action_text": "grant sorrel access", "requester": "sorrel"})
    assert s == 422


def test_binding_recorded_and_canonical_is_stable(base):
    """The challenge's binding equals what the hook re-derives from the SAME
    canonical call — minter and enforcer must hash identical strings."""
    c = new_challenge(base, tool_call=TOOL_CALL)
    binding_from_minter = c["binding_sha256"]
    recanonicalized = gate_core.sha256_hex(tools.canonical_for_hook(TOOL_CALL["tool"], TOOL_CALL["args"]))
    assert binding_from_minter == recanonicalized


def test_approve_and_verify_locally(base, autumn):
    c = new_challenge(base)
    s, page = call(base, f"/a/{c['challenge_id']}")
    assert s == 200 and "meta-hackathon" in page and "Approve with passkey" in page
    s, r = approve(base, autumn, c["challenge_id"])
    assert s == 200 and r["status"] == "approved"
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert rec["status"] == "approved" and rec["action_sha256"] == hashlib.sha256(ACTION.encode()).hexdigest()
    assert local_verify.check(rec, ACTION, ORIGIN, RP_ID, autumn.pem) == []
    # local verifier rejects a different action text / a different pinned key / tampered signature
    assert local_verify.check(rec, ACTION + " and Maintainer", ORIGIN, RP_ID, autumn.pem)
    assert "public key does not match the pinned key" in local_verify.check(
        rec, ACTION, ORIGIN, RP_ID,
        SoftAuthenticator().key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    bad = json.loads(json.dumps(rec))
    sig = bytearray(unb64u(bad["assertion"]["signature"]))
    sig[-1] ^= 1
    bad["assertion"]["signature"] = b64u(bytes(sig))
    assert local_verify.check(bad, ACTION, ORIGIN, RP_ID, autumn.pem)


def test_enforcement_blocking_and_consumption(base, autumn):
    """The hook story, executed against the real gate: block when unapproved,
    allow exactly once when an approved bound challenge exists, fail closed after."""
    pin_once(gate_core.data_dir(), autumn.pem)
    patterns = [r"ssh git@100"]  # the subject is: tool_name + canonical args JSON
    # unapproved -> block
    v = tools.hook_verdict("terminal", {"command": "ssh git@100.64.0.10 -p 2222 grant-sorrel"},
                           patterns, require_passkey=True)
    assert v is not None and v["action"] == "block" and "gate_challenge" in v["message"]
    # mint the challenge WITH the binding the message tells the model to make
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    v = tools.hook_verdict(TOOL_CALL["tool"], TOOL_CALL["args"], patterns, require_passkey=True)
    assert v is None  # allowed exactly once
    row = gate_core.pending_for_binding(c["binding_sha256"])
    assert row is None  # consumed; a second identical shot must block again
    v = tools.hook_verdict(TOOL_CALL["tool"], TOOL_CALL["args"], patterns, require_passkey=True)
    assert v is not None and v["action"] == "block"
    # enforcement off -> inert whatever the args look like
    assert tools.hook_verdict("terminal", TOOL_CALL["args"], patterns, require_passkey=False) is None
    assert tools.hook_verdict("terminal", {"command": "ls"}, patterns, require_passkey=True) is None


def test_mismatch_and_replay_denied(base, autumn):
    c = new_challenge(base)
    approve(base, autumn, c["challenge_id"])
    other = hashlib.sha256(b"Delete repository autumn/meta-hackathon permanently").hexdigest()
    s, r = call(base, f"/verify/{c['challenge_id']}?action_sha256={other}")
    assert r == {"status": "denied"}  # never reveals the right hash
    # second approval of the same challenge (replay) is refused
    s, r = call(base, f"/a/{c['challenge_id']}/finish", autumn.get({"challenge": b64u(b"x" * 64)}))
    assert s == 409 and r["status"] == "denied"
    # an old assertion replayed onto a NEW challenge fails (challenge bound to nonce + text)
    c2 = new_challenge(base)
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    replay = {"id": rec["assertion"]["credential_id"], "rawId": rec["assertion"]["credential_id"],
              "type": "public-key", "clientExtensionResults": {},
              "response": {"authenticatorData": rec["assertion"]["authenticator_data"],
                           "clientDataJSON": rec["assertion"]["client_data_json"],
                           "signature": rec["assertion"]["signature"]}}
    s, r = call(base, f"/a/{c2['challenge_id']}/finish", replay)
    assert s == 403 and r["status"] == "denied"
    s, r = call(base, f"/verify/{c2['challenge_id']}?action_sha256={c2['action_sha256']}")
    assert r["status"] == "pending"


def test_no_approval_without_valid_assertion(base, autumn):
    c = new_challenge(base)
    impostor = SoftAuthenticator()
    impostor.cred_id = autumn.cred_id  # claims Autumn's credential id, wrong key
    s, opts = call(base, f"/a/{c['challenge_id']}/options", {})
    s, r = call(base, f"/a/{c['challenge_id']}/finish", impostor.get(opts))
    assert s == 403
    s, r = approve(base, autumn, c["challenge_id"], flags=0x01)  # presence but no user verification
    assert s == 403
    s, r = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert r["status"] == "pending"


def test_unknown_id_not_enumerable(base):
    s, r = call(base, f"/verify/{secrets.token_urlsafe(24)}?action_sha256={'0' * 64}")
    assert r == {"status": "denied"}


def test_expired(base, autumn):
    c = new_challenge(base)
    time.sleep(2.5)
    s, r = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert r["status"] == "expired"
    s, r = call(base, f"/a/{c['challenge_id']}/options", {})
    assert s == 409


def test_deny(base, autumn):
    c = new_challenge(base)
    s, r = call(base, f"/a/{c['challenge_id']}/deny", {})
    s, r = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert r == {"status": "denied"}


def test_audit_chain(base, autumn):
    ok, msg = gate_core.audit_verify()
    assert ok, msg
    p = Path(TMP) / "audit.jsonl"
    lines = p.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["requester"] = "autumn"
    lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")
    assert not gate_core.audit_verify()[0]


def test_tool_handlers_json_shapes(base, autumn):
    """Handlers never raise; success and error carry the same JSON shape."""
    # bad actions are rejected cleanly
    out = json.loads(tools.gate_challenge({"action_text": "short", "requester": "x"}))
    assert out["ok"] is False and "at least 40" in out["error"]
    # a real challenge -> handler returns instructions and a URL
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "sorrel"}))
    assert out["ok"] is True and out["url"].startswith("http") and "gate_verify" in out["instructions"]
    # status handler shape
    st = json.loads(tools.gate_status({"audit_check": True}))
    assert st["ok"] is True and "gate" in st


def pin_once(data_dir, pem, owner=None):
    if local_verify.pinned(data_dir, owner) is None:
        return local_verify.pin(data_dir, pem, owner)
    return str(local_verify.pin_for(data_dir, owner))


# ------------------------------------------- finding 1: approval confusion
def test_approval_page_shows_bound_tool_call(base):
    """The human signs what executes: the page must render the exact canonical
    tool call the binding covers, in its own prominent block, and say that the
    bound call — not the prose — is what executes."""
    c = new_challenge(base, tool_call=TOOL_CALL)
    s, page = call(base, f"/a/{c['challenge_id']}")
    assert s == 200
    canonical = tools.canonical_for_hook(TOOL_CALL["tool"], TOOL_CALL["args"])
    assert "THE EXACT COMMAND YOU ARE APPROVING" in page
    assert html.escape(canonical) in page  # the byte-exact canonical JSON, escaped
    assert "not the prose" in page and "executes" in page
    # text-only challenge: no bound-call block, and that is stated plainly
    c2 = new_challenge(base, requester="sorrel")
    s, page2 = call(base, f"/a/{c2['challenge_id']}")
    assert s == 200
    assert "THE EXACT COMMAND YOU ARE APPROVING" not in page2
    assert "No tool call is bound" in page2


def test_verify_record_is_minimized_to_local_verification_fields(base, autumn):
    """An approved /verify record contains exactly what local parent
    verification needs, not requester/audit/binding metadata that widens the
    bearer-readable disclosure."""
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert s == 200 and rec["status"] == "approved"
    assert set(rec) == {
        "status", "challenge_id", "action_sha256", "action_text", "approved_at",
        "origin", "rp_id", "challenge_b64url", "assertion", "credential_public_key",
    }
    assert "requester" not in rec
    assert "audit_head" not in rec
    assert "binding_sha256" not in rec
    assert "tool_call" not in rec
    assert "created_at" not in rec


def test_parent_verification_accepts_minimized_verify_record(base, autumn, monkeypatch):
    """Parent verification still succeeds when /verify omits non-crypto
    metadata, using only the minimized record contract."""
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION}))
    assert out["ok"] is True and out["verified"] is True, out


def test_gate_verify_reports_bound_tool_call(monkeypatch, base, autumn):
    """gate_verify tells the calling agent exactly what it verified, so it can
    confirm the approval covers the call it is about to make."""
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)  # fetch from the test gate
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION}))
    assert out["ok"] is True and out["verified"] is True, out
    assert out["bound_tool_call"] == TOOL_CALL
    assert out["approved_tool_call"] == TOOL_CALL
    assert out["binding_sha256"] == c["binding_sha256"]
    assert out["dispatch_binding"] == {
        "canonical_tool_call": tools.canonical_for_hook(TOOL_CALL["tool"], TOOL_CALL["args"]),
        "binding_sha256": c["binding_sha256"],
    }


def test_gate_verify_refuses_different_requested_tool_call(monkeypatch, base, autumn):
    """A caller cannot turn a verified approval into authorization for another call."""
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    different = {"tool": "terminal", "args": {"command": "delete everything"}}
    out = json.loads(tools.gate_verify({
        "challenge_id": c["challenge_id"], "action_text": ACTION,
        "tool_call": different,
    }))
    assert out["ok"] is True and out["verified"] is False
    assert any("does not match the approved tool call" in p for p in out["problems"])


def test_hook_refuses_row_with_inconsistent_bound_tool_call(monkeypatch):
    """The hook checks the stored call as well as its indexed binding hash."""
    call = {"tool": "terminal", "args": {"command": "echo approved"}}
    row = {"id": "row", "binding_sha256": gate_core.canonical_binding(call),
           "tool_call": json.dumps({"tool": "terminal", "args": {"command": "echo altered"}},
                                    sort_keys=True, separators=(",", ":"))}
    monkeypatch.setattr(gate_core, "pending_for_binding", lambda binding: row)
    verdict = tools.hook_verdict(call["tool"], call["args"], [r"echo"], True)
    assert verdict is not None and verdict["action"] == "block"
    assert "bound tool call" in verdict["message"]


def test_challenge_and_verify_paths_do_not_register_or_pin(monkeypatch, base):
    """Trust-anchor registration remains an explicit operator ceremony; these
    paths only read credentials/pins and never create either one."""
    before_credentials = gate_core.credential_count()
    pins_dir = gate_core.data_dir() / "pins"
    before_pins = sorted((p.name, p.read_bytes()) for p in pins_dir.glob("*.pem")) if pins_dir.exists() else []
    c = new_challenge(base, tool_call=TOOL_CALL)
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION}))
    assert out["verified"] is False
    after_pins = sorted((p.name, p.read_bytes()) for p in pins_dir.glob("*.pem")) if pins_dir.exists() else []
    assert gate_core.credential_count() == before_credentials
    assert after_pins == before_pins


def test_gate_challenge_requires_tool_call_when_enforced(monkeypatch):
    """With enforcement on, an action matching an authority pattern cannot be
    minted as signable prose alone — the exact tool_call must be bound."""
    from passkey_gate import cli
    text = ("Delete the build scratch tree by running rm -rf /tmp/scratch-build "
            "on the workshop host tonight.")
    monkeypatch.setattr(cli, "_cfg_cache", {"require_passkey": True, "patterns": [r"rm -rf"]})
    out = json.loads(tools.gate_challenge({"action_text": text, "requester": "sorrel"}))
    assert out["ok"] is False and "tool_call" in out["error"] and "exact" in out["error"]
    # supplying the exact call is accepted and binds it
    call_obj = {"tool": "terminal", "args": {"command": "rm -rf /tmp/scratch-build"}}
    out = json.loads(tools.gate_challenge({"action_text": text, "requester": "sorrel",
                                           "tool_call": call_obj}))
    assert out["ok"] is True and out["binding_sha256"]
    # enforcement off -> text-only challenges stay allowed
    monkeypatch.setattr(cli, "_cfg_cache", {"require_passkey": False, "patterns": [r"rm -rf"]})
    out = json.loads(tools.gate_challenge({"action_text": text, "requester": "sorrel"}))
    assert out["ok"] is True
    # enforcement on but the action matches no pattern -> text-only stays allowed
    monkeypatch.setattr(cli, "_cfg_cache", {"require_passkey": True, "patterns": [r"never-matches-this"]})
    out = json.loads(tools.gate_challenge({"action_text": text, "requester": "sorrel"}))
    assert out["ok"] is True


# ------------------------------- findings 3+4: consume race + approval expiry
def _bound_call(marker):
    """A tool call unique to one test: binding-scoped lookups (the hook,
    pending_for_binding) must not be satisfiable by approved rows that older
    tests legitimately leave behind for the shared canonical TOOL_CALL."""
    return {"tool": "terminal",
            "args": {"command": f"ssh git@100.64.0.10 -p 2222 probe-{marker}"}}


def expire_challenge(cid):
    """Fast-forward one challenge row past expires_at (the suite manipulates
    the temp DB directly rather than sleeping out the 2s TTL)."""
    gate_core.db().execute("update challenges set expires_at=? where id=?",
                           (time.time() - 1.0, cid))


def test_concurrent_consume_claims_exactly_once(base, autumn):
    """Finding 3 (engine): two threads racing consume() on the same approved
    row — the claim is one conditional UPDATE, so SQLite adjudicates it and
    exactly one caller ever gets True."""
    call = _bound_call("consume-race")
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    start = threading.Barrier(2, timeout=10)
    results = []

    def racer():
        start.wait()
        results.append(gate_core.consume(c["challenge_id"], c["binding_sha256"]))

    threads = [threading.Thread(target=racer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [False, True]  # one claim, never two
    assert gate_core.consume(c["challenge_id"], c["binding_sha256"]) is False


def test_concurrent_hook_race_allows_exactly_one(base, autumn, monkeypatch):
    """Finding 3 (hook): two identical tool calls that both look up the same
    approved challenge before either claims it — only ONE may execute; the
    loser must be blocked, not silently allowed."""
    pin_once(gate_core.data_dir(), autumn.pem)
    call = _bound_call("hook-race")
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    patterns = [r"ssh git@100"]
    bar = threading.Barrier(2, timeout=10)
    real_consume = gate_core.consume

    def synchronized_consume(cid, binding_sha):
        bar.wait()  # both threads hold the looked-up row before either claims
        return real_consume(cid, binding_sha)

    monkeypatch.setattr(gate_core, "consume", synchronized_consume)
    verdicts = []

    def shoot():
        verdicts.append(tools.hook_verdict(call["tool"], call["args"],
                                           patterns, require_passkey=True))

    threads = [threading.Thread(target=shoot) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    allowed = [v for v in verdicts if v is None]
    blocked = [v for v in verdicts if v is not None]
    assert len(allowed) == 1, verdicts  # pre-fix: the race allowed both
    assert len(blocked) == 1 and blocked[0]["action"] == "block"
    assert "already consumed or expired" in blocked[0]["message"]
    # the approval is spent: nothing more can execute on it
    assert gate_core.pending_for_binding(c["binding_sha256"]) is None


def test_expired_approval_never_executes(base, autumn):
    """Finding 4: an approval past expires_at authorises nothing — the hook
    blocks and the engine refuses the claim (leaving the row untouched)."""
    call = _bound_call("expiry-hook")
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    expire_challenge(c["challenge_id"])
    assert gate_core.consume(c["challenge_id"], c["binding_sha256"]) is False
    v = tools.hook_verdict(call["tool"], call["args"], [r"ssh git@100"],
                           require_passkey=True)
    assert v is not None and v["action"] == "block"
    assert "gate_challenge" in v["message"]  # points at a fresh approval
    row = gate_core.db().execute("select * from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert row["status"] == "approved"  # refused, not silently spent


def test_expired_approval_does_not_verify(base, autumn):
    """Finding 4: /verify reports an approved-but-expired challenge as
    'expired' — no verifiable record for a stale signature — and stays
    non-enumerable (wrong sha is still plain 'denied')."""
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    expire_challenge(c["challenge_id"])
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert s == 200 and rec["status"] == "expired"
    assert "assertion" not in rec  # no signature material for a stale approval
    s, r = call(base, f"/verify/{c['challenge_id']}?action_sha256={'f' * 64}")
    assert r == {"status": "denied"}  # unknown id vs wrong sha: indistinguishable


def test_gate_verify_rejects_stale_approval(monkeypatch, base, autumn):
    """End to end: gate_verify surfaces the expiry and refuses to vouch for a
    stale approval even before the local checks run."""
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    expire_challenge(c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"],
                                        "action_text": ACTION}))
    assert out["ok"] is True and out["verified"] is False
    assert out["status"] == "expired"


def test_hook_fails_closed_on_error(base, autumn, monkeypatch):
    """Finding 3 (fail closed): an exception anywhere in the verdict path must
    block — never allow, never raise — and must not spend the approval."""
    def boom(*a, **k):
        raise RuntimeError("gate db locked")
    call = _bound_call("fail-closed")
    patterns = [r"ssh git@100"]
    real_pending = gate_core.pending_for_binding
    monkeypatch.setattr(gate_core, "pending_for_binding", boom)
    v = tools.hook_verdict(call["tool"], call["args"], patterns, True)
    assert v is not None and v["action"] == "block"
    monkeypatch.setattr(gate_core, "pending_for_binding", real_pending)
    # approval in hand, but the claim itself explodes -> block, approval intact
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(gate_core, "consume", boom)
    v = tools.hook_verdict(call["tool"], call["args"], patterns, True)
    assert v is not None and v["action"] == "block"
    assert gate_core.pending_for_binding(c["binding_sha256"]) is not None


# --------------------------------- finding 10: consumption keeps approval time
def test_consume_preserves_approval_time(base, autumn):
    """Finding 10: the claim stamps consumed_at and must not touch
    decided_at — the row keeps the human's approval time, so the audit
    story can tell WHEN the human approved from WHEN the agent executed."""
    call = _bound_call("consumed-at")
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    row = gate_core.db().execute("select * from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    decided = row["decided_at"]
    assert decided is not None  # what approve() recorded
    assert gate_core.consume(c["challenge_id"], c["binding_sha256"]) is True
    row = gate_core.db().execute("select * from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert row["status"] == "consumed"
    assert row["decided_at"] == decided  # approval time survives the claim
    assert row["consumed_at"] is not None  # consumption has its own stamp
    assert row["consumed_at"] >= decided  # and happens at/after the approval


def test_consumed_at_null_until_consumed(base, autumn):
    """Finding 10: pending and approved-but-unclaimed rows carry no
    consumption stamp."""
    call = _bound_call("consumed-at-null")
    c = new_challenge(base, tool_call=call)
    row = gate_core.db().execute("select consumed_at from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert row["consumed_at"] is None
    approve(base, autumn, c["challenge_id"])
    row = gate_core.db().execute("select consumed_at from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert row["consumed_at"] is None  # approved, not yet consumed


def test_verify_record_reports_both_timestamps(base, autumn):
    """Finding 10 surfacing: /verify answers a spent approval with BOTH
    stamps (approval time + consumption time), carries no consumed_at
    before consumption, and stays non-enumerable for strangers."""
    bound = _bound_call("consumed-at-verify")
    c = new_challenge(base, tool_call=bound)
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert rec["status"] == "pending" and "consumed_at" not in rec
    approve(base, autumn, c["challenge_id"])
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert rec["status"] == "approved" and "consumed_at" not in rec
    assert gate_core.consume(c["challenge_id"], c["binding_sha256"]) is True
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert rec["status"] == "consumed"
    assert rec["approved_at"] is not None
    assert rec["consumed_at"] is not None and rec["consumed_at"] >= rec["approved_at"]
    assert "assertion" not in rec  # a spent approval hands out no signature material
    # a stranger with the id but the wrong sha still learns nothing
    s, r = call(base, f"/verify/{c['challenge_id']}?action_sha256={'f' * 64}")
    assert r == {"status": "denied"}


def test_gate_verify_surfaces_consumed_at(monkeypatch, base, autumn):
    """Finding 10 surfacing: gate_verify reports a spent approval as
    'consumed' with both timestamps instead of a bare denial."""
    call = _bound_call("consumed-at-gate-verify")
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    assert gate_core.consume(c["challenge_id"], c["binding_sha256"]) is True
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"],
                                        "action_text": ACTION}))
    assert out["ok"] is True and out["verified"] is False
    assert out["status"] == "consumed"
    assert out["approved_at"] is not None
    assert out["consumed_at"] is not None and out["consumed_at"] >= out["approved_at"]


def test_old_schema_db_migrates_with_consumed_at(tmp_path, monkeypatch):
    """Finding 10 migration: a pre-fix database (challenges already consumed
    under the old overwrite-decided_at behavior, no consumed_at column) must
    open cleanly — db() adds the column, historical rows backfill NULL."""
    monkeypatch.setenv("GATE_DATA", str(tmp_path))
    con = sqlite3.connect(tmp_path / "gate.db")  # the old schema shape, pre-fix
    con.executescript("""
        CREATE TABLE challenges(id TEXT PRIMARY KEY, action_text TEXT NOT NULL,
        action_sha256 TEXT NOT NULL, binding_sha256 TEXT, tool_call TEXT, requester TEXT NOT NULL,
        requester_owner TEXT, why TEXT, parent_approval TEXT, parent_verified TEXT,
        challenge BLOB NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
        status TEXT NOT NULL, decided_at REAL, credential_id TEXT, authenticator_data TEXT,
        client_data_json TEXT, signature TEXT, user_handle TEXT);
    """)
    old_cid = "old-schema-consumed-row-0000000000000"
    old_sha = hashlib.sha256(b"old row action text that is long enough").hexdigest()
    con.execute("insert into challenges(id, action_text, action_sha256, requester, challenge,"
                " created_at, expires_at, status, decided_at) values(?,?,?,?,?,?,?,?,?)",
                (old_cid, "old row action text that is long enough", old_sha, "sorrel",
                 b"\x00" * 64, 100.0, 200.0, "consumed", 150.0))
    con.commit()
    con.close()
    c = gate_core.db()  # migration runs here; must not raise
    cols = {r["name"]: r["type"] for r in c.execute("pragma table_info(challenges)").fetchall()}
    assert cols.get("consumed_at", "").upper() == "REAL"  # column added
    row = c.execute("select * from challenges where id=?", (old_cid,)).fetchone()
    assert row["status"] == "consumed" and row["decided_at"] == 150.0  # data intact
    assert row["consumed_at"] is None  # NULL backfill for pre-fix rows
    # the migrated row is served like any other: state plus both timestamps
    rec = gate_core.challenge_status(old_cid, old_sha)
    assert rec["status"] == "consumed" and rec["approved_at"] == 150.0
    assert rec["consumed_at"] is None


# ------------------- findings 14 + 9: record-bound challenge + never-raise
def test_assertion_bound_to_exact_recorded_challenge(base, autumn):
    """Finding 14: a signature obtained under one gate challenge must not
    verify a DIFFERENT record minted for the same action text — the nonce is
    sha256(action_text) + entropy, so the assertion is bound to the exact
    recorded challenge, not just the action hash embedded in its prefix."""
    c1 = new_challenge(base)
    approve(base, autumn, c1["challenge_id"])
    c2 = new_challenge(base)
    approve(base, autumn, c2["challenge_id"])
    s, rec1 = call(base, f"/verify/{c1['challenge_id']}?action_sha256={c1['action_sha256']}")
    s, rec2 = call(base, f"/verify/{c2['challenge_id']}?action_sha256={c2['action_sha256']}")
    assert s == 200 and rec1["status"] == "approved" and rec2["status"] == "approved"
    assert rec1["action_sha256"] == rec2["action_sha256"]
    assert rec1["challenge_b64url"] != rec2["challenge_b64url"]  # same text, different entropy
    # control: each record verifies against its own recorded challenge
    assert local_verify.check(rec1, ACTION, ORIGIN, RP_ID, autumn.pem) == []
    assert local_verify.check(rec2, ACTION, ORIGIN, RP_ID, autumn.pem) == []
    # exploit: rec1's valid signed assertion presented under rec2's record —
    # same action hash, different nonce. Pre-fix this verified; it must not.
    swapped = {**rec1, "challenge_b64url": rec2["challenge_b64url"]}
    problems = local_verify.check(swapped, ACTION, ORIGIN, RP_ID, autumn.pem)
    assert any("does not match the recorded challenge" in p for p in problems), problems
    assert problems  # never verified


def test_check_never_raises_on_malformed_records(base, autumn):
    """Finding 9: check() must return a problems list for ANY malformed or
    incomplete record — never raise (gate_verify's JSON handler contract)."""
    c = new_challenge(base)
    approve(base, autumn, c["challenge_id"])
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert s == 200 and rec["status"] == "approved"
    variants = {
        "missing assertion": {k: v for k, v in rec.items() if k != "assertion"},
        "missing credential_public_key": {k: v for k, v in rec.items() if k != "credential_public_key"},
        "missing challenge_b64url": {k: v for k, v in rec.items() if k != "challenge_b64url"},
        "missing action_sha256": {k: v for k, v in rec.items() if k != "action_sha256"},
        "missing approved_at, max_age set": {k: v for k, v in rec.items() if k != "approved_at"},
        "assertion not a dict": {**rec, "assertion": "not-a-dict"},
        "garbage base64 client data": {**rec, "assertion": {**rec["assertion"], "client_data_json": "a" * 5}},
        "client data not JSON": {**rec, "assertion": {**rec["assertion"], "client_data_json": b64u(b"not json")}},
        "garbage base64 signature": {**rec, "assertion": {**rec["assertion"], "signature": "###"}},
        "authenticator data too short": {**rec, "assertion": {**rec["assertion"], "authenticator_data": b64u(b"tiny")}},
        "garbage public key pem": {**rec, "credential_public_key": {"spki_pem": "not a pem"}},
        "record is not an object": "approved",
        "empty record": {},
    }
    for name, bad in variants.items():
        problems = local_verify.check(bad, ACTION, ORIGIN, RP_ID, autumn.pem,
                                       max_age=600 if name.startswith("missing approved_at") else None)
        assert isinstance(problems, list) and problems, name  # problems, never an exception
    # a record stripped of its recorded challenge can never verify (finding 14's other face)
    problems = local_verify.check(variants["missing challenge_b64url"], ACTION, ORIGIN, RP_ID, autumn.pem)
    assert any("does not match the recorded challenge" in p for p in problems), problems


# ---------------- findings 17 + 7: config-load failure + stale config cache
class FakeCtx:
    """Hermes-free plugin context: a settings dict with an optional injected
    storage failure — the exact seams apply_config() reads through."""

    def __init__(self, settings=None, fail_get=False):
        self.settings = {
            "origin": ORIGIN, "rp_id": RP_ID, "port": 0, "challenge_ttl": 2,
            "require_passkey": False, "authority_patterns": [],
            **(settings or {}),
        }
        self.fail_get = fail_get

    def get_config(self, key, default=None):
        if self.fail_get:
            raise RuntimeError("settings storage unavailable")
        return self.settings.get(key, default)

    def set_config(self, key, value):
        self.settings[key] = value


def reset_gate_config(monkeypatch, ctx=None):
    """Fresh config-cache state for one test, with gate_core.configure made
    inert so config tests cannot disturb the shared gate the rest of the
    suite talks to (apply_config still runs for real, including its typed
    coercions — those raise before configure is ever reached)."""
    from passkey_gate import cli
    monkeypatch.setattr(gate_core, "configure", lambda **kw: None)
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    monkeypatch.setattr(cli, "_cfg_cache", None)
    monkeypatch.setattr(cli, "_cfg_stamp", None, raising=False)
    monkeypatch.setattr(cli, "_settings_source", lambda: None, raising=False)
    return cli


def test_config_load_failure_fails_closed(monkeypatch):
    """Finding 17: a config that is PRESENT but fails to load (storage
    failure, malformed setting) must fail CLOSED — require_passkey treated
    as on for verdicts, an error marker carried, and the hook BLOCKS with a
    message that says the config failed to load. Pre-fix it silently
    allowed everything for the rest of the process."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    call = {"command": "ssh git@100.64.0.10 -p 2222 finding17-probe"}

    # present-but-raising: the settings storage itself explodes
    cli._ctx_ref = FakeCtx(fail_get=True)
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is True, cfg
    assert "RuntimeError" in cfg["_config_error"]
    v = passkey_gate._on_pre_tool_call("terminal", call, "t")
    assert v is not None and v["action"] == "block"
    assert "failed to load" in v["message"]
    assert "no approved passkey challenge" not in v["message"]
    # gate_challenge surfaces the config failure distinctly too
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "sorrel"}))
    assert out["ok"] is False and "failed to load" in out["error"]
    # a challenge bound to an exact tool_call needs no config and still mints
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "sorrel",
                                           "tool_call": TOOL_CALL}))
    assert out["ok"] is True and out["binding_sha256"]

    # present-but-malformed: a setting value that cannot be typed
    cli._ctx_ref = FakeCtx({"port": "abc", "require_passkey": True})
    cli._cfg_cache = None
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is True and "ValueError" in cfg["_config_error"]
    v = passkey_gate._on_pre_tool_call("terminal", call, "t")
    assert v is not None and v["action"] == "block" and "failed to load" in v["message"]


def test_unparseable_settings_source_fails_closed(monkeypatch):
    """Finding 17's production face inside Hermes: a config.yaml that exists
    but won't parse is served to readers as silent DEFAULTS (here: no
    passkey-gate settings at all, so enforcement off). Once the gate has been
    configured, its config canary is missing from those defaults, and the
    gate fails closed instead of running on settings nobody chose."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    ctx = FakeCtx({"require_passkey": True, "authority_patterns": [r"^terminal "]})
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    cli.stamp_config_canary(ctx)                      # an operator configured it
    assert cli.apply_config_safe()["require_passkey"] is True
    cli._cfg_cache = None
    ctx.settings.clear()                             # Hermes fell back to defaults
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is True, cfg
    assert "wasn't read as expected" in cfg["_config_error"]
    v = passkey_gate._on_pre_tool_call("terminal", {"command": "ls"}, "t")
    assert v is not None and v["action"] == "block" and "failed to load" in v["message"]


def test_cmd_set_takes_effect_without_restart(monkeypatch):
    """Finding 7 (stale-cache half): `hermes passkey-gate set require_passkey
    true` must be visible to the NEXT hook call in the same process — the
    running gateway must not keep the old enforcement state until restart."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    ctx = FakeCtx({"require_passkey": False, "authority_patterns": [r"ssh git@100"]})
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    call = {"command": "ssh git@100.64.0.10 -p 2222 cmd-set-probe"}
    assert passkey_gate._on_pre_tool_call("terminal", call, "t1") is None  # off: allowed

    out = cli.cmd_set(ctx, ["require_passkey", "true"])
    assert "require_passkey = true" in out

    v = passkey_gate._on_pre_tool_call("terminal", call, "t2")  # same process, no restart
    assert v is not None and v["action"] == "block"
    assert "gate_challenge" in v["message"]  # an ordinary enforcement block

    # finding 16: turning enforcement OFF is gate-weakening — refused without
    # a passkey approval of the exact server-derived phrase, and the next
    # verdict shows enforcement still ON (a refused change never leaks into
    # the cache, so the finding-7 reload story is unchanged)
    out = cli.cmd_set(ctx, ["require_passkey", "false"])
    assert "require_passkey = false" not in out
    assert "turns enforcement OFF" in out
    v = passkey_gate._on_pre_tool_call("terminal", call, "t3")
    assert v is not None and v["action"] == "block"


def test_settings_source_edit_reloads_without_restart(monkeypatch):
    """Finding 7 (out-of-band half): an edit to the settings source (config
    form, a second CLI process, a plain editor) must be observed by the
    running gate through the source's file signature — one stat per call,
    no restart, no permanently stale cache."""
    cli = reset_gate_config(monkeypatch)
    src = Path(TMP) / "fake-config.yaml"
    src.write_text("require_passkey: true\n")
    monkeypatch.setattr(cli, "_settings_source", lambda: src)
    ctx = FakeCtx({"require_passkey": True, "authority_patterns": []})
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    assert cli.apply_config_safe()["require_passkey"] is True

    # out-of-band edit: the values change AND the file signature moves
    ctx.settings["require_passkey"] = False
    st = src.stat()
    os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is False and "_config_error" not in cfg

    # no signature change -> the cache legitimately holds
    ctx.settings["require_passkey"] = True
    assert cli.apply_config_safe()["require_passkey"] is False


def test_absent_config_keeps_default_off(monkeypatch):
    """The not-configured case: with no config source at all (no Hermes
    runtime), default-off is legitimate and unchanged — no error marker, no
    block. Existing off-by-default behavior must survive the fix."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    assert cli.apply_config_safe() == {"require_passkey": False, "patterns": []}
    assert passkey_gate._on_pre_tool_call("terminal", {"command": "rm -rf /tmp/x"}, "t") is None


def test_register_with_broken_config_fails_closed(monkeypatch):
    """A config broken from the start must not kill registration — a dead
    register() leaves NO hook at all, the one fail-open path left. The
    plugin registers, and every call blocks on the config-error marker."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    registered = []

    class Ctx(FakeCtx):
        def register_tool(self, **kw):
            registered.append(kw["name"])

        def register_hook(self, name, handler):
            registered.append(name)

        # exact Hermes v0.23 PluginContext signature (a looser fake hid a
        # real load failure: the plugin never registered in Hermes)
        def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
            registered.append(name)

    passkey_gate.register(Ctx(fail_get=True))  # must not raise
    assert "pre_tool_call" in registered
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is True and cfg["_config_error"]
    v = passkey_gate._on_pre_tool_call("terminal", {"command": "ls"}, "t")
    assert v is not None and v["action"] == "block" and "failed to load" in v["message"]


# ------------------- finding 16: enforcement config is not agent-mutable
def weaken_phrase(key, new_value, old_value):
    """The server-derived phrase a passkey must sign to authorize a
    gate-weakening `set` (finding 16), naming old and new values (v0.7
    review M5)."""
    from passkey_gate import cli as _cli
    return _cli.weakening_phrase(key, new_value, old_value)


WEAKEN_OFF_PHRASE = weaken_phrase("require_passkey", False, True)


def settings_challenge(phrase):
    """A settings-change challenge minted the way `set` mints it (v0.7 review
    M1: only these can authorise a settings change)."""
    return dict(gate_core.create_challenge(phrase, "hermes-cli", _kind=gate_core.SETTINGS_KIND))


def _set_ctx(monkeypatch, **settings):
    """A FakeCtx wired through reset_gate_config for one cmd_set test."""
    cli = reset_gate_config(monkeypatch)
    ctx = FakeCtx(settings)
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    return cli, ctx


def _audit_records(event):
    path = Path(TMP) / "audit.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("event") == event:
            out.append(rec)
    return out


def _config_audit(key):
    return [r for r in _audit_records("config_changed") if r.get("key") == key]


def test_set_weakening_refused_without_approval(monkeypatch, base, autumn):
    """Finding 16 exploit: `set require_passkey false` while enforcement is ON,
    no approval — must be refused, the setting untouched, and the refusal
    itself must teach the recovery: the exact server-derived approval phrase,
    a minted approval URL for the human, and the --approve re-run."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    out = cli.cmd_set(ctx, ["require_passkey", "false"])
    assert "require_passkey = false" not in out  # not applied
    assert ctx.settings["require_passkey"] is True  # enforcement untouched
    assert WEAKEN_OFF_PHRASE in out  # the exact approval phrase, verbatim
    assert "--approve" in out  # how the change gets completed
    m = re.search(r"/a/([A-Za-z0-9_-]+)", out)
    assert m, out  # a minted approval URL to hand the human
    row = gate_core.db().execute("select * from challenges where id=?",
                                 (m.group(1),)).fetchone()
    assert row is not None and row["action_text"] == WEAKEN_OFF_PHRASE
    assert row["status"] == "pending"


def test_set_weakening_applied_with_passkey_approval(monkeypatch, base, autumn):
    """The same weakening change WITH a real human passkey signature over the
    exact phrase: fetched through gate_verify's path, verified locally against
    the pinned owner key, applied, and audited with the challenge id."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    c = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)  # the gate_verify fetch path
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c["challenge_id"]])
    assert "require_passkey = false" in out, out
    assert ctx.settings["require_passkey"] is False
    cc = _config_audit("require_passkey")
    assert cc, "config_changed audit entry missing"
    assert cc[-1]["weakened"] is True and cc[-1]["approved"] == c["challenge_id"]
    assert cc[-1]["old"] is True and cc[-1]["new"] is False


def test_set_weakening_consumes_the_approval_challenge(monkeypatch, base, autumn):
    """F1 (fresh review, live-reproduced twice with a real software
    authenticator): applying a gate-weakening change under --approve must
    burn the approval challenge in the same atomic conditional-UPDATE
    discipline as gate_core.consume() — the challenge is terminal afterwards
    (status consumed, consumed_at stamped), the verify endpoint answers
    'consumed' instead of still handing out an approved record, and the
    config_changed audit entry names the challenge id that was spent."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    c = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c["challenge_id"]])
    assert "require_passkey = false" in out, out
    # the challenge is spent: terminal status with BOTH stamps (decided_at
    # is the human's approval time, consumed_at is this application's claim)
    row = gate_core.db().execute("select status, consumed_at, decided_at from challenges"
                                 " where id=?", (c["challenge_id"],)).fetchone()
    assert row["status"] == "consumed", "challenge must be terminal after apply"
    assert row["consumed_at"] is not None and row["decided_at"] is not None
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert rec["status"] == "consumed", "verify endpoint must not report approved"
    assert rec["consumed_at"] and rec["approved_at"]
    # the burn is in the audit story: challenge_consumed for the claim, and
    # config_changed records the challenge id it consumed
    assert [r for r in _audit_records("challenge_consumed")
            if r.get("challenge_id") == c["challenge_id"]], "challenge_consumed missing"
    cc = _config_audit("require_passkey")
    assert cc and cc[-1]["approved"] == c["challenge_id"]
    assert cc[-1].get("consumed") == c["challenge_id"], \
        "config_changed must name the consumed challenge id"


def test_set_weakening_replay_of_used_approval_refused(monkeypatch, base, autumn):
    """The reviewer's live-reproduced scenario (probe_freshreview_replay.py):
    the human signs ONCE, cmd_set applies, the operator re-arms the gate,
    and the agent replays the SAME --approve challenge id. Pre-fix that
    disarmed the gate twice more within challenge_ttl with no new
    signature; post-fix every replay is refused with the single-use rule,
    the setting is untouched, and no phantom config_changed is audited."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    c = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    cid = c["challenge_id"]
    # 1. the one legitimate application — the human signed exactly this
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", cid])
    assert "require_passkey = false" in out, out
    # 2. the operator re-arms (the free, approval-free direction)
    out = cli.cmd_set(ctx, ["require_passkey", "true"])
    assert ctx.settings["require_passkey"] is True
    audited_before = len(_config_audit("require_passkey"))
    # 3. the replay: same cid, no new signature — refused, gate stays armed
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", cid])
    assert "REFUSED" in out, "a replayed approval must never re-apply"
    assert "single-use" in out, out  # the refusal names the single-use rule
    assert cid in out  # ...and the spent challenge it names
    assert ctx.settings["require_passkey"] is True  # NOT disarmed by the replay
    assert len(_config_audit("require_passkey")) == audited_before  # no phantom change
    # 4. a third identical replay: refused the same way, still untouched
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", cid])
    assert "REFUSED" in out and "single-use" in out, out
    assert ctx.settings["require_passkey"] is True


def test_set_weakening_concurrent_replays_exactly_one_applies(monkeypatch, base, autumn):
    """F1's race face: two simultaneous applications of the SAME approved
    challenge both pass verification while the row is still approved, so
    only the atomic claim can arbitrate — exactly one applies, the loser is
    refused with the single-use rule, and the audit log carries exactly one
    config_changed story for the race."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    c = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    cid = c["challenge_id"]
    audited_before = len(_config_audit("require_passkey"))

    # Both racers read the current value and pass verification BEFORE
    # either can apply, and both reach the atomic claim while the row is
    # still approved: barriers inside the verification and claim steps
    # make the double-apply deterministic instead of timing-dependent
    # (mirrors the consume() race test's discipline).
    verify_gate = threading.Barrier(2)
    claim_gate = threading.Barrier(2)
    orig_verify = cli._verify_weakening_approval
    orig_claim = gate_core.consume_approval

    def synced_verify(approve_cid, phrase):
        verify_gate.wait(timeout=30)
        return orig_verify(approve_cid, phrase)

    def synced_claim(cid, sha):
        claim_gate.wait(timeout=30)
        return orig_claim(cid, sha)

    monkeypatch.setattr(cli, "_verify_weakening_approval", synced_verify)
    monkeypatch.setattr(gate_core, "consume_approval", synced_claim)

    results = {}

    def racer(i):
        try:
            results[i] = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", cid])
        except Exception as exc:  # a thread crash must fail the test, not vanish
            results[i] = f"THREAD-CRASH {type(exc).__name__}: {exc}"

    threads = [threading.Thread(target=racer, args=(i,)) for i in (1, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    applied = [i for i, out in results.items() if "require_passkey = false" in out]
    refused = [i for i, out in results.items() if "REFUSED" in out]
    assert len(applied) == 1 and len(refused) == 1, results
    assert "single-use" in results[refused[0]]
    assert ctx.settings["require_passkey"] is False  # the winner's effect stands
    assert len(_config_audit("require_passkey")) == audited_before + 1


def test_set_weakening_fresh_approval_for_a_second_weakening(monkeypatch, base, autumn):
    """F1 must not over-block: the single-use rule spends one approval per
    application — a fresh human signature keeps working. A second, different
    weakening after the first approval was consumed applies normally, and
    the same key can be weakened again after re-arming with another fresh
    signature."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True,
                        authority_patterns=[r"rm -rf"])
    pin_once(gate_core.data_dir(), autumn.pem)
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    # first weakening: require_passkey off, its approval consumed on apply
    c1 = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c1["challenge_id"])
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c1["challenge_id"]])
    assert "require_passkey = false" in out, out
    # second weakening, DIFFERENT key, fresh signature: applies normally
    phrase2 = weaken_phrase("authority_patterns", [], [r"rm -rf"])
    c2 = settings_challenge(phrase2)
    approve(base, autumn, c2["challenge_id"])
    out = cli.cmd_set(ctx, ["authority_patterns", "[]", "--approve", c2["challenge_id"]])
    assert ctx.settings["authority_patterns"] == [], out
    cc = _config_audit("authority_patterns")
    assert cc and cc[-1]["weakened"] is True and cc[-1]["approved"] == c2["challenge_id"]
    # the same key again: re-arm, fresh signature, applies again
    cli.cmd_set(ctx, ["require_passkey", "true"])
    c3 = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c3["challenge_id"])
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c3["challenge_id"]])
    assert "require_passkey = false" in out, out
    assert ctx.settings["require_passkey"] is False


def test_set_strengthening_is_free_and_audited(monkeypatch):
    """Turning enforcement ON is the direction an attacker never wants: it
    applies immediately with no approval, and is still audited."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=False)
    out = cli.cmd_set(ctx, ["require_passkey", "true"])
    assert "require_passkey = true" in out
    assert ctx.settings["require_passkey"] is True
    cc = _config_audit("require_passkey")
    assert cc and cc[-1]["weakened"] is False and cc[-1]["approved"] is None
    assert cc[-1]["old"] is False and cc[-1]["new"] is True


def test_set_authority_pattern_removal_refused_without_approval(monkeypatch):
    """Disarming a pattern is the finding-16 exploit in list form: removing
    'rm -rf' from authority_patterns without a passkey approval is refused."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True,
                        authority_patterns=[r"ssh git@100", r"rm -rf"])
    out = cli.cmd_set(ctx, ["authority_patterns", '["ssh git@100"]'])
    assert ctx.settings["authority_patterns"] == [r"ssh git@100", r"rm -rf"]
    assert weaken_phrase("authority_patterns", ["ssh git@100"], [r"ssh git@100", r"rm -rf"]) in out
    assert "--approve" in out


def test_set_authority_patterns_emptying_refused_without_approval(monkeypatch):
    """Emptying the pattern list disarms every pattern at once — refused."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True,
                        authority_patterns=[r"ssh git@100"])
    out = cli.cmd_set(ctx, ["authority_patterns", "[]"])
    assert ctx.settings["authority_patterns"] == [r"ssh git@100"]
    assert weaken_phrase("authority_patterns", [], [r"ssh git@100"]) in out


def test_set_authority_pattern_addition_is_free(monkeypatch):
    """Adding a pattern only tightens the gate — applied with no approval."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True,
                        authority_patterns=[r"ssh git@100"])
    out = cli.cmd_set(ctx, ["authority_patterns", '["ssh git@100", "curl"]'])
    assert ctx.settings["authority_patterns"] == ["ssh git@100", "curl"]
    cc = _config_audit("authority_patterns")
    assert cc and cc[-1]["weakened"] is False and cc[-1]["approved"] is None
    assert cc[-1]["new"] == ["ssh git@100", "curl"]


def test_set_parent_allowlist_addition_refused_without_approval(monkeypatch):
    """Adding a parent-gate allowlist entry widens who the gate will fetch —
    gate-weakening, so it is refused without a passkey approval."""
    cli, ctx = _set_ctx(monkeypatch,
                        parent_gate_allowlist=["https://peer-a.example.ts.net:8445"])
    new = '["https://peer-a.example.ts.net:8445","https://peer-b.example.ts.net:8445"]'
    out = cli.cmd_set(ctx, ["parent_gate_allowlist", new])
    assert ctx.settings["parent_gate_allowlist"] == ["https://peer-a.example.ts.net:8445"]
    assert weaken_phrase("parent_gate_allowlist", json.loads(new),
                         ["https://peer-a.example.ts.net:8445"]) in out
    assert "--approve" in out


def test_set_parent_allowlist_removal_is_free(monkeypatch):
    """Removing an allowlist entry narrows the gate — free, and the classic
    flag-free dispatch shape keeps working for it."""
    cli, ctx = _set_ctx(monkeypatch,
                        parent_gate_allowlist=["https://peer-a.example.ts.net:8445",
                                                "https://peer-b.example.ts.net:8445"])
    out = cli.dispatch(ctx, "set parent_gate_allowlist https://peer-a.example.ts.net:8445")
    assert ctx.settings["parent_gate_allowlist"] == ["https://peer-a.example.ts.net:8445"]
    assert "parent_gate_allowlist = " in out
    cc = _config_audit("parent_gate_allowlist")
    assert cc and cc[-1]["weakened"] is False and cc[-1]["approved"] is None


def test_set_approve_with_wrong_action_text_refused(monkeypatch, base, autumn):
    """--approve with a challenge the human signed for DIFFERENT action text
    (an unconsumed but mismatched approval) must not authorize the change."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base)  # the classic ACTION text, genuinely human-signed
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c["challenge_id"]])
    assert ctx.settings["require_passkey"] is True  # unchanged
    assert "REFUSED" in out and "denied" in out  # mismatched sha -> denied


def test_set_approve_rejects_unapproved_and_bogus_challenges(monkeypatch, base, autumn):
    """--approve with a challenge nobody has signed yet, or a bogus id,
    refuses; nothing is applied."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    pending = settings_challenge(WEAKEN_OFF_PHRASE)
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", pending["challenge_id"]])
    assert ctx.settings["require_passkey"] is True
    assert "REFUSED" in out and "pending" in out
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", "A" * 24])
    assert ctx.settings["require_passkey"] is True
    assert "REFUSED" in out


# --------------------------- findings 18 + 12: pin ceremony hardening
def _pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _pem_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.mark.parametrize("pem, reason", [
    ("not a PEM", "PEM"),
    (_pem_private(ec.generate_private_key(ec.SECP256R1())), "public key"),
    (_pem_public(rsa.generate_private_key(public_exponent=65537, key_size=2048)), "EC"),
    (_pem_public(ec.generate_private_key(ec.SECP384R1())), "secp256r1"),
])
def test_pin_rejects_non_p256_public_pem_before_write(tmp_path, pem, reason):
    with pytest.raises(ValueError, match=reason):
        local_verify.pin(tmp_path, pem)
    assert not (tmp_path / "pinned_owner.pem").exists()


def test_pin_valid_key_is_exclusive_secure_and_symlink_safe(tmp_path):
    pem = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    path = Path(local_verify.pin(tmp_path, pem))
    assert path.read_text() == pem.strip() + "\n"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exists"):
        local_verify.pin(tmp_path, _pem_public(ec.generate_private_key(ec.SECP256R1())))
    assert path.read_text() == pem.strip() + "\n"

    peer_dir = tmp_path / "pins"
    peer_dir.mkdir()
    target = tmp_path / "untouched.pem"
    target.write_text("original")
    replacement = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    # finding 26: alice's destination is now derived from owner + key, so the
    # symlink must squat the exact file the ceremony will create
    link = peer_dir / local_verify.pin_for(tmp_path, "alice", replacement).name
    link.symlink_to(target)
    with pytest.raises(ValueError, match="already exists"):
        local_verify.pin(tmp_path, replacement, "alice")
    assert target.read_text() == "original"


def test_cmd_pin_refuses_invalid_and_existing_without_claiming_pinned(tmp_path, monkeypatch):
    from passkey_gate import cli
    pem_file = tmp_path / "bad.pem"
    pem_file.write_text("not a PEM")
    monkeypatch.setattr(gate_core, "data_dir", lambda: tmp_path / "data")
    out = cli.cmd_pin(None, [str(pem_file)])
    assert "REFUSED" in out and "pinned" not in out.lower()
    assert not (tmp_path / "data" / "pinned_owner.pem").exists()

    good = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    pem_file.write_text(good)
    assert "pinned owner key" in cli.cmd_pin(None, [str(pem_file)])
    out = cli.cmd_pin(None, [str(pem_file)])
    assert "REFUSED" in out and "already exists" in out
    assert "pinned owner key" not in out


# ----------------- finding 26: collision-resistant pin filenames
_LONG = "Autumn" + "x" * 34          # 40 chars: everything after this is truncated away


@pytest.mark.parametrize("owner_a, owner_b", [
    ("Sorrel!", "Sorrel-"),                 # '!' and '-' both slug to '-'
    (_LONG + "-one", _LONG + "-two"),       # >40 chars: same truncated slug
])
def test_slug_colliding_owners_pin_to_distinct_files_and_stay_attributed(
        tmp_path, owner_a, owner_b):
    """Finding 26: owners whose labels slug identically must not share a pin
    file (pre-fix the second pin was REFUSED as an overwrite of the first),
    and a lookup must never be served the other human's key."""
    pem_a = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    pem_b = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    assert local_verify._owner_slug(owner_a) == local_verify._owner_slug(owner_b)  # collision is real
    path_a = Path(local_verify.pin(tmp_path, pem_a, owner_a))
    path_b = Path(local_verify.pin(tmp_path, pem_b, owner_b))
    assert path_a != path_b
    for p, pem in ((path_a, pem_a), (path_b, pem_b)):
        assert p.parent == tmp_path / "pins"
        assert p.read_text() == pem.strip() + "\n"
        assert p.stat().st_mode & 0o777 == 0o600
        assert p.name.startswith(local_verify._owner_slug(owner_a) + "-")  # slug stays readable
    assert local_verify.pinned(tmp_path, owner_a) == pem_a.strip()
    assert local_verify.pinned(tmp_path, owner_b) == pem_b.strip()


def test_unpinned_slug_peer_is_not_served_the_other_pin(tmp_path):
    """Finding 26's core harm, one-sided: only 'Sorrel!'s key is pinned — a
    challenge claiming the slug-colliding owner 'Sorrel-' must find NO pin
    (so it asks for the key out of band), never silently verify against
    Sorrel!'s key."""
    pem_a = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    local_verify.pin(tmp_path, pem_a, "Sorrel!")
    assert local_verify.pinned(tmp_path, "Sorrel-") is None
    assert local_verify.pinned(tmp_path, "Sorrel!") == pem_a.strip()


def test_second_key_for_one_owner_pins_a_new_file_and_pinned_fails_closed(tmp_path):
    """Finding 26 + D8: a second, DIFFERENT key for one owner maps to its own
    file — the key material breaks the collision — so D8's exclusive-create
    refusal no longer turns 'same owner, new key' into a silent trust-anchor
    stand-off; the SAME key is still refused as an overwrite. The price is
    ambiguity, and pinned() pays it fail-closed: it names the files and
    refuses to guess which key is theirs; the operator keeps exactly one."""
    pem1 = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    pem2 = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    path1 = Path(local_verify.pin(tmp_path, pem1, "bob"))
    path2 = Path(local_verify.pin(tmp_path, pem2, "bob"))
    assert path1 != path2 and path1.exists() and path2.exists()
    with pytest.raises(ValueError, match="already exists"):   # same key, same file: D8 unchanged
        local_verify.pin(tmp_path, pem1, "bob")
    with pytest.raises(ValueError) as exc:                    # two keys, one owner: fail closed
        local_verify.pinned(tmp_path, "bob")
    msg = str(exc.value)
    assert "multiple pins" in msg
    assert path1.name in msg and path2.name in msg            # operator is told exactly what to resolve
    path2.unlink()                                            # resolve -> verification works again
    assert local_verify.pinned(tmp_path, "bob") == pem1.strip()


def test_pin_filename_derives_from_both_owner_and_key_material(tmp_path):
    """The filename collision is broken by BOTH inputs: same key under two
    owners -> two files (owner side), same owner with two keys -> two files
    (key side, previous test)."""
    pem = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    path_bob = Path(local_verify.pin(tmp_path, pem, "bob"))
    path_alice = Path(local_verify.pin(tmp_path, pem, "alice"))
    assert path_bob != path_alice
    assert local_verify.pinned(tmp_path, "bob") == pem.strip()
    assert local_verify.pinned(tmp_path, "alice") == pem.strip()


def test_legacy_slug_pin_filename_is_still_found(tmp_path):
    """Back-compat (finding 26): committed deployments carry pins/<slug>.pem
    files — pinned() must still find them; and when a new-format pin joins one
    for the same owner, the same fail-closed rule applies (keep exactly one
    file — even byte-identical content does not un-ambiguate the store)."""
    pem = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    pins = tmp_path / "pins"
    pins.mkdir()
    (pins / "bob.pem").write_text(pem)
    assert local_verify.pinned(tmp_path, "bob") == pem.strip()
    newer = _pem_public(ec.generate_private_key(ec.SECP256R1()))
    local_verify.pin(tmp_path, newer, "bob")
    with pytest.raises(ValueError, match="multiple pins") as exc:
        local_verify.pinned(tmp_path, "bob")
    assert "bob.pem" in str(exc.value)
    (pins / "bob.pem").write_text(newer)          # identical content is still ambiguous
    with pytest.raises(ValueError, match="multiple pins"):
        local_verify.pinned(tmp_path, "bob")
    (pins / "bob.pem").unlink()                   # keep exactly one
    assert local_verify.pinned(tmp_path, "bob") == newer.strip()


def test_set_approve_requires_a_pinned_owner_key(monkeypatch, base, autumn):
    """Pin missing -> refuse: an approval that cannot be checked against the
    out-of-band pinned key authorizes nothing (a self-registered rogue
    credential must not pass --approve)."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    c = settings_challenge(WEAKEN_OFF_PHRASE)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    monkeypatch.setattr(local_verify, "pinned", lambda data_dir, owner=None: None)
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c["challenge_id"]])
    assert ctx.settings["require_passkey"] is True
    assert "REFUSED" in out and "pin" in out


def test_set_approve_flag_needs_a_challenge_id(monkeypatch):
    """A dangling --approve is a usage error, never a silent apply."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve"])
    assert ctx.settings["require_passkey"] is True
    assert "challenge id" in out


# --------------- findings 21 + 13: signature-counter clone detection
def _fresh_gate_credential(tmp_path, monkeypatch, initial_count=0):
    """An isolated gate DB carrying one freshly registered SoftAuthenticator,
    so counter tests can present chosen sign counts without disturbing the
    shared module gate's credential bookkeeping (every approve elsewhere
    advances its stored counter)."""
    monkeypatch.setenv("GATE_DATA", str(tmp_path))
    a = SoftAuthenticator()
    tok = mint_token()
    opts = gate_core.registration_options(tok)
    r = gate_core.registration_finish(tok, opts["session_id"],
                                      a.create(opts, initial_count=initial_count))
    assert r.get("status") == "registered", r
    a.pem = r["spki_pem"]
    return a


def _stored_count(a):
    row = gate_core.db().execute("select sign_count from credentials where id=?",
                                 (b64u(a.cred_id),)).fetchone()
    assert row is not None
    return row["sign_count"]


def _approve_with_count(a, count):
    """Mint a challenge, then approve it with an assertion presenting a
    CHOSEN signature counter (a genuine authenticator would present its own
    next counter; a clone replays one the gate has already accepted)."""
    c = gate_core.create_challenge(ACTION, "sorrel")
    opts = json.loads(gate_core.approve_options(c["challenge_id"]))
    return c, gate_core.approve_finish(c["challenge_id"], a.get(opts, count=count))


def test_approval_with_advancing_counter_accepted_and_stored(tmp_path, monkeypatch):
    """Findings 21+13 (a): an approval whose counter ADVANCES past the stored
    count is accepted, and the stored credentials.sign_count becomes exactly
    that counter — the bookkeeping every later clone check depends on."""
    a = _fresh_gate_credential(tmp_path, monkeypatch)
    c, r = _approve_with_count(a, count=5)
    assert r == {"status": "approved"}, r
    assert _stored_count(a) == 5


def test_clone_replaying_counter_rejected_with_clone_suspicion(tmp_path, monkeypatch):
    """Findings 21+13 (b): a cloned authenticator replays a counter the gate
    has already accepted (or presents an older, forked one). The approval
    fails with a problem string that NAMES the clone suspicion (not a
    generic 'assertion invalid'), is audited as such, and leaves the
    challenge pending with the stored counter untouched."""
    a = _fresh_gate_credential(tmp_path, monkeypatch)
    _, r = _approve_with_count(a, count=5)
    assert r == {"status": "approved"}, r
    # same counter again on a fresh challenge -> clone evidence by name
    c2, r2 = _approve_with_count(a, count=5)
    assert r2["status"] == "denied", r2
    assert "clone" in r2["error"] and "counter" in r2["error"], r2
    # an older counter (a clone forked earlier) is refused the same way
    c3, r3 = _approve_with_count(a, count=3)
    assert r3["status"] == "denied" and "clone" in r3["error"], r3
    # the refusals were clean: nothing approved, nothing advanced
    assert _stored_count(a) == 5
    for c in (c2, c3):
        row = gate_core.db().execute("select status from challenges where id=?",
                                     (c["challenge_id"],)).fetchone()
        assert row["status"] == "pending"
    audit_text = (Path(str(tmp_path)) / "audit.jsonl").read_text()
    assert "clone suspected" in audit_text  # clone evidence is audited distinctly


def test_counterless_authenticator_keeps_working_across_approvals(tmp_path, monkeypatch):
    """Findings 21+13 (c): counterless authenticators (e.g. platform passkeys)
    report 0 forever — 0 after 0 is NOT regression evidence and must never
    break the approval flow."""
    a = _fresh_gate_credential(tmp_path, monkeypatch)  # attestation counter 0
    for _ in range(3):
        c, r = _approve_with_count(a, count=0)
        assert r == {"status": "approved"}, r
    assert _stored_count(a) == 0  # still counterless, still allowed


def test_registration_stores_the_attestations_initial_counter(tmp_path, monkeypatch):
    """Findings 21+13 (d): registration extracts the credential's INITIAL
    signature counter from the attestation and stores it — the baseline
    every later approval must advance past, so replaying the registration
    counter is already clone-shaped."""
    a = _fresh_gate_credential(tmp_path, monkeypatch, initial_count=7)
    assert _stored_count(a) == 7  # the attestation's counter, not a hardcoded 0
    # the stored baseline is USED: presenting the count it registered with
    # is refused as clone suspicion
    _, r = _approve_with_count(a, count=7)
    assert r["status"] == "denied" and "clone" in r["error"], r
    # ...and one that advances past it is accepted and recorded
    c2, r2 = _approve_with_count(a, count=8)
    assert r2 == {"status": "approved"}, r2
    assert _stored_count(a) == 8


def test_concurrent_clone_claims_let_exactly_one_approval_through(tmp_path, monkeypatch):
    """Findings 21+13 (atomicity): two assertions presenting the SAME counter
    on two different challenges, racing the approval. The counter claim must
    be one conditional UPDATE, so exactly one approval lands; the loser is
    refused as clone suspicion BEFORE its challenge flips to approved.
    Pre-fix both approvals landed and the stored counter was clobbered."""
    a = _fresh_gate_credential(tmp_path, monkeypatch)
    pending = []
    for _ in range(2):
        c = gate_core.create_challenge(ACTION, "sorrel")
        opts = json.loads(gate_core.approve_options(c["challenge_id"]))
        pending.append((c, opts))
    real_verify = gate_core.verify_authentication_response
    bar = threading.Barrier(2, timeout=10)

    def synchronized_verify(**kw):
        bar.wait()  # both assertions have read the SAME stored counter first
        return real_verify(**kw)

    monkeypatch.setattr(gate_core, "verify_authentication_response", synchronized_verify)
    results = []

    def shoot(c, opts):
        results.append(gate_core.approve_finish(c["challenge_id"], a.get(opts, count=9)))

    threads = [threading.Thread(target=shoot, args=ch) for ch in pending]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r["status"] for r in results) == ["approved", "denied"], results
    denied = next(r for r in results if r["status"] == "denied")
    assert "clone" in denied["error"], denied
    assert _stored_count(a) == 9  # advanced exactly once, by the winner
    statuses = [gate_core.db().execute("select status from challenges where id=?",
                                       (c["challenge_id"],)).fetchone()["status"]
                for c, _ in pending]
    assert sorted(statuses) == ["approved", "pending"]  # the loser never landed


def test_check_requires_the_assertions_counter_field(tmp_path, monkeypatch):
    """Finding 21 (offline floor): authenticatorData's fixed header is
    rpIdHash(32) + flags(1) + signCount(4) — an assertion truncated past the
    flags byte carries NO signature counter. No real authenticator and no
    gate-approved record can look like that, so check() must refuse it:
    offline verification cannot VALIDATE the counter (no per-credential
    state), but the assertion must at least SHOW one."""
    a = _fresh_gate_credential(tmp_path, monkeypatch)
    c, r = _approve_with_count(a, count=5)
    assert r == {"status": "approved"}, r
    rec = dict(gate_core.challenge_status(c["challenge_id"], c["action_sha256"]))
    assert local_verify.check(rec, ACTION, ORIGIN, RP_ID, a.pem) == []  # control
    truncated = json.loads(json.dumps(rec))
    ad = local_verify.b64u(truncated["assertion"]["authenticator_data"])
    truncated["assertion"]["authenticator_data"] = b64u(ad[:35])  # header + partial counter
    problems = local_verify.check(truncated, ACTION, ORIGIN, RP_ID, a.pem)
    assert "authenticator_data is missing or malformed" in problems, problems


# ------------------- finding 22: authority_patterns are validated at set time

def test_set_valid_authority_patterns_persist_and_enforce(monkeypatch):
    """Finding 22's other face: set-time validation must not tighten the
    legitimate path. A sound pattern set through cmd_set persists exactly as
    given (a pattern ADDITION stays free — validation happens before the
    weakening classification, never instead of it) and the hook enforces the
    stored list as today: a matching call is blocked and pointed at
    gate_challenge; a non-matching call stays untouched."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    out = cli.cmd_set(ctx, ["authority_patterns", '["^terminal .*rm "]'])
    assert "REFUSED" not in out
    assert ctx.settings["authority_patterns"] == ["^terminal .*rm "]
    v = tools.hook_verdict("terminal", {"command": "rm -rf /tmp/scratch"},
                           ctx.settings["authority_patterns"],
                           ctx.settings["require_passkey"])
    assert v is not None and v["action"] == "block" and "gate_challenge" in v["message"]
    assert tools.hook_verdict("terminal", {"command": "ls"},
                              ctx.settings["authority_patterns"], True) is None


def test_hook_survives_patterns_smuggled_past_cmd_set(monkeypatch, caplog):
    """Finding 22 defense in depth: the settings file is not written only by
    cmd_set, so a pattern can reach config WITHOUT set-time validation (an
    out-of-band edit). Such a pattern must not crash hook_verdict or turn
    into an opaque fail-closed block: it is skipped as non-matching and
    logged, while the sound patterns in the same list still enforce."""
    import logging
    from passkey_gate import cli
    call = {"tool": "terminal", "args": {"command": "ssh git@100.64.0.10"}}
    with caplog.at_level(logging.WARNING, logger="passkey_gate.tools"):
        # a list of ONLY unusable patterns: nothing can match -> verdict None
        for smuggled in (["^terminal ("],   # does not compile
                         ["*"],              # does not compile
                         [123, None]):       # not even strings
            assert tools.hook_verdict(call["tool"], call["args"], smuggled, True) is None, smuggled
        # broken + sound in one list: the sound pattern still enforces
        v = tools.hook_verdict(call["tool"], call["args"],
                               ["^terminal (", r"ssh git@100"], True)
        assert v is not None and v["action"] == "block"
        # every skipped pattern is logged so the operator can find the dead rule
        assert any("non-matching" in r.getMessage() for r in caplog.records)
    # the prose-check loop in gate_challenge is equally smuggle-proof: the
    # handler answers JSON, it never raises, with a broken pattern in config
    monkeypatch.setattr(cli, "_cfg_cache", {"require_passkey": True, "patterns": [123]})
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "sorrel"}))
    assert out["ok"] is True  # broken pattern skipped; the challenge mints normally


def test_block_message_carries_the_pattern_only_as_delimited_data():
    """Finding 22: the matched pattern reaches the agent reading the block
    message only as clearly delimited, escaped, length-capped DATA — a
    stable rule ID (its position in the configured list) plus a
    backtick-fenced pattern — never as free prose an out-of-band config
    edit could aim at the agent."""
    v = tools.hook_verdict("terminal", {"command": "ls"}, ["^terminal"], True)
    assert v is not None and v["action"] == "block"
    # the exact shape: stable rule ID, then the fenced pattern
    assert "(matched rule authority_patterns[0]: `^terminal`)" in v["message"]
    # the rule ID is the pattern's position in the configured list
    v = tools.hook_verdict("terminal", {"command": "ls"},
                           ["^nope", "^other", "^terminal"], True)
    assert "(matched rule authority_patterns[2]: `^terminal`)" in v["message"]
    # a pattern carrying backticks cannot break out of the fence
    v = tools.hook_verdict("terminal", {"command": "rm `whoami` /tmp"},
                           ["rm `whoami`"], True)
    assert v["action"] == "block"
    assert "rule authority_patterns[0]: `rm \\`whoami\\``" in v["message"]
    # an oversized pattern is echoed capped, never in full: this one is
    # legal at set time (199 chars <= MAX_PATTERN_LEN) but over the echo cap
    long_pat = "^terminal(?:" + "a" * 184 + ")? "  # the big group is optional -> still matches
    assert len(long_pat) <= tools.MAX_PATTERN_LEN and len(long_pat) > tools.PATTERN_DISPLAY_CAP
    v = tools.hook_verdict("terminal", {"command": "ls"}, [long_pat], True)
    assert v["action"] == "block"
    cap = tools.PATTERN_DISPLAY_CAP
    assert ("rule authority_patterns[0]: `" + long_pat[:cap] + "…`") in v["message"]
    assert "a" * (cap + 10) not in v["message"]  # the untruncated tail never reaches the agent


# ------------------------- hook re-verifies approvals against the pinned key
def test_hook_refuses_approval_from_unpinned_credential(base, autumn):
    """An approval signed by a credential other than the pinned owner key —
    e.g. a software key an agent registered through a bootstrap token it
    minted itself — must never let an enforced call through. The DB row
    saying 'approved' is not proof; the hook re-verifies against the pin."""
    pin_once(gate_core.data_dir(), autumn.pem)
    rogue = SoftAuthenticator()
    tok = mint_token()
    s, opts = call(base, "/register/options", {"token": tok})
    assert s == 200
    s, r = call(base, "/register/finish", {"token": tok, "session_id": opts["session_id"],
                                           "credential": rogue.create(opts)})
    assert s == 200, r
    bound = _bound_call("rogue-credential")
    c = new_challenge(base, tool_call=bound, requester="rogue-probe")
    s, r = approve(base, rogue, c["challenge_id"])
    assert s == 200 and r.get("status") == "approved", r  # the gate accepted it...
    v = tools.hook_verdict(bound["tool"], bound["args"], [r"ssh git@100"], require_passkey=True)
    assert v is not None and v["action"] == "block"  # ...the hook does not
    assert "pinned owner key" in v["message"]
    row = gate_core.db().execute("select status from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert row["status"] == "approved"  # refused, not spent
    # and the genuine owner's approval of the same call still works
    c2 = new_challenge(base, tool_call=bound, requester="rogue-probe")
    approve(base, autumn, c2["challenge_id"])
    assert tools.hook_verdict(bound["tool"], bound["args"], [r"ssh git@100"],
                              require_passkey=True) is None


def test_hook_blocks_when_no_owner_key_pinned(monkeypatch, base, autumn):
    """With no pin there is nothing to verify against: fail closed."""
    bound = _bound_call("no-pin")
    c = new_challenge(base, tool_call=bound, requester="nopin-probe")
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(local_verify, "pinned", lambda *a, **k: None)
    v = tools.hook_verdict(bound["tool"], bound["args"], [r"ssh git@100"], require_passkey=True)
    assert v is not None and v["action"] == "block" and "no owner key is pinned" in v["message"]


# ------------------------------------------------ HTTP surface hardening
def _raw_post(base, path, body: bytes, headers: dict):
    req = urllib.request.Request(base + path, method="POST", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_http_challenge_requires_mint_token(base):
    """The exposed origin is reachable by more than this host's agents:
    anonymous HTTP minting is refused; the operator's mint token works."""
    body = json.dumps({"action_text": ACTION, "requester": "stranger"}).encode()
    s, r = _raw_post(base, "/challenge", body, {"Content-Type": "application/json"})
    assert s == 401 and "mint token" in r["error"]
    s, r = _raw_post(base, "/challenge", body, {"Content-Type": "application/json",
                                                 "Authorization": "Bearer wrong-token"})
    assert s == 401
    s, r = _raw_post(base, "/challenge", body, {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + gate_core.mint_api_token()})
    assert s == 201 and r["challenge_id"]


def test_mint_token_is_stable_and_private(base):
    t1, t2 = gate_core.mint_api_token(), gate_core.mint_api_token()
    assert t1 == t2 and len(t1) >= 40
    mode = (gate_core.data_dir() / gate_core.MINT_TOKEN_NAME).stat().st_mode & 0o777
    assert mode == 0o600


def test_cross_site_form_post_to_deny_is_refused(base):
    """A cross-site <form> can only send simple content types; the gate
    accepts JSON only, so a text/plain deny never reaches the handler."""
    c = new_challenge(base, tool_call=_bound_call("csrf-deny"), requester="csrf-probe")
    s, r = _raw_post(base, f"/a/{c['challenge_id']}/deny", b"{}", {"Content-Type": "text/plain"})
    assert s == 415
    row = gate_core.db().execute("select status from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert row["status"] == "pending"


def test_negative_content_length_does_not_hang(base):
    """rfile.read(-1) would wait for EOF and pin a server thread."""
    import socket
    from urllib.parse import urlparse
    u = urlparse(base)
    with socket.create_connection((u.hostname, u.port), timeout=5) as sock:
        sock.sendall(b"POST /a/x/deny HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: -1\r\n\r\n")
        sock.settimeout(5)
        reply = sock.recv(200)
    assert reply.startswith(b"HTTP/1.0 400") or reply.startswith(b"HTTP/1.1 400"), reply


def test_signature_covers_tool_call_binding(base, autumn):
    """H5: the binding is part of the signed nonce. Rewriting an approved
    row's tool_call + binding_sha256 in the DB (a consistent tamper the
    stored-call re-hash cannot see) must not yield an executable approval."""
    pin_once(gate_core.data_dir(), autumn.pem)
    signed_call = _bound_call("signed-binding")
    c = new_challenge(base, tool_call=signed_call, requester="h5-probe")
    row = gate_core.db().execute("select challenge from challenges where id=?",
                                 (c["challenge_id"],)).fetchone()
    assert gate_core.challenge_covers_binding(row["challenge"], c["binding_sha256"])
    approve(base, autumn, c["challenge_id"])
    evil = {"tool": "terminal", "args": {"command": "ssh git@100.64.0.10 -p 2222 drop-everything"}}
    evil_json = gate_core.canonical_binding_json(evil)
    gate_core.db().execute("update challenges set tool_call=?, binding_sha256=? where id=?",
                           (evil_json, gate_core.sha256_hex(evil_json), c["challenge_id"]))
    v = tools.hook_verdict(evil["tool"], evil["args"], [r"ssh git@100"], require_passkey=True)
    assert v is not None and v["action"] == "block"
    assert "does not cover this tool-call binding" in v["message"]


def test_gate_verify_tolerates_surrounding_whitespace(monkeypatch, base, autumn):
    """The gate signs the stripped text; a trailing newline in the caller's
    copy must still verify (it used to fail 'action_sha256 does not match')."""
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base, requester="ws-probe")
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"],
                                        "action_text": "  " + ACTION + "\n"}))
    assert out["verified"] is True, out


def test_handlers_never_raise_on_bad_types():
    """Hermes handler contract: same JSON shape on error, never an exception."""
    out = json.loads(tools.gate_verify({"challenge_id": "x", "action_text": ACTION,
                                        "wait_seconds": "abc"}))
    assert out["ok"] is False and "wait_seconds" in out["error"]
    out = json.loads(tools.gate_verify({"challenge_id": 5, "action_text": ACTION}))
    assert out["ok"] is False
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "a",
                                           "requester_owner": 7}))
    assert out["ok"] is False and "requester_owner" in out["error"]



def test_cli_registers_with_hermes_signature_and_runs(monkeypatch, capsys):
    """register() must use Hermes's register_cli_command(name, help,
    setup_fn, handler_fn) contract, and the command must actually dispatch
    when argparse drives it the way `hermes <name> ...` does."""
    import argparse
    import passkey_gate
    reset_gate_config(monkeypatch)
    seen = {}

    class Ctx(FakeCtx):
        def register_tool(self, **kw):
            pass

        def register_hook(self, name, handler):
            pass

        def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
            assert isinstance(help, str) and callable(setup_fn) and callable(handler_fn)
            seen.update(name=name, setup_fn=setup_fn, handler_fn=handler_fn)

    passkey_gate.register(Ctx())
    assert seen["name"] == "passkey-gate"
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    p = sub.add_parser("passkey-gate")
    seen["setup_fn"](p)
    p.set_defaults(func=seen["handler_fn"])
    args = parser.parse_args(["passkey-gate", "nonsense-subcommand"])
    assert args.func(args) == 2
    assert "usage: hermes passkey-gate" in capsys.readouterr().out


# ------------------------------------------- A4 (v0.7 review M3): never fail open
def test_unreadable_canary_content_fails_closed_not_open(monkeypatch, tmp_path):
    """A canary copy that isn't valid UTF-8 raised UnicodeDecodeError out of
    the hook, and Hermes treats a raising hook as 'allow'."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    ctx = FakeCtx({"require_passkey": True, "authority_patterns": [r"^terminal .*rm -rf"]})
    monkeypatch.setattr(cli, "_ctx_ref", ctx)
    cli.stamp_config_canary(ctx)
    cli._canary_file().write_bytes(b"\xff\xfe\x00junk")
    cli._cfg_cache = None
    v = passkey_gate._on_pre_tool_call("terminal", {"command": "rm -rf ./important"}, "t")
    assert v is not None and v["action"] == "block", v


def test_any_exception_in_the_hook_blocks(monkeypatch):
    import passkey_gate
    reset_gate_config(monkeypatch)
    from passkey_gate import cli as _cli
    def boom():
        raise RuntimeError("unexpected")
    monkeypatch.setattr(_cli, "apply_config_safe", boom)
    v = passkey_gate._on_pre_tool_call("terminal", {"command": "ls"}, "t")
    assert v is not None and v["action"] == "block" and "unexpected" in v["message"]
    # a future Hermes that stops passing task_id must not turn into 'allow' either
    v = passkey_gate._on_pre_tool_call("terminal", {"command": "ls"})
    assert v is not None and v["action"] == "block"


# ------------- v0.7 review M1 / A2 and M5 / A6: settings approvals
def test_a_tool_call_approval_cannot_authorise_a_settings_change(monkeypatch, base, autumn):
    """M1 exploit: the agent mints the exact settings phrase as action text,
    bound to a harmless tool call; the page tells the human to judge the
    command; the human approves 'read README'. That must not turn
    enforcement off."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    pin_once(gate_core.data_dir(), autumn.pem)
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    c = new_challenge(base, text=WEAKEN_OFF_PHRASE, requester="helpful-agent",
                      tool_call={"tool": "read_file", "args": {"path": "README.md"}})
    approve(base, autumn, c["challenge_id"])
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c["challenge_id"]])
    assert ctx.settings["require_passkey"] is True, out
    assert "wasn't created by passkey-gate for a settings change" in out
    # and a text-only agent request with the same phrase doesn't count either
    c2 = new_challenge(base, text=WEAKEN_OFF_PHRASE, requester="helpful-agent")
    approve(base, autumn, c2["challenge_id"])
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c2["challenge_id"]])
    assert ctx.settings["require_passkey"] is True, out
    assert not gate_core.consume_approval(c2["challenge_id"], gate_core.sha256_hex(WEAKEN_OFF_PHRASE))


def test_agents_cannot_use_the_gates_own_requester_name(base):
    s, r = call(base, "/challenge", {"action_text": ACTION, "requester": "Hermes-CLI"})
    assert s == 422 and "reserved" in r["error"]
    out = json.loads(tools.gate_challenge({"action_text": ACTION, "requester": "hermes-cli"}))
    assert out["ok"] is False and "reserved" in out["error"]


def test_settings_phrase_shows_what_is_removed_and_the_old_value():
    """M5: a near-identical edit (capital T never matches the 'terminal'
    tool) must read as removing the existing pattern, not as the same rule."""
    from passkey_gate import cli as _cli
    old = ["^terminal .*(rm -rf|curl )"]
    new = ["^Terminal .*(rm -rf|curl )"]
    phrase = _cli.weakening_phrase("authority_patterns", new, old)
    assert 'REMOVES 1 pattern(s): "^terminal .*(rm -rf|curl )"' in phrase
    assert 'ADDS 1 pattern(s): "^Terminal .*(rm -rf|curl )"' in phrase
    assert "from " + json.dumps(old, separators=(",", ":")) in phrase


def test_a_settings_approval_only_applies_to_the_state_it_was_granted_for(monkeypatch, base, autumn):
    """The phrase names the old value, so an approval granted while the list
    was A can't be used after the list has changed to B."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True, authority_patterns=["a", "b"])
    pin_once(gate_core.data_dir(), autumn.pem)
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    c = settings_challenge(weaken_phrase("authority_patterns", ["a"], ["a", "b"]))
    approve(base, autumn, c["challenge_id"])
    ctx.settings["authority_patterns"] = ["a", "b", "c"]         # state moved on
    out = cli.cmd_set(ctx, ["authority_patterns", '["a"]', "--approve", c["challenge_id"]])
    assert ctx.settings["authority_patterns"] == ["a", "b", "c"], out


def test_settings_requests_get_their_own_banner_and_skip_the_global_cap(monkeypatch):
    reset_gate_config(monkeypatch)
    monkeypatch.setattr(gate_core, "MAX_PENDING_CHALLENGES_TOTAL", 0)
    c = settings_challenge(WEAKEN_OFF_PHRASE)                     # not starved by agents
    row = gate_core.db().execute("select * from challenges where id=?", (c["challenge_id"],)).fetchone()
    assert "OWN SECURITY SETTINGS" in gate_core.approval_page(row)


# ------------------------------- v0.7 review M4 / A5: one trust store in Hermes
def test_gate_data_override_is_ignored_inside_hermes(monkeypatch, tmp_path):
    """Inside Hermes, GATE_DATA must not redirect pins, approvals, the canary
    or the audit log to a store a shell can seed."""
    import types
    real = tmp_path / "hermes-plugin-data"
    fake_mod = types.ModuleType("plugins.plugin_storage")
    fake_mod.plugin_data_dir = lambda name: real
    monkeypatch.setitem(sys.modules, "plugins", types.ModuleType("plugins"))
    monkeypatch.setitem(sys.modules, "plugins.plugin_storage", fake_mod)
    monkeypatch.setenv("GATE_DATA", str(tmp_path / "attacker-seeded"))
    assert gate_core.data_dir() == real
    monkeypatch.delitem(sys.modules, "plugins.plugin_storage")
    assert gate_core.data_dir() == tmp_path / "attacker-seeded"   # outside Hermes: honoured


# ------------------- 8 Nov field incident: approved call run with an extra arg
def test_hook_explains_extra_argument_and_still_blocks(base, autumn):
    """The agent got `{command}` signed but ran `{command, timeout: 60}`.
    The binding differs, so the hook must still block, and it must say which
    argument differs and repeat the approved call, not tell the agent to go
    and get another signature. The approval stays unspent, and the
    verbatim retry goes through."""
    pin_once(gate_core.data_dir(), autumn.pem)
    call = _bound_call("near-miss")
    patterns = [r"ssh git@100"]
    c = new_challenge(base, tool_call=call, requester="bramble")
    approve(base, autumn, c["challenge_id"])
    with_timeout = dict(call["args"], timeout=60)
    v = tools.hook_verdict(call["tool"], with_timeout, patterns, True)
    assert v is not None and v["action"] == "block"
    assert "adds `timeout` = 60" in v["message"]
    assert json.dumps(call, sort_keys=True) in v["message"]
    assert gate_core.pending_for_binding(c["binding_sha256"]) is not None  # not spent
    assert tools.hook_verdict(call["tool"], call["args"], patterns, True) is None


def test_hook_hint_names_missing_and_changed_arguments(base, autumn):
    call = {"tool": "terminal", "args": {"command": "ssh git@100.64.0.10 probe-changed",
                                         "timeout": 30, "workdir": "/srv"}}
    c = new_challenge(base, tool_call=call, requester="bramble")
    approve(base, autumn, c["challenge_id"])
    v = tools.hook_verdict("terminal", {"command": call["args"]["command"], "timeout": 90},
                           [r"ssh git@100"], True)
    assert v["action"] == "block"
    assert "changes `timeout` (approved: 30, this call: 90)" in v["message"]
    assert "leaves out `workdir`" in v["message"]
    assert gate_core.pending_for_binding(c["binding_sha256"]) is not None


def test_hook_gives_no_hint_for_an_unrelated_call(base, autumn):
    """No argument in common: a different action, so the normal message."""
    call = _bound_call("unrelated-approved")
    c = new_challenge(base, tool_call=call, requester="bramble")
    approve(base, autumn, c["challenge_id"])
    v = tools.hook_verdict("terminal", {"command": "ssh git@100.64.0.10 something-else-entirely"},
                           [r"ssh git@100"], True)
    assert v["action"] == "block"
    assert "no approved passkey challenge covers it" in v["message"]


def test_near_miss_hint_ignores_pending_and_consumed(base, autumn):
    """Only an approved, unspent approval can be the near miss: an unsigned
    request or a used approval gives no hint."""
    pending = _bound_call("hint-pending")
    new_challenge(base, tool_call=pending, requester="bramble")
    assert tools.near_miss_hint("terminal", dict(pending["args"], timeout=1)) is None
    spent = _bound_call("hint-spent")
    pin_once(gate_core.data_dir(), autumn.pem)
    c = new_challenge(base, tool_call=spent, requester="bramble")
    approve(base, autumn, c["challenge_id"])
    assert tools.hook_verdict(spent["tool"], spent["args"], [r"ssh git@100"], True) is None
    assert tools.near_miss_hint("terminal", dict(spent["args"], timeout=1)) is None


def test_gate_verify_tells_agent_to_run_the_call_verbatim(monkeypatch, base, autumn):
    pin_once(gate_core.data_dir(), autumn.pem)
    call = _bound_call("dispatch-note")
    c = new_challenge(base, tool_call=call, requester="bramble")
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)
    out = json.loads(tools.gate_verify({"challenge_id": c["challenge_id"], "action_text": ACTION}))
    assert out["verified"] is True
    assert "nothing added or removed" in out["dispatch_note"]
