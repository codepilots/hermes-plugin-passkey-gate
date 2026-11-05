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
        self.origin, self.rp_id = origin, rp_id

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return encode_cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _cd(self, typ, challenge_b64u):
        return json.dumps({"type": typ, "challenge": challenge_b64u, "origin": self.origin,
                           "crossOrigin": False}).encode()

    def create(self, opts):
        rp_hash = hashlib.sha256(opts["rp"]["id"].encode()).digest()
        auth = rp_hash + bytes([0x45]) + struct.pack(">I", 0) + b"\0" * 16 \
            + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        att = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(self._cd("webauthn.create", opts["challenge"])),
                             "attestationObject": b64u(att), "transports": ["internal"]}}

    def get(self, opts, flags=0x05):
        self.count += 1
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
    req = urllib.request.Request(base + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
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


def test_verify_record_includes_bound_tool_call(base, autumn):
    """The /verify record carries the canonical tool call (already public on
    the page), byte-exact so it can be hashed straight against binding_sha256."""
    c = new_challenge(base, tool_call=TOOL_CALL)
    approve(base, autumn, c["challenge_id"])
    s, rec = call(base, f"/verify/{c['challenge_id']}?action_sha256={c['action_sha256']}")
    assert s == 200 and rec["status"] == "approved"
    assert json.loads(rec["tool_call"]) == TOOL_CALL
    assert hashlib.sha256(rec["tool_call"].encode()).hexdigest() == c["binding_sha256"]


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
    assert out["binding_sha256"] == c["binding_sha256"]


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
    c = new_challenge(base, tool_call=call)
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(gate_core, "consume", boom)
    v = tools.hook_verdict(call["tool"], call["args"], patterns, True)
    assert v is not None and v["action"] == "block"
    assert gate_core.pending_for_binding(c["binding_sha256"]) is not None


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
    but will not parse is served to readers as silent DEFAULTS by the config
    loader. The gate must detect the recorded parse failure and fail closed
    instead of running on defaults the admin never chose."""
    import passkey_gate
    cli = reset_gate_config(monkeypatch)
    monkeypatch.setattr(cli, "_ctx_ref",
                        FakeCtx({"require_passkey": False, "authority_patterns": []}))
    monkeypatch.setattr(cli, "_active_settings_error", raising=False,
                        value=lambda: "config.yaml has a formatting error at line 12")
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is True, cfg
    assert "formatting error" in cfg["_config_error"]
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
    assert "passkey-gate: set require_passkey=false" in out
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

        def register_cli_command(self, name, fn):
            registered.append(name)

    passkey_gate.register(Ctx(fail_get=True))  # must not raise
    assert "pre_tool_call" in registered
    cfg = cli.apply_config_safe()
    assert cfg["require_passkey"] is True and cfg["_config_error"]
    v = passkey_gate._on_pre_tool_call("terminal", {"command": "ls"}, "t")
    assert v is not None and v["action"] == "block" and "failed to load" in v["message"]


# ------------------- finding 16: enforcement config is not agent-mutable
WEAKEN_OFF_PHRASE = ("passkey-gate: set require_passkey=false — "
                     "confirm this gate-weakening change")


def weaken_phrase(key, canonical_value):
    """The spec-exact server-derived phrase a passkey must sign to authorize a
    gate-weakening `set`: 'passkey-gate: set <key>=<canonical-new-value> —
    confirm this gate-weakening change'."""
    return (f"passkey-gate: set {key}={canonical_value} — "
            "confirm this gate-weakening change")


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
    c = new_challenge(base, text=WEAKEN_OFF_PHRASE, requester="hermes-cli")
    approve(base, autumn, c["challenge_id"])
    monkeypatch.setattr(tools, "_base_url", lambda: base)  # the gate_verify fetch path
    out = cli.cmd_set(ctx, ["require_passkey", "false", "--approve", c["challenge_id"]])
    assert "require_passkey = false" in out, out
    assert ctx.settings["require_passkey"] is False
    cc = _config_audit("require_passkey")
    assert cc, "config_changed audit entry missing"
    assert cc[-1]["weakened"] is True and cc[-1]["approved"] == c["challenge_id"]
    assert cc[-1]["old"] is True and cc[-1]["new"] is False


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
    assert weaken_phrase("authority_patterns", '["ssh git@100"]') in out
    assert "--approve" in out


def test_set_authority_patterns_emptying_refused_without_approval(monkeypatch):
    """Emptying the pattern list disarms every pattern at once — refused."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True,
                        authority_patterns=[r"ssh git@100"])
    out = cli.cmd_set(ctx, ["authority_patterns", "[]"])
    assert ctx.settings["authority_patterns"] == [r"ssh git@100"]
    assert weaken_phrase("authority_patterns", "[]") in out


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
    assert weaken_phrase("parent_gate_allowlist", new) in out
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
    pending = new_challenge(base, text=WEAKEN_OFF_PHRASE, requester="hermes-cli")
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
    link = peer_dir / "alice.pem"
    link.symlink_to(target)
    replacement = _pem_public(ec.generate_private_key(ec.SECP256R1()))
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


def test_set_approve_requires_a_pinned_owner_key(monkeypatch, base, autumn):
    """Pin missing -> refuse: an approval that cannot be checked against the
    out-of-band pinned key authorizes nothing (a self-registered rogue
    credential must not pass --approve)."""
    cli, ctx = _set_ctx(monkeypatch, require_passkey=True)
    c = new_challenge(base, text=WEAKEN_OFF_PHRASE, requester="hermes-cli")
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
