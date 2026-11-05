"""Cross-human collaboration tests.

The signer may be a human who has NEVER met the asking agent, on a gate
they've never seen. These tests pin the etiquette: named owner + a plain
`why` for them, parent chains carrying an owner, the parent record
re-checked locally before it's claimed on the page, and the page rendering
the whole story.
"""
import base64
import hashlib
import json
import os
import secrets
import struct
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest
import urllib.error

TMP = tempfile.mkdtemp()
PARENT_ORIGIN = "https://parent-host.example.ts.net:8445"
PARENT_RP = "parent-host.example.ts.net"
os.environ.update(GATE_DATA=TMP, GATE_CHALLENGE_TTL="60", GATE_ORIGIN=PARENT_ORIGIN, GATE_RP_ID=PARENT_RP)

from passkey_gate import cli, gate_core, local_verify, tools  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from webauthn.helpers import encode_cbor  # noqa: E402

ACTION = ("Grant GitLab user sorrel Developer access to project autumn/meta-hackathon "
          "on 100.64.0.10:5080, expiring 2026-11-08.")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, origin=PARENT_ORIGIN, rp_id=PARENT_RP):
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
def parent_gate():
    # env set here (run time), NOT at import: pytest collects test modules in
    # name order but runs fixtures in test order — import-time env writes from
    # a later module bleed into an earlier module's run and poison it.
    os.environ.update(GATE_DATA=TMP, GATE_CHALLENGE_TTL="60",
                      GATE_ORIGIN=PARENT_ORIGIN, GATE_RP_ID=PARENT_RP)
    srv = gate_core.ThreadingHTTPServer(("127.0.0.1", 0), gate_core.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    # register the peer human's passkey on their own gate
    a = SoftAuthenticator()  # self-reports the env-configured origin/rp_id
    tok = secrets.token_urlsafe(32)
    gate_core.db().execute("insert into bootstrap_tokens values(?,?,?,NULL)",
                           (hashlib.sha256(tok.encode()).hexdigest(), time.time(), time.time() + 900))
    s, opts = call(base, "/register/options", {"token": tok})
    assert s == 200
    s, r = call(base, "/register/finish", {"token": tok, "session_id": opts["session_id"], "credential": a.create(opts)})
    assert s == 200
    a.pem = r["spki_pem"]
    yield base, a
    srv.shutdown()


def call(base, path, body=None):
    req = urllib.request.Request(base + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if r.headers.get_content_type() == "application/json"
                              else raw.decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def approve_on(base, a, cid):
    s, opts = call(base, f"/a/{cid}/options", {})
    assert s == 200, opts
    s, r = call(base, f"/a/{cid}/finish", a.get(opts))
    assert s == 200 and r["status"] == "approved", r
    return r


def test_cross_human_requires_owner_and_why(monkeypatch):
    """Different human => the agent must introduce itself and explain."""
    monkeypatch.setenv("GATE_DATA", TMP)
    ctx_out = tools.gate_challenge({"action_text": ACTION, "requester": "sorrel",
                                    "requester_owner": "bob"})
    assert json.loads(ctx_out)["ok"] is False and "`why`" in json.loads(ctx_out)["error"]
    ok_out = json.loads(tools.gate_challenge({
        "action_text": ACTION, "requester": "sorrel", "requester_owner": "bob",
        "why": "Signing lets Sorrel's agent push to the hackathon repo Autumn hosts."}))
    assert ok_out["ok"] is True and "ANOTHER HUMAN" in ok_out["instructions"]


def test_parent_chain_requires_owner_and_verifies(monkeypatch, parent_gate):
    parent_base, parent_auth = parent_gate
    # finding 5: parent fetches happen only for allowlisted peer origins —
    # this test's stub parent gate is deliberately on the allowlist
    monkeypatch.setenv("GATE_PARENT_ALLOWLIST", json.dumps([parent_base]))
    # the peer human approves the sibling challenge on THEIR gate
    s, c = call(parent_base, "/challenge", {"action_text": ACTION, "requester": "sorrel"})
    assert s == 201
    approve_on(parent_base, parent_auth, c["challenge_id"])
    bad = tools.gate_challenge({"action_text": ACTION, "requester": "bramble",
                                "parent_approval": {"base": parent_base,
                                                    "challenge_id": c["challenge_id"],
                                                    "action_sha256": c["action_sha256"]}})
    assert json.loads(bad)["ok"] is False and "owner" in json.loads(bad)["error"]
    # with the owner named but THEIR key unpinned locally: honest 'unverified'
    mid = json.loads(tools.gate_challenge({
        "action_text": ACTION, "requester": "bramble",
        "parent_approval": {"base": parent_base, "challenge_id": c["challenge_id"],
                            "action_sha256": c["action_sha256"], "owner": "bob"}}))
    assert mid["ok"] is True
    row = gate_core.db().execute("select parent_verified from challenges where id=?",
                                 (mid["challenge_id"],)).fetchone()
    assert row["parent_verified"].startswith("unverified")  # no pin yet -> said so, not claimed
    # pin the peer key out of band -> now verifies
    local_verify.pin(gate_core.data_dir(), parent_auth.pem, "bob")
    after = json.loads(tools.gate_challenge({
        "action_text": ACTION + " (retry with pinned peer key)", "requester": "bramble",
        "parent_approval": {"base": parent_base, "challenge_id": c["challenge_id"],
                            "action_sha256": c["action_sha256"], "owner": "bob"}}))
    row = gate_core.db().execute("select parent_verified from challenges where id=?",
                                 (after["challenge_id"],)).fetchone()
    assert row["parent_verified"].startswith("verified")


def test_page_renders_the_whole_story(parent_gate):
    parent_base, parent_auth = parent_gate
    s, c = call(parent_base, "/challenge",
                {"action_text": ACTION, "requester": "sorrel", "requester_owner": "bob",
                 "why": "Signing lets Sorrel's agent push hackathon work."})
    assert s == 201
    s, page = call(parent_base, f"/a/{c['challenge_id']}")
    assert s == 200
    assert "agent of bob" in page
    assert "Why this ask" in page
    assert "Denying is always safe" in page
    assert "meta-hackathon" in page
    # a foreign-human ask cannot dodge the why: server-side floor
    s, r = call(parent_base, "/challenge",
                {"action_text": ACTION, "requester": "sorrel", "requester_owner": "stranger-guy"})
    assert s == 422  # no `why` for an unknown owner
