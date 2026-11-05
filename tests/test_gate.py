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
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
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
    local_verify.pin(gate_core.data_dir(), autumn.pem)
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
