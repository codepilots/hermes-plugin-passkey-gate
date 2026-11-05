"""Local verification ported from Autumn's proved `verify_local.py`.

Don't trust the gate endpoint's yes/no: re-derive every claim locally.
``check(rec, action_text, expected_origin, expected_rp_id, pinned_pem, max_age)``
returns a problems list; empty == cryptographically verified. Needs only
``cryptography`` (a Hermes core dep), no network.

Checks, all local:
  1. sha256(action_text) == rec.action_sha256
  2. clientDataJSON: type == webauthn.get, origin == expected,
     challenge[:32] == sha256(action_text)  (approval bound to EXACT text)
  3. authenticatorData: rpIdHash == sha256(rp_id), UP and UV flags set
  4. signature over authenticatorData || sha256(clientDataJSON) verifies
     with the public key in the record
  5. public key == the PINNED key (first seen out of band), so a compromised
     gate can't substitute its own key
  6. approval recency (optional max_age)
"""
import base64
import hashlib
import json
import re
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def check(rec, action_text, expected_origin, expected_rp_id, pinned_pem=None, max_age=None):
    errs = []
    sha = hashlib.sha256(action_text.encode("utf-8")).hexdigest()
    if rec.get("status") != "approved":
        return [f"status is {rec.get('status')!r}, not approved"]
    if rec["action_sha256"] != sha:
        errs.append("action_sha256 does not match the action text")
    if rec["origin"] != expected_origin or rec["rp_id"] != expected_rp_id:
        errs.append("record origin/rp_id differ from expected")
    a = rec["assertion"]
    cdj_raw = b64u(a["client_data_json"])
    cd = json.loads(cdj_raw)
    if cd.get("type") != "webauthn.get":
        errs.append("clientData type is not webauthn.get")
    if cd.get("origin") != expected_origin:
        errs.append(f"clientData origin {cd.get('origin')!r} != {expected_origin!r}")
    if b64u(cd.get("challenge", ""))[:32].hex() != sha:
        errs.append("signed challenge is not bound to this action text")
    ad = b64u(a["authenticator_data"])
    if ad[:32] != hashlib.sha256(expected_rp_id.encode()).digest():
        errs.append("rpIdHash mismatch")
    flags = ad[32]
    if not flags & 0x01:
        errs.append("user-presence flag not set")
    if not flags & 0x04:
        errs.append("user-verification flag not set")
    pem = rec["credential_public_key"]["spki_pem"]
    if pinned_pem is not None and pinned_pem.strip() != pem.strip():
        errs.append("public key does not match the pinned key")
    key = serialization.load_pem_public_key(pem.encode())
    signed = ad + hashlib.sha256(cdj_raw).digest()
    sig = b64u(a["signature"])
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, signed)
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            errs.append("unsupported key type")
    except InvalidSignature:
        errs.append("SIGNATURE INVALID")
    if max_age is not None and time.time() - rec["approved_at"] > max_age:
        errs.append(f"approval older than {max_age}s")
    return errs


def pin_file_path(data_dir):
    """Where the pinned owner key lives: first-seen out of band, then trusted."""
    import pathlib
    return pathlib.Path(data_dir) / "pinned_owner.pem"


def _owner_slug(owner: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "-", owner.strip().lower())[:40]


def pin_for(data_dir, owner: str | None):
    import pathlib
    if not owner:
        return pathlib.Path(data_dir) / "pinned_owner.pem"
    return pathlib.Path(data_dir) / "pins" / f"{_owner_slug(owner)}.pem"


def pin(data_dir, pem: str, owner: str | None = None) -> str:
    path = pin_for(data_dir, owner)
    path.parent.mkdir(parents=True, exist_ok=True)
    # normalise exactly like check() compares (strip outer whitespace)
    path.write_text(pem.strip() + "\n")
    path.chmod(0o600)
    return str(path)


def pinned(data_dir, owner: str | None = None):
    path = pin_for(data_dir, owner)
    return path.read_text().strip() if path.exists() else None


def verify_parent_approval(parent: dict, data_dir, timeout: int = 10) -> str:
    """Check a prior approval that was signed on ANOTHER human's gate.

    The parent gate is asked for the record by (id, action_sha256) — it
    denies wrong/mismatched pairs with the same 'denied' it gives unknown
    ids, so a bare claim 'my human approved challenge X' survives this only
    if the parent gate itself confirms it. When the parent owner's key is
    PINNED locally, the public key in the record must equal it; signature
    and text-binding re-checks stay the parent gate's responsibility (the
    parent has the action text; this side usually does not).

    Returns a short verdict string for the approval page: 'verified',
    'unverified (...)' or 'key-mismatch'.
    """
    try:
        url = f"{parent['base']}/verify/{parent['challenge_id']}?action_sha256={parent['action_sha256']}"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            rec = json.loads(r.read())
    except Exception as exc:
        return f"unverified (parent gate unreachable: {type(exc).__name__})"
    if rec.get("status") != "approved":
        return f"unverified (parent status {rec.get('status')!r})"
    owner = parent.get("owner") or ""
    pinned_pem = pinned(data_dir, owner) if owner else None
    if pinned_pem is None:
        return f"unverified (no pinned key for {owner!r} — ask for it out of band, then re-challenge)"
    rec_pem = (rec.get("credential_public_key") or {}).get("spki_pem", "")
    if rec_pem.strip() != pinned_pem.strip():
        return "KEY MISMATCH: the parent gate's record does not match the pinned owner key"
    return f"verified against pinned key for {owner}"

