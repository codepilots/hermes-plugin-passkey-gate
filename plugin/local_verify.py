"""Local verification ported from Autumn's proved `verify_local.py`.

Don't trust the gate endpoint's yes/no: re-derive every claim locally.
``check(rec, action_text, expected_origin, expected_rp_id, pinned_pem, max_age)``
returns a problems list; empty == cryptographically verified. It NEVER
raises: any malformed or missing field becomes a problem entry. Needs only
``cryptography`` (a Hermes core dep), no network.

Checks, all local:
  1. sha256(action_text) == rec.action_sha256
  2. clientDataJSON: type == webauthn.get, origin == expected,
     challenge[:32] == sha256(action_text)  (approval bound to EXACT text)
     and challenge == the record's OWN recorded challenge (finding 14:
     a signature minted under one nonce cannot verify another record,
     even one for the same action text)
  3. authenticatorData: rpIdHash == sha256(rp_id), UP and UV flags set
  4. signature over authenticatorData || sha256(clientDataJSON) verifies
     with the public key in the record
  5. public key == the PINNED key (first seen out of band), so a compromised
     gate can't substitute its own key
  6. approval recency (optional max_age)
"""
import base64
import hashlib
import os
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from . import netfetch


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_or_none(s):
    """b64u that returns None instead of raising on garbage/non-strings —
    check() must never raise, so malformed fields become problems (finding 9)."""
    try:
        return b64u(s)
    except Exception:
        return None


def check(rec, action_text, expected_origin, expected_rp_id, pinned_pem=None, max_age=None):
    """Problems list for an approval record; empty == cryptographically
    verified. NEVER raises (finding 9): every malformed or missing field
    appends a problem. The signed assertion must be bound to the EXACT
    challenge recorded for THIS record (finding 14) — not merely to a nonce
    whose leading bytes hash the action text, which would let a signature
    obtained under one challenge verify another record of the same text.
    """
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    if not isinstance(action_text, str):
        return ["action_text must be a string"]
    if rec.get("status") != "approved":
        return [f"status is {rec.get('status')!r}, not approved"]
    errs = []
    try:
        sha = hashlib.sha256(action_text.encode("utf-8")).hexdigest()
        if rec.get("action_sha256") != sha:
            errs.append("action_sha256 does not match the action text")
        if rec.get("origin") != expected_origin or rec.get("rp_id") != expected_rp_id:
            errs.append("record origin/rp_id differ from expected")
        a = rec.get("assertion")
        if not isinstance(a, dict):
            a = {}
            errs.append("record has no signed assertion")
        cdj_raw = _b64u_or_none(a.get("client_data_json"))
        cd = {}
        if cdj_raw is None:
            cdj_raw = b""
            errs.append("client_data_json is not decodable base64url")
        else:
            try:
                cd = json.loads(cdj_raw)
            except ValueError:
                cd = {}
                errs.append("client_data_json is not valid JSON")
        if not isinstance(cd, dict):
            cd = {}
            errs.append("client_data_json is not a JSON object")
        if cd.get("type") != "webauthn.get":
            errs.append("clientData type is not webauthn.get")
        if cd.get("origin") != expected_origin:
            errs.append(f"clientData origin {cd.get('origin')!r} != {expected_origin!r}")
        signed_challenge = _b64u_or_none(cd.get("challenge", ""))
        if signed_challenge is None:
            signed_challenge = b""
            errs.append("signed challenge is not decodable base64url")
        # defense in depth: the recorded nonce embeds sha256(action_text)
        if signed_challenge[:32].hex() != sha:
            errs.append("signed challenge is not bound to this action text")
        # finding 14: the assertion signs THIS record's exact nonce (action
        # hash + entropy) — a mismatch (or a record with no challenge_b64url)
        # means the signature was minted for a different gate record
        recorded_challenge = _b64u_or_none(rec.get("challenge_b64url"))
        if recorded_challenge is None or signed_challenge != recorded_challenge:
            errs.append("signed challenge does not match the recorded challenge")
        ad = _b64u_or_none(a.get("authenticator_data"))
        if not ad or len(ad) < 33:
            errs.append("authenticator_data is missing or malformed")
            ad = b""
        else:
            if ad[:32] != hashlib.sha256(expected_rp_id.encode()).digest():
                errs.append("rpIdHash mismatch")
            flags = ad[32]
            if not flags & 0x01:
                errs.append("user-presence flag not set")
            if not flags & 0x04:
                errs.append("user-verification flag not set")
        cpk = rec.get("credential_public_key")
        pem = cpk.get("spki_pem") if isinstance(cpk, dict) else None
        key = None
        if not isinstance(pem, str) or not pem.strip():
            errs.append("record has no credential_public_key.spki_pem")
        else:
            if pinned_pem is not None and pinned_pem.strip() != pem.strip():
                errs.append("public key does not match the pinned key")
            try:
                key = serialization.load_pem_public_key(pem.encode())
            except Exception:
                errs.append("credential_public_key.spki_pem is not a loadable public key")
        sig = _b64u_or_none(a.get("signature"))
        if key is None or not cdj_raw or not ad or sig is None:
            errs.append("signature could not be verified with this record")
        else:
            signed = ad + hashlib.sha256(cdj_raw).digest()
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
            except Exception:
                errs.append("signature could not be verified with this record")
        if max_age is not None:
            approved_at = rec.get("approved_at")
            if not isinstance(approved_at, (int, float)):
                errs.append("record has no approved_at timestamp")
            elif time.time() - approved_at > max_age:
                errs.append(f"approval older than {max_age}s")
    except Exception:  # finding 9: nothing may escape check() — malformed beats crashing
        errs.append("record malformed (verification aborted)")
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
    """Validate and first-seen pin a P-256 EC public PEM.

    The destination is created directly and exclusively: no replacement and
    no symlink following are permitted by this ceremony.
    """
    if isinstance(pem, str):
        normalized = pem.strip().encode() + b"\n"
    elif isinstance(pem, bytes):
        normalized = pem.strip() + b"\n"
    else:
        raise ValueError("PEM must be text or bytes containing an EC public key")
    try:
        key = serialization.load_pem_public_key(normalized)
    except Exception as exc:
        raise ValueError(f"PEM is not a loadable public key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("pinned key must be an EC public key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("pinned EC public key must use curve secp256r1")

    path = pin_for(data_dir, owner)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = None
    try:
        fd = os.open(str(path), flags, 0o600)
        os.fchmod(fd, 0o600)
        data = normalized
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fsync(fd)
    except FileExistsError as exc:
        raise ValueError(f"pin destination already exists: {path}; replacement is refused") from exc
    except OSError as exc:
        raise ValueError(f"could not create pin securely at {path}: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)
    return str(path)


def pinned(data_dir, owner: str | None = None):
    path = pin_for(data_dir, owner)
    return path.read_text().strip() if path.exists() else None


def verify_parent_approval(parent: dict, data_dir, timeout: int = 10,
                           allowlist=None, child_action_sha256: str | None = None) -> str:
    """Check a prior approval that was signed on ANOTHER human's gate.

    The parent gate is asked for the record by (id, action_sha256) — it
    denies wrong/mismatched pairs with the same 'denied' it gives unknown
    ids, so a bare claim 'my human approved challenge X' survives this only
    if the parent gate itself confirms it. But its yes/no is NEVER trusted:
    finding 6 — the COMPLETE signed record is fetched and verified LOCALLY
    with ``check()``: signature over authenticatorData||sha256(clientDataJSON)
    against the PINNED key, clientData type webauthn.get, the signed
    challenge bound to the record's own recorded challenge_b64url (finding
    14), RP ID hash, UP/UV flags, and action_sha256 == the hash of the
    record's own action_text. The expected origin/rp_id are the record's OWN
    declared ones (the fetch target is allowlisted + pinned; the crypto
    against the pinned key is the real barrier), so the signed material
    must be self-consistent with them. A record without the fields check()
    needs is unverified, with the reason.

    Finding 19 — the child's action_sha256 is supplied by the caller and the
    policy is hash equality: the fetched record's action_sha256 must equal
    the CLAIMED one (the claim must match what was actually signed), and
    then (b) parent hash == child hash -> 'verified — the same action was
    signed on <owner>'s gate'; (c) parent hash != child hash -> 'context
    only: <owner> approved a DIFFERENT action (hash mismatch) — their
    signature does not cover this one', displayed as context, never as
    'verified'. Without a child hash, equality is unchecked and the verdict
    says so rather than claiming 'verified'.

    Finding 5: the parent base is fetched ONLY when its origin is on the
    allowlist (exact scheme+host+port match, no wildcards; an empty
    allowlist — the default — means NO parent fetch at all) and it resolves
    outside private/loopback space. Both are checked BEFORE any network
    I/O, so an unlisted base yields its verdict without ever touching the
    network — no reachability oracle. Finding 23: the fetch never follows a
    redirect.

    Returns a short verdict string for the approval page: 'verified — ...',
    'context only: ...' or 'unverified (...)'.
    """
    try:
        allow = [str(x) for x in allowlist] if isinstance(allowlist, (list, tuple)) else []
        base = str(parent["base"]).strip().rstrip("/")
        problem = netfetch.base_not_fetchable(base, allow)
        if problem:
            return f"unverified ({problem})"
        url = f"{base}/verify/{parent['challenge_id']}?action_sha256={parent['action_sha256']}"
        with netfetch.open_no_redirect(url, timeout=timeout) as r:
            rec = json.loads(r.read())
    except netfetch.RedirectBlocked as exc:
        return (f"unverified (parent gate answered with a redirect ({exc.code}) — "
                "never followed)")
    except Exception as exc:
        return f"unverified (parent gate unreachable: {type(exc).__name__})"
    if not isinstance(rec, dict):
        return "unverified (parent answer is not a JSON approval record)"
    if rec.get("status") != "approved":
        return f"unverified (parent status {rec.get('status')!r})"
    owner = parent.get("owner") or ""
    pinned_pem = pinned(data_dir, owner) if owner else None
    if pinned_pem is None:
        return f"unverified (no pinned key for {owner!r} — ask for it out of band, then re-challenge)"
    # the claim must match what was actually signed (finding 19): the record
    # the parent returns must be the claimed challenge carrying the claimed
    # action hash — anything else is a claim the record does not back
    rec_sha = str(rec.get("action_sha256", "")).strip().lower()
    claimed_sha = str(parent.get("action_sha256", "")).strip().lower()
    if rec_sha != claimed_sha:
        return ("unverified (the parent record's action_sha256 does not match the "
                "claimed action hash — the claim is not what the parent gate signed)")
    if str(rec.get("challenge_id", "")) != str(parent.get("challenge_id", "")):
        return ("unverified (the parent gate returned a record for a different "
                "challenge id than the one claimed)")
    # check() needs the record's own action text and declared origin/rp_id;
    # without them nothing can be verified locally
    missing = [k for k in ("action_text", "origin", "rp_id")
               if not isinstance((v := rec.get(k)), str) or not v.strip()]
    if missing:
        return (f"unverified (the parent record is missing {', '.join(missing)} — "
                "it cannot be verified locally)")
    errs = check(rec, rec["action_text"], rec["origin"], rec["rp_id"], pinned_pem=pinned_pem)
    if errs:
        return ("unverified (local verification of the parent record failed: "
                + "; ".join(errs) + ")")
    child_sha = str(child_action_sha256 or "").strip().lower()
    if not child_sha:
        return (f"context only: {owner}'s approval is fully verified on their gate, "
                "but no child action hash was supplied, so equality with this "
                "action was not checked")
    if rec_sha == child_sha:
        return f"verified — the same action was signed on {owner}'s gate"
    return (f"context only: {owner} approved a DIFFERENT action (hash mismatch) — "
            "their signature does not cover this one")

