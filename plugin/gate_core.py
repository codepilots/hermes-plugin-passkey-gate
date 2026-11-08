"""Gate engine — ported from Autumn's proven `approval-gate` service (2026-10-25).

The WebAuthn core is deliberately kept close to the battle-tested original:
agents (or this plugin itself) create challenges bound bit-for-bit to the exact
action text; only a human passkey can approve; there is no route that approves
without a valid WebAuthn assertion, and no agent ever holds a private key.

Changes vs the original standalone service (kept minimal on purpose):
  - data dir defaults to the plugin's durable data dir if GATE_DATA is unset
    (plugin data survives installs/updates; the original used a project dir),
  - a `binding_sha256` column lets a challenge be bound to a *canonical tool
    call* (used by the pre_tool_call enforcement hook), not just free prose,
  - `configure(...)` replaces direct env reads where the plugin shell already
    knows config-derived values,
  - consumed challenges: an enforcement hook flips status approved -> consumed
    once the action fires, so a signature authorises one deliberate action.
"""
import collections
import contextlib
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import local_verify, netfetch

try:  # cross-process audit-log lock (POSIX)
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
try:  # cross-process audit-log lock (Windows)
    import msvcrt
except ImportError:
    msvcrt = None

from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response,
                      verify_registration_response)
from webauthn.helpers import (bytes_to_base64url, decode_credential_public_key,
                              decoded_public_key_to_cryptography)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)
from cryptography.hazmat.primitives import serialization

_plugin_data_dir = None


def _default_data_dir() -> Path:
    """Prefer the plugin's durable data dir; fall back to the module dir/tests."""
    if _plugin_data_dir is not None:
        return Path(_plugin_data_dir)
    try:
        from plugins.plugin_storage import plugin_data_dir
        return Path(plugin_data_dir("passkey-gate"))
    except Exception:
        return Path(os.environ.get("GATE_DATA", Path(__file__).resolve().parent / "data"))


# Runtime configuration (set by configure(); env fallback keeps CLI parity).
# These are deliberately explicit: a zero/negative TTL expires immediately and
# an invalid port either crashes serve or sends exposure at the wrong target.
PORT_MIN, PORT_MAX = 1, 65535
CHALLENGE_TTL_MIN, CHALLENGE_TTL_MAX = 1, 86400
BOOTSTRAP_TTL_MIN, BOOTSTRAP_TTL_MAX = 1, 86400
_settings = {}


def _validated_number(name, value, minimum, maximum):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer in the allowed range {minimum}..{maximum}")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be an integer in the allowed range {minimum}..{maximum}") from exc
    # Do not silently accept fractional or otherwise non-integral values.
    if isinstance(value, float) and value != number:
        raise ValueError(f"{name} must be an integer in the allowed range {minimum}..{maximum}")
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} must be an integer in the allowed range {minimum}..{maximum}; got {value!r}")
    return number


def validate_port(value):
    return _validated_number("port", value, PORT_MIN, PORT_MAX)


def validate_challenge_ttl(value):
    return _validated_number("challenge_ttl", value, CHALLENGE_TTL_MIN, CHALLENGE_TTL_MAX)


def validate_bootstrap_ttl(value):
    return _validated_number("bootstrap_ttl", value, BOOTSTRAP_TTL_MIN, BOOTSTRAP_TTL_MAX)


def configure(data_dir=None, rp_id=None, origin=None, port=None, challenge_ttl=None,
              bootstrap_ttl=None, parent_allowlist=None):
    global _plugin_data_dir, _settings
    # Validate everything before changing either data-dir or runtime settings.
    configured_port = validate_port(port if port is not None else os.environ.get("GATE_PORT", "8655"))
    configured_challenge_ttl = validate_challenge_ttl(
        challenge_ttl if challenge_ttl is not None else os.environ.get("GATE_CHALLENGE_TTL", "600"))
    configured_bootstrap_ttl = validate_bootstrap_ttl(
        bootstrap_ttl if bootstrap_ttl is not None else os.environ.get("GATE_BOOTSTRAP_TTL", "900"))
    if data_dir is not None:
        _plugin_data_dir = Path(data_dir)
    defaults = {
        "RP_ID": rp_id or os.environ.get("GATE_RP_ID", "localhost"),
        "ORIGIN": origin or os.environ.get("GATE_ORIGIN", ""),
        "PORT": configured_port,
        "CHALLENGE_TTL": configured_challenge_ttl,
        "BOOTSTRAP_TTL": configured_bootstrap_ttl,
        "PARENT_ALLOWLIST": ([str(x).strip() for x in parent_allowlist]
                             if parent_allowlist is not None else None),
    }
    _settings.update(defaults)


def rp_id() -> str:
    return _settings.get("RP_ID") or os.environ.get("GATE_RP_ID", "localhost")


def origin() -> str:
    return _settings.get("ORIGIN") or os.environ.get("GATE_ORIGIN", "")


def port() -> int:
    value = _settings["PORT"] if "PORT" in _settings else os.environ.get("GATE_PORT", "8655")
    return validate_port(value)


def challenge_ttl() -> int:
    value = (_settings["CHALLENGE_TTL"] if "CHALLENGE_TTL" in _settings
             else os.environ.get("GATE_CHALLENGE_TTL", "600"))
    return validate_challenge_ttl(value)


def bootstrap_ttl() -> int:
    value = (_settings["BOOTSTRAP_TTL"] if "BOOTSTRAP_TTL" in _settings
             else os.environ.get("GATE_BOOTSTRAP_TTL", "900"))
    return validate_bootstrap_ttl(value)


def parent_allowlist() -> list:
    """Allowed parent-gate ORIGINS (finding 5): exact scheme+host+port
    strings, no wildcards. Empty (the default) means NO parent fetch at
    all — a claimed prior approval then renders as unverified, never
    fetched. Env form (GATE_PARENT_ALLOWLIST, a JSON list) mirrors the
    other settings and fails closed on garbage."""
    raw = _settings.get("PARENT_ALLOWLIST")
    if raw is None:
        try:
            parsed = json.loads(os.environ.get("GATE_PARENT_ALLOWLIST", "[]"))
        except ValueError:
            parsed = []
        raw = [str(x).strip() for x in parsed] if isinstance(parsed, list) else []
    return [x for x in (raw or []) if x]


def data_dir() -> Path:
    return Path(os.environ.get("GATE_DATA") or (_plugin_data_dir or Path(__file__).resolve().parent / "data"))


def instance_id() -> str:
    """Short, non-revealing id of THIS gate's data dir, served on /health so
    `setup` and `service status` can tell this gate from another program on
    the same port (an older approval-gate, a different Hermes profile)."""
    return hashlib.sha256(str(data_dir().resolve()).encode()).hexdigest()[:16]


REG_TTL = 300
MIN_ACTION_CHARS = 40
MIN_ACTION_WORDS = 6
MAX_ACTION_CHARS = 4000
USER_ID = b"passkey-gate-user"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# Finding 11: challenge creation is rate-limited so an agent cannot flood
# the human with approval pages (and the DB with challenge rows + audit
# lines). A cap bites only while the count of PENDING, UNEXPIRED
# challenges is at the limit — a challenge that expires or gets decided
# frees its slot immediately, so throttling never outlives the TTL.
MAX_PENDING_CHALLENGES_PER_REQUESTER = 10
MAX_PENDING_CHALLENGES_TOTAL = 100

_lock = threading.Lock()


@contextlib.contextmanager
def _audit_lock():
    """Serialize audit-log access across THREADS and PROCESSES (fresh-review
    F3): the agent process and the `serve` process both append, and a
    process-local lock let them read the same tail and write duplicate seq
    numbers or read a half-written line. An advisory lock on a sibling lock
    file (fcntl on POSIX, msvcrt on Windows) covers every writer and the
    readers that need a consistent tail."""
    with _lock:
        lock_path = data_dir() / "audit.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows only
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no cover - Windows only
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)


# ---------------------------------------------------------------- storage
def db():
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    c = sqlite3.connect(d / "gate.db", isolation_level=None, timeout=10)
    c.row_factory = sqlite3.Row
    c.executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY, public_key BLOB NOT NULL,
        sign_count INTEGER NOT NULL, created_at REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS bootstrap_tokens(token_hash TEXT PRIMARY KEY,
        created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL);
    CREATE TABLE IF NOT EXISTS reg_sessions(id TEXT PRIMARY KEY, token_hash TEXT NOT NULL,
        challenge BLOB NOT NULL, expires_at REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, action_text TEXT NOT NULL,
        action_sha256 TEXT NOT NULL, binding_sha256 TEXT, tool_call TEXT, requester TEXT NOT NULL,
        requester_owner TEXT, why TEXT, parent_approval TEXT, parent_verified TEXT,
        challenge BLOB NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
        status TEXT NOT NULL, decided_at REAL, consumed_at REAL, credential_id TEXT,
        authenticator_data TEXT, client_data_json TEXT, signature TEXT, user_handle TEXT);
    """)
    for col, coltype in (("requester_owner", "TEXT"), ("why", "TEXT"), ("parent_approval", "TEXT"),
                         ("parent_verified", "TEXT"), ("tool_call", "TEXT"), ("consumed_at", "REAL")):
        try:
            c.execute(f"alter table challenges add column {col} {coltype}")
        except sqlite3.OperationalError:
            pass  # column exists (fresh CREATE) or another writer just added it
    return c


def _safe_rollback(c):
    """Undo an unfinished BEGIN IMMEDIATE (refusal, unexpected error). A
    transaction that never opened or already committed is not an error
    here — the original exception is what matters."""
    try:
        c.execute("ROLLBACK")
    except sqlite3.OperationalError:
        pass


def audit(event, **fields):
    """Append to a hash-chained JSONL log. Each line commits to the previous
    line's hash, so an edit or deletion WITHIN the file breaks the chain.
    Finding 8: a wholesale rewrite of the whole file can recompute a
    self-consistent chain — the head must be anchored out of band
    (`hermes passkey-gate audit-notarize`) to make that detectable."""
    path = data_dir() / "audit.jsonl"
    with _audit_lock():
        prev, seq = "0" * 64, 0
        if path.exists():
            lines = path.read_text().splitlines()
            if lines:
                last = json.loads(lines[-1])
                prev, seq = last["hash"], last["seq"] + 1
        rec = {"seq": seq, "ts": time.time(), "event": event, **fields, "prev": prev}
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        rec["hash"] = hashlib.sha256(body.encode()).hexdigest()
        with open(path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(path, 0o600)
        return rec["hash"]


def audit_head():
    path = data_dir() / "audit.jsonl"
    with _audit_lock():
        if not path.exists():
            return None
        lines = path.read_text().splitlines()
    return json.loads(lines[-1])["hash"] if lines else None


def audit_checkpoints():
    """Read-only helper for the finding-8 notarization ceremony: walk the
    log exactly as audit_verify() does and return (ok, msg, heads), where
    heads[i] is the running chain hash after entry i (heads[-1] is the
    current head). The chain computation is unchanged — this only re-derives
    the same hashes so an operator-kept notary can be compared against them."""
    path = data_dir() / "audit.jsonl"
    prev = "0" * 64
    heads = []
    with _audit_lock():
        lines = path.read_text().splitlines() if path.exists() else []
    for i, line in enumerate(lines):
        rec = json.loads(line)
        h = rec.pop("hash")
        if rec["seq"] != i or rec["prev"] != prev:
            return False, f"chain broken at line {i}", heads
        if hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != h:
            return False, f"hash mismatch at line {i}", heads
        prev = h
        heads.append(h)
    return True, f"{len(heads)} records, head {prev}", heads


def audit_verify():
    """Internal consistency of the chain ONLY (partial edits, deletions,
    accidental corruption). This is NOT tamper evidence against an attacker
    who can rewrite the whole log — they can recompute every hash. Evidence
    against a wholesale rewrite requires an external anchor of the head:
    `hermes passkey-gate audit-notarize` (finding 8)."""
    ok, msg, _ = audit_checkpoints()
    return ok, msg


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_binding_json(tool_call: dict) -> str:
    """Canonical JSON of a structured tool call — the byte-exact form that
    binding_sha256 hashes, that the approval page renders, and that the
    /verify record returns, so all three always agree bit-for-bit."""
    return json.dumps(tool_call, sort_keys=True, separators=(",", ":"))


def canonical_binding(tool_call: dict) -> str:
    """Canonical hash of a structured tool call — what the enforcement hook
    re-derives at execution time so a challenge covers exactly one action."""
    return sha256_hex(canonical_binding_json(tool_call))


def specificity_problem(text):
    """Floor against vague approvals: an approval on 'grant Sorrel access' can be stretched."""
    if len(text) < MIN_ACTION_CHARS:
        return f"action_text must be at least {MIN_ACTION_CHARS} characters"
    if len(text) > MAX_ACTION_CHARS:
        return f"action_text must be at most {MAX_ACTION_CHARS} characters"
    if len(text.split()) < MIN_ACTION_WORDS:
        return f"action_text must be at least {MIN_ACTION_WORDS} words"
    return None


def pubkey_pem(cose):
    key = decoded_public_key_to_cryptography(decode_credential_public_key(cose))
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()


# ---------------------------------------------------------------- challenge API (no HTTP)
class GateResult(dict):
    pass


class ChallengeLimitError(ValueError):
    """Finding 11: this requester's (or the whole gate's) budget of pending,
    unexpired challenges is exhausted — a deliberate refusal, never a
    crash. Subclasses ValueError so every existing refusal path (the
    gate_challenge tool handler, the CLI, the HTTP handler) already
    surfaces it as a clean error message."""


def create_challenge(action_text: str, requester: str, tool_call: dict | None = None,
                     requester_owner: str | None = None, why: str | None = None,
                     parent_approval: dict | None = None) -> GateResult:
    """Mint a challenge bound to exact action text (and optionally a canonical tool call).

    The challenge's WebAuthn nonce embeds sha256(action_text), so the signed
    assertion is bound to this exact text — the human signs a specific action,
    not a role or a session.

    Cross-human fields: `requester_owner` names the AGENT's OWN human (the
    signer may be a different human), and `why` is ONE plain sentence for the
    signer explaining what this enables. `parent_approval` (dict {base,
    challenge_id, action_sha256, owner}) records a prior approval already
    signed on another human's gate — rendered on the page with the local
    verification verdict, so chains of sign-off stay checkable.

    Finding 11: minting is rate-limited — at most
    MAX_PENDING_CHALLENGES_PER_REQUESTER pending, unexpired challenges per
    requester, MAX_PENDING_CHALLENGES_TOTAL across the whole gate; over a
    cap this raises ChallengeLimitError instead of inserting.
    """
    if not isinstance(action_text, str) or not isinstance(requester, str):
        raise ValueError("action_text and requester required")
    requester = requester.strip()
    if not requester or len(requester) > 64:
        raise ValueError("requester must be 1-64 chars")
    owner = (requester_owner or "").strip()
    if len(owner) > 64:
        raise ValueError("requester_owner must be at most 64 chars")
    why = (why or "").strip()
    if not why and owner and owner.lower() != requester.lower():
        raise ValueError(
            "why is required when the requester's owner is named: the signer "
            "may not know that agent or that human, so the page must explain "
            "what the action enables")
    if len(why) > 400:
        raise ValueError("why must be at most 400 characters (one clear sentence)")
    parent = None
    if parent_approval is not None:
        try:
            parent = {
                "base": str(parent_approval["base"]).strip().rstrip("/"),
                "challenge_id": str(parent_approval["challenge_id"]).strip(),
                "action_sha256": str(parent_approval["action_sha256"]).strip().lower(),
                "owner": str(parent_approval.get("owner", "")).strip()[:64],
            }
            if not ID_RE.match(parent["challenge_id"]) or not SHA_RE.match(parent["action_sha256"]):
                raise ValueError("challenge_id/action_sha256 malformed")
            # finding 23: parse the base — the old https:// prefix check let
            # credential-carrying and hostless URLs through to a fetch
            netfetch.parse_gate_origin(parent["base"])
        except (KeyError, ValueError) as exc:
            detail = f" — {exc}" if isinstance(exc, ValueError) else f" (missing {exc})"
            raise ValueError(
                "parent_approval needs {base (https), challenge_id, action_sha256, owner}"
                + detail)
    text = action_text.strip()
    prob = specificity_problem(text)
    if prob:
        audit("challenge_rejected", requester=requester, reason=prob)
        raise ValueError(prob)
    sha = sha256_hex(text)
    binding_json = canonical_binding_json(tool_call) if tool_call else None
    binding = sha256_hex(binding_json) if binding_json else None
    cid = secrets.token_urlsafe(24)
    # nonce = sha256(text) ‖ entropy — and for a bound challenge,
    # sha256(text) ‖ binding_sha256 ‖ entropy, so the human's signature
    # covers the exact tool call, not just a DB column next to it
    chal = (bytes.fromhex(sha) + bytes.fromhex(binding) + secrets.token_bytes(16)
            if binding else bytes.fromhex(sha) + secrets.token_bytes(32))
    now = time.time()
    parent_json = json.dumps(parent, sort_keys=True, separators=(",", ":")) if parent else None
    pv = (local_verify.verify_parent_approval(parent, data_dir(),
                                              allowlist=parent_allowlist(),
                                              child_action_sha256=sha)
          if parent else None)
    c = db()
    try:
        # Finding 11: the quota check and the insert are ONE write
        # transaction — BEGIN IMMEDIATE takes the write lock up front, so
        # concurrent minters cannot each see room for one more and
        # overshoot the caps (SQLite serializes this the same way it
        # serializes the consume() claim; no TOCTOU window). Only pending,
        # unexpired rows hold quota: an expired or decided challenge does
        # not count toward either cap.
        c.execute("BEGIN IMMEDIATE")
        mine = c.execute("select count(*) from challenges where requester=?"
                         " and status='pending' and expires_at>=?", (requester, now)).fetchone()[0]
        if mine >= MAX_PENDING_CHALLENGES_PER_REQUESTER:
            raise ChallengeLimitError(
                f"challenge limit reached for requester {requester!r}: {mine} pending "
                f"challenges are already open (max {MAX_PENDING_CHALLENGES_PER_REQUESTER}). "
                "The human must approve or deny one, or it must expire, before "
                "another can be minted.")
        total = c.execute("select count(*) from challenges where status='pending'"
                          " and expires_at>=?", (now,)).fetchone()[0]
        if total >= MAX_PENDING_CHALLENGES_TOTAL:
            raise ChallengeLimitError(
                f"challenge limit reached: {total} pending challenges are open across "
                f"all requesters (max {MAX_PENDING_CHALLENGES_TOTAL}). The gate will "
                "not bury the human in approval pages; resolve or let pending "
                "challenges expire first.")
        c.execute(
            "insert into challenges(id,action_text,action_sha256,binding_sha256,tool_call,requester,"
            "requester_owner,why,parent_approval,parent_verified,challenge,created_at,expires_at,status)"
            " values(?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')",
            (cid, text, sha, binding, binding_json, requester, owner or None, why or None,
             parent_json, pv, chal, now, now + challenge_ttl()))
        c.execute("COMMIT")
    except ChallengeLimitError as exc:
        _safe_rollback(c)
        audit("challenge_rejected", requester=requester, reason=str(exc))
        raise
    except BaseException:
        _safe_rollback(c)
        raise
    audit("challenge_created", challenge_id=cid, action_sha256=sha,
          binding_sha256=binding, requester=requester, requester_owner=owner or None,
          why=why or None, parent_challenge_id=(parent or {}).get("challenge_id"),
          expires_at=now + challenge_ttl())
    url = f"{origin()}/a/{cid}" if origin() else None
    return GateResult(challenge_id=cid, url=url, action_sha256=sha,
                      binding_sha256=binding, expires_at=now + challenge_ttl())


def challenge_status(cid: str, sha: str) -> GateResult:
    """Status lookup, never enumerable: wrong/mismatched sha => 'denied', same as 'no such id'.
    The sha is REQUIRED (pass the empty string when unknown — that denies)."""
    denied = GateResult(status="denied")
    if not ID_RE.match(cid) or not isinstance(sha, str) or not SHA_RE.match(sha):
        return denied
    row = db().execute("select * from challenges where id=?", (cid,)).fetchone()
    if row is None:
        return denied
    if not hmac.compare_digest(row["action_sha256"], sha.lower()):
        audit("verify_mismatch", challenge_id=cid, presented_sha256=sha, outcome="denied")
        return denied  # never reveal the correct hash
    st = row["status"]
    if st == "pending":
        return GateResult(status="expired" if time.time() > row["expires_at"] else "pending",
                          expires_at=row["expires_at"])
    if st == "approved":
        if time.time() > row["expires_at"]:
            # a stale approval must not verify (finding 4): no signed record is
            # handed out once expires_at has passed, even though it was signed
            return GateResult(status="expired", expires_at=row["expires_at"])
        cred = db().execute("select * from credentials where id=?", (row["credential_id"],)).fetchone()
        audit("verify_approved", challenge_id=cid, action_sha256=row["action_sha256"], outcome="approved")
        rec = GateResult(status="approved", challenge_id=cid, action_sha256=row["action_sha256"],
                         action_text=row["action_text"],
                         approved_at=row["decided_at"],
                         rp_id=rp_id(), origin=origin(),
                         challenge_b64url=bytes_to_base64url(row["challenge"]),
                         assertion={"credential_id": row["credential_id"],
                                    "authenticator_data": row["authenticator_data"],
                                    "client_data_json": row["client_data_json"],
                                    "signature": row["signature"], "user_handle": row["user_handle"]})
        if cred is not None:
            rec["credential_public_key"] = {"cose_b64url": bytes_to_base64url(cred["public_key"]),
                                            "spki_pem": pubkey_pem(cred["public_key"])}
        return rec
    if st == "consumed":
        # Finding 10: a spent approval answers with BOTH stamps — decided_at
        # stays the human's approval time, consumed_at is when the agent's
        # claim spent it — and never with signature material (it is used up).
        return GateResult(status="consumed", challenge_id=cid, action_sha256=row["action_sha256"],
                          approved_at=row["decided_at"], consumed_at=row["consumed_at"])
    return denied


def consume(cid: str, binding_sha: str) -> bool:
    """Atomically claim an approved, unconsumed, UNEXPIRED challenge.

    The claim is one conditional UPDATE — SQLite serialises concurrent
    writers, so of any number of racers exactly one updates the row and
    earns True; every loser gets False and must not execute. An approval
    past expires_at is stale and can never be claimed (finding 4).

    Finding 10: the claim stamps consumed_at and leaves decided_at exactly
    what approve() set — the human's approval time survives consumption, so
    the audit story can tell approval from execution apart.
    """
    now = time.time()
    cur = db().execute("update challenges set status='consumed', consumed_at=? "
                       "where id=? and status='approved' and binding_sha256=? "
                       "and expires_at>=?", (now, cid, binding_sha, now))
    if cur.rowcount == 1:
        audit("challenge_consumed", challenge_id=cid, binding_sha256=binding_sha)
    return cur.rowcount == 1


def consume_approval(cid: str, action_sha: str) -> bool:
    """F1 (fresh review): atomically claim an APPROVED, UNEXPIRED,
    text-bound challenge by id + action hash — the claim behind
    `set --approve`, so a gate-weakening approval authorises exactly ONE
    application and a replay of the same --approve cid can never re-apply.

    consume() cannot serve here: it matches on binding_sha256, and a
    weakening approval is minted text-only (binding_sha256 is NULL), which
    an `= ?` comparison never matches. The discipline is otherwise
    identical — ONE conditional UPDATE flips the row to its terminal
    'consumed' state and stamps consumed_at (finding 10: decided_at keeps
    the human's approval time); SQLite serialises concurrent writers, so
    of any number of simultaneous applications of the same approval
    exactly one earns True and every loser gets False and must refuse.
    The action_sha256 condition mirrors _verify_weakening_approval's
    exact-phrase check (D7), so only the challenge the human signed for
    THIS change can be spent on it; a stale approval past expires_at can
    never be claimed (finding 4).
    """
    now = time.time()
    sha = (action_sha or "").strip().lower()
    cur = db().execute(
        "update challenges set status='consumed', consumed_at=? "
        "where id=? and status='approved' and action_sha256=? and expires_at>=?",
        (now, cid, sha, now))
    if cur.rowcount == 1:
        audit("challenge_consumed", challenge_id=cid, action_sha256=sha,
              consumed_by="hermes-cli set --approve")
    return cur.rowcount == 1


def challenge_consumed(cid: str) -> bool:
    """F1: has this challenge id already been claimed? cmd_set uses it to
    route a replay of a spent approval to the single-use refusal instead
    of the generic verification failure, so the operator learns the rule."""
    row = db().execute("select status from challenges where id=?", (cid,)).fetchone()
    return row is not None and row["status"] == "consumed"


def pending_for_binding(binding_sha: str) -> sqlite3.Row | None:
    """Approved, unexpired challenge covering this binding — an approval past
    expires_at must not satisfy the enforcement hook: stale signatures never
    authorise execution, and only a fresh claim in consume() lets one through."""
    return db().execute(
        "select * from challenges where binding_sha256=? and status='approved' "
        "and expires_at>=?", (binding_sha, time.time())).fetchone()


def challenge_covers_binding(challenge: bytes, binding_sha: str) -> bool:
    """Does this signed nonce commit to binding_sha (bytes 32..64)?"""
    try:
        return (isinstance(challenge, (bytes, bytearray, memoryview)) and len(challenge) == 80
                and bytes(challenge)[32:64] == bytes.fromhex(binding_sha))
    except (TypeError, ValueError):
        return False


def approved_for_binding(binding_sha: str) -> list:
    """Every approved, unexpired challenge covering this binding (oldest
    first) — the hook falls back through these when the first one does not
    verify against the pinned owner key, so a rogue approval cannot shadow
    a genuine one."""
    return db().execute(
        "select * from challenges where binding_sha256=? and status='approved' "
        "and expires_at>=? order by created_at", (binding_sha, time.time())).fetchall()


def approve_options(cid: str) -> str | None:
    row = db().execute("select * from challenges where id=?", (cid,)).fetchone()
    if row is None or row["status"] != "pending" or time.time() > row["expires_at"]:
        return None
    creds = db().execute("select id from credentials").fetchall()
    if not creds:
        return None
    from webauthn.helpers import base64url_to_bytes
    opts = generate_authentication_options(
        rp_id=rp_id(), challenge=row["challenge"], timeout=120000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"])) for r in creds],
        user_verification=UserVerificationRequirement.REQUIRED)
    return options_to_json(opts)


def approve_finish(cid: str, assertion: dict):
    """Verify a WebAuthn assertion and mark approved. Enforces: known credential,
    valid signature, UV required, challenge bound to the stored nonce, single use.

    Findings 21 + 13: the assertion's four-byte signature counter (authData
    offset 33) must ADVANCE past the last count accepted for this credential
    — a counter that does not advance is clone evidence (cloned authenticator
    or replay) and is refused by name, distinctly audited. The stored
    credentials.sign_count advances in ONE conditional UPDATE (consume()'s
    lock discipline) BEFORE the challenge flips, so concurrent assertions
    presenting the same counter cannot both be accepted. Counterless
    authenticators (e.g. platform passkeys) report 0 forever: 0 after 0 is
    allowed and is NOT regression evidence. Residual risk: a clone of a
    counterless authenticator is undetectable by counter — inherent to
    WebAuthn, not a gate defect (finding 13's limitation).
    """
    row = db().execute("select * from challenges where id=?", (cid,)).fetchone()
    if row is None or row["status"] != "pending":
        audit("approve_rejected", challenge_id=cid, reason="not pending")
        return {"error": "not pending", "status": "denied"}
    if time.time() > row["expires_at"]:
        return {"error": "expired", "status": "denied"}
    cred_id = assertion.get("id")
    cred = db().execute("select * from credentials where id=?", (cred_id,)).fetchone()
    if cred is None:
        audit("approve_rejected", challenge_id=cid, reason="unknown credential")
        return {"error": "unknown credential", "status": "denied"}
    resp = assertion.get("response")
    if not isinstance(resp, dict):
        # malformed assertion: nothing to verify — the same clean refusal
        # the crypto pass below gives any unparseable credential
        audit("approve_rejected", challenge_id=cid, reason="assertion invalid: no response")
        return {"error": "assertion invalid", "status": "denied"}
    stored_count = cred["sign_count"]
    # Findings 21 + 13: clone detection on the sign counter. Authenticators
    # keep a monotonically increasing counter; an assertion that does not
    # advance past the stored count for THIS credential is evidence of a
    # cloned authenticator or a replay, so it is refused with a problem
    # string that names the suspicion (the crypto verification below
    # enforces the same rule generically — this guard gives the failure its
    # true name first, and the conditional UPDATE below enforces it
    # atomically under concurrency). 0 after 0 is a counterless
    # authenticator and is allowed — see the residual risk in the docstring.
    presented_count = None
    try:
        auth_data = local_verify.b64u(resp["authenticatorData"])  # counter: offset 33, 4 bytes
        if len(auth_data) >= 37:
            presented_count = int.from_bytes(auth_data[33:37], "big")
    except Exception:
        presented_count = None  # malformed authData: the verification below rejects it
    if (presented_count is not None and presented_count <= stored_count
            and not (presented_count == 0 and stored_count == 0)):
        problem = (f"clone suspected: signature counter {presented_count} does not "
                   f"advance past the stored count {stored_count} for this credential")
        audit("approve_rejected", challenge_id=cid, reason=problem)
        return {"error": problem, "status": "denied"}
    try:
        v = verify_authentication_response(
            credential=assertion, expected_challenge=row["challenge"], expected_rp_id=rp_id(),
            expected_origin=origin(), credential_public_key=cred["public_key"],
            credential_current_sign_count=stored_count, require_user_verification=True)
    except Exception as exc:
        audit("approve_rejected", challenge_id=cid, reason=f"assertion invalid: {type(exc).__name__}")
        return {"error": "assertion invalid", "status": "denied"}
    c = db()
    # Findings 21 + 13: advance the stored counter ATOMICALLY — a single
    # conditional UPDATE with the same lock discipline as consume(). SQLite
    # serializes writers, so of concurrent assertions only the one that
    # really advances the count updates the row; a racer presenting the same
    # (or an older) counter gets rowcount 0 and is refused as clone
    # evidence, BEFORE its challenge is approved. The claim runs before the
    # challenge flip on purpose: losing the flip only means another approval
    # claimed THIS challenge (the assertion was fresh, so the counter it
    # reported stands), but losing the claim means this approval must never
    # happen. Counterless (0 after 0) has nothing to advance; its
    # idempotent claim still confirms the stored count IS 0 — if a
    # concurrent approval advanced it, this 0 is now the regression
    # evidence the refusal says it is.
    if presented_count == 0 and stored_count == 0:
        cur = c.execute("update credentials set sign_count=0 where id=? and sign_count=0",
                        (cred_id,))
    else:
        cur = c.execute("update credentials set sign_count=? where id=? and sign_count<?",
                        (v.new_sign_count, cred_id, v.new_sign_count))
    if cur.rowcount != 1:
        problem = (f"clone suspected: signature counter {v.new_sign_count} did not "
                   "atomically advance the stored count for this credential "
                   "(a concurrent assertion already advanced it — clone or replay)")
        audit("approve_rejected", challenge_id=cid, reason=problem)
        return {"error": problem, "status": "denied"}
    cur = c.execute("update challenges set status='approved', decided_at=?, credential_id=?,"
                    " authenticator_data=?, client_data_json=?, signature=?, user_handle=?"
                    " where id=? and status='pending'",
                    (time.time(), cred_id, resp["authenticatorData"], resp["clientDataJSON"],
                     resp["signature"], resp.get("userHandle"), cid))
    if cur.rowcount != 1:  # lost a race / replay: single use
        audit("approve_rejected", challenge_id=cid, reason="already decided")
        return {"error": "already decided", "status": "denied"}
    audit("challenge_approved", challenge_id=cid, action_sha256=row["action_sha256"],
          requester=row["requester"], credential_id=cred_id, outcome="approved")
    return {"status": "approved"}


def deny(cid: str):
    row = db().execute("select * from challenges where id=?", (cid,)).fetchone()
    if row is None or row["status"] != "pending" or time.time() > row["expires_at"]:
        return {"error": "not pending", "status": "denied"}
    cur = db().execute("update challenges set status='denied', decided_at=? where id=? and status='pending'",
                       (time.time(), cid))
    if cur.rowcount == 1:
        audit("challenge_denied", challenge_id=cid, action_sha256=row["action_sha256"],
              requester=row["requester"], outcome="denied")
    return {"status": "denied"}


def credential_count() -> int:
    return db().execute("select count(*) from credentials").fetchone()[0]


def key_fingerprint(spki_pem: str) -> str:
    """Short, human-comparable fingerprint of a public key: the first 16
    bytes of SHA-256 over its DER SubjectPublicKeyInfo, as colon-separated
    hex. Shown on the registration page AND by `hermes passkey-gate
    credentials`, so the human can match the key they just made on their
    phone against the one they are about to pin."""
    der = serialization.load_pem_public_key(spki_pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(der).hexdigest()[:32].upper()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


# Crockford base32: no I, L, O or U, so a code read off a phone screen can't
# be mistyped as a look-alike letter
_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_LOOKALIKES = str.maketrans({"O": "0", "I": "1", "L": "1"})


def key_confirmation_code(spki_pem: str) -> str:
    """The short code the registration page shows in large type and the
    operator TYPES into `setup` (or `pin --code`): 10 Crockford-base32
    characters (50 bits) of SHA-256 over the key's DER SubjectPublicKeyInfo,
    as XXXXX-XXXXX. Typing it moves the key's identity from the phone into
    the terminal, which is what the pin is trusted on — the operator no
    longer has to compare a long fingerprint by eye."""
    der = serialization.load_pem_public_key(spki_pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    n = int.from_bytes(hashlib.sha256(der).digest()[:7], "big") >> 6  # top 50 bits
    chars = "".join(_CODE_ALPHABET[(n >> (5 * i)) & 31] for i in range(9, -1, -1))
    return f"{chars[:5]}-{chars[5:]}"


def normalize_confirmation_code(text: str) -> str:
    """What the operator typed, in canonical XXXXX-XXXXX form (case, spaces
    and dashes ignored; O/I/L read as 0/1), or '' if it can't be a code."""
    raw = "".join(ch for ch in str(text or "").upper() if ch not in " -_\t")
    raw = raw.translate(_CODE_LOOKALIKES)
    if len(raw) != 10 or any(ch not in _CODE_ALPHABET for ch in raw):
        return ""
    return f"{raw[:5]}-{raw[5:]}"


def list_credentials() -> list[dict]:
    """Registered credentials, oldest first: id, registration time, SPKI PEM,
    fingerprint. Read-only — pinning stays an explicit operator step."""
    out = []
    for r in db().execute("select id, public_key, created_at from credentials order by created_at"):
        pem = pubkey_pem(r["public_key"])
        out.append({"credential_id": r["id"], "registered_at": r["created_at"],
                    "spki_pem": pem, "fingerprint": key_fingerprint(pem),
                    "code": key_confirmation_code(pem)})
    return out


# ---------------------------------------------------------------- HTTP mint token
MINT_TOKEN_NAME = "mint-token"


def mint_api_token() -> str:
    """The bearer token that HTTP `POST /challenge` requires — created once
    (0600, O_EXCL) in the gate data dir. The operator hands it to remote
    agents that must mint on this gate; local agents mint in-process."""
    path = data_dir() / MINT_TOKEN_NAME
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    try:
        tok = secrets.token_urlsafe(32)
        os.write(fd, tok.encode())
    finally:
        os.close(fd)
    audit("mint_token_created")
    return tok


def mint_token_ok(header) -> bool:
    if not isinstance(header, str) or not header.startswith("Bearer "):
        return False
    path = data_dir() / MINT_TOKEN_NAME
    if not path.exists():
        return False
    expected = path.read_text().strip()
    return bool(expected) and hmac.compare_digest(header[7:].strip().encode(), expected.encode())


# ---------------------------------------------------------------- registration (bootstrap)
def mint_bootstrap_token() -> str:
    """One-time, 15-min token for passkey registration. The token is returned to
    THIS caller only and never logged; the audit records only its expiry."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    db().execute("insert into bootstrap_tokens values(?,?,?,NULL)",
                 (hashlib.sha256(token.encode()).hexdigest(), now, now + bootstrap_ttl()))
    audit("bootstrap_token_created", expires_at=now + bootstrap_ttl())
    return f"{origin()}/register#{token}" if origin() else token


def registration_options(token: str):
    th = hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) and len(token) >= 20 else None
    if th is None:
        return None
    row = db().execute("select * from bootstrap_tokens where token_hash=?", (th,)).fetchone()
    if row is None or row["used_at"] is not None or time.time() > row["expires_at"]:
        return None
    existing = db().execute("select id from credentials").fetchall()
    from webauthn.helpers import base64url_to_bytes
    opts = generate_registration_options(
        rp_id=rp_id(), rp_name="Hermes passkey-gate", user_name="owner", user_id=USER_ID,
        user_display_name="Owner (approvals)", timeout=180000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"])) for r in existing])
    sid = secrets.token_urlsafe(24)
    db().execute("insert into reg_sessions values(?,?,?,?)",
                 (sid, th, opts.challenge, time.time() + REG_TTL))
    out = json.loads(options_to_json(opts))
    out["session_id"] = sid
    out["_token_hash"] = th
    return out


def registration_finish(token: str, session_id: str, credential: dict):
    th = hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) and len(token) >= 20 else None
    sess = db().execute("select * from reg_sessions where id=?", (session_id,)).fetchone()
    if th is None or sess is None or sess["token_hash"] != th or time.time() > sess["expires_at"]:
        audit("register_rejected", reason="bad session/token")
        return {"error": "registration session invalid"}
    try:
        v = verify_registration_response(credential=credential, expected_challenge=sess["challenge"],
                                         expected_rp_id=rp_id(), expected_origin=origin(),
                                         require_user_verification=True)
    except Exception as exc:
        audit("register_rejected", reason=f"attestation invalid: {type(exc).__name__}")
        return {"error": "registration invalid"}
    c = db()
    cur = c.execute("update bootstrap_tokens set used_at=? where token_hash=? and used_at is null",
                    (time.time(), th))
    if cur.rowcount != 1:
        return {"error": "token already used"}
    cid = bytes_to_base64url(v.credential_id)
    # Findings 21 + 13: the attestation's sign_count is the clone-detection
    # baseline — every later approval must advance past it, so registration
    # stores exactly what the attestation reported, never a hardcoded 0.
    c.execute("insert into credentials values(?,?,?,?)",
              (cid, v.credential_public_key, v.sign_count, time.time()))
    c.execute("delete from reg_sessions where token_hash=?", (th,))
    audit("credential_registered", credential_id=cid,
          public_key_sha256=hashlib.sha256(v.credential_public_key).hexdigest())
    pem = pubkey_pem(v.credential_public_key)
    return {"status": "registered", "credential_id": cid, "spki_pem": pem,
            "fingerprint": key_fingerprint(pem), "code": key_confirmation_code(pem)}


# ---------------------------------------------------------------- HTTP service (serve CLI)
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>{body}</main><script src="/static/app.js"></script></body></html>"""


def approval_page(row):
    left = max(0, int(row["expires_at"] - time.time()))
    state = row["status"]
    if state == "pending" and left == 0:
        state = "expired"
    actions = ""
    if state == "pending":
        actions = ('<div class="buttons"><button id="approve" class="approve">Approve with passkey</button>'
                   '<button id="deny" class="deny">Deny</button></div>'
                   '<p class="hint">Denying is always safe: it just declines. If you do nothing, '
                   'the request expires and nothing happens.</p>')
    who = html.escape(row["requester"])
    if row["requester_owner"]:
        who += f' <span class="owner">(agent of {html.escape(row["requester_owner"])})</span>'
    why_block = ""
    if row["why"]:
        why_block = f'<p class="why"><b>Why this ask:</b> {html.escape(row["why"])}</p>'
    if row["tool_call"]:
        call_block = (
            '<div class="bound-call"><h2>THE EXACT COMMAND YOU ARE APPROVING</h2>'
            '<pre class="command">' + html.escape(row["tool_call"]) + '</pre>'
            '<p><b>This command, not the prose above, is what executes if you approve.</b> '
            'The description can say anything, so check the command itself.</p></div>')
    else:
        call_block = (
            '<div class="bound-call text-only"><b>No tool call is bound to this request.</b> '
            'This is a text-only approval: your signature covers the text above, and '
            'nothing here is bound for execution.</div>')
    parent_block = ""
    if row["parent_approval"]:
        try:
            p = json.loads(row["parent_approval"])
            verdict = row["parent_verified"] or "unverified"
            short_sha = (p.get("action_sha256") or "")[:12]
            parent_block = (
                '<div class="parent"><b>Already signed by another human?</b> This request says '
                f'{html.escape(p.get("owner") or "another owner")}&#39;s gate approved it first '
                f'(id <code>{html.escape(str(p.get("challenge_id"))[:12])}&hellip;</code>, action sha '
                f'<code>{html.escape(short_sha)}&hellip;</code>). Verdict checked from here, locally: '
                f'<b>{html.escape(verdict)}</b>. If unverified, ask for their pinned key out of band '
                'before trusting it &mdash; the claim alone is not evidence.</div>')
        except Exception:
            parent_block = '<div class="parent"><b>Prior approval record unreadable</b> &mdash; treat as unverified.</div>'
    expiry = (f' &middot; expires in {left // 60}m {left % 60:02d}s' if state == "pending" else "")
    body = f"""
<h1>Approval request</h1>
<div class="from"><p class="label">From</p><p class="who">{who}</p>
<p class="meta"><span class="pill pill-{state}" id="state">{state}</span>{expiry}</p></div>
{why_block}
<p class="label">What it wants to do</p>
<pre class="action">{html.escape(row['action_text'])}</pre>
{call_block}
{parent_block}
<p class="warn">Approving signs exactly this request and nothing else. Only you can sign it:
agents can't, and a message saying "someone approved it" counts for nothing without this
signature.</p>
{actions}<p id="msg"></p>
<details class="hint"><summary>Technical details</summary>
<p>Action sha256 <code>{row['action_sha256']}</code><br>Request <code>{row['id'][:12]}&hellip;</code></p>
</details>
<div id="cid" data-id="{row['id']}"></div>"""
    return PAGE.format(title="Approval request", body=body)


REGISTER_PAGE = PAGE.format(title="Set up your approval passkey", body="""
<section id="intro">
<h1>Set up your approval passkey</h1>
<p>Your agents will sometimes ask you to approve an important action. You approve
it here, on this phone, with your face, fingerprint or screen lock. This page creates
the passkey that does that. Agents can never use it themselves.</p>
<ol class="steps">
<li>Tap <b>Create passkey</b>.</li>
<li>Your phone asks to save a passkey. Allow it. If it offers a choice, save it on
<b>this phone</b>, not in a password manager you share with anyone.</li>
<li>This page then shows a <b>10-character code</b>. Type that code into the computer
where the setup is waiting. That is the only thing you need to copy.</li>
</ol>
<div class="buttons"><button id="register" class="approve">Create passkey</button></div>
</section>
<section id="done" hidden>
<h1 class="ok">&#10003; Passkey created</h1>
<p>Last step: go back to the computer and type this code where it asks for it.</p>
<p class="code-label">Your confirmation code</p>
<p class="code" id="code"></p>
<p class="hint">The code proves to the computer that the passkey it is about to trust is
the one on this phone. You can close this page once the computer says it is done.</p>
<details class="hint"><summary>Technical details</summary>
<p>Key fingerprint <code id="fp"></code><br>Credential <code id="credid"></code></p>
</details>
</section>
<p id="msg"></p>""")


# fresh-review F5: bounds on the HTTP surface
GET_RATE_WINDOW_S = 10      # sliding window for the gate-wide GET cap
GET_RATE_MAX = 300          # GETs (non-static) per window, all clients together
MAX_CONNECTIONS = 64        # concurrent connections; extra ones are closed
_get_hits: "collections.deque[float]" = collections.deque()
_get_hits_lock = threading.Lock()


def _get_rate_ok() -> bool:
    now = time.monotonic()
    with _get_hits_lock:
        while _get_hits and now - _get_hits[0] > GET_RATE_WINDOW_S:
            _get_hits.popleft()
        if len(_get_hits) >= GET_RATE_MAX:
            return False
        _get_hits.append(now)
        return True


class BoundedHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a ceiling on concurrent connections: past
    MAX_CONNECTIONS a new connection is closed at once instead of costing a
    thread (each handler also times out after Handler.timeout seconds)."""
    daemon_threads = True

    def __init__(self, *a, max_connections=None, **kw):
        self._slots = threading.BoundedSemaphore(max_connections or MAX_CONNECTIONS)
        super().__init__(*a, **kw)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "passkey-gate/1"
    # a client that stops sending must not pin a server thread forever
    timeout = 30

    def log_message(self, fmt, *args):
        pass  # never log paths/queries (ids are bearer-like)

    def _static(self) -> Path:
        return Path(__file__).resolve().parent / "static"

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8"
                         if ctype.startswith("text") or ctype.endswith("json") else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self';"
                         " connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n < 0 or n > 64 * 1024:
            # negative lengths would make rfile.read() wait for EOF
            raise ValueError("bad body length")
        return json.loads(self.rfile.read(n) or b"{}")

    # ---- GET
    def do_GET(self):
        _refresh_config()
        u = urlparse(self.path)
        p = u.path
        if not p.startswith("/static/") and not _get_rate_ok():
            # fresh-review F5: a gate-wide cap (behind tailscale serve every
            # client is 127.0.0.1, so per-IP limits would mean nothing)
            return self._send(429, {"error": "too many requests — slow down and retry"})
        if p == "/health":
            return self._send(200, {"status": "ok", "service": "passkey-gate",
                                    "instance": instance_id(), "rp_id": rp_id(), "origin": origin(),
                                    "credentials": credential_count(),
                                    "challenge_ttl_s": challenge_ttl(), "audit_head": audit_head()})
        if p.startswith("/static/"):
            name = p.rsplit("/", 1)[-1]
            f = self._static() / name
            if name in ("app.js", "style.css") and f.exists():
                return self._send(200, f.read_bytes(),
                                  "text/javascript" if name.endswith(".js") else "text/css")
            return self._send(404, {"error": "not found"})
        if p == "/register":
            return self._send(200, REGISTER_PAGE, "text/html")
        m = re.fullmatch(r"/a/([A-Za-z0-9_-]+)", p)
        if m and ID_RE.match(m.group(1)):
            row = db().execute("select * from challenges where id=?", (m.group(1),)).fetchone()
            if row:
                return self._send(200, approval_page(row), "text/html")
            return self._send(404, PAGE.format(title="Not found",
                                               body="<h1>No such request</h1>"), "text/html")
        m = re.fullmatch(r"/verify/([A-Za-z0-9_-]+)", p)
        if m:
            sha = (parse_qs(u.query).get("action_sha256") or [""])[0].lower()
            return self._send(200, dict(challenge_status(m.group(1), sha)))
        return self._send(404, {"error": "not found"})

    # ---- POST
    def do_POST(self):
        _refresh_config()
        p = urlparse(self.path).path
        # JSON only: a cross-site <form> can send text/plain or urlencoded
        # bodies without a CORS preflight, never application/json — so this
        # stops CSRF against /a/<id>/deny and the other POST endpoints.
        if self.headers.get_content_type() != "application/json":
            return self._send(415, {"error": "Content-Type must be application/json"})
        if p == "/challenge" and not mint_token_ok(self.headers.get("Authorization")):
            # Minting over HTTP needs the gate's mint token: the exposed
            # origin is reachable by more than this host's agents, and an
            # anonymous minter could post phishing pages on the trusted
            # origin or fill the pending-challenge cap. Local agents mint
            # in-process through gate_challenge and never need it.
            return self._send(401, {"error": "minting over HTTP needs the gate mint token "
                                    "(Authorization: Bearer <token>; see "
                                    "'hermes passkey-gate mint-token')"})
        try:
            body = self._json()
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        try:
            if p == "/challenge":
                c = create_challenge(body.get("action_text"), body.get("requester"),
                                     body.get("tool_call") or None,
                                     requester_owner=body.get("requester_owner"),
                                     why=body.get("why"),
                                     parent_approval=body.get("parent_approval"))
                return self._send(201, dict(c))
            if p == "/register/options":
                out = registration_options(body.get("token"))
                if out is None:
                    audit("register_rejected", reason="bad/expired/used token")
                    return self._send(403, {"error": "registration token invalid, expired or used"})
                out.pop("_token_hash")
                return self._send(200, out)
            if p == "/register/finish":
                r = registration_finish(body.get("token"), body.get("session_id"),
                                        body.get("credential"))
                ok = isinstance(r, dict) and r.get("status") == "registered"
                return self._send(200 if ok else 403, r)
            m = re.fullmatch(r"/a/([A-Za-z0-9_-]+)/(options|finish|deny)", p)
            if m and ID_RE.match(m.group(1)):
                cid, verb = m.group(1), m.group(2)
                if verb == "options":
                    opts = approve_options(cid)
                    if opts is None:
                        audit("approve_rejected", challenge_id=cid, reason="no options (not pending / expired / no credential)")
                        return self._send(409, {"error": "not pending", "status": "denied"})
                    return self._send(200, json.loads(opts))
                if verb == "finish":
                    r = approve_finish(cid, body)
                    ok = isinstance(r, dict) and r.get("status") == "approved"
                    # replay / already-decided / not-pending are 409, not 403
                    code = 200 if ok else (409 if r.get("error") in ("already decided", "not pending", "expired") else 403)
                    return self._send(code, r)
                if verb == "deny":
                    r = deny(cid)
                    return self._send(200, r)
        except ChallengeLimitError as exc:  # finding 11: throttled, same error shape, 429
            audit("error", path=p.split("/")[1] if "/" in p else p, error="ChallengeLimitError")
            return self._send(429, {"error": str(exc)})
        except ValueError as exc:  # input problems the caller can fix (422, not 400)
            audit("error", path=p.split("/")[1] if "/" in p else p, error=type(exc).__name__)
            return self._send(422, {"error": str(exc)})
        except Exception as exc:  # fail closed, no stack traces to the client
            audit("error", path=p.split("/")[1] if "/" in p else p, error=type(exc).__name__)
            return self._send(400, {"error": "rejected", "reason": type(exc).__name__})
        return self._send(404, {"error": "not found"})


# Set by `hermes passkey-gate serve`: re-applies plugin settings when the
# settings file changed (one stat per request, cached), so `expose` or `set
# origin` take effect on a running gate without a restart.
_config_refresh = None


def _refresh_config():
    if _config_refresh is not None:
        try:
            _config_refresh()
        except Exception:
            logging.getLogger(__name__).exception("passkey-gate: settings refresh failed")


def serve(host="127.0.0.1", http_port=None):
    bind_port = validate_port(http_port if http_port is not None else port())
    db()
    srv = BoundedHTTPServer((host, bind_port), Handler)
    print(f"passkey-gate on {host}:{srv.server_address[1]} rp_id={rp_id()} origin={origin()}", flush=True)
    srv.serve_forever()
