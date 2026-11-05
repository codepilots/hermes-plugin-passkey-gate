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
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import local_verify

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


# Runtime configuration (set by configure(); env fallback keeps CLI parity)
_settings = {}


def configure(data_dir=None, rp_id=None, origin=None, port=None, challenge_ttl=None,
              bootstrap_ttl=None):
    global _plugin_data_dir, _settings
    if data_dir is not None:
        _plugin_data_dir = Path(data_dir)
    defaults = {
        "RP_ID": rp_id or os.environ.get("GATE_RP_ID", "localhost"),
        "ORIGIN": origin or os.environ.get("GATE_ORIGIN", ""),
        "PORT": int(port if port is not None else os.environ.get("GATE_PORT", "8655")),
        "CHALLENGE_TTL": int(challenge_ttl if challenge_ttl is not None
                             else os.environ.get("GATE_CHALLENGE_TTL", "600")),
        "BOOTSTRAP_TTL": int(bootstrap_ttl if bootstrap_ttl is not None
                             else os.environ.get("GATE_BOOTSTRAP_TTL", "900")),
    }
    _settings.update(defaults)


def rp_id() -> str:
    return _settings.get("RP_ID") or os.environ.get("GATE_RP_ID", "localhost")


def origin() -> str:
    return _settings.get("ORIGIN") or os.environ.get("GATE_ORIGIN", "")


def port() -> int:
    return int(_settings.get("PORT") or os.environ.get("GATE_PORT", "8655"))


def challenge_ttl() -> int:
    return int(_settings.get("CHALLENGE_TTL") or os.environ.get("GATE_CHALLENGE_TTL", "600"))


def bootstrap_ttl() -> int:
    return int(_settings.get("BOOTSTRAP_TTL") or os.environ.get("GATE_BOOTSTRAP_TTL", "900"))


def data_dir() -> Path:
    return Path(os.environ.get("GATE_DATA") or (_plugin_data_dir or Path(__file__).resolve().parent / "data"))


REG_TTL = 300
MIN_ACTION_CHARS = 40
MIN_ACTION_WORDS = 6
MAX_ACTION_CHARS = 4000
USER_ID = b"passkey-gate-user"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

_lock = threading.Lock()


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
        action_sha256 TEXT NOT NULL, binding_sha256 TEXT, requester TEXT NOT NULL,
        requester_owner TEXT, why TEXT, parent_approval TEXT, parent_verified TEXT,
        challenge BLOB NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
        status TEXT NOT NULL, decided_at REAL, credential_id TEXT, authenticator_data TEXT,
        client_data_json TEXT, signature TEXT, user_handle TEXT);
    """)
    for col in ("requester_owner", "why", "parent_approval", "parent_verified"):
        try:
            c.execute(f"alter table challenges add column {col} TEXT")
        except sqlite3.OperationalError:
            pass  # column exists (fresh CREATE) or another writer just added it
    return c


def audit(event, **fields):
    """Append to a hash-chained JSONL log. Each line commits to the previous line's hash,
    so any edit or deletion breaks the chain (audit-verify)."""
    path = data_dir() / "audit.jsonl"
    with _lock:
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
    if not path.exists():
        return None
    lines = path.read_text().splitlines()
    return json.loads(lines[-1])["hash"] if lines else None


def audit_verify():
    path = data_dir() / "audit.jsonl"
    prev = "0" * 64
    n = 0
    for i, line in enumerate(path.read_text().splitlines() if path.exists() else []):
        rec = json.loads(line)
        h = rec.pop("hash")
        if rec["seq"] != i or rec["prev"] != prev:
            return False, f"chain broken at line {i}"
        if hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != h:
            return False, f"hash mismatch at line {i}"
        prev, n = h, n + 1
    return True, f"{n} records, head {prev}"


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_binding(tool_call: dict) -> str:
    """Canonical hash of a structured tool call — what the enforcement hook
    re-derives at execution time so a challenge covers exactly one action."""
    body = json.dumps(tool_call, sort_keys=True, separators=(",", ":"))
    return sha256_hex(body)


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
            if not ID_RE.match(parent["challenge_id"]) or not SHA_RE.match(parent["action_sha256"]) \
                    or not (parent["base"].startswith("https://")
                            or parent["base"].startswith("http://127.0.0.1")
                            or parent["base"].startswith("http://localhost")):
                raise ValueError
        except (KeyError, ValueError):
            raise ValueError("parent_approval needs {base (https), challenge_id, action_sha256, owner}")
    text = action_text.strip()
    prob = specificity_problem(text)
    if prob:
        audit("challenge_rejected", requester=requester, reason=prob)
        raise ValueError(prob)
    sha = sha256_hex(text)
    binding = canonical_binding(tool_call) if tool_call else None
    cid = secrets.token_urlsafe(24)
    chal = bytes.fromhex(sha) + secrets.token_bytes(32)  # nonce = text sha256 + entropy
    now = time.time()
    parent_json = json.dumps(parent, sort_keys=True, separators=(",", ":")) if parent else None
    pv = local_verify.verify_parent_approval(parent, data_dir()) if parent else None
    db().execute(
        "insert into challenges(id,action_text,action_sha256,binding_sha256,requester,"
        "requester_owner,why,parent_approval,parent_verified,challenge,created_at,expires_at,status)"
        " values(?,?,?,?,?,?,?,?,?,?,?,?, 'pending')",
        (cid, text, sha, binding, requester, owner or None, why or None,
         parent_json, pv, chal, now, now + challenge_ttl()))
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
    if st != "approved":
        return denied
    cred = db().execute("select * from credentials where id=?", (row["credential_id"],)).fetchone()
    audit("verify_approved", challenge_id=cid, action_sha256=row["action_sha256"], outcome="approved")
    rec = GateResult(status="approved", challenge_id=cid, action_sha256=row["action_sha256"],
                     binding_sha256=row["binding_sha256"], requester=row["requester"],
                     created_at=row["created_at"], approved_at=row["decided_at"],
                     rp_id=rp_id(), origin=origin(),
                     challenge_b64url=bytes_to_base64url(row["challenge"]),
                     assertion={"credential_id": row["credential_id"],
                                "authenticator_data": row["authenticator_data"],
                                "client_data_json": row["client_data_json"],
                                "signature": row["signature"], "user_handle": row["user_handle"]})
    if cred is not None:
        rec["credential_public_key"] = {"cose_b64url": bytes_to_base64url(cred["public_key"]),
                                        "spki_pem": pubkey_pem(cred["public_key"])}
    rec["audit_head"] = audit_head()
    return rec


def consume(cid: str, binding_sha: str) -> bool:
    """Mark an approved, unconsumed challenge as consumed (single deliberate use).
    Returns True exactly once — the enforcement hook treats False as fail-closed."""
    c = db()
    cur = c.execute("update challenges set status='consumed', decided_at=? "
                    "where id=? and status='approved' and binding_sha256=?",
                    (time.time(), cid, binding_sha))
    if cur.rowcount == 1:
        audit("challenge_consumed", challenge_id=cid, binding_sha256=binding_sha)
    return cur.rowcount == 1


def pending_for_binding(binding_sha: str) -> sqlite3.Row | None:
    return db().execute(
        "select * from challenges where binding_sha256=? and status='approved'", (binding_sha,)).fetchone()


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
    valid signature, UV required, challenge bound to the stored nonce, single use."""
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
    try:
        v = verify_authentication_response(
            credential=assertion, expected_challenge=row["challenge"], expected_rp_id=rp_id(),
            expected_origin=origin(), credential_public_key=cred["public_key"],
            credential_current_sign_count=cred["sign_count"], require_user_verification=True)
    except Exception as exc:
        audit("approve_rejected", challenge_id=cid, reason=f"assertion invalid: {type(exc).__name__}")
        return {"error": "assertion invalid", "status": "denied"}
    resp = assertion["response"]
    c = db()
    cur = c.execute("update challenges set status='approved', decided_at=?, credential_id=?,"
                    " authenticator_data=?, client_data_json=?, signature=?, user_handle=?"
                    " where id=? and status='pending'",
                    (time.time(), cred_id, resp["authenticatorData"], resp["clientDataJSON"],
                     resp["signature"], resp.get("userHandle"), cid))
    if cur.rowcount != 1:  # lost a race / replay: single use
        audit("approve_rejected", challenge_id=cid, reason="already decided")
        return {"error": "already decided", "status": "denied"}
    c.execute("update credentials set sign_count=? where id=?", (v.new_sign_count, cred_id))
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
    c.execute("insert into credentials values(?,?,?,?)",
              (cid, v.credential_public_key, v.sign_count, time.time()))
    c.execute("delete from reg_sessions where token_hash=?", (th,))
    audit("credential_registered", credential_id=cid,
          public_key_sha256=hashlib.sha256(v.credential_public_key).hexdigest())
    return {"status": "registered", "credential_id": cid, "spki_pem": pubkey_pem(v.credential_public_key)}


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
                   '<p class="hint">Denying is always safe: it just declines, and nothing happens '
                   'until someone signs.</p>')
    who = html.escape(row["requester"])
    if row["requester_owner"]:
        who += f' <span class="owner">(agent of {html.escape(row["requester_owner"])})</span>'
    why_block = ""
    if row["why"]:
        why_block = f'<p class="why"><b>Why this ask:</b> {html.escape(row["why"])}</p>'
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
    body = f"""
<h1>Approval request</h1>
<p class="meta">From <b>{who}</b> &middot; status <b id="state">{state}</b>
{'&middot; expires in ' + str(left // 60) + 'm ' + str(left % 60) + 's' if state == 'pending' else ''}</p>
{why_block}
<p class="warn">Read the whole action. Approving authorises exactly this text and nothing else.
You are the only one who can sign this &mdash; agents cannot, and no relay of
"someone approved it" counts without this signature.</p>
<pre class="action">{html.escape(row['action_text'])}</pre>
<p class="sha">sha256 {row['action_sha256']}</p>
{parent_block}
{actions}<p id="msg"></p>
<div id="cid" data-id="{row['id']}"></div>"""
    return PAGE.format(title="Approval request", body=body)


REGISTER_PAGE = PAGE.format(title="Register passkey", body="""
<h1>Register approval passkey</h1>
<p>This registers a passkey that agents can never use themselves. Use your own authenticator
(phone / security key) &mdash; not a shared vault.</p>
<div class="buttons"><button id="register" class="approve">Register passkey</button></div>
<p id="msg"></p>""")


class Handler(BaseHTTPRequestHandler):
    server_version = "passkey-gate/1"

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
        if n > 64 * 1024:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"{}")

    # ---- GET
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p == "/health":
            return self._send(200, {"status": "ok", "rp_id": rp_id(), "origin": origin(),
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
        p = urlparse(self.path).path
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
        except ValueError as exc:  # input problems the caller can fix (422, not 400)
            audit("error", path=p.split("/")[1] if "/" in p else p, error=type(exc).__name__)
            return self._send(422, {"error": str(exc)})
        except Exception as exc:  # fail closed, no stack traces to the client
            audit("error", path=p.split("/")[1] if "/" in p else p, error=type(exc).__name__)
            return self._send(400, {"error": "rejected", "reason": type(exc).__name__})
        return self._send(404, {"error": "not found"})


def serve(host="127.0.0.1", http_port=None):
    db()
    srv = ThreadingHTTPServer((host, int(http_port if http_port is not None else port())), Handler)
    print(f"passkey-gate on {host}:{srv.server_address[1]} rp_id={rp_id()} origin={origin()}", flush=True)
    srv.serve_forever()
