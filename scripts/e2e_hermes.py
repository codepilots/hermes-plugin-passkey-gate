"""End-to-end check through REAL Hermes machinery: the plugin manager, the
tool registry, and Hermes's own pre_tool_call directive dispatch, against a
real `hermes passkey-gate serve`. A software authenticator stands in for the
human's phone, so it runs unattended (no tailscale, no network).

Run it in a THROWAWAY Hermes home so your real profile is untouched:

    export HERMES_HOME=$(mktemp -d) GATE_PORT=18655
    hermes plugins install "codepilots/hermes-plugin-passkey-gate#plugin" --yes-deps --enable
    HPY=$(hermes --print-runtime-command | python3 -c 'import json,sys;print(json.load(sys.stdin)[0])')
    "$HPY" -I -c "import sys; sys.path.insert(0, '$HOME/.hermes/hermes-agent'); \
        sys._hermes_pin_default_home = True; import hermes_bootstrap; \
        exec(open('scripts/e2e_hermes.py').read())"

Prints PASS/FAIL per step and exits non-zero on any failure.
"""
import base64, hashlib, json, os, re, secrets, struct, subprocess, sys, time, urllib.request, urllib.error
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import encode_cbor

PORT = int(os.environ["GATE_PORT"])
ORIGIN, RP = f"http://localhost:{PORT}", "localhost"
H = os.environ["HERMES_HOME"]
ok = True


def step(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


def hermes(*a):
    r = subprocess.run(["hermes", "passkey-gate", *a], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "COLUMNS": "200"})
    return r.returncode, r.stdout + r.stderr


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def post(path, body, headers=None):
    req = urllib.request.Request(ORIGIN + path, method="POST", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class Soft:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1()); self.cid = secrets.token_bytes(32); self.n = 0

    def cd(self, t, ch):
        return json.dumps({"type": t, "challenge": ch, "origin": ORIGIN, "crossOrigin": False}).encode()

    def create(self, o):
        n = self.key.public_key().public_numbers()
        cose = encode_cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        auth = hashlib.sha256(o["rp"]["id"].encode()).digest() + bytes([0x45]) + struct.pack(">I", 0) \
            + b"\0" * 16 + struct.pack(">H", 32) + self.cid + cose
        att = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(self.cd("webauthn.create", o["challenge"])),
                             "attestationObject": b64u(att), "transports": ["internal"]}}

    def get(self, o):
        self.n += 1
        auth = hashlib.sha256(RP.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.n)
        cd = self.cd("webauthn.get", o["challenge"])
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cid), "rawId": b64u(self.cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"authenticatorData": b64u(auth), "clientDataJSON": b64u(cd),
                             "signature": b64u(sig), "userHandle": None}}


# --- operator ceremony through the real CLI
for k, v in (("origin", ORIGIN), ("rp_id", RP), ("port", str(PORT))):
    rc, out = hermes("set", k, v)
    step(f"hermes passkey-gate set {k}", rc == 0 and "REFUSED" not in out, out[-200:])
serve = subprocess.Popen(["hermes", "passkey-gate", "serve"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, env=os.environ.copy())
for _ in range(60):
    try:
        urllib.request.urlopen(ORIGIN + "/health", timeout=1); break
    except Exception:
        time.sleep(0.5)
try:
    with urllib.request.urlopen(ORIGIN + "/health", timeout=3) as r:
        step("hermes passkey-gate serve → /health", json.loads(r.read())["status"] == "ok")
    rc, out = hermes("bootstrap")
    tok = re.search(r"/register#([A-Za-z0-9_-]{20,})", out)
    step("hermes passkey-gate bootstrap prints a registration link", tok, out[-300:])
    human = Soft()
    s, o = post("/register/options", {"token": tok.group(1)})
    s, r = post("/register/finish", {"token": tok.group(1), "session_id": o["session_id"], "credential": human.create(o)})
    step("passkey registration", s == 200 and r.get("status") == "registered", r)
    # the human's flow: the registration page shows a fingerprint; the
    # operator finds the same fingerprint in `credentials` and pins it
    rc, out = hermes("credentials")
    step("hermes passkey-gate credentials shows the page's fingerprint", r.get("fingerprint") in out, out[-300:])
    rc, out = hermes("pin", "--credential", r["credential_id"][:12])
    step("hermes passkey-gate pin --credential", rc == 0 and "REFUSED" not in out
         and r["fingerprint"] in out, out[-200:])
    for k, v in (("require_passkey", "true"), ("authority_patterns", "^terminal .*rm -rf")):
        rc, out = hermes("set", k, v)
        step(f"hermes passkey-gate set {k} (strengthening, no approval needed)", rc == 0 and "REFUSED" not in out, out[-200:])

    # --- the agent side, through Hermes's own plugin loader + dispatch
    from hermes_cli.plugins import discover_plugins, get_plugin_manager, _get_pre_tool_call_directive_details
    from tools.registry import registry
    discover_plugins(force=True)
    step("plugin loaded by Hermes's plugin manager",
         all(registry.get_entry(n) for n in ("gate_challenge", "gate_verify", "gate_status")))
    call = {"tool": "terminal", "args": {"command": "rm -rf ./build-cache"}}
    d = _get_pre_tool_call_directive_details(call["tool"], call["args"])
    step("unapproved destructive call is BLOCKED by the real hook", d.action == "block", d)
    d2 = _get_pre_tool_call_directive_details("terminal", {"command": "ls -la"})
    step("non-matching call passes", d2.action != "block", d2)
    text = "Delete the local build cache directory ./build-cache so the next build starts clean"
    c = json.loads(json.dumps(registry.dispatch("gate_challenge", {"action_text": text, "requester": "bramble",
                                                                  "tool_call": call})))
    c = json.loads(c) if isinstance(c, str) else c
    step("gate_challenge via registry returns an approval URL", c.get("ok") and c.get("url", "").startswith(ORIGIN), c)
    cid = c["challenge_id"]
    with urllib.request.urlopen(f"{ORIGIN}/a/{cid}", timeout=5) as r:
        page = r.read().decode()
    step("approval page shows the exact bound command", "rm -rf ./build-cache" in page)
    s, o = post(f"/a/{cid}/options", {})
    s, r = post(f"/a/{cid}/finish", human.get(o))
    step("human approves with the passkey", s == 200 and r.get("status") == "approved", r)
    v = registry.dispatch("gate_verify", {"challenge_id": cid, "action_text": text})
    v = json.loads(v) if isinstance(v, str) else v
    step("gate_verify: verified locally against the pinned key", v.get("verified") is True, v)
    d = _get_pre_tool_call_directive_details(call["tool"], call["args"])
    step("approved call is ALLOWED exactly once", d.action != "block", d)
    d = _get_pre_tool_call_directive_details(call["tool"], call["args"])
    step("replay of the same call is BLOCKED (approval consumed)", d.action == "block", d)
    rc, out = hermes("audit-verify")
    step("hermes passkey-gate audit-verify", rc == 0 and "broken" not in out.lower(), out[-200:])
finally:
    serve.terminate(); serve.wait(timeout=10)
print("E2E", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
