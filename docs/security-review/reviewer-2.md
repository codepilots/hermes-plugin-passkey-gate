# Independent review 2 — passkey-gate v0.4.0

> **Historical record.** Apart from its title and this note, the review is kept
> exactly as written, as evidence of
> what was found. It describes v0.4.0 (commit `69bcd7e6`), 5 November 2026. Its findings are reconciled into [security-review.md](../security-review.md) as findings 1–28.
> File paths, line numbers and behaviour refer to that version, and many of
> the problems it describes have since been fixed.
> For what was fixed and what is still open, see the [remediation ledger](remediation.md); for the residual risks that are accepted rather than fixed, see the [threat model](threat-model.md).

## Verdict

**Not safe to ship publicly as a security plugin.** The WebAuthn cryptographic verification path is mostly sound, but the authorization boundary is not: approvals can be detached from the exact execution, parent approvals can be misleading, and concurrent enforcement can allow the same approval twice.

## Findings

### 1. Critical — Enforcement consume race allows duplicate execution

**Evidence:** `plugin/tools.py:190-203`, `plugin/gate_core.py:334-343`

`hook_verdict()`:

1. Reads an approved row with `pending_for_binding()`.
2. Calls `consume()`.
3. Ignores the boolean result from `consume()`.
4. Returns `None` regardless.

Two concurrent tool calls can both read the same approved challenge before either update commits. One `consume()` succeeds and the other returns `False`, but both hooks allow execution.

**Exploit scenario**

An agent or plugin launches two identical high-authority tool calls concurrently:

```python
threads = [
    Thread(target=run_tool_call),
    Thread(target=run_tool_call),
]
```

Both observe the same approved binding. Both return an allow result. The human’s single approval authorizes two executions.

**Fix**

Require the result:

```python
if not gate_core.consume(row["id"], binding):
    return {"action": "block", "message": "approval already consumed"}
return None
```

Prefer an atomic “claim-and-consume” operation that returns the row only when the update succeeds, and perform lookup plus consumption in one transaction.

---

### 2. High — Local verification does not bind the assertion to the gate’s recorded challenge

**Evidence:** `plugin/local_verify.py:51-52`; recorded challenge is returned at `plugin/gate_core.py:322`

The verifier checks only:

```python
b64u(cd.get("challenge", ""))[:32].hex() == sha
```

It does **not** compare the complete signed challenge to `rec["challenge_b64url"]`.

The gate creates a challenge containing:

```python
sha256(action_text) + random_entropy
```

Therefore, a valid signature over the same action but a different entropy suffix is accepted as if it belonged to the returned gate record.

**Exploit scenario**

An attacker obtains a valid signed assertion for action text `A` from one challenge, then constructs a record with:

- the signed assertion from challenge 1,
- `challenge_b64url` from challenge 2 or an arbitrary nonce with the same action hash,
- the same pinned public key.

`local_verify.check()` accepts it. The assertion is not cryptographically tied to the challenge record being presented.

**Fix**

Require exact equality:

```python
signed_challenge = cd.get("challenge", "")
if signed_challenge != rec["challenge_b64url"]:
    errs.append("signed challenge does not match recorded challenge")
```

Also decode and compare bytes, not only base64url strings.

---

### 3. High — `gate_verify` does not verify that the action being executed is the approved tool call

**Evidence:** `plugin/tools.py:71-113`; `plugin/schemas.py:89-120`

`gate_verify` verifies `challenge_id` plus `action_text`. It has no `tool_call` parameter and does not require or compare `binding_sha256`.

The exact tool binding is enforced only by the optional pre-tool hook. That hook is disabled by default:

**Evidence:** `plugin/plugin.yaml:44-53`

```yaml
require_passkey:
  default: false
```

**Exploit scenario**

An agent obtains approval for:

> “Upload this specific file to the staging bucket…”

It calls `gate_verify()` with the approved text, receives `verified: true`, then performs a different action—such as uploading a different file or using a production bucket—because no execution-time binding is checked.

This directly permits “bind one text but execute another” whenever enforcement is disabled or the action is performed outside the hook.

**Fix**

For security-sensitive use:

- Make enforcement mandatory for configured authority tools, not opt-in.
- Pass the actual canonical tool call into `gate_verify`.
- Recompute and compare `binding_sha256`.
- Require the execution layer itself to consume the approval atomically immediately before execution.
- Do not treat `verified: true` from a text-only check as authorization for arbitrary subsequent actions.

---

### 4. High — Parent approval verification proves only “a pinned key appeared in an approved-looking response”

**Evidence:** `plugin/local_verify.py:114-143`

`verify_parent_approval()` checks:

- HTTP response status is `"approved"`;
- the returned public key matches the locally pinned key.

It does **not** locally verify:

- the parent assertion signature;
- client-data type/origin/challenge;
- RP ID hash;
- UV/UP flags;
- action text binding;
- sign count;
- equality between the parent action and the child action.

The function’s docstring explicitly says these checks remain the parent gate’s responsibility, but the child gate is trusting an external HTTP response as authorization evidence.

**Exploit scenario**

A compromised or malicious parent gate returns:

```json
{
  "status": "approved",
  "credential_public_key": {
    "spki_pem": "<correct pinned key>"
  }
}
```

No assertion is required. The child page renders:

> “verified against pinned key…”

A signer may treat that as meaningful prior approval even though no valid parent assertion exists.

A second variant uses a valid approval for an unrelated action. The child request accepts it because the supplied parent `action_sha256` is never compared with the child action hash.

**Fix**

The parent response must include the complete signed record, and the child must locally run the same verification routine against:

- the parent action text;
- the parent challenge;
- the parent origin/RP ID;
- the pinned parent key;
- the expected action hash.

Require exact equality between the parent and child action hash if the parent is intended to authorize the same action. Otherwise label it as advisory context, never “verified.”

---

### 5. High — Parent approval URL is an SSRF primitive

**Evidence:** `plugin/gate_core.py:255-270`; `plugin/local_verify.py:128-133`

The requester supplies `parent["base"]`. The server then performs:

```python
urllib.request.urlopen(url, timeout=timeout)
```

Validation only checks string prefixes for `https://`, `http://127.0.0.1`, or `http://localhost`.

**Exploit scenario**

A remote caller submits a parent URL pointing to an HTTPS internal service. The gate makes a server-side request to it. Even if response contents are not fully exposed, this enables blind SSRF, internal service probing, and triggering GET side effects.

**Fix**

Do not fetch arbitrary parent URLs from the public challenge endpoint. Use:

- an explicit allowlist of trusted parent gate origins;
- strict URL parsing and hostname validation;
- no redirects;
- IP resolution checks blocking private, loopback, link-local, and metadata ranges;
- preferably an agent-side fetch rather than a server-side fetch.

---

### 6. Medium — Pin management is overwriteable and race/symlink unsafe

**Evidence:** `plugin/local_verify.py:100-111`; `plugin/cli.py:158-166`

`pin()` overwrites an existing key unconditionally:

```python
path.write_text(...)
```

It does not implement first-seen pinning, confirmation, key fingerprint display, or refusal to replace an established key.

It also follows symlinks and does not ensure the `pins` directory has restrictive permissions. `gate_core.db()` chmods the main data directory, but `local_verify.pin()` does not chmod the directory itself.

**Exploit scenario**

A process or agent with access to the plugin data directory can replace the pinned key, or arrange a symlink before `pin()` writes. Subsequent approvals using an attacker-controlled key can pass local verification.

**Fix**

- Refuse overwrite unless an explicit human-confirmed `--replace` operation is used.
- Write with `open(..., O_CREAT|O_EXCL|O_NOFOLLOW)` or equivalent.
- Use atomic rename from a securely created temporary file.
- Set `data_dir` and `pins` to `0700`, files to `0600`.
- Pin and display a SHA-256 fingerprint, not only PEM text.
- Validate that the PEM contains an allowed public-key type.

---

### 7. Medium — Owner-label slug collisions can select the wrong pinned key

**Evidence:** `plugin/local_verify.py:89-97`

```python
re.sub(r"[^a-z0-9_-]", "-", owner.strip().lower())[:40]
```

Different owner strings can map to the same filename, and long names are truncated.

**Exploit scenario**

Two distinct owners such as labels differing only by punctuation, or two names sharing the first 40 characters, resolve to the same pin file. A parent approval for one displayed owner can be checked against another owner’s key.

**Fix**

Use a collision-resistant filename, for example:

```python
slug + "-" + sha256(owner.encode()).hexdigest()[:16]
```

Better: store the canonical owner identifier and key fingerprint in a structured database, not a lossy filename.

---

### 8. Medium — Independent local verification omits sign-count validation

**Evidence:** `plugin/local_verify.py:53-80`

The local verifier checks the authenticator-data flags and signature but never parses or validates the four-byte signature counter.

The server-side WebAuthn library receives `credential_current_sign_count` at `plugin/gate_core.py:381-384`, so the online approval path delegates this to the library. However, the advertised offline verifier is not equivalent: it accepts a valid signature with a regressed or replayed counter.

**Exploit scenario**

A cloned authenticator or replayed exported record can pass `local_verify.check()` if the signature and pinned key are valid, even if the authenticator counter indicates cloning or rollback.

**Fix**

Return and validate the authenticator counter. Require monotonic advancement against locally stored per-credential state, or clearly state that offline verification is not replay protection and never use it as sole authorization.

---

### 9. Medium — Registration is socially engineerable and not protected by an existing credential

**Evidence:** `plugin/gate_core.py:420-429`, `plugin/gate_core.py:432-481`, `plugin/cli.py:112-122`

Any caller able to invoke the CLI can mint a bootstrap token. Registration then accepts the first valid WebAuthn credential for that token. There is no existing-owner authentication or human confirmation tied to the bootstrap request.

**Exploit scenario**

An agent mints a registration URL, presents it as required setup or “repair,” and persuades the owner to register an attacker-controlled passkey. The attacker then has the credential accepted by the gate.

**Fix**

Require an out-of-band human-controlled bootstrap authorization:

*** display a short code in the local terminal that must be entered on the registration page;
- require an existing credential for replacement/additional registration;
- make registration links clearly identify the requesting host and fingerprint;
- support explicit revocation and credential inventory.

---

### 10. Low/Medium — Challenge URLs and approval records are bearer-readable

**Evidence:** `plugin/gate_core.py:491-536`, `plugin/gate_core.py:597-607`

`/a/<id>` exposes the complete action text to anyone with the ID. `/verify/<id>?action_sha256=...` exposes the signed assertion, public key, requester, timestamps, and audit head.

The IDs are high entropy, but URLs are routinely copied into chat logs, browser history, proxies, and monitoring systems.

**Exploit scenario**

A leaked approval URL reveals sensitive operational instructions or the full signed evidence record. The URL cannot approve by itself, but it provides authorization metadata and action disclosure.

**Fix**

Use a separate short-lived viewing token, avoid placing identifiers in URLs where possible, bind approval-page access to an authenticated channel, and minimize `/verify` output. Never return full assertions and public keys to unauthenticated callers unless explicitly required.

## Areas that appear sound

- SQL statements use parameters; I found no SQL injection in the reviewed files.
- Challenge IDs and action hashes are format-validated.
- Server-side challenge status intentionally avoids revealing whether an ID exists for mismatched hashes.
- Server-side WebAuthn verification delegates origin, RP ID, challenge, signature, UV, and sign-count checks to the library.
- Approval and registration state transitions use conditional SQL updates to prevent straightforward single-threaded replay.
- Audit entries are hash chained, though the audit log is not itself an authorization source.

## Files modified

None.

## Verification limitations

The repository’s Python environment lacks the `webauthn` dependency, so the full test suite could not be executed in this environment. The findings above are based on the complete source review and direct control-flow analysis; the most serious race and parent-verification issues are evident independently of the missing dependency.