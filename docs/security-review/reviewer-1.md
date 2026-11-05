## Findings

### 1. **Critical — approval can be reused concurrently**
**Evidence:** `plugin/tools.py:190-203`, `plugin/gate_core.py:334-343,346-349`

`hook_verdict()` first selects an approved row, then calls `consume()`, but ignores the Boolean result:

```python
row = gate_core.pending_for_binding(binding)
...
gate_core.consume(row["id"], binding)
return None
```

`consume()` is atomic, but the check and consume are not one operation. Two concurrent tool calls can both read the same approved row. One consumes it; the other receives `False` from `consume()` and still returns `None`, allowing both executions.

**Exploit:** Obtain one approval for a destructive command, then issue two identical tool calls concurrently. Both hooks can pass before or around the consumption race.

**Fix:** Make selection and consumption one atomic SQL operation and only allow execution when it returns exactly one row:

```sql
UPDATE challenges
SET status='consumed', decided_at=?
WHERE id=? AND status='approved'
  AND binding_sha256=? AND expires_at >= ?
RETURNING id
```

Or change `consume()` to return the consumed row and have `hook_verdict()` block when it returns false.

---

### 2. **Critical — human can approve misleading text for a different tool call**
**Evidence:** `plugin/gate_core.py:223-230,271-287`; `plugin/tools.py:45-46`; `plugin/schemas.py:73-82`

`tool_call` is optional. The server independently accepts arbitrary `action_text` and arbitrary `tool_call`; it never verifies that the prose accurately describes the structured call. The enforcement hook checks only `binding_sha256`, not the relationship between the binding and the displayed text.

**Exploit:**

1. Agent creates a challenge with action text such as “List the deployment status on staging.”
2. It binds the challenge to `{"tool":"terminal","args":{"command":"rm -rf ..."}}`.
3. Human reads and signs the harmless-looking text.
4. The hook consumes the approval and allows the destructive call.

The same issue applies to a truthful-looking `why`, requester identity, and parent-approval narrative.

**Fix:** For enforced calls, require `tool_call`; recompute the exact canonical call server-side and require the challenge creator to provide a structured, human-rendered description generated from that call. At minimum, show the canonical tool name and arguments prominently on the approval page and require `gate_challenge` to reject `require_passkey`-eligible challenges without a binding. Ideally sign one structured authorization object containing both the canonical call and human-readable explanation.

---

### 3. **High — enforcement can be disabled through configuration**
**Evidence:** `plugin/plugin.yaml:44-53`; `plugin/cli.py:205-221,65-76`; `plugin/tools.py:178-189`

`require_passkey` defaults to `false`, and `cmd_set()` permits changing it at runtime. There is no authentication, authorization, immutable policy file, or special protection for:

```text
hermes passkey-gate set require_passkey false
hermes passkey-gate set authority_patterns []
```

If the agent can invoke an unlisted CLI or shell path, it can disable the gate before executing the privileged action. The enforcement hook then intentionally returns `None`.

**Exploit:** Configure a pattern for `terminal`, but leave the CLI command itself outside the pattern. The agent runs the CLI to disable enforcement, then executes the action.

**Fix:** Treat enforcement policy as operator-owned configuration, not agent-mutatable state. Remove runtime mutation of `require_passkey` and `authority_patterns`, or require an independent passkey/operator confirmation for changes. At minimum, protect all `hermes passkey-gate set` paths with a non-bypassable policy and audit/reload atomically.

---

### 4. **High — configuration-load failures fail open**
**Evidence:** `plugin/cli.py:93-103`

On any configuration error, `apply_config_safe()` caches:

```python
{"require_passkey": False, "patterns": []}
```

The log explicitly says “enforcement stays off until config loads.” Because `_cfg_cache` is then populated, the disabled state persists for the process.

**Exploit:** Cause a malformed setting, storage failure, plugin-data permission error, or transient exception in `apply_config()`. The next privileged tool call runs without enforcement.

**Fix:** Configuration failure must return a block directive, not an empty disabled configuration. Cache a validated immutable policy only after successful loading. Distinguish “not configured” from “configuration failed.”

---

### 5. **High — approval is consumed before the actual tool execution**
**Evidence:** `plugin/tools.py:187-203`; Hermes execution path applies execution middleware afterward (`model_tools.py:941-957`)

The hook consumes the authorization before the tool is dispatched. If later execution middleware transforms arguments, wraps a connector, or otherwise changes the effective operation, the approval has authorized the pre-middleware call but the executed call may differ.

The repository’s own Hermes runtime shows that execution middleware runs after the pre-tool hook.

**Exploit:** A middleware/plugin changes a path, command, recipient, or connector payload after the passkey hook has approved and consumed the original arguments.

**Fix:** Bind and verify the final arguments immediately before dispatch, after all argument transformations. Better: make the enforcement hook return an authorization token and consume it at the final dispatch boundary, where the final canonical call is known.

---

### 6. **High — CLI pinning is not actually first-seen pinning**
**Evidence:** `plugin/local_verify.py:100-106`

`pin()` always overwrites the existing key:

```python
path.write_text(pem.strip() + "\n")
```

This contradicts the “first seen out of band, then trusted” design.

**Exploit:** Any process or agent able to invoke the CLI can replace the owner key with an attacker-controlled public key, then obtain approvals using the attacker’s corresponding private key. The local verifier will accept them.

**Fix:** Refuse to overwrite an existing pin unless an explicit, separately authenticated key-rotation procedure succeeds. Validate the PEM before writing. Audit key rotation with old/new fingerprints.

---

### 7. **High — parent approvals are not locally cryptographically verified**
**Evidence:** `plugin/local_verify.py:114-143`

`verify_parent_approval()` checks only:

- remote response says `status == "approved"`
- returned public key equals the locally pinned key

It does not call `local_verify.check()` on the parent record. Thus it does not verify the parent signature, client-data challenge, RP ID, origin, UV flags, or action binding.

**Exploit:** A compromised or malicious parent gate can return an altered “approved” record using the pinned public key. The page will display a positive-looking parent status, despite no locally verified WebAuthn assertion.

**Fix:** Fetch the full parent record and run the complete local cryptographic verifier against it. The parent record must include the original action text or a signed structured authorization object. Do not show “verified” until all checks pass.

---

### 8. **High — parent approval can mislead humans about what was approved**
**Evidence:** `plugin/gate_core.py:255-270`; `plugin/local_verify.py:114-143`; `plugin/gate_core.py:509-520`

The child challenge accepts a parent’s independent `action_sha256`, but never requires it to match the child action text or structured tool binding. The page says another human approved it first, even if the parent approval was for an unrelated action.

**Exploit:** Supply a real approved parent challenge for “read logs” while the child request asks the signer to authorize deletion. The page presents the prior approval as relevant context without proving semantic or hash equivalence.

**Fix:** Require exact equality of the parent and child authorization hashes for chaining, or label parent approvals strictly as unrelated context. Display both action texts and require the signer to independently approve the current action.

---

### 9. **Medium — challenge TTL does not constrain approved challenges**
**Evidence:** `plugin/gate_core.py:311-315,334-349`; `plugin/tools.py:190-203`

`pending_for_binding()` and `consume()` select approved challenges without checking `expires_at`. The TTL is checked while pending and during approval, but an approval obtained just before expiry remains usable indefinitely.

**Exploit:** Human approves a high-impact action; the agent stores the approval and executes it much later, after the intended ten-minute authorization window.

**Fix:** Add `expires_at > now` to both the lookup and atomic consume query. Add a separate, explicit approval-validity TTL if pending and approved lifetimes are meant to differ.

---

### 10. **Medium — broad or attacker-influenced regex matching is unsafe as an authority boundary**
**Evidence:** `plugin/tools.py:167-175`; `plugin/plugin.yaml:49-53`

Patterns are arbitrary regexes over:

```text
tool_name + " " + canonical JSON(args)
```

This creates several problems:

- `re.search()` allows an unanchored substring to trigger unexpectedly.
- Regex behavior is dependent on JSON spelling and escaping.
- Pattern text is inserted directly into the block message at `tools.py:195-200`.
- A pattern containing newlines, terminal escapes, or misleading prose can manipulate the agent’s interpretation of why it was blocked.
- Broad patterns can be weakened by alternate tool names, aliases, connectors, nested bridges, or semantically equivalent arguments.

This is primarily policy fragility rather than a direct bypass, but the block message is presented as authoritative guidance to the agent.

**Fix:** Use structured matchers rather than arbitrary regex, or compile/validate patterns at configuration time. Use full-match semantics where appropriate. Escape pattern text before displaying it, cap its length, and report a stable rule identifier rather than attacker-readable raw regex. Test aliases, connector names, bridge tools, Unicode, numeric/string coercions, and nested arguments.

---

### 11. **Medium — origin and health requests follow redirects, enabling SSRF**
**Evidence:** `plugin/tools.py:143-157`; `plugin/cli.py:263-268`; `plugin/local_verify.py:129-133`

`urllib.request.urlopen()` follows redirects by default. The configured origin is only prefix-checked by the CLI (`cli.py:214-218`); it is not parsed and pinned to a host/scheme/port. A configured HTTPS endpoint can redirect to an internal HTTP or HTTPS service.

**Exploit:** Set or induce an origin such as `https://attacker.example`, which redirects `/verify` or `/health` to `http://127.0.0.1:...`, cloud metadata, or another internal service. This gives an attacker a server-side request primitive and can make status checks report attacker-controlled JSON.

Local verification limits approval forgery in the normal `gate_verify` path, but it does not eliminate the SSRF or misleading status risks. Parent verification is especially sensitive because it trusts remote response fields more broadly.

**Fix:** Parse origins with `urllib.parse`, require HTTPS except explicit loopback development mode, disable redirects, and validate the final host against the configured origin. Use an HTTP client with redirect policy and private-network blocking. Apply the same rules to parent bases.

---

### 12. **Medium — cloudflared timeout can hang indefinitely**
**Evidence:** `plugin/expose.py:175-197`

The loop has a deadline, but `proc.stdout.readline()` can block indefinitely when cloudflared emits no newline:

```python
line = proc.stdout.readline()
```

The `watch_seconds` limit is therefore not reliable.

**Exploit:** A stalled or unusual cloudflared process causes the CLI to hang indefinitely, potentially leaving a tunnel process running and preventing configuration or recovery.

**Fix:** Use nonblocking I/O/selectors, a reader thread with a queue and deadline, or poll the process and read bounded output without blocking. Always kill and wait for the child on timeout and exceptions.

---

### 13. **Medium — failed Tailscale HTTPS rules may not be removed**
**Evidence:** `plugin/expose.py:149-150`

The code creates an HTTPS rule but cleanup invokes:

```python
tailscale serve --bg --http=<port> off
```

That may disable a different HTTP rule rather than the failed HTTPS rule, leaving stale exposure configuration.

**Fix:** Remove the exact HTTPS rule using the corresponding `--https=<port>` operation, then re-read the serve map and verify that only the plugin-created rule was removed.

---

### 14. **Low/Medium — owner pin path collisions**
**Evidence:** `plugin/local_verify.py:89-97`

Owner labels are reduced to a slug:

```python
re.sub(r"[^a-z0-9_-]", "-", owner.strip().lower())[:40]
```

Different owners can collide (`alice@example.com` and `alice@example!com`), and labels consisting only of punctuation can all map to the same filename.

**Exploit:** Pinning one peer’s key overwrites or is mistaken for another peer’s key, causing cross-human attribution and trust errors.

**Fix:** Use a collision-resistant filename, such as a hash of the exact normalized owner identifier, and store the original owner label inside the pin record.

---

### 15. **Low — invalid CLI numeric settings can create denial of service**
**Evidence:** `plugin/cli.py:224-249`; `plugin/gate_core.py:63-77`

`port` and `challenge_ttl` accept arbitrary integers, including negative values and unsuitable ports. Negative TTLs cause immediate expiry; invalid ports make `serve` fail.

**Fix:** Enforce ranges: valid TCP port range, positive challenge TTL, bounded bootstrap TTL, and sensible maximums. Validate `rp_id` as a hostname and origin as a parsed URL rather than string prefixes.

## Hook and fail-open assessment

- Hermes’s current plugin dispatcher is documented and implemented to fail closed for `pre_tool_call` timeout/exception paths.
- However, this plugin itself converts configuration failures into `require_passkey=False` (`cli.py:93-103`), which is an explicit fail-open path.
- `require_passkey: false` and an empty pattern list are legitimate defaults, so enforcement is absent unless configuration is correct and remains loaded.
- Hermes has explicit `skip_pre_tool_call_hook=True` internal paths. Those are intended internal bypasses, but the security model should document which callers are trusted and ensure no model-controlled route can set that flag.
- The test suite passes (`29 passed`), but it does not cover concurrent duplicate calls, config failure, post-hook argument mutation, pin replacement, SSRF redirects, parent signature verification, or misleading prose/binding mismatches.

## Overall verdict

**Not safe to describe as a strong enforcement boundary in its current form.**

The most serious issues are:

1. **Concurrent reuse due to ignored atomic-consume failure**
2. **Human-visible action text not cryptographically or structurally tied to the enforced tool call**
3. **Agent-writable enforcement configuration**
4. **Key pin replacement**
5. **Parent approvals not locally signature-verified**
6. **Pre-hook authorization consumed before final dispatch arguments are known**

The WebAuthn cryptographic core and ordinary single-threaded happy path are reasonably structured, and the existing tests validate that path. The enforcement hook needs another security-hardening pass before it should protect destructive or irreversible actions.