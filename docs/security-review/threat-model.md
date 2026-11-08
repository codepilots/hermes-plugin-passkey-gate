# Passkey-gate threat model and residual architectural limitations

**Applies to:** passkey-gate v0.6.0, security review dated 5 November 2026
(`69bcd7e6` review context; remediation campaign D9). This document preserves
and qualifies findings **2 (CRITICAL), 15 (HIGH), and 20 (MEDIUM)**. It is a
residual-risk statement, not a claim that those findings are eliminated.

## Security boundary and trust assumptions

Passkey-gate can verify WebAuthn assertions and bind an approval to canonical
text and, when supplied, a canonical structured `tool_call`. That verification
is useful only inside a deployment with a boundary the agent cannot alter.
The following must be operator-owned and outside the agent's write/control
authority:

- trust anchors (pinned owner and peer public keys);
- enforcement configuration, including `require_passkey` and authority
  patterns;
- the plugin code and its dependencies;
- the gate database, audit data, pin files, and other verification data; and
- the final dispatch/executor boundary that turns an approved call into an
  external effect.

If the agent can edit any of those, replace or monkeypatch the plugin, alter the
DB, or invoke the pin/bootstrap path, passkey-gate is **not a security
boundary**. Its approvals are advisory in that deployment. No process-local
cryptographic check can defend against a compromised host or process that can
replace code, monkeypatch modules, alter the database, or bypass the hook.

The `bootstrap` CLI command and `pin` CLI command are explicit operator
ceremonies, not automatic registration. They must be run by an operator through
an out-of-band procedure. The plugin deliberately does not invent an
agent-vs-human context signal: a caller that can invoke these commands is
already inside the assumed control plane. Verification and challenge creation
must not create credentials or pin files; first registration and first pin are
never implicit side effects.

## Finding 2 — agent-controlled trust anchors (CRITICAL)

The local verifier trusts the configured/pinned key and local process state. It
cannot distinguish an operator's pin from an agent-written replacement when the
agent controls the files, process, or CLI. Finding D8 prevents silent pin
replacement and validates pin material, but that is not a complete security
boundary against an agent that can edit the installation/data directory or
invoke the ceremony itself. Finding D7 protects the policy path only within the
same assumption.

Required deployment controls are concrete, not optional documentation:

- install the plugin root-owned and read-only where practical;
- make the data directory and pin files root/operator-owned;
- lock configuration and protect it with restrictive filesystem ACLs;
- run the gate/verifier under a separate service account;
- deny the agent access to the plugin install, DB, audit log, config, and pins;
- provide no agent-reachable bootstrap or pin command; and
- use a separate host/service or broker when the agent and verifier otherwise
  share an unrestricted process/control plane.

With those controls, the operator can treat the pin and bootstrap ceremonies as
out-of-band setup. Without them, the strongest honest description is a local
tamper-evident record of an assertion, not prevention of self-approval.

## Finding 20 — bootstrap/registration ceremony (MEDIUM)

A bootstrap token is one-time and short-lived, but minting it is still an
explicit CLI operation and the first valid WebAuthn registration is not bound to
an already registered operator credential. An agent can initiate that flow, and
an operator can be socially engineered into registering the wrong authenticator.
The code therefore makes no automatic registration claim and does not add fake
authentication based on an unverifiable caller-context flag.

The operator procedure must deliver bootstrap authorization out of band (for
example, a physical/operator-controlled device or an authenticated operator
channel), use the operator's own authenticator rather than a shared agent vault,
and keep the gate and registration data outside the agent's control. For a
stronger deployment, use an operator-controlled bootstrap code/approval and
require an existing credential for additions or replacement; implement that as
an independently authenticated ceremony or broker, not as an in-process claim.

**v0.6.0 mitigation (hackathon-readiness review H1).** Registration is still
not bound to an existing credential, but a credential registered through a
token the agent minted itself no longer buys anything on its own: the
enforcement hook, `gate_verify`, and `set --approve` all re-verify the signed
assertion against the **pinned** owner key, so approvals signed by any other
credential are refused. The residual is now the pin itself — keep
`pin` an operator ceremony and the pin files outside the agent's write reach.

## Finding 15 — final dispatch substitution (HIGH)

`gate_challenge` stores the canonical tool-call JSON and its
`binding_sha256`. `gate_verify` exposes `approved_tool_call` and
`dispatch_binding` (canonical JSON plus hash), and the pre-tool hook recomputes
the exact canonical call, checks the stored call/hash consistency, and refuses a
mismatch before consuming the approval. A caller that supplies a different
`tool_call` to `gate_verify` receives `verified: false`.

These are local binding checks and an API contract, not control of the final
executor. WebAuthn proves user presence/verification for the signed challenge;
it does **not** prove that the final downstream tool execution matches that
challenge. Parent approvals are context/authorization inputs only when the
full local checks pass; they do not solve dispatch-boundary substitution.

Any middleware, plugin, serializer, connector, shell wrapper, or executor that
changes arguments after the hook can still create a different effect unless
the final boundary rechecks and enforces the exact `dispatch_binding`. The
final executor/dispatcher must therefore enforce the same canonical payload
and hash immediately before execution, consume authorization there, or the
system must use a separate broker that owns this enforcement boundary. Do not
claim that passkey-gate alone controls downstream execution.

## Finding 27 — bearer-readable challenge pages and verification evidence (LOW/MEDIUM)

The gate now minimizes an approved `/verify/<id>?action_sha256=...` response to
only the fields needed by `verify_parent_approval()` and `local_verify.check()`:
`status`, `challenge_id`, `action_sha256`, `action_text`, `approved_at`,
`origin`, `rp_id`, `challenge_b64url`, the signed `assertion`, and the
`credential_public_key`. It no longer returns `binding_sha256`, the canonical
`tool_call`, `requester`, `created_at`, or `audit_head`. Parent verification and
local cryptographic checking continue to use the retained action, nonce,
assertion, key, origin/RP, and approval timestamp fields.

This is minimization, not authentication. The action text and cryptographic
evidence are still bearer-readable to anyone who obtains the high-entropy
identifier and action hash. `/a/<id>` remains unchanged: it still exposes the
approval ceremony to a bearer of the challenge ID. The local plugin has no
independent authenticated operator channel from which to issue a second viewing
token or bind browser access, and replacing the ID with an unauthenticated
viewing token would merely create another bearer secret and could disrupt the
human ceremony. A deployment that needs confidentiality must provide the
missing channel outside this plugin (for example, an operator-authenticated
broker/session or a separately issued, short-lived single-use viewing token
whose issuance is itself authenticated). URLs must still be treated as
sensitive and kept out of logs, history, chat, and monitoring.

## Residual risk summary

D9 is **partially addressed**:

- no automatic credential registration or pin creation is performed by
  challenge/verification paths, and tests cover that invariant;
- approved results expose the exact canonical tool call and binding contract;
- mismatched requested calls and inconsistent stored bindings are refused; but
- findings 2 and 20 remain architectural deployment requirements, and finding
  15 remains unless the final executor/broker enforces the binding outside the
  agent-controlled process.

The review's original numbered findings and date/version context remain in
`docs/security-review.md`; this document is the explicit residual limitation
for D9 rather than a "fixed" label.
