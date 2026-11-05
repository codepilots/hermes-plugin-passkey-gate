# Remediation ledger — passkey-gate security review

Tracks the fix campaign for `docs/security-review.md` (findings 1–28).
Process: one finding (or tightly-coupled finding group) delegated per
subagent, sequentially. Each fix is verified independently by the primary
agent (diff review + full test suite + targeted probe), then committed, then
logged here with evidence. Status legend: ⬜ queued · 🔄 delegated ·
✅ fixed+verified · 📝 addressed-by-documentation (residual limitation
explicitly stated) · ⛔ blocked.

Baseline: commit `efc3bb8` ("docs: catalog entry updated for 0.4.0"),
review as of `bec3b78` (v0.4.0). Test suite baseline: **29 passed**
(`.venv/bin/python -m pytest tests/ -q`, verified 5 Nov 2026).

Coupled findings are fixed in one delegation where the review itself says
they land in the same code path (noted inline). Original low findings 9–13
fold into items below (9→D3, 10→D11, 11→D12, 12→D8, 13→D13).

## Items

| # | Findings | Severity | Status | Evidence |
|---|----------|----------|--------|----------|
| D1 | 1 — approval page never shows the bound tool call | CRITICAL | ✅ | commit `4956b48`; 33 passed; exploit probe green |
| D2 | 3+4 — consume race + approval expiry (atomic claim-and-consume) | CRITICAL+HIGH | ✅ | commit `36a193e`; 39 passed; 8-way race probe green |
| D3 | 14+9 — assertion↔challenge binding; local_verify never-raise | HIGH+LOW | ⬜ | |
| D4 | 17+7 — block on config failure; wrap verdict fail-closed; config reload | HIGH+MEDIUM | ⬜ | |
| D5 | 5+23 — SSRF: parent allowlist + strict URL parse, no redirects | HIGH+MEDIUM | ⬜ | |
| D6 | 6+19 — parent approval: full local signature verify + hash equality | HIGH | ⬜ | |
| D7 | 16 — enforcement config agent-mutable | HIGH | ⬜ | |
| D8 | 18+12 — pin ceremony: no silent overwrite, O_EXCL/no-follow, PEM validation | HIGH | ⬜ | |
| D9 | 2+20+15 — threat model, bootstrap/registration hardening, dispatch-boundary limitation | CRITICAL (arch) | ⬜ | |
| D10 | 8 — audit chain: honest claim + external head notarization | MEDIUM | ⬜ | |
| D11 | 10 — consumed_at column, preserve decided_at | LOW | ⬜ | |
| D12 | 11 — challenge creation rate limit | LOW | ⬜ | |
| D13 | 21+13 — sign-count validation + clone-detection limits | MEDIUM | ⬜ | |
| D14 | 22 — regex pattern validation + safe block-message display | MEDIUM | ⬜ | |
| D15 | 24 — cloudflared reader deadline | MEDIUM | ⬜ | |
| D16 | 25 — tailscale exact-rule cleanup | MEDIUM | ⬜ | |
| D17 | 26 — owner-slug collision-resistant pin filenames | LOW/MED | ⬜ | |
| D18 | 27 — bearer-readable verify records: minimize + document | LOW/MED | ⬜ | |
| D19 | 28 — numeric setting range validation | LOW | ⬜ | |

## Log

### D2 — findings 3 (CRITICAL) + 4 (HIGH): atomic claim-and-consume ✅

- **Delegated:** make consume() the atomic adjudicator (one conditional
  UPDATE with expiry), block on False in hook_verdict, enforce expires_at at
  lookup/consume/verify, fail-closed exception wrapping. Subagent completed
  in ~231s, TDD (6 new tests first), left uncommitted.
- **Verification (independent):** full suite re-run by parent — 39 passed;
  diff review — consume() claim is a single UPDATE (rowcount==1 wins),
  challenge_status returns bare 'expired' (no signed payload) for stale
  approvals, hook_verdict try/except blocks on any failure; probe
  (`cache/scratch/probe_d2_independent.py`): 8-way consume race → exactly
  one winner; sequential re-use blocked; stale approval dead at lookup,
  consume, hook, and verify; injected exception → block, never allow.
- **Deviations:** none material. The fail-closed wrap also landed part of
  finding 7's fix here — D4's scope narrowed to config-load caching +
  config reload (no re-wrap needed).
- **Commit:** `36a193e`. **Follow-up outside this repo:** Autumn's personal
  `verify_local.py` (the proved original the plugin's local_verify was
  ported from) shares the finding-14 gap fixed next in D3 — flag for a
  matching patch once D3 lands.

### D1 — finding 1 (CRITICAL): bound tool call now rendered ✅

- **Delegated:** persist the canonical tool_call, render it on the approval
  page, include it in /verify and gate_verify, reject enforced prose without
  a binding. Subagent completed in ~226s, TDD (4 new tests first).
- **Verification (independent):** full suite re-run by parent — 33 passed;
  diff review — migration follows the existing ALTER TABLE pattern, page
  block HTML-escapes the canonical JSON, canonical_binding_json() keeps
  page/verify/hook byte-identical; adversarial probe
  (`cache/scratch/probe_d1_independent.py`) replayed the review's exact
  exploit (prose "List the workshop directory…" bound to
  `rm -rf ./projects`): destructive call visible+escaped on the
  page, page JSON hashes to the enforced binding, enforced prose with no
  binding rejected.
- **Deviations accepted:** /verify carries the canonical call as a byte-exact
  JSON string (hashable against binding_sha256); gate_challenge's pattern
  check matches action_text when no tool_call exists (only signal present).
- **Commit:** `4956b48`. Deferred refinement (not blocking): deriving
  action_text from the tool_call at mint time.

