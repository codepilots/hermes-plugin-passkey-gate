"""Finding 8 (D10): honest audit-chain claims + external head notarization.

The hash chain inside the gate data dir detects partial edits and accidental
corruption ONLY: an attacker with write access to that directory can rewrite
the whole log and recompute a fully self-consistent chain that passes
internal verification. `audit-notarize` anchors the current chain head to an
operator-controlled file OUTSIDE that write surface, and `audit-verify
--notary` compares the chain against the anchor, reporting INTACT / GROWN /
REWRITTEN(DIVERGED).

The central tamper test below simulates exactly that attacker: an old entry
is modified and every later hash recomputed, so the INTERNAL check passes —
the notary comparison alone must catch the rewrite.
"""
import hashlib
import json
from datetime import datetime

import pytest

from passkey_gate import cli, gate_core


class FakeCtx:
    """Same shape as tests/test_settings.FakeCtx: plugin-namespaced config."""

    def __init__(self):
        self.store = {}

    def get_config(self, key, default=None):
        return self.store.get(key, default)

    def set_config(self, key, value):
        self.store[key] = value


@pytest.fixture
def data(tmp_path, monkeypatch):
    d = tmp_path / "gate-data"
    d.mkdir()
    monkeypatch.setenv("GATE_DATA", str(d))
    return d


@pytest.fixture
def audit_log(data):
    return data / "audit.jsonl"


def seed(n):
    """Append n audit entries through the real gate_core.audit()."""
    for i in range(n):
        gate_core.audit("notary_test", idx=i)


def rewrite_consistent(records, mutate):
    """Simulate the finding-8 attacker: mutate a record, then recompute seq,
    prev and hash for every line so the chain is fully self-consistent."""
    mutate(records)
    prev = "0" * 64
    lines = []
    for i, rec in enumerate(records):
        rec.pop("hash", None)
        rec["seq"], rec["prev"] = i, prev
        rec["hash"] = hashlib.sha256(
            json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        lines.append(json.dumps(rec, sort_keys=True, separators=(",", ":")))
        prev = rec["hash"]
    return lines


# ---------------------------------------------------------------- notarize

def test_notarize_appends_timestamp_and_head(audit_log, tmp_path):
    seed(3)
    head = gate_core.audit_head()
    notary = tmp_path / "operator-notes" / "gate-notary.log"
    out = cli.dispatch(None, f"audit-notarize --to {notary}")
    assert "notarized" in out.lower()
    lines = notary.read_text().splitlines()
    assert len(lines) == 1
    ts, recorded = lines[0].split()
    datetime.fromisoformat(ts)  # the timestamp is real ISO 8601
    assert recorded == head
    assert (notary.stat().st_mode & 0o777) == 0o600
    # a later notarization APPENDS the then-current head (never replaces)
    seed(2)
    head2 = gate_core.audit_head()
    cli.dispatch(None, f"audit-notarize --to {notary}")
    lines = notary.read_text().splitlines()
    assert len(lines) == 2 and lines[1].split()[1] == head2 and head2 != head


def test_notarize_without_to_prints_head_and_instructions(data, tmp_path):
    seed(2)
    head = gate_core.audit_head()
    out = cli.dispatch(None, "audit-notarize")  # no --to, no ctx, no config
    assert head in out
    assert "out of band" in out.lower()
    # teaches real places to keep it that the agent cannot write
    assert "password manager" in out.lower() or "another host" in out.lower()
    # nothing was written anywhere — the ceremony is print-only in this mode
    assert sorted(p.name for p in data.iterdir()) == ["audit.jsonl"]


def test_notarize_refuses_notary_inside_gate_data_dir(data, audit_log):
    """The anchor only anchors if it lives outside the log's own directory —
    an attacker who can rewrite the audit log could rewrite a notary kept
    beside it."""
    seed(1)
    sneaky = data / "notary.log"
    out = cli.dispatch(None, f"audit-notarize --to {sneaky}")
    assert "refus" in out.lower()
    assert not sneaky.exists()


def test_notarize_defaults_to_configured_path(data, tmp_path):
    seed(2)
    notary = tmp_path / "cfg-notary.log"
    ctx = FakeCtx()
    ctx.store["audit_notary_path"] = str(notary)
    out = cli.dispatch(ctx, "audit-notarize")  # set once, run bare ever after
    assert "notarized" in out.lower()
    assert notary.read_text().split()[1] == gate_core.audit_head()


def test_notarize_on_empty_log_says_so(data):
    out = cli.dispatch(None, "audit-notarize --to /tmp/notary-should-not-be-created.log")
    assert "empty" in out


# ---------------------------------------------------------- audit-verify

def test_verify_without_notary_is_internal_only(data):
    seed(3)
    out = cli.dispatch(None, "audit-verify")
    assert out.startswith("OK ")  # backward-compatible shape
    assert "internal" in out.lower()
    assert "no notary" in out.lower() or "no external" in out.lower()


def test_verify_with_missing_notary_file_says_internal_only(data, tmp_path):
    seed(2)
    out = cli.dispatch(None, f"audit-verify --notary {tmp_path / 'absent.log'}")
    assert out.startswith("OK ")
    assert "does not exist" in out
    assert "internal" in out.lower()


def test_verify_intact_when_head_notarized(data, tmp_path):
    seed(3)
    notary = tmp_path / "n.log"
    cli.dispatch(None, f"audit-notarize --to {notary}")
    out = cli.dispatch(None, f"audit-verify --notary {notary}")
    assert "INTACT AND NOTARIZED" in out
    assert "0 new" in out


def test_verify_grown_counts_new_entries_since_notarization(data, tmp_path):
    seed(3)
    notary = tmp_path / "n.log"
    cli.dispatch(None, f"audit-notarize --to {notary}")
    seed(4)  # append-only growth past the anchor is normal
    out = cli.dispatch(None, f"audit-verify --notary {notary}")
    assert "GROWN SINCE NOTARIZATION" in out
    assert "4 new" in out
    assert "INTACT" not in out


def test_verify_detects_rewrite_that_passes_internal_check(data, audit_log, tmp_path):
    """The heart of finding 8: the attacker CAN make the chain internally
    consistent, so the internal check must PASS — the notarized head is the
    only thing that catches the rewrite."""
    seed(4)
    notary = tmp_path / "n.log"
    cli.dispatch(None, f"audit-notarize --to {notary}")
    records = [json.loads(l) for l in audit_log.read_text().splitlines()]
    lines = rewrite_consistent(records, lambda rs: rs[1].__setitem__("event", "approved"))
    audit_log.write_text("\n".join(lines) + "\n")
    ok, msg = gate_core.audit_verify()
    assert ok, "attacker rewrite must pass the internal check (that IS finding 8)"
    out = cli.dispatch(None, f"audit-verify --notary {notary}")
    assert "DIVERGED" in out
    assert "rewrit" in out.lower()


def test_verify_detects_truncation(data, audit_log, tmp_path):
    seed(3)
    notary = tmp_path / "n.log"
    cli.dispatch(None, f"audit-notarize --to {notary}")
    seed(3)  # 6 entries; anchor the head twice
    cli.dispatch(None, f"audit-notarize --to {notary}")
    # attacker truncates the log to 4 entries: an internally-consistent prefix
    audit_log.write_text("\n".join(audit_log.read_text().splitlines()[:4]) + "\n")
    ok, _ = gate_core.audit_verify()
    assert ok, "a valid prefix is internally consistent — truncation alone must not look fine"
    out = cli.dispatch(None, f"audit-verify --notary {notary}")
    assert "DIVERGED" in out
    assert "truncat" in out.lower() or "rewrit" in out.lower()


def test_verify_broken_internal_chain_reports_broken(data, audit_log, tmp_path):
    seed(3)
    notary = tmp_path / "n.log"
    cli.dispatch(None, f"audit-notarize --to {notary}")
    records = [json.loads(l) for l in audit_log.read_text().splitlines()]
    records[0]["event"] = "tampered"  # partial edit WITHOUT recomputation
    audit_log.write_text("\n".join(
        json.dumps(r, sort_keys=True, separators=(",", ":")) for r in records) + "\n")
    out = cli.dispatch(None, f"audit-verify --notary {notary}")
    assert out.startswith("BROKEN ")


def test_verify_surfaces_malformed_notary_file(data, tmp_path):
    seed(2)
    notary = tmp_path / "n.log"
    notary.write_text("this line is not a notary record\n")
    out = cli.dispatch(None, f"audit-verify --notary {notary}")
    assert "malformed" in out


def test_verify_uses_configured_notary_path(data, tmp_path):
    seed(2)
    notary = tmp_path / "cfg-notary.log"
    ctx = FakeCtx()
    ctx.store["audit_notary_path"] = str(notary)
    out = cli.dispatch(ctx, "audit-verify")  # configured but not created yet
    assert "does not exist" in out
    cli.dispatch(None, f"audit-notarize --to {notary}")
    out = cli.dispatch(ctx, "audit-verify")
    assert "INTACT AND NOTARIZED" in out


# ------------------------------------------------- settings contract

def test_audit_notary_path_is_not_a_security_key():
    """audit_notary_path only names where anchors are kept — deliberately NOT
    in SECURITY_KEYS (finding 16 protects gate-enforcement settings only)."""
    assert "audit_notary_path" in cli.SETTINGS_SPEC
    assert "audit_notary_path" not in cli.SECURITY_KEYS
