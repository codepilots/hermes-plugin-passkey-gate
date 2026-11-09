"""CLI settings tests: parse/validate/persist/show round trips against a fake ctx
that mimics ctx.get_config / ctx.set_config (plugin namespaced settings)."""

import json

import pytest

from passkey_gate import cli


class FakeCtx:
    def __init__(self):
        # a new fake config models a fresh install, which has no armed
        # config canary either (the canary file is per-test, see conftest)
        cli._canary_file().unlink(missing_ok=True)
        self.store = {}

    def get_config(self, key, default=None):
        return self.store.get(key, default)

    def set_config(self, key, value):
        self.store[key] = value


def _cli(ctx, cmd: str) -> str:
    return cli.dispatch(ctx, cmd)


def test_parse_setting_types():
    assert cli.parse_setting("port", "9001")[0] == 9001
    assert cli.parse_setting("require_passkey", "true")[0] is True
    assert cli.parse_setting("require_passkey", "no")[0] is False
    assert cli.parse_setting("require_passkey", "maybe")[0] is None
    assert cli.parse_setting("authority_patterns", '["a", "b"]')[0] == ["a", "b"]
    assert cli.parse_setting("authority_patterns", "a, b")[0] == ["a", "b"]  # comma fallback
    assert cli.parse_setting("origin", " https://host.ts.net ")[0] == "https://host.ts.net"


def test_set_and_show_roundtrip():
    ctx = FakeCtx()
    out = _cli(ctx, "set origin https://real.example.ts.net:8445")
    assert "origin = \"https://real.example.ts.net:8445\"" in out
    assert ctx.store["origin"] == "https://real.example.ts.net:8445"
    out = _cli(ctx, "set require_passkey true")
    assert ctx.store["require_passkey"] is True
    out = _cli(ctx, "set authority_patterns ^terminal .*(rm |curl )")
    # no commas + not valid JSON → the whole string is ONE pattern
    assert ctx.store["authority_patterns"] == ["^terminal .*(rm |curl )"]
    show = _cli(ctx, "get")
    assert all(f"  {k} = " in show for k in cli.SETTINGS_SPEC)


def test_set_rejects_bad_values():
    ctx = FakeCtx()
    out = _cli(ctx, "set nope 1")
    assert "unknown setting" in out
    out = _cli(ctx, "set port notanumber")
    assert "error" in out.lower() or "invalid" in out.lower()
    out = _cli(ctx, "set origin http://evil.example.ts.net")
    assert "https" in out and ctx.store.get("origin") is None  # rejected before write
    out = _cli(ctx, "set origin https://fine.example.ts.net")
    assert ctx.store["origin"] == "https://fine.example.ts.net"


def test_numeric_settings_reject_out_of_range_without_persistence():
    ctx = FakeCtx()
    for key, bad in (("challenge_ttl", ["0", "-1", "86401"]),
                     ("port", ["0", "-1", "65536", "not-an-int"])):
        for raw in bad:
            out = _cli(ctx, f"set {key} {raw}")
            assert "REFUSED" in out and "allowed range" in out, (key, raw, out)
            assert key not in ctx.store


def test_numeric_settings_accept_range_boundaries():
    # fresh config per value: raising challenge_ttl is a gate-weakening
    # change (H11), so the max is checked from a config already at the max
    for key, low, high in (("challenge_ttl", 60, 86400), ("port", 1, 65535)):
        for value in (low, high):
            ctx = FakeCtx()
            if key == "challenge_ttl" and value == high:
                ctx.store[key] = high
            out = _cli(ctx, f"set {key} {value}")
            assert ctx.store[key] == value, out


def test_malformed_legacy_numeric_settings_fail_closed_without_crashing():
    ctx = FakeCtx()
    ctx.store.update(port=-1, challenge_ttl="not-an-int")
    # apply_config is the runtime boundary; it must turn malformed legacy
    # values into the existing fail-closed config marker, not crash.
    cli._ctx_ref = ctx
    try:
        state = cli._load_config_state()
    finally:
        cli._ctx_ref = None
    assert state["require_passkey"] is True
    assert "_config_error" in state


def test_runtime_numeric_boundaries_and_malformed_values_fail_closed(monkeypatch):
    from passkey_gate import gate_core

    original = gate_core._settings.copy()
    try:
        gate_core.configure(port=1, challenge_ttl=1, bootstrap_ttl=1)
        assert gate_core.port() == 1
        assert gate_core.challenge_ttl() == 1
        assert gate_core.bootstrap_ttl() == 1
        gate_core.configure(port=65535, challenge_ttl=86400, bootstrap_ttl=86400)
        assert gate_core.port() == 65535
        assert gate_core.challenge_ttl() == 86400
        assert gate_core.bootstrap_ttl() == 86400
        for key, value in (("PORT", 0), ("CHALLENGE_TTL", "bad"), ("BOOTSTRAP_TTL", 86401)):
            monkeypatch.setitem(gate_core._settings, key, value)
            with pytest.raises(ValueError, match="allowed range"):
                {"PORT": gate_core.port, "CHALLENGE_TTL": gate_core.challenge_ttl,
                 "BOOTSTRAP_TTL": gate_core.bootstrap_ttl}[key]()
    finally:
        gate_core._settings.clear()
        gate_core._settings.update(original)


def test_expose_refuses_invalid_legacy_port_before_backend(monkeypatch):
    ctx = FakeCtx()
    ctx.store["port"] = 0
    called = []
    monkeypatch.setattr(cli.expose, "auto_expose", lambda *args: called.append(args))
    out = _cli(ctx, "expose auto")
    assert "REFUSED" in out and "allowed range" in out
    assert called == []


def test_http_serve_refuses_invalid_port_before_bind():
    from passkey_gate import gate_core

    with pytest.raises(ValueError, match="allowed range"):
        gate_core.serve(http_port=0)


def test_set_loopback_http_is_tolerated():
    ctx = FakeCtx()
    out = _cli(ctx, "set origin http://127.0.0.1:8655")
    assert ctx.store["origin"] == "http://127.0.0.1:8655"


def test_set_origin_is_parsed_not_prefix_checked():
    """Finding 23: `set origin` must PARSE the URL — the old prefix check let
    credential-carrying, hostless, and unparseable-port origins through."""
    ctx = FakeCtx()
    rejected = [
        "https://user:secret@host.ts.net",   # credentials ride along
        "https://",                          # no host at all
        "https://:8445",                     # port without a host
        "https://host.ts.net:notaport",      # unparseable port
        "http://192.168.1.9:8655",           # plain http off loopback (private is NOT the dev exception)
        "ftp://host.ts.net",
    ]
    for bad in rejected:
        out = _cli(ctx, f"set origin {bad}")
        assert "origin rejected" in out, bad
        assert ctx.store.get("origin") is None, bad  # rejected before persisting
    accepted = ["https://fine.example.ts.net", "https://real.example.ts.net:8445",
                "http://localhost:8655", "http://127.0.0.1:8655"]
    for good in accepted:
        ctx = FakeCtx()  # first-time setup each time (moving an origin needs approval, H11)
        out = _cli(ctx, f"set origin {good}")
        assert ctx.store["origin"] == good, out


# The same finding-23 rule at the two remaining origin consumers (claims
# issue 3 of the fresh v0.5.0 review): gate_verify and the cmd_set
# weakening-approval re-check previously accepted the configured origin via
# a bare startswith('http://'/'https://') prefix check and must parse instead,
# exactly like `set origin` — including keeping the documented loopback-http
# dev exception.
_ORIGIN_REJECTED = [
    "https://",                          # prefix-craft: no host at all
    "https://:8445",                     # prefix-craft: port without a host
    "https://user:secret@host.ts.net",   # credentials ride along
    "https://host.ts.net:notaport",      # unparseable port
    "http://192.168.1.9:8655",           # plain http off loopback
    "ftp://host.ts.net",                 # not an http(s) scheme
    "not-a-url",                         # no scheme at all
]
# A scary-looking hostname is still a syntactically valid https origin: the
# parse cannot judge names, only structure — so it is ACCEPTED, matching
# `set origin` exactly (consistency is the rule the review demands).
_ORIGIN_ACCEPTED = [
    "https://fine.example.ts.net:8445",
    "https://evil.example.ts.net.evil.com",
    "http://localhost:8655",             # documented dev exception
    "http://127.0.0.1:8655",             # documented dev exception
]


def test_gate_verify_origin_is_parsed_not_prefix_checked(monkeypatch):
    from passkey_gate import tools

    def never_fetch(*a, **k):
        raise AssertionError("a refused origin must never reach a fetch")

    monkeypatch.setattr(tools, "_fetch_verify", never_fetch)
    for origin in _ORIGIN_REJECTED:
        monkeypatch.setattr(tools, "_base_url", lambda o=origin: o)
        out = json.loads(tools.gate_verify({"challenge_id": "A" * 24,
                                            "action_text": "x" * 50}))
        assert out["ok"] is False, origin
        assert "origin" in out["error"], (origin, out)
    monkeypatch.setattr(tools, "_fetch_verify",
                        lambda *a, **k: {"status": "error", "error": "stub"})
    for origin in _ORIGIN_ACCEPTED:
        monkeypatch.setattr(tools, "_base_url", lambda o=origin: o)
        out = json.loads(tools.gate_verify({"challenge_id": "A" * 24,
                                            "action_text": "x" * 50}))
        assert out["ok"] is True, (origin, out)  # past the origin gate


def test_weakening_approval_origin_is_parsed_not_prefix_checked(monkeypatch):
    from passkey_gate import tools

    def never_fetch(*a, **k):
        raise AssertionError("a refused origin must never reach a fetch")

    monkeypatch.setattr(tools, "_fetch_verify", never_fetch)
    for origin in _ORIGIN_REJECTED:
        monkeypatch.setattr(tools, "_base_url", lambda o=origin: o)
        problems = cli._verify_weakening_approval("c" * 24, "set require_passkey=false — confirm")
        assert len(problems) == 1 and "origin" in problems[0], (origin, problems)
    monkeypatch.setattr(tools, "_fetch_verify",
                        lambda *a, **k: {"status": "pending"})
    for origin in _ORIGIN_ACCEPTED:
        monkeypatch.setattr(tools, "_base_url", lambda o=origin: o)
        problems = cli._verify_weakening_approval("c" * 24, "set require_passkey=false — confirm")
        assert not any("origin" in p for p in problems), (origin, problems)


def test_set_parent_gate_allowlist_roundtrip():
    """Finding 5's config key: allowed parent-gate origins, parsed as a list
    (JSON or comma form) and persisted like every other setting. Finding 16:
    ADDING an allowlist entry is gate-weakening, so it is refused without a
    passkey approval; REMOVING entries applies immediately."""
    ctx = FakeCtx()
    out = _cli(ctx, "set parent_gate_allowlist https://peer-a.example.ts.net:8445,https://peer-b.example.ts.net:8445")
    # the comma form parses (the refusal echoes the canonical new value), but
    # adding entries is gate-weakening -> refused, nothing persisted
    assert ctx.store.get("parent_gate_allowlist") is None
    assert '["https://peer-a.example.ts.net:8445","https://peer-b.example.ts.net:8445"]' in out
    assert "This weakens the gate" in out
    assert "--approve" in out
    # removing an entry is strengthening: parsed, persisted, no approval needed
    ctx.store["parent_gate_allowlist"] = ["https://peer-a.example.ts.net:8445",
                                          "https://peer-b.example.ts.net:8445"]
    out = _cli(ctx, "set parent_gate_allowlist https://peer-a.example.ts.net:8445")
    assert ctx.store["parent_gate_allowlist"] == ["https://peer-a.example.ts.net:8445"]
    show = _cli(ctx, "get")
    assert "parent_gate_allowlist" in show


def test_settings_spec_matches_manifest():
    """Keys must be exactly the plugin.yaml config_schema keys — drift surfaces here."""
    from pathlib import Path
    import yaml
    manifest_path = Path(__file__).resolve().parents[1] / "plugin" / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    schema_keys = set((manifest.get("config_schema") or {}).keys())
    # config_canary is declared (so a schema-driven settings form keeps it)
    # but is never settable with `set`
    assert schema_keys == set(cli.SETTINGS_SPEC.keys()) | {cli.CANARY_KEY}
    assert cli.CANARY_KEY not in cli.SETTINGS_SPEC


# ---------------- finding 22: authority_patterns are validated at set time

def test_set_authority_patterns_invalid_regex_refused():
    """Finding 22: an unparseable pattern must never reach config. cmd_set
    compiles every pattern and refuses the WHOLE list — a broken regex
    throws at match time (fail-closed but opaque), so nothing persists
    around it. The refusal names the offending entry; nothing is written."""
    ctx = FakeCtx()
    bad_lists = [
        '["^terminal ("]',         # unbalanced group — re.error at compile
        '["[", "ssh git@100"]',    # one broken entry poisons the whole list
        '["*"]',                   # nothing to repeat
        '[42]',                    # not a string — the regex engine cannot take it
        '["ssh git@100", 7]',      # one non-string poisons the whole list
    ]
    for bad in bad_lists:
        out = _cli(ctx, f"set authority_patterns {bad}")
        assert "REFUSED" in out, bad
        assert "patterns[" in out, bad  # the refusal names the offending entry
        assert ctx.store.get("authority_patterns") is None, bad  # nothing persisted
    # the pattern that shared a poisoned list is fine on its own
    out = _cli(ctx, "set authority_patterns [\"ssh git@100\"]")
    assert ctx.store["authority_patterns"] == ["ssh git@100"]


def test_set_authority_patterns_length_and_count_caps():
    """Finding 22: caps bound the ReDoS surface of operator patterns — an
    over-long pattern or an oversized list is refused whole (nothing
    persisted); the boundary values themselves are allowed."""
    ctx = FakeCtx()
    out = _cli(ctx, f'set authority_patterns ["{"a" * 201}"]')
    assert "REFUSED" in out and "200" in out
    assert ctx.store.get("authority_patterns") is None  # refused -> not stored
    out = _cli(ctx, f'set authority_patterns ["{"a" * 200}"]')
    assert ctx.store["authority_patterns"] == ["a" * 200]  # exactly at the cap
    ctx = FakeCtx()  # fresh config for the count cap
    out = _cli(ctx, f"set authority_patterns {json.dumps(['p%d' % i for i in range(101)])}")
    assert "REFUSED" in out and "100" in out
    assert ctx.store.get("authority_patterns") is None
    out = _cli(ctx, f"set authority_patterns {json.dumps(['p%d' % i for i in range(100)])}")
    assert len(ctx.store["authority_patterns"]) == 100  # exactly at the cap



# ------------------- H11: TTL increases and origin/rp_id moves are gated
def test_raising_challenge_ttl_needs_approval_lowering_is_free():
    ctx = FakeCtx()
    ctx.store["challenge_ttl"] = 600
    out = _cli(ctx, "set challenge_ttl 86400")
    assert "REFUSED" in out and "weakens" in out
    assert ctx.store["challenge_ttl"] == 600
    out = _cli(ctx, "set challenge_ttl 120")
    assert ctx.store["challenge_ttl"] == 120, out


def test_first_origin_is_free_moving_it_needs_approval():
    ctx = FakeCtx()
    out = _cli(ctx, "set origin https://real.example.ts.net:8445")
    assert ctx.store["origin"] == "https://real.example.ts.net:8445", out
    out = _cli(ctx, "set origin https://evil.example.ts.net")
    assert "REFUSED" in out and "weakens" in out and "out of band" in out
    assert ctx.store["origin"] == "https://real.example.ts.net:8445"
    out = _cli(ctx, "set rp_id real.example.ts.net")
    assert ctx.store["rp_id"] == "real.example.ts.net", out
    out = _cli(ctx, "set rp_id example.ts.net")
    assert "REFUSED" in out and ctx.store["rp_id"] == "real.example.ts.net"


def test_expose_does_not_move_an_established_origin(monkeypatch):
    from passkey_gate import expose
    ctx = FakeCtx()
    ctx.store.update(origin="https://real.example.ts.net:8445", rp_id="real.example.ts.net")
    monkeypatch.setattr(expose, "tailscale_expose", lambda port: {
        "ok": True, "backend": "tailscale", "url": "https://other.example.ts.net:8443",
        "rp_id": "other.example.ts.net", "persistent": True})
    out = _cli(ctx, "expose tailscale")
    assert "NOT saved" in out and "set origin" in out
    assert ctx.store["origin"] == "https://real.example.ts.net:8445"
    assert ctx.store["rp_id"] == "real.example.ts.net"


# ------------------- status explains an unreachable gate in plain English
def test_status_without_origin_says_origin_not_configured():
    out = json.loads(_cli(FakeCtx(), "status"))
    assert out["gate"]["reachable"] is False
    assert out["gate"]["error"] == "origin not configured"
    assert "expose" in out["gate"]["next_step"]


def test_status_with_nothing_listening_says_start_serve():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    ctx = FakeCtx()
    ctx.store["origin"] = f"http://127.0.0.1:{port}"
    out = json.loads(_cli(ctx, "status"))
    assert "nothing is listening" in out["gate"]["error"]
    assert "serve" in out["gate"]["next_step"]


# ------------------- pinning from the registered credential (phone run UX)
def _fake_creds(n=1):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from passkey_gate import gate_core
    out = []
    for i in range(n):
        pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        out.append({"credential_id": f"cred{i}abcdefghijkl", "registered_at": 1_700_000_000 + i,
                    "spki_pem": pem, "fingerprint": gate_core.key_fingerprint(pem),
                    "code": gate_core.key_confirmation_code(pem)})
    return out


def test_credentials_lists_fingerprints_and_pin_by_id(monkeypatch, tmp_path):
    from passkey_gate import gate_core, local_verify
    creds = _fake_creds(1)
    monkeypatch.setattr(gate_core, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(gate_core, "list_credentials", lambda: creds)
    out = _cli(FakeCtx(), "credentials")
    assert creds[0]["fingerprint"] in out and creds[0]["code"] in out and "pin --code" in out
    out = _cli(FakeCtx(), "pin --credential cred0abc")
    assert "pinned owner key" in out and creds[0]["fingerprint"] in out, out
    assert local_verify.pinned(tmp_path).strip() == creds[0]["spki_pem"].strip()
    assert "[PINNED owner key]" in _cli(FakeCtx(), "credentials")


def test_pin_by_id_refuses_ambiguous_or_short_prefix(monkeypatch, tmp_path):
    from passkey_gate import gate_core
    creds = _fake_creds(2)
    monkeypatch.setattr(gate_core, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(gate_core, "list_credentials", lambda: creds)
    out = _cli(FakeCtx(), "pin --credential cred0abc")
    assert "pinned owner key" in out  # unique prefix still works with two registered
    assert "at least 6" in _cli(FakeCtx(), "pin --credential cre")
    out = _cli(FakeCtx(), "pin --credential cred0abcdefgh_nope")
    assert "REFUSED: 0 registered passkeys match" in out
    out = _cli(FakeCtx(), "credentials")
    assert "2 passkeys are registered" in out and out.count("[PINNED owner key]") == 1


def test_key_fingerprint_is_stable_and_matches_registration(monkeypatch):
    from passkey_gate import gate_core
    pem = _fake_creds(1)[0]["spki_pem"]
    fp = gate_core.key_fingerprint(pem)
    assert fp == gate_core.key_fingerprint(pem) and len(fp.split(":")) == 8


# ------------------------------------------------ config canary (finding 17)
def test_canary_never_configured_stays_default_off():
    from passkey_gate import cli
    assert cli.config_canary_problem(FakeCtx()) is None   # nothing armed: honest default


def test_set_arms_the_canary_and_a_lost_config_fails_closed(tmp_path):
    from passkey_gate import cli
    ctx = FakeCtx()
    _cli(ctx, "set require_passkey true")
    value = ctx.store[cli.CANARY_KEY]
    assert (tmp_path / "config-canary").read_text() == value     # copy kept outside config
    assert cli.config_canary_problem(ctx) is None
    ctx.store.clear()                                            # loader fell back to defaults
    assert "missing" in cli.config_canary_problem(ctx)
    ctx.store[cli.CANARY_KEY] = "0000000000000000"               # another profile's config
    assert "different" in cli.config_canary_problem(ctx)


def test_set_and_expose_refuse_while_the_config_is_unread():
    """Writing into a config Hermes couldn't read could replace the real
    settings and then 'match' the canary, hiding the problem."""
    from passkey_gate import cli
    ctx = FakeCtx()
    _cli(ctx, "set require_passkey true")
    ctx.store.clear()
    out = _cli(ctx, "set challenge_ttl 60")
    assert out.startswith("REFUSED") and "wasn't read as expected" in out
    assert "challenge_ttl" not in ctx.store
    assert cli.cmd_expose(ctx, []).startswith("REFUSED")


def test_canary_is_not_armed_when_writing_the_config_fails(tmp_path):
    from passkey_gate import cli

    class ReadOnlyCtx(FakeCtx):
        def set_config(self, key, value):
            if key == cli.CANARY_KEY:
                raise OSError("config not writable")
            super().set_config(key, value)
    ctx = ReadOnlyCtx()
    with pytest.raises(OSError):
        cli.stamp_config_canary(ctx)
    assert not (tmp_path / "config-canary").exists()   # never fail closed on our own failed write
    assert cli.config_canary_problem(ctx) is None


def test_status_reports_the_config_check():
    from passkey_gate import cli
    ctx = FakeCtx()
    assert "not armed" in json.loads(_cli(ctx, "status"))["config_check"]
    _cli(ctx, "set require_passkey true")
    assert json.loads(_cli(ctx, "status"))["config_check"] == "ok"
    ctx.store.clear()
    assert json.loads(_cli(ctx, "status"))["config_check"].startswith("FAILING")
