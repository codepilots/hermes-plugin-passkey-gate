"""CLI settings tests: parse/validate/persist/show round trips against a fake ctx
that mimics ctx.get_config / ctx.set_config (plugin namespaced settings)."""

import json

from passkey_gate import cli


class FakeCtx:
    def __init__(self):
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
        out = _cli(ctx, f"set origin {good}")
        assert ctx.store["origin"] == good, out


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
    assert "confirm this gate-weakening change" in out
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
    assert schema_keys == set(cli.SETTINGS_SPEC.keys())
