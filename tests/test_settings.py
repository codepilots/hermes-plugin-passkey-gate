"""CLI settings tests: parse/validate/persist/show round trips against a fake ctx
that mimics ctx.get_config / ctx.set_config (plugin namespaced settings)."""

import json

from passkey_gate import _cmd_cli, _parse_setting, _SETTINGS_SPEC


class FakeCtx:
    def __init__(self):
        self.store = {}

    def get_config(self, key, default=None):
        return self.store.get(key, default)

    def set_config(self, key, value):
        self.store[key] = value


def test_parse_setting_types():
    assert _parse_setting("port", "9001")[0] == 9001
    assert _parse_setting("require_passkey", "true")[0] is True
    assert _parse_setting("require_passkey", "no")[0] is False
    assert _parse_setting("require_passkey", "maybe")[0] is None
    assert _parse_setting("authority_patterns", '["a", "b"]')[0] == ["a", "b"]
    assert _parse_setting("authority_patterns", "a, b")[0] == ["a", "b"]  # comma fallback
    assert _parse_setting("origin", " https://host.ts.net ")[0] == "https://host.ts.net"


def test_set_and_show_roundtrip():
    ctx = FakeCtx()
    out = _cmd_cli(ctx, "set origin https://real.example.ts.net:8445")
    assert "origin = \"https://real.example.ts.net:8445\"" in out
    assert ctx.store["origin"] == "https://real.example.ts.net:8445"
    out = _cmd_cli(ctx, "set require_passkey true")
    assert ctx.store["require_passkey"] is True
    out = _cmd_cli(ctx, "set authority_patterns ^terminal .*(rm |curl )")
    # no commas + not valid JSON → the whole string is ONE pattern
    assert ctx.store["authority_patterns"] == ["^terminal .*(rm |curl )"]
    show = _cmd_cli(ctx, "get")
    assert all(f"  {k} = " in show for k in _SETTINGS_SPEC)


def test_set_rejects_bad_values():
    ctx = FakeCtx()
    out = _cmd_cli(ctx, "set nope 1")
    assert "unknown setting" in out
    out = _cmd_cli(ctx, "set port notanumber")
    assert "port" in out and "error" in out.lower() or "invalid" in out.lower()
    out = _cmd_cli(ctx, "set origin http://evil.example.ts.net")
    assert "https" in out and ctx.store.get("origin") is None  # rejected before write
    out = _cmd_cli(ctx, "set origin https://fine.example.ts.net")
    assert ctx.store["origin"] == "https://fine.example.ts.net"


def test_set_loopback_http_is_tolerated():
    ctx = FakeCtx()
    out = _cmd_cli(ctx, "set origin http://127.0.0.1:8655")
    assert ctx.store["origin"] == "http://127.0.0.1:8655"


def test_settings_spec_matches_manifest():
    """Keys must be exactly the plugin.yaml config_schema keys — drift surfaces here."""
    from pathlib import Path
    import yaml
    manifest_path = Path(__file__).resolve().parents[1] / "plugin" / "plugin.yaml"
    manifest = yaml.safe_load(manifest_path.read_text())
    schema_keys = set((manifest.get("config_schema") or {}).keys())
    assert schema_keys == set(_SETTINGS_SPEC.keys())
