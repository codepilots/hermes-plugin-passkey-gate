"""Test bootstrap: make `from passkey_gate import ...` work despite the dash.

The catalog layout is a monorepo (plugin under plugin/passkey-gate/ with its
own __init__, tests at the repo root) — pytest must not treat the plugin dir
as a package marker, so it doesn't get one; this loads it by path instead.
"""

import importlib.util
import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugin"

if "passkey_gate" not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        "passkey_gate", PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    _plugin = importlib.util.module_from_spec(_spec)
    sys.modules["passkey_gate"] = _plugin
    _spec.loader.exec_module(_plugin)


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_config_canary(monkeypatch, tmp_path):
    """Each test gets its own config-canary file: a canary armed by one test
    (any `set` arms it) must not make later tests' fake configs look like a
    config Hermes failed to read."""
    from passkey_gate import cli
    monkeypatch.setattr(cli, "_canary_file", lambda: tmp_path / "config-canary")
