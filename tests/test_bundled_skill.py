"""The bundled skills ship with the plugin and register cleanly."""

from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "plugin"
SKILLS = sorted((PLUGIN_DIR / "skills").glob("*/SKILL.md"))
SKILL = PLUGIN_DIR / "skills" / "approval-layers-test" / "SKILL.md"
EXPECTED = {"approval-layers-test", "malformed-request-test"}


def _frontmatter(text):
    assert text.startswith("---\n"), "frontmatter must start at byte 0"
    head, sep, body = text[4:].partition("\n---\n")
    assert sep and body.strip(), "frontmatter must close and be followed by a body"
    fields = {}
    for line in head.splitlines():
        if line and not line.startswith(" ") and ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
    return fields, body


@pytest.mark.parametrize("skill", SKILLS, ids=lambda p: p.parent.name)
def test_skill_file_is_well_formed(skill):
    text = skill.read_text()
    fields, body = _frontmatter(text)
    assert fields["name"] == skill.parent.name
    assert len(fields["description"]) <= 60 and fields["description"].endswith(".")
    for section in ("## When to Use", "## Safety rules", "## Procedure", "## Pitfalls", "## Verification"):
        assert section in body
    # Shipped text must not carry one machine's paths.
    assert "/home/" not in text


def test_expected_skills_ship():
    assert {p.parent.name for p in SKILLS} == EXPECTED


def _ctx(seen, with_skills=True):
    class Ctx:
        def get_config(self, key, default=None):
            return default

        def set_config(self, key, value):
            pass

        def register_tool(self, **kw):
            pass

        def register_hook(self, name, fn):
            pass

        def register_cli_command(self, **kw):
            pass

        def register_approval_transport(self, name, fn):
            pass

    if with_skills:
        def register_skill(self, name, path, description=""):
            seen.append((name, Path(path), description))
        Ctx.register_skill = register_skill
    return Ctx()


def test_register_offers_bundled_skill(monkeypatch):
    import passkey_gate
    from passkey_gate import cli
    monkeypatch.setattr(cli, "_ctx_ref", None)
    monkeypatch.setattr(cli, "_cfg_cache", None)
    seen = []
    passkey_gate.register(_ctx(seen))
    assert ("approval-layers-test", SKILL, "Live-test Hermes's three command-approval layers safely.") in seen
    assert {name for name, _, _ in seen} == EXPECTED


def test_register_without_skill_api_still_works(monkeypatch):
    import passkey_gate
    from passkey_gate import cli
    monkeypatch.setattr(cli, "_ctx_ref", None)
    monkeypatch.setattr(cli, "_cfg_cache", None)
    passkey_gate.register(_ctx([], with_skills=False))  # older Hermes: no register_skill


def test_skill_registration_failure_is_contained(monkeypatch):
    import passkey_gate
    from passkey_gate import cli
    monkeypatch.setattr(cli, "_ctx_ref", None)
    monkeypatch.setattr(cli, "_cfg_cache", None)
    hooks = []
    ctx = _ctx([])

    def boom(name, path, description=""):
        raise ValueError("refused")

    ctx.register_skill = boom
    ctx.register_hook = lambda name, fn: hooks.append(name)
    passkey_gate.register(ctx)  # must not raise
    assert "pre_tool_call" in hooks
