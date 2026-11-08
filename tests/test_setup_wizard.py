"""The guided first run (`setup`), confirmation codes, `pin --code`, and the
background-service module — all with the gate, network and service manager
faked, so nothing here touches systemd, tailscale or a real phone."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkey_gate import cli, gate_core, local_verify, service, setup_wizard


class FakeCtx:
    def __init__(self, **store):
        self.store = dict(store)

    def get_config(self, key, default=None):
        return self.store.get(key, default)

    def set_config(self, key, value):
        self.store[key] = value


def _cred(i=0):
    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"credential_id": f"cred{i}abcdefghijkl", "registered_at": 1_700_000_000 + i,
            "spki_pem": pem, "fingerprint": gate_core.key_fingerprint(pem),
            "code": gate_core.key_confirmation_code(pem)}


# ------------------------------------------------------------ confirmation codes
def test_confirmation_code_shape_and_stability():
    c = _cred()
    code = c["code"]
    assert code == gate_core.key_confirmation_code(c["spki_pem"])
    assert len(code) == 11 and code[5] == "-"
    assert not set(code.replace("-", "")) & set("ILOU")  # no look-alike letters
    assert _cred(1)["code"] != code


@pytest.mark.parametrize("typed", ["7kq2m-x9d4r", "7KQ2MX9D4R", " 7KQ2M X9D4R ", "7kq2m_x9d4r"])
def test_normalize_accepts_how_people_type_it(typed):
    assert gate_core.normalize_confirmation_code(typed) == "7KQ2M-X9D4R"


def test_normalize_maps_lookalikes_and_rejects_junk():
    assert gate_core.normalize_confirmation_code("O1LI0-00000") == "0111" + "0-00000"
    for bad in ("", "short", "7KQ2M-X9D4R7", "7KQ2M-X9D4!", None):
        assert gate_core.normalize_confirmation_code(bad) == ""


# ------------------------------------------------------------ pin --code
def test_pin_by_code(monkeypatch, tmp_path):
    creds = [_cred(0), _cred(1)]
    monkeypatch.setattr(gate_core, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(gate_core, "list_credentials", lambda: creds)
    monkeypatch.setattr(gate_core, "audit", lambda *a, **k: None)
    out = cli.dispatch(FakeCtx(), "pin --code " + creds[1]["code"].lower().replace("-", ""))
    assert "pinned owner key" in out and creds[1]["code"] in out, out
    assert local_verify.pinned(tmp_path).strip() == creds[1]["spki_pem"].strip()


def test_pin_by_code_refuses_unknown_or_malformed(monkeypatch, tmp_path):
    monkeypatch.setattr(gate_core, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(gate_core, "list_credentials", lambda: [_cred()])
    assert "REFUSED" in cli.dispatch(FakeCtx(), "pin --code 00000-00000")
    assert "usage" in cli.dispatch(FakeCtx(), "pin --code nope")
    assert local_verify.pinned(tmp_path) is None


def test_register_page_explains_the_code():
    page = gate_core.REGISTER_PAGE
    assert "Create passkey" in page and "confirmation code" in page.lower()
    assert 'id="code"' in page and "only thing you need to copy" in page


# ------------------------------------------------------------ the wizard
class Script:
    """Answers the wizard's questions in order; records everything said."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts, self.said = [], []

    def ask(self, prompt):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def say(self, text=""):
        self.said.append(str(text))

    @property
    def text(self):
        return "\n".join(self.said)


class FakeResp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def world(monkeypatch, tmp_path):
    """A fake machine: a service manager, a gate that comes up when the
    service is installed, tailscale exposure, and a phone that registers
    a passkey a moment after the QR code is shown."""
    state = {"up": False, "installed": False, "creds": [], "phone": _cred(7), "minted": 0}
    monkeypatch.setattr(gate_core, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(gate_core, "audit", lambda *a, **k: None)
    monkeypatch.setattr(gate_core, "bootstrap_ttl", lambda: 900)
    monkeypatch.setattr(gate_core, "list_credentials", lambda: list(state["creds"]))

    def mint():
        state["minted"] += 1
        return "https://host.example.ts.net/register#tok"
    monkeypatch.setattr(gate_core, "mint_bootstrap_token", mint)
    monkeypatch.setattr(service, "manager", lambda: "systemd")
    monkeypatch.setattr(service, "installed", lambda: state["installed"])
    state["other_port"] = None

    def probe(port):
        if port == state["other_port"]:
            return "other"
        return "ours" if state["up"] else "free"
    monkeypatch.setattr(service, "probe", probe)

    def install(port):
        state["installed"] = state["up"] = True
        return True, "installed passkey-gate.service"
    monkeypatch.setattr(service, "install", install)

    def expose(ctx, rest):
        ctx.set_config("origin", "https://host.example.ts.net")
        return "exposure ready: https://host.example.ts.net"
    monkeypatch.setattr(cli, "cmd_expose", expose)
    monkeypatch.setattr(setup_wizard.netfetch, "open_no_redirect", lambda url, timeout=8: FakeResp())

    def sleep(_):  # the phone registers while the wizard is waiting
        if state["minted"] and state["phone"] not in state["creds"]:
            state["creds"].append(state["phone"])
    state["sleep"] = sleep
    return state


def _run(world, answers, ctx=None):
    s = Script(answers)
    ctx = ctx or FakeCtx()
    out = setup_wizard.Wizard(ctx, ask=s.ask, say=s.say, sleep=world["sleep"]).run()
    return out, s, ctx


def test_wizard_happy_path(world, tmp_path):
    code = world["phone"]["code"]
    out, s, ctx = _run(world, ["", code.lower(), "n"])
    assert "Setup complete" in out, s.text + out
    assert "background service" in out and "https://host.example.ts.net" in out
    assert local_verify.pinned(tmp_path).strip() == world["phone"]["spki_pem"].strip()
    assert ctx.store["origin"] == "https://host.example.ts.net"
    assert "require_passkey" not in ctx.store  # enforcement declined


def test_wizard_wrong_code_then_right(world, tmp_path):
    out, s, _ = _run(world, ["", "00000-00000", "junk", world["phone"]["code"], "n"])
    assert "doesn't match" in s.text and "isn't a code" in s.text
    assert "Setup complete" in out
    assert local_verify.pinned(tmp_path) is not None


def test_wizard_never_pins_a_code_that_does_not_match(world, tmp_path):
    out, s, _ = _run(world, ["", "00000-00000", "00000-00001", "00000-00002"])
    assert "Nothing was pinned" in s.text and "Setup complete" not in out
    assert local_verify.pinned(tmp_path) is None


def test_wizard_ignores_passkeys_that_existed_before_the_qr(world, tmp_path):
    old = _cred(3)
    world["creds"].append(old)  # registered earlier, not by this phone just now
    out, s, _ = _run(world, ["", old["code"], world["phone"]["code"], "n"])
    assert "doesn't match" in s.text
    assert local_verify.pinned(tmp_path).strip() == world["phone"]["spki_pem"].strip()


def test_wizard_rerun_skips_finished_steps(world, tmp_path):
    _run(world, ["", world["phone"]["code"], "n"])
    minted = world["minted"]
    ctx = FakeCtx(origin="https://host.example.ts.net")
    out, s, _ = _run(world, ["n"], ctx)
    assert "gate is running as a background service" in s.text
    assert "already pinned" in s.text and world["phone"]["code"] in s.text
    assert world["minted"] == minted  # no new registration link
    assert "Setup complete" in out


def test_wizard_turns_on_enforcement(world):
    out, s, ctx = _run(world, ["", world["phone"]["code"], "y", ""])
    assert ctx.store["require_passkey"] is True
    assert ctx.store["authority_patterns"] == [setup_wizard.DEFAULT_PATTERN]
    assert "enforcement on" in out


def test_wizard_without_background_service_waits_for_terminal(world, monkeypatch):
    monkeypatch.setattr(service, "manager", lambda: None)
    answers = iter(["", "", world["phone"]["code"], "n"])

    def ask(prompt):
        if prompt.startswith("Press Enter once") and not world["up"]:
            # first Enter: still nothing; the operator then starts serve
            world["up"] = world.get("tried", False)
            world["tried"] = True
        return next(answers)
    s = Script([])
    out = setup_wizard.Wizard(FakeCtx(), ask=ask, say=s.say, sleep=world["sleep"]).run()
    assert "hermes passkey-gate serve" in s.text and "Nothing is answering" in s.text
    assert "Setup complete" in out and "service install" in out


def test_wizard_moves_off_a_port_held_by_another_program(world):
    world["other_port"] = 8655  # e.g. the old approval-gate prototype
    out, s, ctx = _run(world, ["", "", world["phone"]["code"], "n"])
    assert "isn't this gate" in s.text
    assert ctx.store["port"] == 8656 and "127.0.0.1:8656" in out


def test_probe_tells_this_gate_from_another(monkeypatch):
    monkeypatch.setattr(service, "local_health",
                        lambda port, timeout=2.0: {"status": "ok", "instance": gate_core.instance_id()})
    assert service.probe(1) == "ours"
    monkeypatch.setattr(service, "local_health",
                        lambda port, timeout=2.0: {"status": "ok", "instance": "someone-else"})
    assert service.probe(1) == "other"
    monkeypatch.setattr(service, "local_health", lambda port, timeout=2.0: {"status": "ok"})
    assert service.probe(1) == "other"  # an older gate / the prototype: no instance id


def test_wizard_quit_is_clean(world):
    out, s, _ = _run(world, ["q"])
    assert out.startswith("setup stopped")


def test_setup_refuses_without_a_terminal(monkeypatch):
    monkeypatch.setattr(setup_wizard.sys.stdin, "isatty", lambda: False, raising=False)
    assert "interactive" in cli.dispatch(FakeCtx(), "setup")


# ------------------------------------------------------------ service module
def test_unit_text_pins_home_and_quotes():
    text = service.unit_text("/opt/my tools/hermes", "/home/a/.hermes/profiles/100%")
    assert 'ExecStart="/opt/my tools/hermes" passkey-gate serve' in text
    assert 'Environment="HERMES_HOME=/home/a/.hermes/profiles/100%%"' in text
    assert "Restart=on-failure" in text and "WantedBy=default.target" in text


def test_plist_text_escapes():
    text = service.plist_text("/Apps/a&b/hermes", "/Users/a/.hermes")
    assert "<string>/Apps/a&amp;b/hermes</string>" in text
    assert "<key>HERMES_HOME</key><string>/Users/a/.hermes</string>" in text
    assert "<key>RunAtLoad</key><true/>" in text


def test_systemd_install_and_uninstall(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("USER", "autumn")
    monkeypatch.setattr(service, "platform", "linux")
    monkeypatch.setattr(service.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(service, "hermes_home", lambda: "/home/autumn/.hermes")
    monkeypatch.setattr(service, "probe", lambda port: "free")

    def run(cmd, timeout=30):
        calls.append(cmd)
        if cmd[:2] == ["loginctl", "show-user"]:
            return 0, "Linger=no"
        return 0, ""
    monkeypatch.setattr(service, "run", run)
    ok, text = service.install(8655)
    unit = tmp_path / "systemd" / "user" / "passkey-gate.service"
    assert ok and unit.exists(), text
    assert 'ExecStart="/usr/bin/hermes" passkey-gate serve' in unit.read_text()
    assert ["systemctl", "--user", "enable", "passkey-gate.service"] in calls
    assert ["systemctl", "--user", "restart", "passkey-gate.service"] in calls
    assert "enable-linger autumn" in text  # reported, never run
    assert not any("sudo" in c for c in calls)
    assert "background service" in cli.dispatch(FakeCtx(), "service status")
    ok, text = service.uninstall()
    assert ok and not unit.exists()
    assert ["systemctl", "--user", "disable", "--now", "passkey-gate.service"] in calls


def test_install_without_a_manager_gives_instructions(monkeypatch):
    monkeypatch.setattr(service, "platform", "freebsd")
    monkeypatch.setattr(service.shutil, "which", lambda n: "/usr/local/bin/hermes" if n == "hermes" else None)
    ok, text = service.install(8655)
    assert not ok and "nohup" in text and "/usr/local/bin/hermes passkey-gate serve" in text


def test_service_usage():
    assert cli.dispatch(FakeCtx(), "service bogus").startswith("usage:")
