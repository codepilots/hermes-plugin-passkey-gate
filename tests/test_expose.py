"""Exposure-layer tests: port picking, URL derivation, RP-ID derivation,
auto-selection order — all against fixtures captured from the developer's
real tailscale setup (status JSON shape verbatim from tailscale 1.104.4).

tailscale_expose rule management (finding 25) is tested against a FAKE
tailscale binary: a tiny Python program injected via the `binpath` seam that
implements `serve status --json`, `status --json`, path-scoped serve
create/off, and logs every invocation so tests can assert the EXACT serve
commands — and prove other services' rules are never touched.
"""

import json
import os
import sys
from pathlib import Path

from passkey_gate import expose

REAL_STATUS = json.loads(r"""
{
  "TCP": {
    "5900": {"TCPForward": "localhost:5901"},
    "8443": {"HTTPS": true},
    "8444": {"HTTPS": true},
    "8445": {"HTTPS": true},
    "8446": {"HTTPS": true}
  },
  "Web": {
    "gate-host.example-tailnet.ts.net:8443": {
      "Handlers": {"/": {"Proxy": "http://127.0.0.1:5984"}}
    }
  }
}
""")

REAL_HOST = "gate-host.example-tailnet.ts.net"


def test_pick_https_port_skips_claimed_433_and_844x():
    # all four 844x ports claimed by other services in the real fixture; 443 free
    assert expose.pick_https_port(REAL_STATUS) == 443


def test_pick_https_port_falls_through_when_443_taken():
    status = {"TCP": {"443": {"HTTPS": True}}}
    assert expose.pick_https_port(status) == 8443


def test_pick_https_port_none_when_all_taken():
    status = {"TCP": {str(p): {"HTTPS": True} for p in expose.TAILSCALE_PORTS}}
    assert expose.pick_https_port(status) is None


def test_origin_from_host():
    assert expose.origin_from_host(REAL_HOST, 443) == f"https://{REAL_HOST}"
    assert expose.origin_from_host(REAL_HOST, 8445) == f"https://{REAL_HOST}:8445"


def test_locate_url_finds_own_entry():
    assert (expose._locate_url(REAL_STATUS, REAL_HOST, 8443)
            == f"https://{REAL_HOST}:8443")
    assert expose._locate_url(REAL_STATUS, REAL_HOST, 443) is None


def test_auto_selection_prefers_configured_origin(monkeypatch):
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": True})
    monkeypatch.setattr(expose, "tailscale_expose",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be reached")))
    result = expose.auto_expose(8655, "https://my-gate.example.com:9000", "my-gate.example.com")
    assert result["ok"] and result["backend"] == "configured" and result["url"] == "https://my-gate.example.com:9000"


def test_auto_selection_uses_tailscale_when_present(monkeypatch):
    calls = []
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": True})
    monkeypatch.setattr(expose, "tailscale_expose", lambda *a: calls.append("ts") or {"ok": True, "url": "ts", "backend": "tailscale"})
    result = expose.auto_expose(8655, "", "")
    assert calls == ["ts"] and result["backend"] == "tailscale"


def test_detect_backends_offers_only_tailscale():
    """No third-party tunnel backend: the only auto-exposure is tailscale serve."""
    assert set(expose.detect_backends()) == {"tailscale"}
    assert not hasattr(expose, "cloudflare_expose")


def test_configured_origin_without_rp_id_derives_rp_id_from_host(monkeypatch):
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": False})
    result = expose.auto_expose(8655, "https://gate.example.com:8445", "")
    assert result["ok"] and result["rp_id"] == "gate.example.com"


def test_rp_id_from_origin():
    assert expose.rp_id_from_origin("https://host.tailnet.ts.net:8445") == "host.tailnet.ts.net"
    assert expose.rp_id_from_origin("") is None
    assert expose.rp_id_from_origin("not a url") is None


def test_auto_selection_no_backends(monkeypatch):
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": False})
    result = expose.auto_expose(8655, "", "")
    assert not result["ok"] and "tailscale" in result["error"]


# --- tailscale serve rule management (finding 25): fake tailscale binary ---
#
# The fake is a tiny Python program (shebang = the venv interpreter running
# this suite; no network, no real tailscale) that maintains a JSON state file:
#   serve status --json                    -> print the TCP/Web serve map
#   status --json                          -> print {"Self": {"DNSName": ...}}
#   serve --bg --https=P --set-path=M TGT  -> upsert the rule at (P, M)
#   serve --bg --https=P --set-path=M off  -> remove the rule at (P, M)
#     (off on a mount that is not served fails, like the real CLI)
# Every invocation is appended to a log so tests assert the EXACT commands.

FAKE_TAILSCALE = r'''#!__PYTHON__
import json, os, sys

argv = sys.argv[1:]
with open(os.environ["TS_LOG"], "a") as f:
    f.write(json.dumps(argv) + "\n")

state_path = os.environ["TS_STATE"]
if os.path.exists(state_path):
    state = json.load(open(state_path))
else:
    state = {"host": "", "TCP": {}, "Web": {}}

def flagval(name):
    for a in argv:
        if a.startswith("--%s=" % name):
            return a.split("=", 1)[1]
    return None

if argv[:2] == ["serve", "status"]:
    print(json.dumps({"TCP": state.get("TCP", {}), "Web": state.get("Web", {})}))
    sys.exit(0)
if argv[:1] == ["status"]:
    print(json.dumps({"Self": {"DNSName": state.get("host")}}))
    sys.exit(0)
if argv[:1] == ["serve"]:
    port = flagval("https")
    if port is None:
        sys.stderr.write("error: --https flag required\n")
        sys.exit(1)
    mount = flagval("set-path") or "/"
    key = state["host"] + ":" + port
    web = state.setdefault("Web", {})
    tcp = state.setdefault("TCP", {})
    entry = web.setdefault(key, {"Handlers": {}})
    if "off" in argv:
        if mount not in entry["Handlers"]:
            sys.stderr.write("error: nothing is being served on the specified path\n")
            sys.exit(1)
        entry["Handlers"].pop(mount)
        if not entry["Handlers"]:
            web.pop(key, None)
            tcp.pop(port, None)
        json.dump(state, open(state_path, "w"))
        sys.exit(0)
    target = None
    for a in argv[1:]:
        if not a.startswith("--") and a not in ("serve", "off"):
            target = a
            break
    if target is None:
        sys.stderr.write("error: no serve target\n")
        sys.exit(1)
    entry["Handlers"][mount] = {"Proxy": target}
    tcp[port] = {"HTTPS": True}
    json.dump(state, open(state_path, "w"))
    sys.exit(0)
sys.stderr.write("error: unhandled args %r\n" % (argv,))
sys.exit(1)
'''


def _fake_tailscale(tmp_path, monkeypatch, status=None, host=REAL_HOST):
    """Write the fake binary + its initial serve state; return
    (binpath, state_file, log_file)."""
    binpath = tmp_path / "tailscale"
    binpath.write_text(FAKE_TAILSCALE.replace("__PYTHON__", sys.executable))
    binpath.chmod(0o755)
    state = tmp_path / "ts-state.json"
    state.write_text(json.dumps({"host": host,
                                 "TCP": (status or {}).get("TCP", {}),
                                 "Web": (status or {}).get("Web", {})}))
    log = tmp_path / "ts-cmds.log"
    monkeypatch.setenv("TS_LOG", str(log))
    monkeypatch.setenv("TS_STATE", str(state))
    return str(binpath), state, log


def _serve_cmds(log):
    """Every serve mutating command the fake received, in order (the frequent
    `serve status --json` polls are excluded)."""
    cmds = []
    for line in Path(log).read_text().splitlines():
        argv = json.loads(line)
        if argv and argv[0] == "serve" and argv[1:2] != ["status"]:
            cmds.append(argv)
    return cmds


def _assert_foreign_untouched(foreign, state_file):
    """Every rule that belonged to another service is byte-identical."""
    after = json.loads(Path(state_file).read_text())
    for hp, entry in (foreign.get("Web") or {}).items():
        assert after["Web"][hp]["Handlers"] == entry["Handlers"], \
            f"another service's rule {hp} was modified"
    for port, val in (foreign.get("TCP") or {}).items():
        assert after["TCP"].get(port) == val, \
            f"another service's TCP entry {port} was modified"


def _port_of(url):
    tail = url.split("://", 1)[-1].split("/", 1)[0]
    return int(tail.rsplit(":", 1)[-1]) if ":" in tail else 443


def _probe_results(ports_ok):
    """Fake _tls_probe: healthy iff the origin's port is in ports_ok.
    Records every URL probed."""
    seen = []

    def probe(url, timeout=12):
        seen.append(url)
        if _port_of(url) in ports_ok:
            return True, "health ok"
        return False, "connection refused"

    return probe, seen


def _foreign_rules():
    """Other services' rules on the same tailnet host (mirrors the developer's
    real host: a VNC forward plus three HTTPS proxies)."""
    return {
        "TCP": {"5900": {"TCPForward": "localhost:5901"},
                "8443": {"HTTPS": True}, "8444": {"HTTPS": True},
                "8446": {"HTTPS": True}},
        "Web": {
            f"{REAL_HOST}:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:5984"}}},
            f"{REAL_HOST}:8444": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8642"}}},
            f"{REAL_HOST}:8446": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8000"}}},
        },
    }


def _write_record(tmp_path, port, target):
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps({"host": REAL_HOST, "port": port, "mount": "/",
                               "target": target,
                               "url": expose.origin_from_host(REAL_HOST, port)}))
    return rec


def test_tailscale_success_creates_exact_rule_leaves_others(tmp_path, monkeypatch):
    """(a) A clean expose creates exactly one rule — OUR exact handle — and
    never touches the other services' rules already on the tailnet host."""
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, _foreign_rules())
    probe, seen = _probe_results({443})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(8655, binpath=ts, record_path=tmp_path / "rec.json")
    assert result["ok"], result
    assert result["url"] == f"https://{REAL_HOST}"  # 443 -> clean URL
    assert result["serve_rule"] == {"host": REAL_HOST, "port": 443, "mount": "/",
                                    "target": "http://127.0.0.1:8655",
                                    "url": f"https://{REAL_HOST}"}
    # EXACT commands: a single create, scoped to our mount path; no off at all
    assert _serve_cmds(log) == [["serve", "--bg", "--https=443", "--set-path=/",
                                 "http://127.0.0.1:8655"]]
    assert seen == [f"https://{REAL_HOST}/health"]
    _assert_foreign_untouched(_foreign_rules(), state)
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:443"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:8655"
    rec = json.loads((tmp_path / "rec.json").read_text())  # successful run records the rule
    assert rec["port"] == 443 and rec["target"] == "http://127.0.0.1:8655" and rec["mount"] == "/"


def test_tailscale_rerun_same_gate_port_keeps_existing_rule(tmp_path, monkeypatch):
    """Re-run with the SAME gate port: the existing rule is verified live and
    KEPT — not one serve create/off command is issued — and the record is
    refreshed."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:443"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8655"}}}
    status["TCP"]["443"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 443, "http://127.0.0.1:8655")
    probe, _ = _probe_results({443})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(8655, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}"
    assert _serve_cmds(log) == []  # zero mutations — the rule was kept
    assert "kept" in result["note"]
    assert json.loads(rec.read_text())["port"] == 443
    _assert_foreign_untouched(_foreign_rules(), state)


def test_tailscale_rerun_changed_gate_port_replaces_only_our_rule(tmp_path, monkeypatch):
    """(b) Re-run with a CHANGED gate port: the previous plugin rule is
    replaced via its EXACT handle (remove-then-set), the other services' rules
    are untouched, and the result says what was replaced."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:443"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8655"}}}
    status["TCP"]["443"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 443, "http://127.0.0.1:8655")
    probe, _ = _probe_results({443})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(9000, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}"
    cmds = _serve_cmds(log)
    # remove-then-set, both scoped to the exact handle; never a --http= cleanup
    assert cmds == [["serve", "--bg", "--https=443", "--set-path=/", "off"],
                    ["serve", "--bg", "--https=443", "--set-path=/",
                     "http://127.0.0.1:9000"]]
    assert all("--http=" not in " ".join(c) for c in cmds)
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:443"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:9000"
    _assert_foreign_untouched(_foreign_rules(), state)
    # says so: the old rule (and the gate port it served) is named
    assert "replaced" in result["note"] and "8655" in result["note"]
    assert result["removed"][0]["port"] == 443
    assert result["removed"][0]["target"] == "http://127.0.0.1:8655"
    rec2 = json.loads(rec.read_text())
    assert rec2["port"] == 443 and rec2["target"] == "http://127.0.0.1:9000"


def test_tailscale_own_stale_rule_frees_port_others_still_claimed(tmp_path, monkeypatch):
    """(d) Port accounting: this plugin's own stale rule frees ITS port for
    reuse (the new run re-serves 8445 instead of skipping past it), while a
    foreign rule on 443 is still respected as claimed."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:443"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9001"}}}
    status["TCP"]["443"] = {"HTTPS": True}
    status["Web"][f"{REAL_HOST}:8445"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8655"}}}
    status["TCP"]["8445"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 8445, "http://127.0.0.1:8655")
    probe, _ = _probe_results({8445})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(9000, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}:8445"
    cmds = _serve_cmds(log)
    assert cmds == [["serve", "--bg", "--https=8445", "--set-path=/", "off"],  # stale rule, exact handle
                    ["serve", "--bg", "--https=8445", "--set-path=/",         # its port reused
                     "http://127.0.0.1:9000"]]
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:443"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:9001"
    _assert_foreign_untouched(_foreign_rules(), state)
    assert json.loads(rec.read_text())["port"] == 8445


def test_tailscale_failed_probe_unrules_only_our_partial_rule(tmp_path, monkeypatch):
    """(c) A candidate that accepts the rule but fails the TLS health probe is
    un-ruled by its exact handle; other services' rules survive; the next
    candidate is tried."""
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, _foreign_rules())
    probe, _ = _probe_results({8445})  # 443 dead, 8445 alive
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(8655, binpath=ts, record_path=tmp_path / "rec.json")
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}:8445"
    cmds = _serve_cmds(log)
    assert cmds == [["serve", "--bg", "--https=443", "--set-path=/", "http://127.0.0.1:8655"],
                    ["serve", "--bg", "--https=443", "--set-path=/", "off"],
                    ["serve", "--bg", "--https=8445", "--set-path=/", "http://127.0.0.1:8655"]]
    assert all("--http=" not in " ".join(c) for c in cmds)  # old wrong-protocol cleanup is gone
    st = json.loads(Path(state).read_text())
    assert f"{REAL_HOST}:443" not in st["Web"]  # our partial rule cleaned
    _assert_foreign_untouched(_foreign_rules(), state)
    assert [r["port"] for r in result["removed"]] == [443]
    assert json.loads((tmp_path / "rec.json").read_text())["port"] == 8445


def test_tailscale_total_failure_cleans_own_rules_and_record(tmp_path, monkeypatch):
    """(c) Nothing works anywhere: the run fails honestly, every partial rule
    it created (plus the dead previous rule it owned) is removed by exact
    handle, other services' rules are untouched, and no record is left
    pointing at a rule that no longer exists."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:8447"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8655"}}}
    status["TCP"]["8447"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 8447, "http://127.0.0.1:8655")
    probe, _ = _probe_results(set())
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(8655, binpath=ts, record_path=rec)
    assert not result["ok"]
    assert "no working HTTPS port" in result["error"]
    cmds = _serve_cmds(log)
    # the dead previous rule first (exact handle), then create+off pairs per candidate
    assert cmds[0] == ["serve", "--bg", "--https=8447", "--set-path=/", "off"]
    creates = [c for c in cmds[1:] if c[-1] != "off"]
    offs = [c for c in cmds[1:] if c[-1] == "off"]
    # candidates: 443, 8445, 8447 (ours, freed), 8448, 8480, 8500, 8600, 8661
    assert len(creates) == len(offs) == 8
    for c, o in zip(creates, offs):
        assert o[:3] == c[:3] and o[3] == "--set-path=/" and o[4] == "off"
        assert c[3] == "--set-path=/" and c[4] == "http://127.0.0.1:8655"
    st = json.loads(Path(state).read_text())
    ours = [k for k in st["Web"] if k not in
            (f"{REAL_HOST}:8443", f"{REAL_HOST}:8444", f"{REAL_HOST}:8446")]
    assert ours == []  # nothing of ours leaked
    _assert_foreign_untouched(_foreign_rules(), state)
    assert not rec.exists()  # no dangling record for a rule that is gone


def test_tailscale_kept_rule_dead_recreated_on_next_port(tmp_path, monkeypatch):
    """A rule that is recorded and live but no longer reachable (gate down):
    removed by exact handle, the port retried once, then the next working
    port; nothing else is touched."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:443"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8655"}}}
    status["TCP"]["443"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 443, "http://127.0.0.1:8655")
    probe, _ = _probe_results({8445})  # 443 dead, 8445 alive
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(8655, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}:8445"
    cmds = _serve_cmds(log)
    assert cmds == [["serve", "--bg", "--https=443", "--set-path=/", "off"],        # dead rule removed exactly
                    ["serve", "--bg", "--https=443", "--set-path=/",               # its port retried once
                     "http://127.0.0.1:8655"],
                    ["serve", "--bg", "--https=443", "--set-path=/", "off"],       # still dead — partial cleaned
                    ["serve", "--bg", "--https=8445", "--set-path=/",
                     "http://127.0.0.1:8655"]]
    st = json.loads(Path(state).read_text())
    assert f"{REAL_HOST}:443" not in st["Web"]
    _assert_foreign_untouched(_foreign_rules(), state)
    assert json.loads(rec.read_text())["port"] == 8445


def test_tailscale_refuses_to_overwrite_foreign_rule_on_target_port(tmp_path, monkeypatch):
    """(a) An explicitly requested port that another service already serves is
    REFUSED — never overwritten — with zero serve mutations."""
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, _foreign_rules())
    probe, _ = _probe_results({8443})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    before = json.loads(Path(state).read_text())
    result = expose.tailscale_expose(8655, target_port=8443, binpath=ts,
                                    record_path=tmp_path / "rec.json")
    assert not result["ok"]
    assert "8443" in result["error"] and "refusing" in result["error"]
    assert "http://127.0.0.1:5984" in result["error"]  # names the rule it refuses to touch
    assert _serve_cmds(log) == []
    assert json.loads(Path(state).read_text()) == before


def test_tailscale_foreign_target_port_refusal_keeps_our_live_rule(tmp_path, monkeypatch):
    """(D16) The parent probe's self-harm edge: a LIVE recorded rule (8445 ->
    gate 9002) plus an explicit target_port that turns out foreign-held (443
    served by another service) must be refused with ZERO mutations — our
    working 8445 rule survives untouched and the record still names it. The
    old code took the replace branch first, dropped the live rule, and only
    then refused: a denied request that destroyed the working serve rule."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:443"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9001"}}}
    status["TCP"]["443"] = {"HTTPS": True}
    status["Web"][f"{REAL_HOST}:8445"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9002"}}}
    status["TCP"]["8445"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 8445, "http://127.0.0.1:9002")
    probe, _ = _probe_results({8445})  # our live rule would answer healthily if probed
    monkeypatch.setattr(expose, "_tls_probe", probe)
    before = json.loads(Path(state).read_text())
    result = expose.tailscale_expose(9002, target_port=443, binpath=ts, record_path=rec)
    # (a) refused with the other-service error, naming the foreign rule
    assert not result["ok"]
    assert "refusing to overwrite another service's serve rule" in result["error"]
    assert "port 443" in result["error"] and "http://127.0.0.1:9001" in result["error"]
    # (b) zero serve mutations at all — the live 8445 rule is STILL in the map
    assert _serve_cmds(log) == [], "the refusal must not issue any serve command"
    assert json.loads(Path(state).read_text()) == before
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:8445"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:9002"
    # (c) the record still names our live 8445 rule — not cleared, not dangling
    rec_after = json.loads(rec.read_text())
    assert rec_after["port"] == 8445 and rec_after["target"] == "http://127.0.0.1:9002"
    # the foreign 443 rule is untouched too
    assert st["Web"][f"{REAL_HOST}:443"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:9001"
    _assert_foreign_untouched(_foreign_rules(), state)


def test_tailscale_claimable_target_port_still_replaces_live_rule(tmp_path, monkeypatch):
    """(D16 companion) The pre-check refuses foreign-held ports ONLY: an
    explicit target_port that IS claimable (8446 free) with a live recorded
    rule on 8445 replaces exactly as before — old rule dropped by its exact
    handle, new rule set, result says replaced — so nothing legitimate is
    blocked by the zero-mutation refusal."""
    foreign = _foreign_rules()
    del foreign["Web"][f"{REAL_HOST}:8446"]  # 8446 free for this run
    del foreign["TCP"]["8446"]
    status = {"TCP": {**foreign["TCP"], "8445": {"HTTPS": True}},
             "Web": {**foreign["Web"],
                     f"{REAL_HOST}:8445": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9002"}}}}}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 8445, "http://127.0.0.1:9002")
    probe, _ = _probe_results({8446})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(9002, target_port=8446, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}:8446"
    # remove-then-set, both scoped to the exact handle
    assert _serve_cmds(log) == [["serve", "--bg", "--https=8445", "--set-path=/", "off"],
                                ["serve", "--bg", "--https=8446", "--set-path=/",
                                 "http://127.0.0.1:9002"]]
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:8446"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:9002"
    assert f"{REAL_HOST}:8445" not in st["Web"]
    assert "replaced" in result["note"] and "8445" in result["note"]
    assert result["removed"][0]["port"] == 8445
    assert json.loads(rec.read_text())["port"] == 8446
    _assert_foreign_untouched(foreign, state)


def test_tailscale_target_port_with_own_stale_rule_is_replaced(tmp_path, monkeypatch):
    """An explicitly requested port holding OUR OWN stale rule (different gate
    port) is replaced via the exact handle, not refused; the other service's
    rule on the neighboring port is untouched."""
    status = {"TCP": {"8443": {"HTTPS": True}, "8444": {"HTTPS": True}},
              "Web": {f"{REAL_HOST}:8444": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8000"}}},
                      f"{REAL_HOST}:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8655"}}}}}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 8443, "http://127.0.0.1:8655")
    probe, _ = _probe_results({8443})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(9000, target_port=8443, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}:8443"
    assert _serve_cmds(log) == [["serve", "--bg", "--https=8443", "--set-path=/", "off"],
                                ["serve", "--bg", "--https=8443", "--set-path=/",
                                 "http://127.0.0.1:9000"]]
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:8444"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:8000"
    assert json.loads(rec.read_text())["target"] == "http://127.0.0.1:9000"


def test_tailscale_changed_rule_never_treated_as_ours(tmp_path, monkeypatch):
    """A record whose rule has since been replaced by ANOTHER service (proxy
    no longer ours) is not ours: never removed, its port stays claimed, and
    the run exposes on the next free port instead."""
    status = _foreign_rules()
    status["Web"][f"{REAL_HOST}:443"] = {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9999"}}}
    status["TCP"]["443"] = {"HTTPS": True}
    ts, state, log = _fake_tailscale(tmp_path, monkeypatch, status)
    rec = _write_record(tmp_path, 443, "http://127.0.0.1:8655")  # predates the takeover
    probe, _ = _probe_results({8445})
    monkeypatch.setattr(expose, "_tls_probe", probe)
    result = expose.tailscale_expose(8655, binpath=ts, record_path=rec)
    assert result["ok"] and result["url"] == f"https://{REAL_HOST}:8445"
    assert _serve_cmds(log) == [["serve", "--bg", "--https=8445", "--set-path=/",
                                 "http://127.0.0.1:8655"]]  # 443 never touched
    st = json.loads(Path(state).read_text())
    assert st["Web"][f"{REAL_HOST}:443"]["Handlers"]["/"]["Proxy"] == "http://127.0.0.1:9999"
    assert "no longer matches" in result["note"]  # honest about the stale record
    assert json.loads(rec.read_text())["port"] == 8445


def test_cli_default_rp_id_prefers_configured_origin_host():
    """With origin set but rp_id empty, the RP ID defaults to the origin's own
    host (previously a missing import made this silently fall to localhost,
    which no real origin accepts)."""
    from passkey_gate import cli
    assert cli.os_default_rp_id("https://gate.example.com:8445") == "gate.example.com"
