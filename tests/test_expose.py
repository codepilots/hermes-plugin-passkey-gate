"""Exposure-layer tests: port picking, URL derivation, tunnel-log parsing,
auto-selection order — all against fixtures captured from the developer's
real tailscale setup (status JSON shape verbatim from tailscale 1.104.4).

cloudflare_expose readiness waits are tested against FAKE cloudflared stubs
(executable /bin/sh scripts, no network, no real binary): a silent child, a
fast-failing child, and a child that prints a plausible quick-tunnel URL.

tailscale_expose rule management (finding 25) is tested against a FAKE
tailscale binary: a tiny Python program injected via the `binpath` seam that
implements `serve status --json`, `status --json`, path-scoped serve
create/off, and logs every invocation so tests can assert the EXACT serve
commands — and prove other services' rules are never touched.
"""

import json
import os
import signal
import sys
import time
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


def test_url_from_tunnel_line():
    assert expose.url_from_tunnel_line("|  https://some-name.trycloudflare.com |") == "https://some-name.trycloudflare.com"
    assert expose.url_from_tunnel_line("|  https://x-y.trycloudflare.com -> http://127.0.0.1:8655") == "https://x-y.trycloudflare.com"
    assert expose.url_from_tunnel_line("2026/11/06 10:00 INFO Registered tunnel connection") is None


def test_auto_selection_prefers_configured_origin(monkeypatch):
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": True, "cloudflared": True})
    monkeypatch.setattr(expose, "tailscale_expose",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be reached")))
    result = expose.auto_expose(8655, "https://my-gate.example.com:9000", "my-gate.example.com")
    assert result["ok"] and result["backend"] == "configured" and result["url"] == "https://my-gate.example.com:9000"


def test_auto_selection_order_tailscale_then_cloudflare(monkeypatch):
    calls = []
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": False, "cloudflared": True})
    monkeypatch.setattr(expose, "tailscale_expose", lambda *a: calls.append("ts") or {"ok": True, "url": "x"})
    # tailscale missing from detection -> never called, straight to cloudflare
    monkeypatch.setattr(expose, "cloudflare_expose", lambda *a: calls.append("cf") or {"ok": True, "url": "cf", "backend": "cloudflare"})
    result = expose.auto_expose(8655, "", "")
    assert calls == ["cf"] and result["backend"] == "cloudflare"
    calls.clear()
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": True, "cloudflared": False})
    monkeypatch.setattr(expose, "tailscale_expose", lambda *a: calls.append("ts") or {"ok": True, "url": "ts", "backend": "tailscale"})
    result = expose.auto_expose(8655, "", "")
    assert calls == ["ts"] and result["backend"] == "tailscale"


def test_auto_selection_no_backends(monkeypatch):
    monkeypatch.setattr(expose, "detect_backends", lambda: {"tailscale": False, "cloudflared": False})
    result = expose.auto_expose(8655, "", "")
    assert not result["ok"] and "tailscale" in result["error"]


# --- cloudflare_expose readiness wait (finding 24): fake cloudflared stubs ---
# No network, no real cloudflared — the binary path is injected via the
# `binpath` argument, and each stub records its PID to $PIDFILE so the tests
# can prove the child is terminated and reaped on every failure path.

def _fake_cloudflared(tmp_path, name, body):
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by someone else


def test_cloudflare_silent_child_hits_reader_deadline(tmp_path, monkeypatch):
    """A cloudflared that emits no newline (blocking readline forever) must
    still end at the deadline with a clear error — never an infinite hang —
    with the child killed and reaped."""
    stub = _fake_cloudflared(tmp_path, "hang", (
        'echo $$ > "$PIDFILE"\n'
        "printf 'booting quick tunnel (partial line, no newline, no URL)'\n"
        "exec sleep 300\n"))
    pidfile = tmp_path / "hang.pid"
    monkeypatch.setenv("PIDFILE", str(pidfile))
    t0 = time.monotonic()
    result = expose.cloudflare_expose(8655, watch_seconds=2, binpath=stub)
    elapsed = time.monotonic() - t0
    assert not result["ok"]
    # the old blocking readline hung for the stub's full 300s sleep
    assert elapsed < 15, f"expose took {elapsed:.1f}s — reader deadline did not bound the wait"
    err = result["error"]
    assert "within 2s" in err, err          # what failed: deadline elapsed, no URL
    assert "killed" in err, err              # what happened to the child
    assert "Check" in err, err               # what to check next
    assert "process" not in result           # no live tunnel handed back on failure
    assert not _pid_alive(int(pidfile.read_text()))  # child terminated AND reaped


def test_cloudflare_immediate_failure_reports_and_reaps(tmp_path, monkeypatch):
    """A cloudflared that fails right away ends quickly with the exit status
    and its recent output surfaced for diagnosis; no child is left behind."""
    stub = _fake_cloudflared(tmp_path, "fail", (
        'echo $$ > "$PIDFILE"\n'
        "echo 'cloudflared: failed to register tunnel: network unreachable'\n"
        "exit 7\n"))
    pidfile = tmp_path / "fail.pid"
    monkeypatch.setenv("PIDFILE", str(pidfile))
    t0 = time.monotonic()
    result = expose.cloudflare_expose(8655, watch_seconds=30, binpath=stub)
    elapsed = time.monotonic() - t0
    assert not result["ok"]
    assert elapsed < 10, f"fast failure took {elapsed:.1f}s"
    err = result["error"]
    assert "exited" in err and "code 7" in err, err
    assert "failed to register tunnel" in err, err  # recent output surfaced
    assert not _pid_alive(int(pidfile.read_text()))  # reaped, no zombie


def _pid_state(pid):
    """/proc state of a pid ('R', 'S', 'Z', ...) or None if it is gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        return data[data.rindex(")") + 2:].split()[0]
    except Exception:
        return None


def test_cloudflare_grandchild_pipe_holder_cannot_wedge_or_leak(tmp_path, monkeypatch):
    """Finding 24 completion. The repro the parent's faulthandler caught: a stub
    shell whose forked GRANDCHILD (sleep 99999) inherits the tunnel pipe's write
    end. The old teardown killed only the direct child, so the grandchild both
    LEAKED and kept the pipe open — the reader thread stayed blocked in
    readline() holding the text wrapper's lock while the main thread deadlocked
    in stream.close() waiting for that lock: cloudflare_expose never returned.
    The fix kills the child's whole process GROUP (start_new_session + killpg),
    so every pipe write-end closes; the reader wakes on EOF, the group dies,
    and the close can no longer block."""
    stub = _fake_cloudflared(tmp_path, "gc", (
        'echo $$ > "$PIDFILE"\n'
        'sleep 99999 &\n'
        'echo $! > "$GCPIDFILE"\n'
        'wait\n'))
    pidfile = tmp_path / "stub.pid"
    gcpidfile = tmp_path / "gc.pid"
    monkeypatch.setenv("PIDFILE", str(pidfile))
    monkeypatch.setenv("GCPIDFILE", str(gcpidfile))
    # capture the reader thread the way cloudflare_expose creates it
    readers = []
    real_thread = expose.threading.Thread

    def _capture_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        readers.append(thread)
        return thread

    monkeypatch.setattr(expose.threading, "Thread", _capture_thread)
    t0 = time.monotonic()
    result = expose.cloudflare_expose(8655, watch_seconds=2, binpath=stub)
    elapsed = time.monotonic() - t0
    # the call RETURNS, bounded — before the fix it wedged forever in close()
    assert elapsed < 20, f"expose took {elapsed:.1f}s — close() wedged on the pipe holder"
    assert not result["ok"]
    err = result["error"]
    assert "within 2s" in err, err          # silent-child deadline error
    assert "killed" in err, err
    assert "process" not in result          # nothing live handed back on failure
    # the reader thread has exited — not parked in readline()
    assert readers, "no reader thread was created"
    readers[0].join(timeout=10)
    assert not readers[0].is_alive(), "reader thread still blocked after expose returned"
    # BOTH the stub and its pipe-holding grandchild are dead and gone
    stub_pid = int(pidfile.read_text())
    gc_pid = int(gcpidfile.read_text())
    for pid, label in ((stub_pid, "stub"), (gc_pid, "grandchild")):
        state = _pid_state(pid)
        if state is not None:  # grandchild is reaped by init, allow it a moment
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and _pid_state(pid) is not None:
                time.sleep(0.05)
        assert _pid_state(pid) is None, (
            f"{label} pid {pid} still in /proc (state {_pid_state(pid)!r}) after "
            f"{elapsed:.1f}s — leaked")


def test_cloudflare_escaped_pipe_holder_still_cannot_wedge(tmp_path, monkeypatch):
    """Worst case for the close(): the pipe holder is OUTSIDE the child's
    process group (it setsid'd itself away), so no group signal can close the
    pipe and the reader stays blocked in readline() holding the wrapper lock.
    _stop_child must then fall back to closing the RAW fd and skip the
    wrapper close — close() can never deadlock — and cloudflare_expose must
    still return with the deadline error. The escapee deliberately left our
    group, so this test kills it itself and proves the reader thread finally
    wakes on the resulting EOF."""
    stub = _fake_cloudflared(tmp_path, "escape", (
        'echo $$ > "$PIDFILE"\n'
        'setsid sleep 99999 &\n'
        'echo $! > "$GCPIDFILE"\n'
        'wait\n'))
    pidfile = tmp_path / "stub.pid"
    gcpidfile = tmp_path / "gc.pid"
    monkeypatch.setenv("PIDFILE", str(pidfile))
    monkeypatch.setenv("GCPIDFILE", str(gcpidfile))
    monkeypatch.setattr(expose, "_STOP_GRACE", 0.5)  # bounded steps, fast test
    readers = []
    real_thread = expose.threading.Thread

    def _capture_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        readers.append(thread)
        return thread

    monkeypatch.setattr(expose.threading, "Thread", _capture_thread)
    t0 = time.monotonic()
    try:
        result = expose.cloudflare_expose(8655, watch_seconds=2, binpath=stub)
        elapsed = time.monotonic() - t0
        assert elapsed < 20, f"expose took {elapsed:.1f}s — close() wedged on the escaped pipe holder"
        assert not result["ok"]
        assert "within 2s" in result["error"], result["error"]
        assert "process" not in result
        # the escaped holder still has the pipe open, so the reader is still
        # blocked — proof that the wrapper close was skipped, not deadlock-bitten
        assert readers and readers[0].is_alive(), (
            "expected the reader to still be blocked on the escaped pipe holder")
    finally:
        gc_pid = int(gcpidfile.read_text())
        try:
            os.kill(gc_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    readers[0].join(timeout=10)
    assert not readers[0].is_alive(), "reader never woke after the escapee died"
    stub_pid = int(pidfile.read_text())
    for pid, label in ((stub_pid, "stub"), (gc_pid, "escaped grandchild")):
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _pid_state(pid) is not None:
            time.sleep(0.05)
        assert _pid_state(pid) is None, (
            f"{label} pid {pid} still in /proc (state {_pid_state(pid)!r})")


def test_cloudflare_tunnel_url_success_unchanged(tmp_path, monkeypatch):
    """A cloudflared that prints a plausible quick-tunnel URL still succeeds,
    keeps the tunnel process alive for the caller, and is cleaned up here."""
    stub = _fake_cloudflared(tmp_path, "ok", (
        'echo $$ > "$PIDFILE"\n'
        "echo '|  https://fake-example-abc123.trycloudflare.com |'\n"
        "exec sleep 300\n"))
    pidfile = tmp_path / "ok.pid"
    monkeypatch.setenv("PIDFILE", str(pidfile))
    result = expose.cloudflare_expose(8655, watch_seconds=30, binpath=stub)
    try:
        assert result["ok"] and result["backend"] == "cloudflare"
        assert result["url"] == "https://fake-example-abc123.trycloudflare.com"
        assert result["rp_id"] == "fake-example-abc123.trycloudflare.com"
        assert result["persistent"] is False
        proc = result["process"]
        assert proc.poll() is None  # the tunnel process stays alive for the caller
    finally:
        proc = result.get("process")
        if proc is not None:
            proc.terminate()
            proc.wait()
    assert not _pid_alive(int(pidfile.read_text()))


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
    then refused: a denied request that destroyed the working tunnel."""
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
