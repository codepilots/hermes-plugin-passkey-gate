"""Exposure-layer tests: port picking, URL derivation, tunnel-log parsing,
auto-selection order — all against fixtures captured from the developer's
real tailscale setup (status JSON shape verbatim from tailscale 1.104.4).

cloudflare_expose readiness waits are tested against FAKE cloudflared stubs
(executable /bin/sh scripts, no network, no real binary): a silent child, a
fast-failing child, and a child that prints a plausible quick-tunnel URL.
"""

import json
import os
import signal
import time

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
