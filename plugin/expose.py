"""Public exposure for the gate — pick-and-remember, per the user's own setup.

WebAuthn needs HTTPS, so the gate has to sit behind a TLS terminator the user
already runs. This module auto-detects what's available and sets it up:

  tailscale   — `tailscale serve --bg <port>:<gate-port>`; tailscaled keeps
                serving after this process exits, so setup can print the URL
                and return. Origin + RP id are derived from `tailscale status
                --json` (Self.DNSName), parsed WITHOUT trusting the CLI: the
                serve status map is re-read and the new entry located in it.
  cloudflare  — `cloudflared tunnel --url http://127.0.0.1:<gate-port>`
                (quick tunnel). Quick-tunnel URLs are EPHEMERAL: they change
                every restart, so this process must keep running to keep the
                origin alive. Named tunnels need a Cloudflare login + domain;
                see README. Passkeys can be used with quick tunnels but a
                freshly-registered one is needed each time the URL changes —
                for anything durable, prefer tailscale or a named tunnel.
  none        — localhost only; instruct the user to set `origin` manually.

RP ID default: the FULL hostname of the origin (always a valid registrable
suffix of itself). `rp_id` config can pin a parent/other suffix to reuse an
existing passkey credential registered under it — credentials only match
origins sharing their RP ID suffix.
"""
import json
import os
import queue
import shutil
import signal
import subprocess
import threading
import time

from . import netfetch

# Ports tried, in order, for tailscale HTTPS serving (443 = clean URL)
TAILSCALE_PORTS = [443, 8443, 8445, 8446, 8447, 8448, 8480, 8500, 8600, 8661]


def url_from_tunnel_line(line: str) -> str | None:
    """Extract a quick-tunnel URL from a cloudflared log line (they print to stdout
    combined here; e.g. `|  https://some-name.trycloudflare.com |`)."""
    if "trycloudflare.com" not in line:
        return None
    for tok in line.split():
        if tok.startswith("https://"):
            return tok
    return None


def _which(name: str):
    return shutil.which(name)


def detect_backends() -> dict:
    return {"tailscale": _which("tailscale") is not None,
            "cloudflared": _which("cloudflared") is not None}


def fetch_status_json(binpath: str = "tailscale", timeout: int = 15) -> dict | None:
    try:
        out = subprocess.run([binpath, "serve", "status", "--json"],
                             capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0 and out.stdout.strip().startswith("{"):
            return json.loads(out.stdout)
    except Exception:
        pass
    return None


def fetch_self_dnsname(binpath: str = "tailscale", timeout: int = 15) -> str | None:
    try:
        out = subprocess.run([binpath, "status", "--json"], capture_output=True,
                             text=True, timeout=timeout)
        if out.returncode == 0:
            dns = (json.loads(out.stdout).get("Self") or {}).get("DNSName") or ""
            return dns.rstrip(".") or None
    except Exception:
        pass
    return None


def _claimed_ports(status: dict) -> set[int]:
    claimed = set()
    if not isinstance(status, dict):
        return claimed
    for key in (str(p) for p in (status.get("TCP") or {})):
        try:
            claimed.add(int(key))
        except ValueError:
            continue
    for host_entry in (status.get("Web") or {}):
        try:
            claimed.add(int(str(host_entry).rsplit(":", 1)[-1]))
        except ValueError:
            continue
    return claimed


def pick_https_port(status: dict) -> int | None:
    """First preferred HTTPS port not already claimed by another serve rule."""
    for p in TAILSCALE_PORTS:
        if p not in _claimed_ports(status):
            return p
    return None


def origin_from_host(host: str, https_port: int) -> str:
    base = f"https://{host}"
    return base if https_port == 443 else f"{base}:{https_port}"


def tailscale_expose(gate_port: int, target_port: int | None = None) -> dict:
    """Serve the gate under the host's tailscale HTTPS URL. tailscaled owns the
    forwarding, so after setup this process can exit.

    A serve rule being ACCEPTED is not proof it WORKS: a local service bound to
    0.0.0.0:<port> (e.g. nginx on 443) can hold the port first, so tailnet
    connections fall through to that service's own TLS instead of tailscale's
    proxy. Every candidate is therefore verified with a real TLS GET of
    /health (cert chain verified, no -k) and rejected ports are un-ruled
    before the next candidate is tried."""
    if not _which("tailscale"):
        return {"ok": False, "backend": "tailscale", "error": "tailscale CLI not found"}
    host = fetch_self_dnsname()
    if not host:
        return {"ok": False, "backend": "tailscale", "error": "tailscale status unavailable (tailscaled down?)"}
    if target_port is not None:
        candidates = [target_port]
    else:
        status = fetch_status_json() or {}
        claimed = _claimed_ports(status)
        candidates = [p for p in TAILSCALE_PORTS if p not in claimed]
    last_error = None
    for port in candidates:
        target = f"http://127.0.0.1:{gate_port}"
        out = subprocess.run(["tailscale", "serve", "--bg", f"--https={port}", target],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            last_error = f"tailscale serve {target} failed: {(out.stderr or out.stdout).strip()[:300]}"
            continue
        status_after = fetch_status_json() or {}
        url = origin_from_host(host, port)  # canonical first
        located = _locate_url(status_after, host, port)
        if located:
            url = located.replace(":443", "")
        probe = _tls_probe(f"{url}/health")
        if probe[0]:
            return {"ok": True, "backend": "tailscale", "url": url,
                    "rp_id": url.split("//", 1)[-1].rsplit(":", 1)[0], "persistent": True,
                    "note": f"tailscaled forwards {url} -> 127.0.0.1:{gate_port}; survives restarts of this process"}
        last_error = f"port {port} did not serve our TLS origin ({probe[1]})"
        # un-rule the dead port without touching anyone else's rules
        subprocess.run(["tailscale", "serve", "--bg", f"--http={port}", "off"],
                       capture_output=True, text=True, timeout=30)
    return {"ok": False, "backend": "tailscale", "error": f"no working HTTPS port found. Last issue: {last_error}"}


def _tls_probe(url: str, timeout: int = 12) -> tuple[bool, str]:
    try:
        with netfetch.open_no_redirect(url, timeout=timeout) as r:
            body = r.read(4096)
            ok = r.status == 200 and b'"status": "ok"' in body
            if ok:
                return True, "health ok"
            return False, f"unexpected response {r.status}" if r.status != 200 else "unexpected body"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:140]}"


def _locate_url(status: dict, host: str, port: int) -> str | None:
    for key in (status.get("Web") or {}):
        k = str(key)
        if host in k and k.endswith(f":{port}"):
            return f"https://{k}" if not k.startswith("http") else k
    return None


def _drain_tunnel_lines(proc, out_q) -> None:
    """Reader thread for cloudflared's combined output (finding 24). Puts each
    line on out_q as ("line", s), the quick-tunnel URL as ("url", u) as soon as
    it appears (then stops draining, as before), and ("eof", None) when the
    stream ends. Daemon thread: even a pipe held open forever cannot wedge the
    caller. Runs alone it would block in readline() — that is why the deadline
    lives in _await_tunnel_url, not here."""
    try:
        for line in proc.stdout:
            url = url_from_tunnel_line(line)
            if url:
                out_q.put(("url", url))
                return
            out_q.put(("line", line))
    except Exception:
        pass
    finally:
        out_q.put(("eof", None))


def _await_tunnel_url(proc, out_q, watch_seconds: float) -> tuple[str | None, str]:
    """Bounded wait for the quick-tunnel URL (finding 24). A silent cloudflared
    emitting no newline can block the reader thread's readline() forever, but
    never this wait: the main thread blocks on the queue with a hard deadline.
    Returns (url, recent_output_tail)."""
    deadline = time.monotonic() + watch_seconds
    recent = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, recent
        try:
            kind, payload = out_q.get(timeout=remaining)
        except queue.Empty:
            return None, recent
        if kind == "url":
            return payload, recent
        if kind == "eof":
            return None, recent
        recent = (recent + payload)[-300:]


def _signal_group(proc, sig) -> None:
    """Send sig to the child's ENTIRE process group (finding 24). The child is
    spawned with start_new_session=True, so it leads its own group and every
    descendant it forks — including pipe-inheriting grandchildren — is a
    member. Killing the group, not just the direct child, is what closes the
    pipe from the descendants' side too; ProcessLookupError just means the
    group is already gone."""
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            proc.send_signal(sig)
        except Exception:
            pass


def _raw_stream_of(stream):
    """The raw FileIO layer under a (text/buffered) wrapper, or the stream
    itself if it is already raw. Raw FileIO close takes none of the wrapper
    locks, so it can never block on a reader mid-read."""
    raw = getattr(stream, "buffer", None)
    raw = getattr(raw, "raw", None)
    return raw if raw is not None else stream


# how long _stop_child waits on each bounded step (direct-child reap, reader
# joins) before escalating; module constant so tests can tighten it
_STOP_GRACE = 5.0


def _stop_child(proc, reader=None, grace: float = _STOP_GRACE) -> None:
    """Tear down a spawned child so nothing leaks and nothing can wedge
    (finding 24). The child runs as its own process-group leader
    (start_new_session), so teardown signals the GROUP: a forked descendant
    that inherited the pipe's write end would otherwise survive the direct
    child's death — leaking AND keeping the reader thread blocked in
    readline() while it holds the text wrapper's buffer lock, which the main
    thread's stream.close() then waits on forever. Group kill closes the
    pipe from the descendants' side too. Defense in depth: if the reader is
    STILL alive after the group kill, close the underlying RAW fd (never the
    wrapper, whose lock the reader holds) and skip the wrapper close while
    the reader lives — the fd, the only OS resource, is already closed, so
    close() cannot block and cannot leak."""
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
    except Exception:
        pass
    if reader is not None:
        # every pipe write-end is dead, so a blocked readline() sees EOF and
        # releases the wrapper locks; give it a moment before closing them
        reader.join(timeout=grace)
        if reader.is_alive():
            # a descendant survived the group TERM and still holds the pipe:
            # force the whole group down, then wait for the EOF to land
            _signal_group(proc, signal.SIGKILL)
            reader.join(timeout=grace)
        if reader.is_alive():
            # last resort: close the raw fds. This takes no wrapper lock, so
            # it cannot block, and it breaks the stream so the reader cannot
            # wedge any later operation either.
            for stream in (proc.stdout, proc.stderr):
                if stream is None:
                    continue
                try:
                    _raw_stream_of(stream).close()
                except Exception:
                    pass
            reader.join(timeout=grace)
    for stream in (proc.stdout, proc.stderr):
        if stream is None:
            continue
        if reader is not None and reader.is_alive() and stream is proc.stdout:
            # reader never woke: closing this wrapper would wait on the very
            # lock it holds (the old deadlock); its raw fd is closed above,
            # so skipping leaks no OS resource
            continue
        try:
            stream.close()
        except Exception:
            pass


def cloudflare_expose(gate_port: int, watch_seconds: int = 45,
                      binpath: str = "cloudflared") -> dict:
    """Run a quick tunnel. Blocks while the tunnel lives — quick-tunnel URLs are
    ephemeral; when this process dies the origin dies with it.

    The readiness wait is bounded (finding 24): a reader thread drains the
    child's output while the main thread waits with a hard deadline, so a
    silent/hung cloudflared ends in a clear error instead of hanging forever.
    The child runs in its own process group (start_new_session): on timeout,
    early exit, or exception the whole GROUP is killed and reaped — a forked
    descendant that inherited the pipe would otherwise leak and keep the
    reader blocked, wedging the stream close — and _stop_child closes the
    raw fd instead of the wrapper if the reader ever stays blocked, so
    cloudflare_expose always returns; on success the child is handed back
    alive."""
    resolved = _which(binpath)
    if not resolved:
        return {"ok": False, "backend": "cloudflare", "error": "cloudflared not found"}
    proc = subprocess.Popen([resolved, "tunnel", "--url", f"http://127.0.0.1:{gate_port}"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            bufsize=1, start_new_session=True)
    out_q = queue.Queue()
    reader = threading.Thread(target=_drain_tunnel_lines, args=(proc, out_q),
                              daemon=True)
    reader.start()
    try:
        url, recent = _await_tunnel_url(proc, out_q, watch_seconds)
    except Exception:
        _stop_child(proc, reader, grace=_STOP_GRACE)
        raise
    if url is None:
        code = proc.poll()
        _stop_child(proc, reader, grace=_STOP_GRACE)
        if code is None:
            error = (f"no quick-tunnel URL appeared within {watch_seconds}s — cloudflared "
                     f"stayed silent (hung, offline, or rate-limited?) and was killed. "
                     f"Check the network and cloudflared install and retry, or use a "
                     f"named tunnel / tailscale")
        else:
            error = (f"cloudflared exited (code {code}) without printing a tunnel URL — "
                     f"recent output: {recent!r}. Check the cloudflared install and "
                     f"network and retry, or use a named tunnel / tailscale")
        return {"ok": False, "backend": "cloudflare", "error": error}
    return {"ok": True, "backend": "cloudflare", "url": url.rstrip(),
            "rp_id": url.rstrip().split("//", 1)[-1].rsplit(":", 1)[0],
            "persistent": False,
            "process": proc,
            "note": ("quick tunnel: URL changes every run; keep this process alive. "
                     "For a stable origin use a named cloudflare tunnel (see README) or tailscale.")}


def auto_expose(gate_port: int, gate_origin_cfg: str = "", gate_rp_id_cfg: str = "") -> dict:
    """Selection logic, called by the `expose` CLI command:
    explicit config origin > tailscale > cloudflared > localhost instructions."""
    if gate_origin_cfg.strip():
        return {"ok": True, "backend": "configured",
                "url": gate_origin_cfg.strip(), "rp_id": gate_rp_id_cfg.strip() or "localhost",
                "persistent": True, "note": "using manually configured origin"}
    b = detect_backends()
    if b["tailscale"]:
        return tailscale_expose(gate_port)
    if b["cloudflared"]:
        return cloudflare_expose(gate_port)
    return {"ok": False, "backend": "none",
            "error": ("no HTTPS path found: install tailscale (https://tailscale.com/download) or cloudflared "
                      "(https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/);"
                      " or set plugins.entries.passkey-gate.settings.origin to an existing HTTPS origin")}
