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
import shutil
import subprocess
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


def cloudflare_expose(gate_port: int, watch_seconds: int = 45) -> dict:
    """Run a quick tunnel. Blocks while the tunnel lives — quick-tunnel URLs are
    ephemeral; when this process dies the origin dies with it."""
    if not _which("cloudflared"):
        return {"ok": False, "backend": "cloudflare", "error": "cloudflared not found"}
    proc = subprocess.Popen(["cloudflared", "tunnel", "--url", f"http://127.0.0.1:{gate_port}"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            bufsize=1)
    url, deadline = None, time.time() + watch_seconds
    while time.time() < deadline:
        line = (proc.stdout or "").readline() if proc.stdout else ""
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
            continue
        url = url_from_tunnel_line(line)
        if url:
            break
    if url is None:
        proc.kill()
        return {"ok": False, "backend": "cloudflare",
                "error": "no quick-tunnel URL appeared (offline or rate-limited?)"}
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
