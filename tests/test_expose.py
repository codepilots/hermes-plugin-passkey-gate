"""Exposure-layer tests: port picking, URL derivation, tunnel-log parsing,
auto-selection order — all against fixtures captured from the developer's
real tailscale setup (status JSON shape verbatim from tailscale 1.104.4)."""

import json
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
