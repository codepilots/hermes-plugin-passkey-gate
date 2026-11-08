"""Shared server-side fetch + URL-validation helpers (findings 5 and 23).

Every HTTP fetch the plugin makes on its own behalf goes through
``open_no_redirect``, so one rule holds everywhere: a 3xx redirect is an
error, never followed — a redirect answer can re-target a fetch at internal
services or cloud metadata, and no server-side fetch may take it.

The URL side of the same findings lives here too: gate URLs are PARSED,
never prefix-checked (``parse_gate_origin``); parent bases must match a
configured allowlist by exact origin — scheme+host+port, no wildcards
(``origin_allowed``); and an allowlisted DNS name must resolve outside
private/loopback space unless the allowlist entry itself names that literal
internal host (``private_network_problem``).
"""
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request


class RedirectBlocked(urllib.error.HTTPError):
    """A 3xx answer, refused: no server-side fetch follows redirects."""

    def __init__(self, url, code, location=""):
        super().__init__(str(url), code,
                         "redirect refused: no server-side fetch may follow it",
                         None, None)
        self.location = location


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Replaces urllib's default redirect follower in every fetch we make."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectBlocked(req.full_url, code, newurl)


_opener = urllib.request.build_opener(_NoRedirectHandler)


def open_no_redirect(url, timeout=10):
    """GET a URL with urlopen semantics except redirects raise RedirectBlocked."""
    return _opener.open(url, timeout=timeout)


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_gate_origin(url):
    """Strict gate-URL parse (finding 23): the scheme must be https (http only
    on loopback/localhost hosts — the existing dev exception), a hostname
    must be present, and no username/password may ride along. Returns
    (scheme, hostname, port) with the default port filled in; raises
    ValueError with the reason otherwise."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL is empty")
    try:
        parts = urllib.parse.urlsplit(url.strip())
        scheme = (parts.scheme or "").lower()
        host = parts.hostname
        user, pw, port = parts.username, parts.password, parts.port
    except ValueError as exc:
        raise ValueError(f"unparseable URL ({exc})") from None
    if user is not None or pw is not None:
        raise ValueError("URL must not carry a username/password")
    if not host:
        raise ValueError("URL has no hostname")
    if scheme == "https":
        pass
    elif scheme == "http" and _is_loopback_host(host):
        pass  # the existing dev exception: plain http on loopback/localhost
    else:
        raise ValueError(
            "scheme must be https (http is tolerated only on loopback/localhost dev origins)")
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def origin_allowed(base, allowlist):
    """The allowlist entry whose origin (scheme+host+port, exact match, no
    wildcards) equals ``base``'s — or None when nothing matches. Malformed
    entries never match: fail closed."""
    try:
        want = parse_gate_origin(base)
    except ValueError:
        return None
    for entry in allowlist or []:
        try:
            if want == parse_gate_origin(entry):
                return entry
        except ValueError:
            continue
    return None


def _address_problem(raw: str):
    """Why this resolved address is internal, or None if it is fine."""
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return "an unparseable address"
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:  # IPv4-mapped IPv6 is judged as its IPv4 self
        ip = mapped
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_private:
        return "a private address"
    if ip.is_unspecified:
        return "an unspecified address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_reserved:
        return "a reserved address"
    return None


def _entry_names_literal_internal_host(entry_host: str) -> bool:
    """True when the allowlist entry itself names a loopback/private host or
    'localhost' — the admin typed that literal deliberately, which is the
    ONLY way an internal parent gate may be used."""
    if not entry_host:
        return False
    if entry_host.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(entry_host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def _resolve_checked(host, allowlist_entry_host, resolver=None):
    """Resolve ``host`` ONCE and judge every address. Returns
    (problem_or_None, address_to_dial_or_None). The address is what the
    fetch must connect to — dialing the hostname again would resolve it a
    second time, and a DNS answer that changes between the check and the
    connect (rebinding) could steer the fetch to an internal address.
    None for the address means 'the allowlist entry itself names this
    literal internal host; dial it as written'."""
    if _entry_names_literal_internal_host(allowlist_entry_host):
        return None, None
    resolver = resolver or socket.getaddrinfo
    try:
        infos = resolver(host, None)
    except Exception:
        return "parent gate host does not resolve", None
    chosen = None
    for info in infos or []:
        try:
            raw = info[-1][0]
        except Exception:
            return "parent gate host could not be resolved", None
        problem = _address_problem(raw)
        if problem:
            return f"parent gate host resolves to {problem}", None
        if chosen is None:
            chosen = raw
    if chosen is None:
        return "parent gate host does not resolve", None
    return None, chosen


def private_network_problem(host, allowlist_entry_host, resolver=None):
    """After the allowlist match: resolve ``host`` and reject internal
    addresses, unless the allowlist entry itself names that literal host.
    Fail closed on resolution errors. Returns None (fine) or a reason."""
    return _resolve_checked(host, allowlist_entry_host, resolver)[0]


def fetch_target(base, allowlist):
    """The whole finding-5 gate on a parent base, checked BEFORE any network
    I/O. Returns (problem_or_None, address_to_dial_or_None); pass the
    address to ``open_pinned`` so the fetch dials exactly what was checked."""
    try:
        _, host, _ = parse_gate_origin(base)
    except ValueError as exc:
        return f"parent gate base is not a valid gate origin ({exc})", None
    entry = origin_allowed(base, allowlist)
    if entry is None:
        return "parent gate not on allowlist", None
    try:
        _, entry_host, _ = parse_gate_origin(entry)
    except ValueError:
        return "parent gate not on allowlist", None
    return _resolve_checked(host, entry_host)


def base_not_fetchable(base, allowlist):
    """Problem string from ``fetch_target`` (None when the base may be fetched)."""
    return fetch_target(base, allowlist)[0]


def _connect(address, port, timeout):
    """Open a TCP socket to a literal, already-validated address — no name
    resolution happens here."""
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except BaseException:
        sock.close()
        raise
    return sock


def open_pinned(url, address, timeout=10):
    """GET ``url`` while dialing ``address`` (from ``fetch_target``) instead
    of re-resolving the hostname. TLS still verifies the certificate against
    the URL's hostname (SNI + hostname check), Host is the URL's host, and a
    3xx raises RedirectBlocked like every other fetch. ``address`` None
    falls back to ``open_no_redirect`` (a literal host the admin allowlisted)."""
    if address is None:
        return open_no_redirect(url, timeout=timeout)
    import http.client
    import ssl
    parts = urllib.parse.urlsplit(url)
    scheme, host, port = parse_gate_origin(f"{parts.scheme}://{parts.netloc}")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

    if scheme == "https":
        ctx = ssl.create_default_context()

        class _Conn(http.client.HTTPSConnection):
            def connect(self):
                self.sock = ctx.wrap_socket(_connect(address, port, timeout),
                                            server_hostname=host)
        conn = _Conn(host, port, timeout=timeout, context=ctx)
    else:
        class _Conn(http.client.HTTPConnection):
            def connect(self):
                self.sock = _connect(address, port, timeout)
        conn = _Conn(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        resp = conn.getresponse()
    except BaseException:
        conn.close()
        raise
    if 300 <= resp.status < 400:
        loc = resp.getheader("Location") or ""
        conn.close()
        raise RedirectBlocked(url, resp.status, loc)
    if resp.status >= 400:
        conn.close()
        raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None)
    return resp
