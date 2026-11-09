"""`hermes passkey-gate setup` — the guided first run.

One command walks the operator through the manual setup commands
(expose, bootstrap, credentials, pin --code; see `hermes passkey-gate --help`), checking each step before moving on:

  1. the gate is running (offers to install it as a background service)
  2. it has an HTTPS address your phone can reach (tailscale, or your origin)
  3. you register a passkey on your phone (QR code in this terminal)
  4. you TYPE the short code your phone shows, and the matching key is pinned
  5. optionally, enforcement is switched on

Re-running it is safe: finished steps are detected and skipped. It is an
operator ceremony, like bootstrap and pin — run it in your own terminal,
never through an agent.
"""
import json
import sys
import time

from . import cli, expose, gate_core, lanes, local_verify, netfetch, service, tools

# Standard: dangerous command words in any flag order, find -delete, and any
# code execution (which can do anything). A best-effort deny-list: an
# adversarial agent can still route around it (v0.7 review M2), which is why
# STRICT exists and why the docs say so.
DEFAULT_PATTERN = (r"(?s)^terminal .*\b(rm|rmdir|shred|dd|curl|wget|scp|sftp|rsync|ssh|nc|chmod|chown)\b"
                   r"|^terminal .*\s-delete\b|^execute_code ")
STRICT_PATTERN = r"^(terminal|execute_code|write_file|patch) "
CODE_TRIES = 3


class _Quit(Exception):
    pass


class Wizard:
    def __init__(self, ctx, ask=None, say=None, sleep=time.sleep, clock=time.time):
        self.ctx = ctx
        self._ask = ask or input
        self._say = say or (lambda text="": print(text, flush=True))
        self.sleep, self.clock = sleep, clock
        self.background = False
        self.code = None

    # ------------------------------------------------------------ io
    def say(self, text=""):
        self._say(text)

    def ask(self, prompt):
        try:
            answer = self._ask(prompt)
        except EOFError:
            raise _Quit()
        if answer is None:
            raise _Quit()
        return answer.strip()

    def confirm(self, prompt, default=True):
        hint = "[Y/n]" if default else "[y/N]"
        answer = self.ask(f"{prompt} {hint} ").lower()
        if answer in ("q", "quit"):
            raise _Quit()
        if not answer:
            return default
        return answer in ("y", "yes")

    def pause(self, prompt="Press Enter to check again, or type q to quit: "):
        if self.ask(prompt).lower() in ("q", "quit"):
            raise _Quit()

    def heading(self, n, title):
        self.say()
        self.say(f"── Step {n} of 4 · {title} " + "─" * max(0, 44 - len(title)))

    # ------------------------------------------------------------ steps
    def step_running(self):
        self.heading(1, "Start the gate")
        port = gate_core.validate_port(self.ctx.get_config("port", default=8655))
        offered = False
        while True:
            state = service.probe(port)
            if state == "ours":
                self.background = service.installed()
                how = "as a background service" if self.background else "in another terminal"
                self.say(f"✓ The gate is running {how} (127.0.0.1:{port}).")
                return port
            if state == "other":
                port = self._other_on_port(port)
                continue
            if service.manager() and not offered:
                offered = True
                self.say("The gate is a small local web service. It can run in the background, so you")
                self.say("don't have to keep a terminal open, and start again whenever you log in.")
                if self.confirm("Run it in the background?"):
                    ok, text = service.install(port)
                    self.say(text)
                    if ok and self._wait_for_local(port, seconds=20):
                        self.background = True
                        self.say(f"✓ The gate is running in the background (127.0.0.1:{port}).")
                        return port
                    if ok:
                        self.say("The service was installed but the gate is not answering yet. "
                                 "Its output: hermes passkey-gate service logs")
                    continue
            self.say("Start it in another terminal and leave that terminal open:")
            self.say("    hermes passkey-gate serve")
            self.pause("Press Enter once it says 'passkey-gate on 127.0.0.1…', or type q to quit: ")
            if service.probe(port) == "free":
                self.say(f"Nothing is answering on 127.0.0.1:{port} yet.")

    def _other_on_port(self, port):
        """Something that is not this gate holds the port: move to another
        one (port is not a security setting) or let the operator free it."""
        self.say(f"✗ Port {port} is already used by a program that isn't this gate (for example")
        self.say("  the older approval-gate prototype, another Hermes profile's gate, or an older")
        self.say("  'passkey-gate serve' that needs restarting).")
        origin = (self.ctx.get_config("origin", default="") or "").strip()
        if origin:
            # v0.7 review H1: the HTTPS address forwards to THIS port. Moving
            # the gate would leave the address pointing at whatever holds it,
            # which could then relay your registration and get its own key
            # pinned. Never move a gate that already has an address.
            self.say(f"  Your HTTPS address ({origin}) forwards to port {port}, so the gate can't")
            self.say("  simply move: the address would then reach that other program instead.")
            self.say("  Stop the other program (if you don't recognise it, treat it as hostile),")
            self.say("  then press Enter to check again.")
            self.pause()
            return port
        suggestion = port + 1 if port < gate_core.PORT_MAX else port - 1
        answer = self.ask(f"Port to use instead [{suggestion}], or s to stop that program "
                          "yourself and re-check: ").lower()
        if answer in ("q", "quit"):
            raise _Quit()
        if answer == "s":
            self.pause("Press Enter once it's stopped: ")
            return port
        out = cli.cmd_set(self.ctx, ["port", answer or str(suggestion)])
        if out.startswith("REFUSED") or "=" not in out.split("\n", 1)[0]:
            self.say(out.split("\n", 1)[0])
            return port
        new = gate_core.validate_port(self.ctx.get_config("port", default=port))
        self.say(f"✓ The gate will use port {new}.")
        if service.installed():
            ok, text = service.control("restart")
            self.say(f"  background service {text}")
        return new

    def _wait_for_local(self, port, seconds):
        end = self.clock() + seconds
        while self.clock() < end:
            if service.probe(port) == "ours":
                return True
            self.sleep(0.5)
        return service.probe(port) == "ours"

    def _probe(self, base, port):
        try:
            with netfetch.open_no_redirect(f"{base}/health", timeout=8) as r:
                if r.status != 200:
                    return {"error": f"the gate at {base} answered HTTP {r.status}", "next_step": ""}
                try:
                    health = json.loads(r.read(65536))
                except ValueError:
                    health = None
        except Exception as exc:
            return tools.gate_unreachable_reason(base, exc)
        if not expose.is_this_gate(health):
            return {"error": f"{base} answers, but not as this passkey-gate",
                    "next_step": "the address points at another service or another gate; fix "
                                 "the forwarding (or re-run 'hermes passkey-gate expose')"}
        # v0.7 review H1: a relaying impostor passes the identity check, so
        # also make sure the address forwards to the port the gate runs on
        target = expose.recorded_target_port()
        if target is not None and target != port:
            return {"error": f"your Tailscale address forwards to port {target}, but the gate "
                             f"runs on port {port} — whatever answers on {target} is not this gate",
                    "next_step": f"run 'hermes passkey-gate set port {target}' (and stop whatever "
                                 f"holds {target}), then run setup again"}
        return None

    def step_address(self, port):
        self.heading(2, "Give it an HTTPS address")
        while True:
            origin = (self.ctx.get_config("origin", default="") or "").strip().rstrip("/")
            if not origin:
                self.say("Your phone reaches the gate over HTTPS. Publishing it on your tailnet")
                self.say("(private to your own devices, nothing goes on the public internet)…")
                self.say(cli.cmd_expose(self.ctx, []))
                origin = (self.ctx.get_config("origin", default="") or "").strip().rstrip("/")
            if origin:
                problem = self._probe(origin, port)
                if problem is None:
                    self.say(f"✓ Reachable at {origin}")
                    return origin
                self.say(f"✗ {problem.get('error')}")
                if problem.get("next_step"):
                    self.say(f"  next: {problem['next_step']}")
            else:
                self.say("✗ No HTTPS address yet. Either:")
                self.say("  • install Tailscale on this computer and your phone, sign both in")
                self.say("    (tailscale up), and enable HTTPS in the Tailscale admin console; or")
                self.say("  • if you already serve HTTPS here (nginx, caddy), point it at")
                self.say("    127.0.0.1:<port> and run: hermes passkey-gate set origin https://…")
            self.pause()

    def step_register(self):
        self.heading(3, "Create your passkey on your phone")
        try:
            pinned = local_verify.pinned(gate_core.data_dir())
        except ValueError:
            pinned = None
        if pinned:
            match = [c for c in gate_core.list_credentials() if c["spki_pem"].strip() == pinned.strip()]
            self.code = match[0]["code"] if match else None
            self.say("✓ An owner key is already pinned" +
                     (f" (code {self.code})." if self.code else "."))
            self.say("  (To start over with a new phone, remove the pin file in "
                     f"{gate_core.data_dir()} first.)")
            return None
        existing = gate_core.list_credentials()
        if existing:
            self.say(f"{len(existing)} passkey(s) are registered here, but none is trusted yet.")
            self.say("If you registered on your phone earlier and didn't finish (the phone now says")
            self.say("it already has a passkey for this gate), you can use that one: you'll need the")
            self.say("code its page showed. Otherwise make a new one.")
            # v0.7 review L13: these passkeys were not registered after a QR
            # this run showed, so the typed code is the only proof of whose
            # they are
            self.say("Only type the code YOUR phone showed. Don't copy one from 'hermes passkey-gate")
            self.say("credentials': that lists every passkey registered here, including any you")
            self.say("didn't make.")
            if self.confirm("Use a passkey that's already registered?", default=False):
                return existing
        while True:
            before = {c["credential_id"] for c in gate_core.list_credentials()}
            url = gate_core.mint_bootstrap_token()
            minutes = gate_core.bootstrap_ttl() // 60
            self.say("Scan this QR code with your phone's camera and open the link:")
            self.say(cli.qr_text(url))
            self.say(f"  {url}")
            self.say(f"  (one-time link, works for {minutes} minutes. Don't paste it into a chat.)")
            self.say()
            self.say("On the phone: tap 'Create passkey' and confirm with your face, fingerprint")
            self.say("or screen lock. The phone then shows a 10-character code.")
            self.say()
            self.say("Waiting for your phone… (Ctrl-C to stop)")
            new = self._wait_for_registration(before, gate_core.bootstrap_ttl())
            if new:
                return new
            self.say("✗ The link expired before a passkey was registered.")
            if not self.confirm("Make a fresh QR code?"):
                raise _Quit()

    def _wait_for_registration(self, before, seconds):
        end = self.clock() + seconds
        while self.clock() < end:
            new = [c for c in gate_core.list_credentials() if c["credential_id"] not in before]
            if new:
                return new
            self.sleep(1)
        return []

    def step_confirm(self, new):
        self.heading(4, "Confirm it's your passkey")
        if new is None:
            self.say("✓ Already done.")
            return True
        self.say("✓ Your phone registered a passkey.")
        if len(new) > 1:
            self.say(f"  ({len(new)} passkeys appeared at once. Only the one whose code you type "
                     "will be trusted.)")
        self.say("Now type the code your phone is showing (like 7KQ2M-X9D4R). This is how the")
        self.say("computer knows the passkey it trusts is the one on YOUR phone.")
        for attempt in range(1, CODE_TRIES + 1):
            typed = self.ask("Code from your phone: ")
            if typed.lower() in ("q", "quit"):
                raise _Quit()
            code = gate_core.normalize_confirmation_code(typed)
            if not code:
                self.say("  That isn't a code: it's 10 letters and digits, e.g. 7KQ2M-X9D4R.")
                continue
            match = [c for c in new if c["code"] == code]
            if not match:
                self.say("  That doesn't match the passkey that was just registered. "
                         "Check the phone screen and type it again.")
                continue
            if len(match) > 1:
                # L13: same rule as 'pin --code' — never pick one silently
                self.say("✗ More than one registered passkey has that code, so it can't tell "
                         "which is yours. Nothing was pinned. Run setup again for a fresh QR code.")
                return False
            c = match[0]
            try:
                local_verify.pin(gate_core.data_dir(), c["spki_pem"], None)
            except (OSError, ValueError) as exc:
                self.say(f"✗ Could not pin the key: {exc}")
                return False
            gate_core.audit("owner_key_pinned", via="setup", credential_id=c["credential_id"],
                            fingerprint=c["fingerprint"])
            self.code = code
            self.say(f"✓ Code matches. Your passkey is now the owner key (code {code}).")
            self.say("  Every approval is checked against it, on this computer.")
            return True
        self.say("✗ Nothing was pinned, so nothing is trusted yet. If the code on your phone")
        self.say("  really doesn't match, that passkey isn't the one that registered here.")
        self.say("  Run setup again for a fresh QR code.")
        return False

    def step_enforce(self):
        self.say()
        self.say("── Optional · Require your passkey for risky commands ─────────")
        if self.ctx.get_config("require_passkey", default=False):
            pats = self.ctx.get_config("authority_patterns", default=[]) or []
            self.say(f"✓ Enforcement is already on ({len(pats)} pattern(s)).")
            return
        self.say("With enforcement on, a tool call matching a pattern is blocked until you")
        self.say("approve that exact call with your passkey. You can change this any time.")
        if not self.confirm("Turn it on now?", default=False):
            self.say("Skipped. Later: hermes passkey-gate set require_passkey true")
            return
        if not (self.ctx.get_config("authority_patterns", default=[]) or []):
            self.say("Which calls should need your approval?")
            self.say("  1  Standard: dangerous terminal commands (rm, curl, ssh, dd…) and any")
            self.say("     code execution. Best effort: a determined agent can find another way.")
            self.say("  2  Strict: every terminal command, code run and file edit. Safest, but")
            self.say("     you'll approve a lot.")
            self.say("  Or type your own regular expression.")
            raw = self.ask("Choose 1, 2, or a regex [1]: ") or "1"
            raw = {"1": DEFAULT_PATTERN, "2": STRICT_PATTERN}.get(raw, raw)
            out = cli.cmd_set(self.ctx, ["authority_patterns", json.dumps([raw])])
            if out.startswith("REFUSED"):
                self.say(out)
                self.say("Enforcement left off. Fix the pattern with: "
                         "hermes passkey-gate set authority_patterns <regex>")
                return
        if not self.step_lanes():
            self.say("Enforcement left off.")
            return
        cli.cmd_set(self.ctx, ["require_passkey", "true"])
        gated = self.ctx.get_config("gated_lanes", default=list(lanes.LANES))
        self.say(f"✓ Enforcement is on, for: {', '.join(lanes.normalize_lanes_ordered(gated)) or 'nothing'}.")

    def step_lanes(self):
        """Which conversations need a passkey. Runs only while enforcement is
        still off: narrowing lanes later needs a passkey approval."""
        self.say()
        self.say("Which conversations should need your passkey?")
        self.say("  1  All of them (safest): you at this computer too.")
        self.say("  2  When you're not at this computer: every chat, bots and other agents.")
        self.say("  3  Only other agents and bots: A2A, Hermes peer DMs, and chat senders")
        self.say("     the platform marks as bots. Chats from people aren't gated.")
        self.say(f"  Or list lanes yourself, comma-separated: {', '.join(lanes.LANES)}")
        self.say("  (README: 'Choosing which chats need a passkey' explains each, and its limits.)")
        raw = self.ask("Choose 1, 2, 3, or lanes [1]: ") or "1"
        chosen = {"1": list(lanes.LANES), "2": ["owner", "others", "bots", "agents"],
                  "3": ["bots", "agents"]}.get(raw) or [x.strip() for x in raw.split(",") if x.strip()]
        out = cli.cmd_set(self.ctx, ["gated_lanes", json.dumps(chosen)], _setup_enforcement_off=True)
        if out.startswith("REFUSED"):
            self.say(out)
            return False
        gated = set(chosen)
        if "others" in gated and "owner" not in gated:
            self.say("Your own chat accounts aren't gated, but other people's are. List yours as")
            self.say("platform:user_id (e.g. telegram:123456789) so the gate can tell them apart.")
            owners = self.ask("Your accounts, comma-separated (Enter to skip): ")
            if owners:
                out = cli.cmd_set(self.ctx, ["owner_senders", owners], _setup_enforcement_off=True)
                if out.startswith("REFUSED"):
                    self.say(out)
                    self.say("No owner accounts saved; your chats count as 'others' for now.")
        return True

    # ------------------------------------------------------------ run
    def run(self):
        problem = cli.config_canary_problem(self.ctx)
        if problem:
            return f"setup stopped before changing anything: {problem}"
        self.say("passkey-gate setup: about 3 minutes, and you'll need your phone.")
        self.say("Run this in your own terminal, never through an agent.")
        try:
            port = self.step_running()
            origin = self.step_address(port)
            new = self.step_register()
            if not self.step_confirm(new):
                return "setup stopped before pinning a key — run 'hermes passkey-gate setup' again"
            self.step_enforce()
        except _Quit:
            return "setup stopped. Run 'hermes passkey-gate setup' again any time; finished steps are skipped."
        except KeyboardInterrupt:
            return "\nsetup interrupted. Run 'hermes passkey-gate setup' again any time; finished steps are skipped."
        cli.stamp_config_canary(self.ctx)  # arms the broken-config check (finding 17)
        enforce = bool(self.ctx.get_config("require_passkey", default=False))
        return "\n".join([
            "",
            "✓ Setup complete.",
            f"  gate        {'background service' if self.background else 'running in a terminal'} "
            f"on 127.0.0.1:{port}",
            f"  address     {origin}",
            f"  owner key   pinned{f' (code {self.code})' if self.code else ''}",
            f"  enforcement {'on' if enforce else 'off'}",
            "",
            "Next:",
            "  • hermes passkey-gate status     — check everything at a glance",
            "  • ask your agent to do something that needs approval; it sends you a link",
            "  • hermes passkey-gate audit-notarize --to ~/gate-notary.log  — anchor the audit log",
        ] + ([] if self.background else
             ["  • hermes passkey-gate service install  — stop needing that terminal"]))


def cmd_setup(ctx, rest, **kw):
    if rest and rest[0] in ("-h", "--help", "help"):
        return __doc__
    if not kw and not sys.stdin.isatty():
        return ("setup is interactive: run 'hermes passkey-gate setup' in a terminal. "
                "(To set up by hand instead, see 'Setting up by hand' in 'hermes passkey-gate --help'.)")
    return Wizard(ctx, **kw).run()
