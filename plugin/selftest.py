"""`hermes passkey-gate test`: check address, phone and passkey end to end.

Shows a QR code for a harmless sample request, waits for the phone, then
checks the signature here, locally, against the pinned owner key, the same
way every real approval is checked. Approving it runs and authorises
nothing (its own request kind, TEST_KIND). When something fails, it says
which part: the gate's address, the phone, or the passkey.

Run it in your own terminal. It changes no settings.
"""
import sys
import time

from . import cli, gate_core

TEST_TEXT = ("Test from 'hermes passkey-gate test' on this computer. Approving it runs "
             "nothing; it checks that your phone and passkey work with this gate.")


class Test:
    def __init__(self, ctx, say=None, sleep=time.sleep, clock=time.time):
        self.ctx = ctx
        self.say = say or (lambda text="": print(text, flush=True))
        self.sleep, self.clock = sleep, clock

    def _wait(self, cid, seconds):
        end = self.clock() + seconds
        while self.clock() < end:
            state = gate_core.challenge_state(cid)
            if state != "pending":
                return state
            self.sleep(1)
        return "expired"

    def run(self) -> str:
        out = cli.status_data(self.ctx)
        gate = out.get("gate") or {}
        if not gate.get("reachable"):
            return "\n".join([
                "✗ Address: the gate can't be reached at its HTTPS address, so your phone",
                f"  couldn't open a link either. {gate.get('error') or ''}".rstrip(),
                f"  next: {gate.get('next_step') or 'hermes passkey-gate status'}"])
        if not out.get("owner_key_pinned"):
            return ("✗ Passkey: no owner key is pinned, so no signature can be trusted yet.\n"
                    "  next: hermes passkey-gate setup")
        try:
            c = gate_core.create_challenge(TEST_TEXT, gate_core.TEST_REQUESTER,
                                           _kind=gate_core.TEST_KIND)
        except ValueError as exc:
            return f"✗ Couldn't create the test request: {exc}"
        cid, ttl = c["challenge_id"], gate_core.challenge_ttl()
        self.say(f"✓ Address: the gate answers at {gate.get('origin') or c.get('url')}")
        self.say("Scan this with your phone's camera and open the link:")
        self.say(cli.qr_text(c["url"]))
        self.say(f"  {c['url']}")
        self.say("Tap Approve and confirm with your face, fingerprint or screen lock.")
        self.say(f"Waiting for your phone… (up to {ttl // 60} min; Ctrl-C to stop)")
        try:
            state = self._wait(cid, ttl)
        except KeyboardInterrupt:
            gate_core.withdraw_challenge(cid, "test stopped", kind=gate_core.TEST_KIND)
            return "\ntest stopped; nothing was changed."
        if state == "approved":
            problems = gate_core.own_request_problems(cid, c["action_sha256"], TEST_TEXT,
                                                      gate_core.TEST_KIND)
            gate_core.consume_approval(cid, c["action_sha256"], kind=gate_core.TEST_KIND,
                                       consumed_by="hermes passkey-gate test")
            if not problems:
                return ("✓ Phone: you opened the link and signed.\n"
                        "✓ Passkey: the signature checks out, here, against your pinned owner key.\n"
                        "Everything works: real approval requests will reach you the same way.")
            return "\n".join(
                ["✓ Phone: you opened the link and signed.",
                 "✗ Passkey: but the signature does NOT verify against your pinned owner key:"]
                + [f"    - {p}" for p in problems]
                + ["  This usually means you signed with a different passkey from the one you",
                   "  pinned (another phone, or a passkey registered here earlier).",
                   "  next: hermes passkey-gate credentials   (compare the codes), or run setup again"])
        if state == "denied":
            return ("✓ Phone: you opened the link and the gate received your answer.\n"
                    "– Passkey: not checked, because you tapped Deny. Run the test again and\n"
                    "  tap Approve to check the signature too.")
        gate_core.withdraw_challenge(cid, "test timed out", kind=gate_core.TEST_KIND)
        return ("✗ Phone: no answer arrived. Check that:\n"
                "  • the phone is signed in to the same tailnet (Tailscale shows it connected)\n"
                "  • the link opens in the phone's browser at all; if not, it's the address or\n"
                "    Tailscale HTTPS certificates, not the passkey\n"
                "  • the page showed Approve; if the phone said it has no passkey for this\n"
                "    site, run setup again to register one")


def cmd_test(ctx, rest, **kw):
    if rest and rest[0] in ("-h", "--help", "help"):
        return __doc__
    if not kw and not sys.stdin.isatty():
        return "test is interactive: run 'hermes passkey-gate test' in a terminal."
    return Test(ctx, **kw).run()
