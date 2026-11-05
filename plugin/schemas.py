"""Tool schemas — what the LLM sees.

The descriptions matter: they tell the model when a passkey approval is
required and how to phrase the challenge it mints (the human reads that
text as the authority document, so it must read like one).
"""

GATE_CHALLENGE = {
    "name": "gate_challenge",
    "description": (
        "Mint a passkey approval request for a high-authority action, BEFORE "
        "performing it. action_text must be a specific, self-contained authority "
        "document the human will read and sign (who grants what, on which system, "
        "what limits, when it expires) — minimum 40 characters and 6 words, vague "
        "text is rejected. The returned URL is the ONLY way the human can approve: "
        "send it to them and clearly say what it approves. Optionally pass "
        "tool_call (same tool name and exact args) so the enforced flow can bind "
        "this approval to that one deliberate execution. Challenge expires (default "
        "10 min) and approvals are single-use."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action_text": {
                "type": "string",
                "description": (
                    "The exact authority text the human will read and sign. "
                    "Must state: what access/change is granted, to whom/what, on "
                    "which system/resource, expiry date where relevant. No vague "
                    "'grant access' one-liners."
                ),
            },
            "requester": {
                "type": "string",
                "description": "Who is asking (agent profile name, session id, or peer lane label). Max 64 chars.",
            },
            "tool_call": {
                "type": "object",
                "description": (
                    "Optional structured binding of the exact tool call this approval "
                    "should cover, shaped as {tool: <name>, args: <same args object>}. "
                    "When enforcement is on, the pre_tool_call hook re-derives this "
                    "binding and only lets the call through if it matches an approved, "
                    "unconsumed challenge."
                ),
            },
        },
        "required": ["action_text", "requester"],
    },
}

GATE_VERIFY = {
    "name": "gate_verify",
    "description": (
        "Locally verify a passkey approval with real cryptography — never trust the "
        "gate server's yes/no on its own. Checks the signed assertion against the "
        "pinned owner public key: sha256 binding, signature, user-verification "
        "flags, origin/RP id, and optional max age. With wait_seconds > 0, polls "
        "the challenge until approved/denied/expired or the wait runs out, so a "
        "just-minted challenge can be awaited before acting. ACT on an action only "
        "when verified is true."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "challenge_id": {
                "type": "string",
                "description": "Challenge id returned by gate_challenge.",
            },
            "action_text": {
                "type": "string",
                "description": "The EXACT action_text the challenge was minted with (as submitted, stripped).",
            },
            "wait_seconds": {
                "type": "integer",
                "description": "Poll until this many seconds elapse waiting for the human to sign (max 120). Omit for an instant one-shot check.",
            },
            "max_age": {
                "type": "integer",
                "description": "Optional: reject approvals older than this many seconds.",
            },
        },
        "required": ["challenge_id", "action_text"],
    },
}

GATE_STATUS = {
    "name": "gate_status",
    "description": (
        "Passkey gate status: is a gate service reachable, how many passkey "
        "credentials are registered, whether an owner key is pinned locally, and "
        "whether the hash-chained audit log verifies intact. Use before relying "
        "on the gate for anything."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "audit_check": {
                "type": "boolean",
                "description": "Also verify the append-only audit chain integrity (default true).",
            },
        },
        "required": [],
    },
}
