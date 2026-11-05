"""Tool schemas — what the LLM sees.

The descriptions matter: they tell the model when a passkey approval is
required and how to phrase the challenge it mints (the human reads that
text as the authority document, so it must read like one).
"""

GATE_CHALLENGE = {
    "name": "gate_challenge",
    "description": (
        "Mint a passkey approval request for a high-authority action, BEFORE "
        "performing it. The signer reads the page you link them to — write for "
        "THEM. action_text must be a specific, self-contained authority "
        "document (what changes, on which system, what limits, when it "
        "expires; minimum 40 chars and 6 words; vagueness is rejected). The "
        "signer may be YOUR OWN human or, in cross-agent collaboration, ANOTHER "
        "HUMAN you have never met: then set requester_owner to name your human, "
        "write `why` in one plain sentence (required then — no jargon, explain "
        "what signing enables and why it is safe), never assume they know your "
        "project. The returned URL is the only way a human can approve: send it "
        "via a channel they actually read, with one line of context. If another "
        "human already approved on their own gate, pass parent_approval so the "
        "page shows that checked, not claimed. Challenge expires (default 10 "
        "min); approvals are single-use and consumed on use."
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
                "description": "The asking AGENT's name (you). Max 64 chars.",
            },
            "requester_owner": {
                "type": "string",
                "description": (
                    "Name of YOUR OWN human (the operator responsible for you). "
                    "Set it whenever the signer might not be your own human — "
                    "it lets them judge the ask. Max 64 chars."
                ),
            },
            "why": {
                "type": "string",
                "description": (
                    "ONE plain sentence for the SIGNER (may be a stranger): what "
                    "signing enables, and why it is safe/needed. Required when "
                    "requester_owner is set and differs from the requester name. Max 400 chars."
                ),
            },
            "parent_approval": {
                "type": "object",
                "description": (
                    "When a prior approval exists on the peer agent's own gate "
                    "(that human signed there): {base: https URL of THEIR gate, "
                    "challenge_id, action_sha256, owner}. The page will show the "
                    "parent record re-checked locally before rendering."
                ),
                "properties": {
                    "base": {"type": "string"},
                    "challenge_id": {"type": "string"},
                    "action_sha256": {"type": "string"},
                    "owner": {"type": "string"},
                },
            },
            "tool_call": {
                "type": "object",
                "description": (
                    "Optional structured binding of the exact tool call this "
                    "approval should cover, shaped as {tool: <name>, args: <the "
                    "same args object>}. When enforcement is on, the "
                    "pre_tool_call hook re-derives this binding and only lets "
                    "the call through if it matches an approved, unconsumed "
                    "challenge."
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
