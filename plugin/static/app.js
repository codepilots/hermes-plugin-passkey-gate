// approval-gate client: WebAuthn ceremonies only. No secrets live here.
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  dec: (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); },
};
const msg = (t, cls) => { const m = document.getElementById("msg"); m.textContent = t; m.className = cls || ""; };
const post = async (url, body) => {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
};

async function approve(cid) {
  msg("Waiting for your passkey…");
  const o = await post(`/a/${cid}/options`);
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: b64u.dec(o.challenge), rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification,
    allowCredentials: (o.allowCredentials || []).map(c => ({ type: c.type, id: b64u.dec(c.id), transports: c.transports })),
  }});
  const r = cred.response;
  await post(`/a/${cid}/finish`, {
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment, clientExtensionResults: cred.getClientExtensionResults(),
    response: { authenticatorData: b64u.enc(r.authenticatorData), clientDataJSON: b64u.enc(r.clientDataJSON),
                signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null },
  });
}

async function register(token) {
  msg("Waiting for your authenticator…");
  const o = await post("/register/options", { token });
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: b64u.dec(o.challenge), rp: o.rp, timeout: o.timeout, attestation: o.attestation,
    user: { id: b64u.dec(o.user.id), name: o.user.name, displayName: o.user.displayName },
    pubKeyCredParams: o.pubKeyCredParams, authenticatorSelection: o.authenticatorSelection,
    excludeCredentials: (o.excludeCredentials || []).map(c => ({ type: c.type, id: b64u.dec(c.id) })),
  }});
  const r = cred.response;
  return post("/register/finish", { token, session_id: o.session_id, credential: {
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment, clientExtensionResults: cred.getClientExtensionResults(),
    response: { clientDataJSON: b64u.enc(r.clientDataJSON), attestationObject: b64u.enc(r.attestationObject),
                transports: r.getTransports ? r.getTransports() : [] },
  }});
}

document.addEventListener("DOMContentLoaded", () => {
  const cidEl = document.getElementById("cid");
  const a = document.getElementById("approve"), d = document.getElementById("deny"), g = document.getElementById("register");
  const done = (state, cls) => { document.getElementById("state").textContent = state; a && a.remove(); d && d.remove(); msg(state === "approved" ? "Approved and recorded." : "Denied.", cls); };
  if (a) a.onclick = () => approve(cidEl.dataset.id).then(() => done("approved", "ok")).catch(e => msg("Not approved: " + e.message, "err"));
  if (d) d.onclick = () => post(`/a/${cidEl.dataset.id}/deny`).then(() => done("denied", "err")).catch(e => msg(e.message, "err"));
  if (g) {
    const token = location.hash.slice(1);
    history.replaceState(null, "", location.pathname);  // drop the token from the address bar
    if (!token) { msg("This link has no registration token. Ask for a fresh one (gate.py bootstrap).", "err"); g.remove(); }
    else g.onclick = () => register(token).then(j => { g.remove(); msg("Registered. Credential " + j.credential_id.slice(0, 12) + "… — key fingerprint " + j.fingerprint + ". On the computer, run 'hermes passkey-gate credentials' and pin the entry with this SAME fingerprint.", "ok"); })
                                           .catch(e => msg("Registration failed: " + e.message, "err"));
  }
});
