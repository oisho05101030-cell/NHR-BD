(function () {
  var RENDER_URL = "https://nhr-bd.onrender.com";
  var h = location.hostname;
  var isStatic = /\.web\.app$|\.firebaseapp\.com$|github\.io$/.test(h);
  var saved = "";
  try { saved = localStorage.getItem("NHR_API_BASE") || ""; } catch (e) {}
  var base = (saved || RENDER_URL || "").replace(/\/+$/, "");
  window.NHR_API_BASE = isStatic ? base : "";
  if (window.NHR_API_BASE) {
    var origFetch = window.fetch.bind(window);
    window.fetch = function (input, init) {
      if (typeof input === "string" && input.startsWith("/api/")) {
        input = window.NHR_API_BASE + input;
      }
      return origFetch(input, init);
    };
  }
  window.nhrB64u = {
    enc: function (b) { return btoa(String.fromCharCode.apply(null, new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); },
    dec: function (s) { return Uint8Array.from(atob(String(s).replace(/-/g, "+").replace(/_/g, "/")), function (c) { return c.charCodeAt(0); }); }
  };
  window.nhrHasSensor = async function () {
    try {
      if (!window.isSecureContext || !window.PublicKeyCredential || !PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) return false;
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) { return false; }
  };
  window.nhrDirectEnroll = async function (ticketId, fbUid) {
    var r = await fetch("/api/fp/ticket/" + encodeURIComponent(ticketId));
    if (!r.ok) throw new Error("expired");
    var T = await r.json();
    var cred = await navigator.credentials.create({
      publicKey: {
        challenge: window.nhrB64u.dec(T.challenge),
        rp: { name: "NHR BD" },
        user: { id: window.nhrB64u.dec(T.userHandle), name: T.label, displayName: T.name },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
        timeout: 60000,
        attestation: "none"
      }
    });
    var resp = cred.response;
    if (!resp.getPublicKey || !resp.getPublicKey()) throw new Error("unsupported");
    var saveRes = await fetch("/api/fp/ticket/" + encodeURIComponent(ticketId) + "/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rawId: window.nhrB64u.enc(cred.rawId),
        clientDataJSON: window.nhrB64u.enc(resp.clientDataJSON),
        publicKey: window.nhrB64u.enc(resp.getPublicKey()),
        alg: resp.getPublicKeyAlgorithm()
      })
    });
    if (!saveRes.ok) throw new Error("verify");
    var savedData = await saveRes.json().catch(function () { return {}; });
    if (window.db && fbUid && savedData.credential) {
      try {
        await window.db.collection("users").doc(fbUid).update({
          hasFingerprint: true,
          fpCredentialJson: JSON.stringify(savedData.credential)
        });
      } catch (e) {}
    }
    return true;
  };
  window.nhrDirectAssert = async function (ticketId) {
    var r = await fetch("/api/fp/ticket/" + encodeURIComponent(ticketId));
    if (!r.ok) throw new Error("expired");
    var T = await r.json();
    var ids = (T.credentialIds && T.credentialIds.length ? T.credentialIds : [T.credentialId]).filter(Boolean);
    var a = await navigator.credentials.get({
      publicKey: {
        challenge: window.nhrB64u.dec(T.challenge),
        allowCredentials: ids.map(function (id) { return { type: "public-key", id: window.nhrB64u.dec(id) }; }),
        userVerification: "required",
        timeout: 60000
      }
    });
    var vRes = await fetch("/api/fp/ticket/" + encodeURIComponent(ticketId) + "/assert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        credentialId: window.nhrB64u.enc(a.rawId),
        clientDataJSON: window.nhrB64u.enc(a.response.clientDataJSON),
        authenticatorData: window.nhrB64u.enc(a.response.authenticatorData),
        signature: window.nhrB64u.enc(a.response.signature)
      })
    });
    if (!vRes.ok) throw new Error("verify");
    return true;
  };
})();
