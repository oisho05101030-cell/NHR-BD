(() => {
  let tm = null;
  const close = () => { if (tm) { clearInterval(tm); tm = null; } $("fpModal").hidden = true; $("qrcode").innerHTML = ""; };
  $("fpCancel").addEventListener("click", close);

  function showQrModal(d, id, pollKey, fbUser) {
    $("qrcode").innerHTML = "";
    const u = d.base + "/m.html?t=" + encodeURIComponent(d.ticket);
    if (window.QRCode) new QRCode($("qrcode"), { text: u, width: 180, height: 180, colorDark: "#0c3b5e" });
    else $("qrcode").textContent = u;
    $("fpWarn").hidden = /^https:\/\//.test(d.base);
    $("fpModal").hidden = false;
    tm = setInterval(async () => {
      try {
        const sr = await fetch("/api/fp/ticket/" + encodeURIComponent(d.ticket) + "/status?k=" + pollKey);
        const st = await sr.json().catch(() => ({}));
        if (st.status === "approved") { finishLogin(st, id, fbUser); }
        else if (st.status === "expired") { close(); $("alert").className = "alert error"; $("alert").textContent = t("fpExpired"); }
      } catch (e) {}
    }, 1500);
  }

  function finishLogin(st, id, fbUser) {
    close();
    const ses = {
      token: st.token,
      uid: (st.user && st.user.uid) || (fbUser && fbUser.uid) || "",
      nid: id,
      nhrId: (st.user && st.user.nhrId) || "",
      name: (st.user && st.user.name) || (fbUser && fbUser.fullName) || "",
      email: (st.user && st.user.email) || (fbUser && fbUser.email) || "",
      role: "patient",
      type: "nid"
    };
    localStorage.setItem("nhr_session", JSON.stringify(ses));
    sessionStorage.setItem("nhr_session", JSON.stringify(ses));
    localStorage.setItem("nhr_user", JSON.stringify(ses));
    $("alert").className = "alert success";
    $("alert").textContent = t("welcome", { name: ses.name || id, what: t("opensNid") });
    setTimeout(() => location.replace("dashboard.html"), 450);
  }

  $("fpBtn").addEventListener("click", async () => {
    clearAlert();
    const id = normId($("idNumber").value);
    if (!/^\d{16}$/.test(id)) { $("alert").className = "alert error"; $("alert").textContent = t("fpNidOnly"); return; }
    $("fpBtn").disabled = true;
    try {
      let fbUser = null;
      if (window.db) {
        try {
          const s = await window.db.collection("users").where("nid", "==", id).limit(1).get();
          if (!s.empty) {
            const d = s.docs[0].data();
            fbUser = { uid: s.docs[0].id, nid: d.nid || id, fullName: d.fullName || d.name || "", email: d.email || "", nhrId: d.nhrId || "" };
          }
        } catch (e) {}
      }
      const a = new Uint8Array(16); crypto.getRandomValues(a);
      const pollKey = [...a].map(b => b.toString(16).padStart(2, "0")).join("");
      const r = await fetch("/api/fp/login-ticket", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, pollKey, lang, fbUser })
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { $("alert").className = "alert error"; $("alert").textContent = t(d.error || "serverErr"); return; }

      const hasSensor = window.nhrHasSensor ? await window.nhrHasSensor() : false;
      if (hasSensor) {
        try {
          await window.nhrDirectAssert(d.ticket);
          const sr = await fetch("/api/fp/ticket/" + encodeURIComponent(d.ticket) + "/status?k=" + pollKey);
          const st = await sr.json().catch(() => ({}));
          if (st.status === "approved") { finishLogin(st, id, fbUser); return; }
        } catch (err) {
          if (window.innerWidth > 768) {
            showQrModal(d, id, pollKey, fbUser);
            return;
          }
          $("alert").className = "alert error";
          $("alert").textContent = err.name === "NotAllowedError"
            ? (lang === "bn" ? "ফিঙ্গারপ্রিন্ট যাচাই বাতিল হয়েছে। আবার চেষ্টা করুন।" : "Fingerprint check cancelled. Tap again to retry.")
            : (lang === "bn" ? "এই ডিভাইসে ফিঙ্গারপ্রিন্ট মেলেনি। Settings থেকে এই ডিভাইসের ফিঙ্গারপ্রিন্ট যোগ করুন।" : "Fingerprint didn't match this device. Sign in with password and add this device's fingerprint in Settings.");
          return;
        }
      }
      showQrModal(d, id, pollKey, fbUser);
    } catch (e) {
      $("alert").className = "alert error";
      $("alert").textContent = t("serverDown");
    } finally {
      $("fpBtn").disabled = false;
    }
  });
})();
