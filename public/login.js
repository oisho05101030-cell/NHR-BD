
document.addEventListener("DOMContentLoaded", () => {
  const loginForm =
    document.getElementById("loginForm") ||
    document.querySelector("form");

  const idInputElement =
    document.getElementById("idNumber") ||
    document.querySelector('input[type="text"]');

  const passwordElement =
    document.getElementById("password") ||
    document.querySelector('input[type="password"]');

  const alertBox = document.getElementById("alert");
  const submitBtn = document.getElementById("submitBtn");

  if (!loginForm || !idInputElement || !passwordElement) {
    console.error("Login form or input fields not found!");
    return;
  }

  function showError(message) {
    if (alertBox) {
      alertBox.className = "alert error";
      alertBox.textContent = message;
    } else {
      alert(message);
    }
  }

  function setLoading(loading) {
    if (submitBtn) {
      submitBtn.disabled = loading;
      submitBtn.classList.toggle("loading", loading);
    }
  }

  function clearError() {
    if (alertBox) {
      alertBox.className = "alert";
      alertBox.textContent = "";
    }
  }

  // Find a user by a field and value
  async function findUser(field, value) {
    const snap = await db.collection("users")
      .where(field, "==", value)
      .limit(1)
      .get();

    if (snap.empty) return null;

    return {
      id: snap.docs[0].id,
      data: snap.docs[0].data()
    };
  }

  // Find doctor using old and new database structures
  async function findDoctor(doctorId) {
    const fields = [
      "doctor.doctorId",
      "doctor.license",
      "bmdc",
      "license"
    ];

    for (const field of fields) {
      const result = await findUser(field, doctorId);
      if (result) return result;
    }

    return null;
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    const id = idInputElement.value.trim();
    const password = passwordElement.value;

    if (!id || !password) {
      showError("অনুগ্রহ করে ID এবং Password প্রদান করুন।");
      return;
    }

    if (
      typeof firebase === "undefined" ||
      typeof auth === "undefined" ||
      typeof db === "undefined"
    ) {
      showError("Firebase initialize হয়নি। Configuration check করুন।");
      return;
    }

    setLoading(true);
    try {
      localStorage.removeItem("nhr_session");
      sessionStorage.removeItem("nhr_session");
      localStorage.removeItem("nhr_user");
      if (auth.currentUser) await auth.signOut();
    } catch (e) {}

    let account = null;
    let targetEmail = "";
    const inputUpper = id.toUpperCase();

    try {
      // ==================================
      // STEP 1: FIND ACCOUNT USING ID
      // ==================================

      if (inputUpper.startsWith("DOC")) {
        // Doctor ID
        account = await findDoctor(inputUpper);

        if (!account) {
          throw new Error("এই Doctor ID দিয়ে কোনো account পাওয়া যায়নি।");
        }

        targetEmail = account.data.email || "";
      }

      else if (inputUpper.startsWith("ADM")) {
  // Admin ID
  targetEmail = `${inputUpper.toLowerCase()}@nhr.bd`;
}

      else if (inputUpper.startsWith("L")) {
        // Facility ID
        targetEmail = `${inputUpper.toLowerCase()}@nhr.bd`;
      }
      else if (inputUpper.startsWith("B")) {
        // Newborn Birth ID
        targetEmail = `${inputUpper.toLowerCase()}@nhr.bd`;
      }

      else {
        // Patient NID
        account = await findUser("nid", id);

        if (!account) {
          throw new Error("এই ID দিয়ে কোনো account পাওয়া যায়নি।");
        }

        targetEmail = account.data.email || "";
      }

      if (!targetEmail) {
        throw new Error("এই account-এর registered email পাওয়া যায়নি।");
      }

      // ==================================
      // STEP 2: FIREBASE PASSWORD CHECK
      // ==================================

      // No Node.js login fallback.
      // Firebase alone verifies the password.

      console.log("SENDING TO FIREBASE:", targetEmail, password);

      const credential = await auth.signInWithEmailAndPassword(
        targetEmail.toLowerCase().trim(),
        password.trim()
      );
      const firebaseUser = credential.user;
      const uid = firebaseUser.uid;

      // ==================================
      // STEP 3: VERIFY FIRESTORE PROFILE
      // ==================================

     // ==================================
      // STEP 3: VERIFY FIRESTORE PROFILE
      // ==================================

      let profile = account ? account.data : null;

      if (!profile) {
        // ১. UID দিয়ে users কালেকশনে খোঁজা
        let userDoc = await db.collection("users").doc(uid).get();
        
        if (!userDoc.exists) {
          userDoc = await db.collection("facilities").doc(inputUpper).get();
        }
        
        
        if (!userDoc.exists) {
          const facSnap = await db.collection("facilities")
            .where("facilityId", "==", inputUpper)
            .limit(1)
            .get();
          if (!facSnap.empty) {
            userDoc = facSnap.docs[0];
          }
        }

        if (userDoc.exists) {
          profile = userDoc.data();
        }
      }

      if (!profile) {
        await auth.signOut();
        throw new Error("এই account-এর user profile পাওয়া যায়নি।");
      }

      // ==================================
      // STEP 4: CHECK ACCOUNT ROLE
      // ==================================

      // ==================================
      // STEP 4: DETERMINE LOGIN ROLE
      // ==================================

      const accountTypes = Array.isArray(profile.accountTypes)
        ? profile.accountTypes.map(x => String(x).toLowerCase())
        : [];

      let loginRole = "";

      if (inputUpper.startsWith("DOC")) {
        loginRole = "doctor";
        const status = String(profile.status || "").trim().toLowerCase();
        if (status !== "verified" && status !== "approved") {
          await auth.signOut();
          throw new Error("আপনার Doctor account এখনো Admin verification পায়নি।");
        }
      }
      else if (inputUpper.startsWith("ADM")) {
        loginRole = "admin";
        if (profile.role !== "admin") {
          await auth.signOut();
          throw new Error("এই account Admin নয়।");
        }
      }
      else if (inputUpper.startsWith("L")) {
        // ছোট বা বড় হাতের L যাই টাইপ করুক, inputUpper.startsWith("L") কন্ডিশন পার হবে
        loginRole = "facility";
      }
     
      else if (inputUpper.startsWith("B")) {
        // Birth ID দিয়ে লগইন করলে Patient পোর্টাল (dashboard.html)-এ নিয়ে যাবে
        loginRole = "patient";
      }
      else {
        if (!accountTypes.includes("patient")) {
          await auth.signOut();
          throw new Error("এই NID দিয়ে Patient account পাওয়া যায়নি।");
        }
        loginRole = "patient";
      }

      // ==================================
      // STEP 5: SAVE SESSION AND REDIRECT
      // ==================================

     const sessionObj = {
        uid: uid,
        role: loginRole,
        type: loginRole,
        email: targetEmail
      };

      localStorage.setItem("nhr_user", JSON.stringify(sessionObj));
      localStorage.setItem("nhr_session", JSON.stringify(sessionObj));

      if (loginRole === "doctor") {
        window.location.replace("doctor.html");
      }

      else if (loginRole === "admin") {
        window.location.replace("admin.html");
      }

      else if (loginRole === "facility") {
        window.location.replace("lab.html");
      }

      else {
        window.location.replace("dashboard.html");
      }

      return;


      await auth.signOut();
      throw new Error("এই account-এর role সঠিক নয়।");

    }

    catch (error) {
      console.error("Login Error:", error);

      // Sign out any partially authenticated session
      if (auth.currentUser) {
        try {
          await auth.signOut();
        } catch (signOutError) {
          console.error("Sign out error:", signOutError);
        }
      }

      if (
        error.code === "auth/wrong-password" ||
        error.code === "auth/invalid-credential"
      ) {
        showError("পাসওয়ার্ড সঠিক নয়। আবার চেষ্টা করুন।");
      }

      else if (error.code === "auth/user-not-found") {
        showError("এই ID-এর Firebase account পাওয়া যায়নি।");
      }

      else if (
        error.code === "permission-denied" ||
        error.code === "firestore/permission-denied"
      ) {
        showError("Firestore permission denied। Security Rules check করুন।");
      }

      else if (
        error.code === "auth/too-many-requests"
      ) {
        showError("অনেকবার ভুল চেষ্টা হয়েছে। কিছুক্ষণ পর আবার চেষ্টা করুন।");
      }

      else {
        showError(error.message || "Login failed। আবার চেষ্টা করুন।");
      }
    }

    finally {
      setLoading(false);
    }
  });
});
