
(() => {
  function makeNhrId(uid) {
    return "NHR-" + uid
      .replace(/[^a-z0-9]/gi, "")
      .slice(0, 10)
      .toUpperCase();
  }

  window.registerWithFirebase = async function (profile, password) {

    if (
      !window.firebase ||
      !firebase.apps.length ||
      !window.auth ||
      !window.db
    ) {
      throw new Error("Firebase configuration is missing.");
    }

    const email = String(profile.email || "")
      .trim()
      .toLowerCase();

    if (!email) {
      throw new Error("Email is required.");
    }

    let credential = null;

    try {
      // Create Firebase Authentication account
      credential = await auth.createUserWithEmailAndPassword(
        email,
        password
      );

      const user = credential.user;
      const uid = user.uid;

      const nhrId = makeNhrId(uid);

      const doctorId = profile.doctor
        ? String(profile.doctor.license || "").toUpperCase()
        : null;

      // Update user display name
      await user.updateProfile({
        displayName: profile.fullName
      });

      // Prepare user information
      const userData = {
        uid: uid,
        nhrId: nhrId,

        fullName: profile.fullName,
        fatherName: profile.fatherName,
        motherName: profile.motherName,

        dateOfBirth: profile.dob,
        gender: profile.gender,

        nid: profile.nid,
        phone: profile.phone,
        email: email,

        emailVerified: false,

        address: {
          division: profile.division,
          district: profile.district,
          details: profile.address
        },

        role: profile.role,
        accountTypes: profile.accountTypes,

        status: profile.role === "doctor"
          ? "pending"
          : "active",

        consent: profile.consent === true,

        consentAt: firebase.firestore.FieldValue.serverTimestamp(),

        createdAt: firebase.firestore.FieldValue.serverTimestamp(),

        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      };

      // Patient information
      if (profile.accountTypes.includes("patient")) {
        userData.health = {
          bloodGroup: profile.bloodGroup || "",
          emergencyContact: profile.emergency || null
        };
      }

      // Doctor information
      if (profile.doctor) {
        userData.doctor = {
          doctorId: doctorId,
          license: doctorId,
          speciality: profile.doctor.speciality,
          hospital: profile.doctor.hospital,
          verificationStatus: "pending"
        };
      }

      // Save information in Firestore
      await db.collection("users")
        .doc(uid)
        .set(userData);

      // Send email verification
      try {
        await user.sendEmailVerification();
      } catch (error) {
        console.warn("Verification email error:", error);
      }

      return {
        uid: uid,
        nhrId: nhrId,
        doctorId: doctorId,
        doctorPending: !!profile.doctor
      };

    } catch (error) {

      // Delete Auth account if Firestore saving fails
      if (credential && credential.user) {
        try {
          await credential.user.delete();
        } catch (deleteError) {
          console.error(deleteError);
          try {
            await auth.signOut();
          } catch (_) {}
        }
      }

      throw error;
    }
  };

})();
