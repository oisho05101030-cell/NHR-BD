
const firebaseConfig = {
  apiKey: "AIzaSyCNmHN7WJIL8c5ZIssV3-2wrYGXTFm_qjk",
  authDomain: "nhrbd-c7a6b.firebaseapp.com",
  projectId: "nhrbd-c7a6b",
  storageBucket: "nhrbd-c7a6b.firebasestorage.app",
  messagingSenderId: "343552125804",
  appId: "1:343552125804:web:e7c7a3ab86a925b5b12149",
  measurementId: "G-RV58C37353"
};

if (!firebase.apps.length) {
  firebase.initializeApp(firebaseConfig);
}

window.auth = firebase.auth();
window.db = firebase.firestore();
