import {
  initializeApp,
  getApps,
  getApp
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";

import {
  getFirestore
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

/*
  Firebase initialization for Aethra.
  Ensures the app is created only once even if multiple modules import this file.
*/

const firebaseConfig = Object.freeze({
  apiKey: "AIzaSyCbfEQyTwry7qNOluYqlHUZuU8AF3bkpgQ",
  authDomain: "aethra-web.firebaseapp.com",
  projectId: "aethra-web",
  storageBucket: "aethra-web.firebasestorage.app",
  messagingSenderId: "280560043528",
  appId: "1:280560043528:web:a6c2e485c8da32c9dab3bd"
});

let app;
let db;

function initializeFirebase() {
  try {
    if (getApps().length > 0) {
      app = getApp();
    } else {
      app = initializeApp(firebaseConfig);
    }

    db = getFirestore(app);
  } catch (error) {
    console.error("Firebase initialization failed:", error);
    throw new Error("Firebase initialization error");
  }
}

initializeFirebase();

export { app, db };
