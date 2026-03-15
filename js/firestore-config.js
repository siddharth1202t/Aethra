import { initializeApp, getApps, getApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

/*
  Firebase initialization for Aethra.
  Ensures the app is created only once even if multiple modules import this file.
*/

const firebaseConfig = {
  apiKey: "AIzaSyCbfEQyTwry7qNOluYqlHUZuU8AF3bkpgQ",
  authDomain: "aethra-web.firebaseapp.com",
  projectId: "aethra-web",
  storageBucket: "aethra-web.firebasestorage.app",
  messagingSenderId: "280560043528",
  appId: "1:280560043528:web:a6c2e485c8da32c9dab3bd"
};

// Prevent multiple Firebase initializations
const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);

// Firestore instance
const db = getFirestore(app);

export { app, db };
