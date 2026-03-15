import {
  initializeApp,
  getApp,
  getApps
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";

import {
  initializeAppCheck,
  ReCaptchaV3Provider
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app-check.js";

const firebaseConfig = {
  apiKey: "AIzaSyCbfEQyTwry7qNOluYqlHUZuU8AF3bkpgQ",
  authDomain: "aethra-web.firebaseapp.com",
  projectId: "aethra-web",
  storageBucket: "aethra-web.firebasestorage.app",
  messagingSenderId: "280560043528",
  appId: "1:280560043528:web:a6c2e485c8da32c9dab3bd"
};

const APP_CHECK_SITE_KEY = "6Lfv_oosAAAAAKl9IR-Hg29NU2JY7u1VJ-GG22mx";

const app = getApps().length ? getApp() : initializeApp(firebaseConfig);

function initAppCheck() {
  if (window.__AETHRA_APP_CHECK_INITIALIZED__) {
    return;
  }

  try {
    initializeAppCheck(app, {
      provider: new ReCaptchaV3Provider(APP_CHECK_SITE_KEY),
      isTokenAutoRefreshEnabled: true
    });

    window.__AETHRA_APP_CHECK_INITIALIZED__ = true;
  } catch (error) {
    const message = String(error?.message || "");

    if (message.toLowerCase().includes("already exists")) {
      window.__AETHRA_APP_CHECK_INITIALIZED__ = true;
      return;
    }

    console.error("App Check initialization failed:", error);
  }
}

initAppCheck();
