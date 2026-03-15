import {
  initializeAppCheck,
  ReCaptchaV3Provider
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app-check.js";
import { app } from "./firestore-config.js";

const APP_CHECK_SITE_KEY = "6Lfv_oosAAAAAKl9IR-Hg29NU2JY7u1VJ-GG22mx";

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
    const message = String(error?.message || "").toLowerCase();

    if (message.includes("already exists")) {
      window.__AETHRA_APP_CHECK_INITIALIZED__ = true;
      return;
    }

    console.error("App Check initialization failed:", error);
  }
}

initAppCheck();
