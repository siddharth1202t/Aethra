import {
  getAuth,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  GoogleAuthProvider,
  reload
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

import { app } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";

const auth = getAuth(app);
const provider = new GoogleAuthProvider();

provider.setCustomParameters({
  prompt: "select_account"
});

function setFormError(message = "") {
  const formError = document.getElementById("formError");
  if (!formError) return;

  formError.textContent = message;
  formError.classList.toggle("show", Boolean(message));
}

function setBusyState(isBusy) {
  const googleBtn = document.getElementById("googleSignInBtn");
  if (googleBtn) {
    googleBtn.disabled = isBusy;
  }
}

function goTo(page) {
  window.location.replace(page);
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
}

function mapGoogleError(error) {
  const code = error?.code || "";
  const message = error?.message || "";

  switch (code) {
    case "auth/popup-closed-by-user":
      return "Google sign-in was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser.";
    case "auth/cancelled-popup-request":
      return "Another sign-in popup was already open.";
    case "auth/unauthorized-domain":
      return "This domain is not authorized in Firebase.";
    case "auth/operation-not-allowed":
      return "Google sign-in is not enabled in Firebase Authentication.";
    case "auth/network-request-failed":
      return "Network error. Please check your connection.";
    default:
      return message || "Google signup failed. Please try again.";
  }
}

async function handleRedirectResultIfAny() {
  try {
    const redirected = await getRedirectResult(auth);

    if (!redirected?.user) return;

    const profileResult = await ensureUserProfile(redirected.user);
    console.log("[Aethra Google] redirect profile result:", profileResult);

    await reload(redirected.user);
    goTo("home.html");
  } catch (error) {
    console.error("[Aethra Google] redirect result failed:", error);
    setFormError(mapGoogleError(error));
  }
}

async function handleGoogleSignup() {
  try {
    setFormError("");
    setBusyState(true);

    console.log("[Aethra Google] button clicked");

    if (isMobileDevice()) {
      console.log("[Aethra Google] using redirect");
      await signInWithRedirect(auth, provider);
      return;
    }

    let credential;

    try {
      console.log("[Aethra Google] trying popup");
      credential = await signInWithPopup(auth, provider);
      console.log("[Aethra Google] popup success");
    } catch (popupError) {
      console.error("[Aethra Google] popup failed:", popupError);

      if (
        popupError?.code === "auth/popup-blocked" ||
        popupError?.code === "auth/cancelled-popup-request"
      ) {
        console.log("[Aethra Google] falling back to redirect");
        await signInWithRedirect(auth, provider);
        return;
      }

      throw popupError;
    }

    const user = credential.user;
    const profileResult = await ensureUserProfile(user);
    console.log("[Aethra Google] popup profile result:", profileResult);

    await reload(user);
    goTo("home.html");
  } catch (error) {
    console.error("[Aethra Google] signup failed:", error);
    setFormError(mapGoogleError(error));
  } finally {
    setBusyState(false);
  }
}

window.aethraGoogleSignup = handleGoogleSignup;

window.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("googleSignInBtn");

  if (!btn) {
    console.error("[Aethra Google] button not found");
    return;
  }

  btn.addEventListener("click", async () => {
    await handleGoogleSignup();
  });

  console.log("[Aethra Google] button listener attached");
});

handleRedirectResultIfAny();
