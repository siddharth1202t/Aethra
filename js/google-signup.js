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

let googleInProgress = false;

function setFormError(message = "") {
  const formError = document.getElementById("formError");
  if (!formError) return;

  formError.textContent = message;
  formError.classList.toggle("show", Boolean(message));
}

function setBusyState(isBusy) {
  const googleBtn = document.getElementById("googleSignInBtn");
  if (!googleBtn) return;

  if (!googleBtn.dataset.originalText) {
    googleBtn.dataset.originalText = googleBtn.textContent.trim();
  }

  googleBtn.disabled = isBusy;
  googleBtn.textContent = isBusy
    ? "Please wait..."
    : googleBtn.dataset.originalText;
}

function goTo(page) {
  window.location.replace(page);
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(navigator.userAgent);
}

function mapGoogleError(error) {
  const code = error?.code || "";
  const message = error?.message || "";

  switch (code) {
    case "auth/popup-closed-by-user":
      return "Google sign-in was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser. Please allow popups and try again.";
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

    await ensureUserProfile(redirected.user);
    await reload(redirected.user);
    goTo("home.html");
  } catch (error) {
    console.error("[Aethra Google] redirect result failed:", error);
    setFormError(mapGoogleError(error));
  }
}

async function handleGoogleSignup() {
  if (googleInProgress) return;
  googleInProgress = true;

  try {
    setFormError("");
    setBusyState(true);

    if (isMobileDevice()) {
      await signInWithRedirect(auth, provider);
      return;
    }

    let credential;

    try {
      credential = await signInWithPopup(auth, provider);
    } catch (popupError) {
      console.error("[Aethra Google] popup failed:", popupError);

      if (
        popupError?.code === "auth/popup-blocked" ||
        popupError?.code === "auth/cancelled-popup-request"
      ) {
        await signInWithRedirect(auth, provider);
        return;
      }

      throw popupError;
    }

    const user = credential.user;

    await ensureUserProfile(user);
    await reload(user);
    goTo("home.html");
  } catch (error) {
    console.error("[Aethra Google] signup failed:", error);
    setFormError(mapGoogleError(error));
  } finally {
    setBusyState(false);
    googleInProgress = false;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("googleSignInBtn");

  if (!btn) {
    console.error("[Aethra Google] button not found");
    return;
  }

  btn.addEventListener("click", handleGoogleSignup);
});

handleRedirectResultIfAny();
