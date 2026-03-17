import {
  getAuth,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  GoogleAuthProvider,
  signOut
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

import { app } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";
import { writeSecurityLog } from "./security-logger.js";
import { getSecurityBehaviorPayload } from "./security-client.js";

const auth = getAuth(app);
const provider = new GoogleAuthProvider();

provider.setCustomParameters({
  prompt: "select_account"
});

const ALLOWED_GOOGLE_AUTH_HOSTS = new Set([
  "aethra-hb2h.vercel.app",
  "aethra-gules.vercel.app"
]);

let googleInProgress = false;

function isAllowedGoogleAuthHost() {
  return ALLOWED_GOOGLE_AUTH_HOSTS.has(window.location.hostname);
}

function goTo(page) {
  window.location.replace(page);
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(navigator.userAgent);
}

function withTimeout(promise, ms, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(message || "Request timed out."));
    }, ms);

    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

function setFormError(message = "") {
  const formError = document.getElementById("formError");
  if (!formError) return;

  formError.textContent = message;
  formError.classList.toggle("show", Boolean(message));

  if (message) {
    formError.style.background = "rgba(255, 102, 102, 0.12)";
    formError.style.borderColor = "rgba(255, 102, 102, 0.2)";
    formError.style.color = "#ffd0d0";
  } else {
    formError.style.background = "";
    formError.style.borderColor = "";
    formError.style.color = "";
  }
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

async function safeSecurityLog(payload) {
  try {
    await writeSecurityLog(payload);
  } catch (error) {
    console.warn("Security log failed:", error);
  }
}

function fireAndForgetSecurityLog(payload) {
  safeSecurityLog(payload).catch((error) => {
    console.warn("Async security log failed:", error);
  });
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function formatRemainingMinutes(ms) {
  const minutes = Math.ceil(Number(ms || 0) / 60000);
  return minutes <= 1 ? "1 minute" : `${minutes} minutes`;
}

function getClientSecurityContext() {
  let behavior = {};

  try {
    behavior = typeof getSecurityBehaviorPayload === "function"
      ? getSecurityBehaviorPayload()
      : {};
  } catch (error) {
    console.warn("Security behavior payload failed:", error);
    behavior = {};
  }

  return {
    behavior,
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    platform: navigator.platform || "",
    screen: {
      width: window.screen?.width || 0,
      height: window.screen?.height || 0
    }
  };
}

async function callLoginAttemptApi(email, action, extra = {}) {
  const res = await fetch("/api/login-attempt", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email,
      action,
      ...extra
    })
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok || !data.success) {
    throw new Error(data?.message || "Signup security check failed.");
  }

  return data;
}

function mapGoogleError(error) {
  const code = error?.code || "";
  const message = String(error?.message || "");

  if (message.toLowerCase().includes("timed out")) {
    return "Google sign-up took too long. Please try again.";
  }

  switch (code) {
    case "auth/popup-closed-by-user":
      return "Google sign-up was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser. Please allow popups and try again.";
    case "auth/cancelled-popup-request":
      return "Another sign-in popup was already open.";
    case "auth/unauthorized-domain":
      return "This domain is not authorized for Google sign-in.";
    case "auth/operation-not-allowed":
      return "Google sign-in is not enabled in Firebase Authentication.";
    case "auth/network-request-failed":
      return "Network error. Please check your connection.";
    case "auth/internal-error":
      return "Google sign-up could not be completed. Please try again.";
    default:
      return message || "Google signup failed. Please try again.";
  }
}

async function handleRedirectResultIfAny() {
  try {
    console.log("[Google Signup] handleRedirectResultIfAny:start");
    const result = await getRedirectResult(auth);

    if (!result?.user) {
      console.log("[Google Signup] handleRedirectResultIfAny:no redirect result");
      return false;
    }

    const user = result.user;
    const securityContext = getClientSecurityContext();

    const checkResult = await callLoginAttemptApi(
      normalizeEmail(user?.email || "google-signup"),
      "check",
      {
        actionLabel: "google_signup_redirect",
        ...securityContext
      }
    );

    if (checkResult?.isLocked) {
      throw new Error(
        `This account is temporarily locked. Please try again in ${formatRemainingMinutes(checkResult.remainingMs)}.`
      );
    }

    await ensureUserProfile(user);
    console.log("[Google Signup] handleRedirectResultIfAny:profile ok");

    fireAndForgetSecurityLog({
      type: "google_signup_success",
      message: "User signed up with Google via redirect",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    goTo("home.html");
    return true;
  } catch (error) {
    const code = error?.code || "";
    const message = String(error?.message || "").toLowerCase();

    console.warn("[Google Signup] redirect warning:", error);

    const ignorableRedirectError =
      code === "auth/internal-error" ||
      code === "auth/no-auth-event" ||
      message.includes("no auth event") ||
      message.includes("internal-error");

    if (ignorableRedirectError) {
      return false;
    }

    try {
      await signOut(auth);
    } catch (signOutError) {
      console.warn("[Google Signup] redirect cleanup signOut failed:", signOutError);
    }

    fireAndForgetSecurityLog({
      type: "google_signup_failed",
      message: error?.message || "Google signup redirect failed",
      email: ""
    });

    setFormError(mapGoogleError(error));
    return false;
  }
}

async function handleGoogleSignup() {
  if (googleInProgress) return;
  googleInProgress = true;

  let signedInUser = null;
  let securityContext = {};

  try {
    setFormError("");
    setBusyState(true);
    console.log("[Google Signup] clicked");

    if (!isAllowedGoogleAuthHost()) {
      setFormError("Google sign-in is only available on the official Aethra domains.");
      return;
    }

    if (isMobileDevice()) {
      fireAndForgetSecurityLog({
        type: "google_signup_redirect_started",
        message: "Google redirect sign-up started",
        email: "google-signup"
      });

      console.log("[Google Signup] using redirect");
      await signInWithRedirect(auth, provider);
      return;
    }

    let credential;

    try {
      console.log("[Google Signup] starting popup");
      credential = await withTimeout(
        signInWithPopup(auth, provider),
        90000,
        "Google sign-up timed out."
      );
      console.log("[Google Signup] popup success");
    } catch (popupError) {
      console.error("[Google Signup] popup failed:", popupError);

      if (
        popupError?.code === "auth/popup-blocked" ||
        popupError?.code === "auth/cancelled-popup-request"
      ) {
        fireAndForgetSecurityLog({
          type: "google_signup_redirect_fallback",
          message: "Popup failed, falling back to redirect",
          email: "google-signup"
        });

        console.log("[Google Signup] falling back to redirect");
        await signInWithRedirect(auth, provider);
        return;
      }

      throw popupError;
    }

    const user = credential.user;
    signedInUser = user;
    securityContext = getClientSecurityContext();

    const checkResult = await callLoginAttemptApi(
      normalizeEmail(user?.email || "google-signup"),
      "check",
      {
        actionLabel: "google_signup",
        ...securityContext
      }
    );

    if (checkResult?.isLocked) {
      throw new Error(
        `This account is temporarily locked. Please try again in ${formatRemainingMinutes(checkResult.remainingMs)}.`
      );
    }

    await ensureUserProfile(user);
    console.log("[Google Signup] ensureUserProfile passed");

    fireAndForgetSecurityLog({
      type: "google_signup_success",
      message: "User signed up with Google",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    goTo("home.html");
  } catch (error) {
    console.error("[Google Signup] failed:", error);

    if (signedInUser) {
      try {
        await signOut(auth);
      } catch (signOutError) {
        console.warn("[Google Signup] cleanup signOut failed:", signOutError);
      }
    }

    fireAndForgetSecurityLog({
      type: "google_signup_failed",
      message: error?.message || "Google signup failed",
      email: signedInUser?.email || "google-signup",
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    setFormError(mapGoogleError(error));
  } finally {
    setBusyState(false);
    googleInProgress = false;
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  const btn = document.getElementById("googleSignInBtn");

  if (!btn) {
    console.error("[Google Signup] button not found");
    return;
  }

  btn.addEventListener("click", handleGoogleSignup);

  try {
    await handleRedirectResultIfAny();
  } catch (error) {
    console.error("[Google Signup] redirect init failed:", error);
  }
});
