import {
  getAuth,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  GoogleAuthProvider,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserLocalPersistence
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

const HOME_PAGE = "home.html";

const ALLOWED_GOOGLE_AUTH_HOSTS = new Set([
  "aethra-hb2h.vercel.app",
  "aethra-gules.vercel.app"
]);

let googleInProgress = false;
let eventsBound = false;
let authFallbackHandled = false;
let persistenceReadyPromise = null;

function isAllowedGoogleAuthHost() {
  return ALLOWED_GOOGLE_AUTH_HOSTS.has(window.location.hostname);
}

function goTo(page) {
  window.location.replace(page);
}

function redirectSignedInUser(user) {
  if (!user) {
    return false;
  }

  goTo(HOME_PAGE);
  return true;
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(
    navigator.userAgent
  );
}

function withTimeout(promise, ms, message) {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      reject(new Error(message || "Request timed out."));
    }, ms);

    promise
      .then((value) => {
        window.clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        window.clearTimeout(timer);
        reject(error);
      });
  });
}

function getGoogleButton() {
  return document.getElementById("googleSignInBtn");
}

function getFormErrorElement() {
  return document.getElementById("formError");
}

function setFormMessage(message = "", type = "error") {
  const formError = getFormErrorElement();
  if (!formError) {
    return;
  }

  const safeMessage = String(message || "").trim();
  formError.textContent = safeMessage;
  formError.classList.toggle("show", Boolean(safeMessage));
  formError.classList.remove("form-error--danger", "form-error--success");

  if (!safeMessage) {
    return;
  }

  formError.classList.add(
    type === "success" ? "form-error--success" : "form-error--danger"
  );
}

function setFormError(message = "") {
  setFormMessage(message, "error");
}

function clearFormError() {
  setFormMessage("");
}

function setBusyState(isBusy) {
  const googleBtn = getGoogleButton();
  if (!googleBtn) {
    return;
  }

  if (!googleBtn.dataset.originalText) {
    googleBtn.dataset.originalText = googleBtn.textContent.trim();
  }

  googleBtn.disabled = Boolean(isBusy);
  googleBtn.textContent = isBusy
    ? "Please wait..."
    : googleBtn.dataset.originalText;

  googleBtn.classList.toggle("is-loading", Boolean(isBusy));
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
    behavior =
      typeof getSecurityBehaviorPayload === "function"
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
  const response = await fetch("/api/login-attempt", {
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

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.success) {
    throw new Error(data?.message || "Signup security check failed.");
  }

  return data;
}

async function ensureAuthPersistence() {
  if (!persistenceReadyPromise) {
    persistenceReadyPromise = setPersistence(auth, browserLocalPersistence)
      .catch((error) => {
        console.error("Failed to set auth persistence:", error);
        return null;
      });
  }

  return persistenceReadyPromise;
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
    const result = await getRedirectResult(auth);

    if (!result?.user) {
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

    fireAndForgetSecurityLog({
      type: "google_signup_success",
      message: "User signed up with Google via redirect",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    authFallbackHandled = true;
    return redirectSignedInUser(user);
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
      console.warn(
        "[Google Signup] redirect cleanup signOut failed:",
        signOutError
      );
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

async function handleAuthenticatedUserFallback() {
  return new Promise((resolve) => {
    let settled = false;

    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      if (settled || authFallbackHandled) {
        return;
      }

      if (!user) {
        return;
      }

      settled = true;
      authFallbackHandled = true;
      unsubscribe();

      try {
        const securityContext = getClientSecurityContext();

        const checkResult = await callLoginAttemptApi(
          normalizeEmail(user?.email || "google-signup"),
          "check",
          {
            actionLabel: "google_signup_auth_state",
            ...securityContext
          }
        );

        if (checkResult?.isLocked) {
          await signOut(auth);
          setFormError(
            `This account is temporarily locked. Please try again in ${formatRemainingMinutes(checkResult.remainingMs)}.`
          );
          resolve(true);
          return;
        }

        await ensureUserProfile(user);

        fireAndForgetSecurityLog({
          type: "google_signup_success",
          message: "User signed up with Google via auth state fallback",
          email: user.email || "",
          userId: user.uid,
          metadata: {
            behavior: securityContext.behavior || {}
          }
        });

        resolve(redirectSignedInUser(user));
      } catch (error) {
        console.error("[Google Signup] auth-state fallback failed:", error);
        setFormError(mapGoogleError(error));
        resolve(true);
      }
    });

    window.setTimeout(() => {
      if (settled) {
        return;
      }

      settled = true;
      unsubscribe();
      resolve(false);
    }, 5000);
  });
}

async function handleGoogleSignup() {
  if (googleInProgress) {
    return;
  }

  googleInProgress = true;

  let signedInUser = null;
  let securityContext = {};

  try {
    clearFormError();
    setBusyState(true);

    if (!isAllowedGoogleAuthHost()) {
      setFormError(
        "Google sign-in is only available on the official Aethra domains."
      );
      return;
    }

    await ensureAuthPersistence();

    if (isMobileDevice()) {
      fireAndForgetSecurityLog({
        type: "google_signup_redirect_started",
        message: "Google redirect sign-up started",
        email: "google-signup"
      });

      await signInWithRedirect(auth, provider);
      return;
    }

    let credential;

    try {
      credential = await withTimeout(
        signInWithPopup(auth, provider),
        90000,
        "Google sign-up timed out."
      );
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

    fireAndForgetSecurityLog({
      type: "google_signup_success",
      message: "User signed up with Google",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    redirectSignedInUser(user);
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

function bindEvents() {
  if (eventsBound) {
    return;
  }

  const btn = getGoogleButton();
  if (!btn) {
    console.error("[Google Signup] button not found");
    return;
  }

  btn.addEventListener("click", handleGoogleSignup);
  eventsBound = true;
}

async function initGoogleSignup() {
  try {
    bindEvents();
    await ensureAuthPersistence();

    if (auth.currentUser) {
      redirectSignedInUser(auth.currentUser);
      return;
    }

    const handledRedirect = await handleRedirectResultIfAny();

    if (!handledRedirect) {
      await handleAuthenticatedUserFallback();
    }
  } catch (error) {
    console.error("[Google Signup] init failed:", error);
    setFormError("Google sign-up could not be initialized. Please refresh.");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initGoogleSignup, {
    once: true
  });
} else {
  initGoogleSignup();
}
