import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  sendPasswordResetEmail,
  reload,
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

const form = document.getElementById("loginForm");
const googleBtn = document.getElementById("googleLoginBtn");
const loginBtn = document.querySelector(".login-btn");
const forgotPasswordBtn = document.getElementById("forgotPasswordBtn");

const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");

const emailError = document.getElementById("emailError");
const passwordError = document.getElementById("passwordError");
const captchaError = document.getElementById("captchaError");
const formError = document.getElementById("formError");

let widgetId = null;
let isSubmitting = false;
let containmentState = null;

function safeString(value, maxLength = 500) {
  return String(value || "").trim().slice(0, maxLength);
}

function goTo(page) {
  window.location.replace(page);
}

function waitForTurnstile(timeout = 10000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    const check = () => {
      if (window.turnstile && typeof window.turnstile.render === "function") {
        resolve();
      } else if (Date.now() - start > timeout) {
        reject(new Error("Turnstile script did not load."));
      } else {
        setTimeout(check, 100);
      }
    };

    check();
  });
}

async function safeSecurityLog(payload) {
  try {
    await writeSecurityLog(payload);
  } catch (error) {
    console.warn("Security log failed:", error);
  }
}

async function fetchContainmentState() {
  try {
    const response = await fetch("/api/security-containment-state", {
      method: "GET",
      headers: {
        "Content-Type": "application/json"
      }
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json().catch(() => null);
    return data && typeof data === "object" ? data : null;
  } catch (error) {
    console.warn("Containment state fetch failed:", error);
    return null;
  }
}

function isReadOnlyMode(state) {
  return state?.flags?.readOnlyMode === true;
}

async function verifyTurnstileToken(token, behavior = {}) {
  const res = await fetch("/api/verify-turnstile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      token,
      behavior,
      sessionId: behavior?.sessionId || ""
    })
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok || !data.success) {
    throw new Error(data?.message || "Captcha verification failed. Please try again.");
  }

  return data;
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
    throw new Error(data?.message || "Login security check failed.");
  }

  return data;
}

function getTurnstileToken() {
  if (widgetId === null || !window.turnstile) return "";
  return window.turnstile.getResponse(widgetId) || "";
}

function resetTurnstile() {
  if (widgetId !== null && window.turnstile) {
    window.turnstile.reset(widgetId);
  }
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(navigator.userAgent);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isLockedMessage(message) {
  return String(message || "").toLowerCase().includes("temporarily locked");
}

function setTemporaryCooldown(button, ms = 3000) {
  if (!button) return;

  const originalText = button.dataset.originalText || button.textContent;
  button.dataset.originalText = originalText;
  button.disabled = true;
  button.textContent = "Please wait...";

  setTimeout(() => {
    button.disabled = false;
    button.textContent = originalText;
  }, ms);
}

function setLoading(button, loadingText = "Please wait...") {
  if (!button) return;

  if (!button.dataset.originalText) {
    button.dataset.originalText = button.textContent;
  }

  button.disabled = true;
  button.textContent = loadingText;
}

function clearLoading(button) {
  if (!button) return;

  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
}

function setButtonsDisabled(disabled) {
  if (loginBtn) loginBtn.disabled = disabled;
  if (googleBtn) googleBtn.disabled = disabled;
  if (forgotPasswordBtn) forgotPasswordBtn.disabled = disabled;
}

function formatRemainingMinutes(ms) {
  const minutes = Math.ceil(Number(ms || 0) / 60000);
  return minutes <= 1 ? "1 minute" : `${minutes} minutes`;
}

function clearFieldState(input, errorEl) {
  if (!input || !errorEl) return;
  errorEl.textContent = "";
  input.classList.remove("input-invalid", "input-valid");
}

function setFieldError(input, errorEl, message) {
  if (!input || !errorEl) return;
  errorEl.textContent = message;
  input.classList.add("input-invalid");
  input.classList.remove("input-valid");
}

function setFieldValid(input, errorEl) {
  if (!input || !errorEl) return;
  errorEl.textContent = "";
  input.classList.remove("input-invalid");
  input.classList.add("input-valid");
}

function showFormError(message) {
  if (!formError) return;
  formError.textContent = message;
  formError.classList.add("show");
  formError.style.background = "rgba(255, 102, 102, 0.12)";
  formError.style.borderColor = "rgba(255, 102, 102, 0.2)";
  formError.style.color = "#ffd0d0";
}

function showFormSuccess(message) {
  if (!formError) return;
  formError.textContent = message;
  formError.classList.add("show");
  formError.style.background = "rgba(125, 255, 179, 0.12)";
  formError.style.borderColor = "rgba(125, 255, 179, 0.2)";
  formError.style.color = "#d4ffe6";
}

function clearFormError() {
  if (!formError) return;
  formError.textContent = "";
  formError.classList.remove("show");
  formError.style.background = "";
  formError.style.borderColor = "";
  formError.style.color = "";
}

function showCaptchaError(message) {
  if (captchaError) {
    captchaError.textContent = message;
  }
}

function clearCaptchaError() {
  if (captchaError) {
    captchaError.textContent = "";
  }
}

function clearAllErrors() {
  clearFieldState(emailInput, emailError);
  clearFieldState(passwordInput, passwordError);
  clearCaptchaError();
  clearFormError();
}

function validateEmail(showUI = true) {
  const email = normalizeEmail(emailInput?.value || "");
  if (emailInput) emailInput.value = email;

  if (!email) {
    if (showUI) setFieldError(emailInput, emailError, "Please enter your email.");
    return false;
  }

  if (!isValidEmail(email)) {
    if (showUI) setFieldError(emailInput, emailError, "Please enter a valid email address.");
    return false;
  }

  if (showUI) setFieldValid(emailInput, emailError);
  return true;
}

function validatePassword(showUI = true) {
  const password = passwordInput?.value || "";

  if (!password) {
    if (showUI) setFieldError(passwordInput, passwordError, "Please enter your password.");
    return false;
  }

  if (showUI) setFieldValid(passwordInput, passwordError);
  return true;
}

function getFriendlyAuthMessage(error) {
  const code = error?.code || "";
  const message = String(error?.message || "");

  if (message.toLowerCase().includes("captcha")) {
    return "Captcha verification failed. Please complete it again.";
  }

  if (isLockedMessage(message)) {
    return message;
  }

  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
      return "Invalid email or password.";
    case "auth/invalid-email":
      return "Please enter a valid email address.";
    case "auth/too-many-requests":
      return "Too many attempts. Please wait and try again later.";
    case "auth/network-request-failed":
      return "Network error. Please check your internet connection.";
    case "auth/popup-closed-by-user":
      return "Google sign-in was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser. Please allow popups or try again.";
    case "auth/cancelled-popup-request":
      return "Another sign-in request is already in progress.";
    case "auth/unauthorized-domain":
      return "This domain is not authorized for Google sign-in.";
    case "auth/operation-not-allowed":
      return "Google sign-in is not enabled right now.";
    case "auth/internal-error":
      return "Google sign-in could not be completed. Please try again.";
    default:
      return safeString(message, 300) || "Login failed. Please try again.";
  }
}

function redirectToHome() {
  goTo("home.html");
}

function redirectToVerifyEmail() {
  goTo("verify-email.html");
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

async function precheckSensitiveAction(email, token, actionLabel = "login_check") {
  const securityContext = getClientSecurityContext();

  const checkResult = await callLoginAttemptApi(email, "check", {
    actionLabel,
    ...securityContext
  });

  if (checkResult?.isLocked) {
    throw new Error(
      `This account is temporarily locked. Please try again in ${formatRemainingMinutes(checkResult.remainingMs)}.`
    );
  }

  if (!token) {
    await safeSecurityLog({
      type: "captcha_missing",
      message: `User attempted ${actionLabel} without captcha`,
      email,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    showCaptchaError("Please complete the captcha first.");
    throw new Error("Captcha missing");
  }

  await verifyTurnstileToken(token, securityContext.behavior || {});
  return securityContext;
}

async function verifyPostGoogleSecurity(user, token, actionLabel) {
  const email = normalizeEmail(user?.email || "google-login");
  const securityContext = getClientSecurityContext();

  const checkResult = await callLoginAttemptApi(email, "check", {
    actionLabel,
    ...securityContext
  });

  if (checkResult?.isLocked) {
    throw new Error(
      `This account is temporarily locked. Please try again in ${formatRemainingMinutes(checkResult.remainingMs)}.`
    );
  }

  if (!token) {
    showCaptchaError("Please complete the captcha first.");
    throw new Error("Captcha missing");
  }

  await verifyTurnstileToken(token, securityContext.behavior || {});
  return securityContext;
}

async function handleRedirectResultIfAny() {
  try {
    const result = await getRedirectResult(auth);

    if (!result?.user) {
      return false;
    }

    const user = result.user;
    const token = getTurnstileToken();

    const securityContext = await verifyPostGoogleSecurity(
      user,
      token,
      "google_login_redirect"
    );

    await ensureUserProfile(user);
    await reload(user);

    await safeSecurityLog({
      type: "google_login_success",
      message: "User logged in with Google via redirect",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    redirectToHome();
    return true;
  } catch (error) {
    const code = error?.code || "";
    const message = String(error?.message || "").toLowerCase();

    console.warn("Redirect sign-in warning:", error);

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
      console.warn("Redirect cleanup sign-out failed:", signOutError);
    }

    await safeSecurityLog({
      type: "google_login_failed",
      message: error?.message || "Google redirect login failed",
      email: ""
    });

    showFormError(getFriendlyAuthMessage(error));
    return false;
  }
}

async function handleEmailLogin() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const isEmailValid = validateEmail(true);
  const isPasswordValid = validatePassword(true);

  if (!isEmailValid || !isPasswordValid) {
    isSubmitting = false;
    setTemporaryCooldown(loginBtn, 1200);
    return;
  }

  const email = normalizeEmail(emailInput?.value || "");
  const password = passwordInput?.value || "";
  const token = getTurnstileToken();

  if (emailInput) {
    emailInput.value = email;
  }

  let securityContext = {};

  try {
    setLoading(loginBtn, "Logging in...");
    clearCaptchaError();

    securityContext = await precheckSensitiveAction(email, token, "email_login");

    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    await ensureUserProfile(user);
    await reload(user);

    await safeSecurityLog({
      type: "login_success",
      message: "User logged in successfully",
      email,
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    if (!user.emailVerified) {
      redirectToVerifyEmail();
      return;
    }

    redirectToHome();
  } catch (error) {
    console.error("Email login failed:", error);

    await safeSecurityLog({
      type: "login_failed",
      message: error?.message || "Unknown login error",
      email,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    const authCode = error?.code || "";
    const isFailedLogin =
      authCode === "auth/invalid-credential" ||
      authCode === "auth/wrong-password" ||
      authCode === "auth/user-not-found" ||
      authCode === "auth/invalid-email";

    if (authCode === "auth/invalid-email") {
      setFieldError(emailInput, emailError, "Please enter a valid email address.");
    }

    if (isLockedMessage(error?.message)) {
      showFormError(error.message);
    } else if (isFailedLogin) {
      try {
        const failStatus = await callLoginAttemptApi(email, "fail", {
          actionLabel: "email_login_fail",
          ...securityContext
        });

        if (failStatus?.isLocked) {
          showFormError(
            `Too many failed attempts. This account is locked for ${formatRemainingMinutes(failStatus.remainingMs)}.`
          );
        } else {
          showFormError(getFriendlyAuthMessage(error));
        }
      } catch (attemptError) {
        console.error("Failed to record login attempt:", attemptError);
        showFormError(getFriendlyAuthMessage(error));
      }
    } else {
      showFormError(getFriendlyAuthMessage(error));
    }

    resetTurnstile();
    setTemporaryCooldown(loginBtn, 3000);
  } finally {
    clearLoading(loginBtn);
    isSubmitting = false;
  }
}

async function handleGoogleLogin() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const token = getTurnstileToken();
  let securityContext = {};
  let signedInUser = null;

  try {
    setLoading(googleBtn, "Please wait...");
    clearCaptchaError();

    if (!token) {
      showCaptchaError("Please complete the captcha first.");
      throw new Error("Captcha missing");
    }

    if (isMobileDevice()) {
      await safeSecurityLog({
        type: "google_login_redirect_started",
        message: "Google redirect sign-in started",
        email: "google-login"
      });

      await signInWithRedirect(auth, provider);
      return;
    }

    let userCredential;

    try {
      userCredential = await signInWithPopup(auth, provider);
    } catch (popupError) {
      if (
        popupError?.code === "auth/popup-blocked" ||
        popupError?.code === "auth/cancelled-popup-request"
      ) {
        await safeSecurityLog({
          type: "google_login_redirect_fallback",
          message: "Popup failed, falling back to redirect",
          email: "google-login"
        });

        await signInWithRedirect(auth, provider);
        return;
      }

      throw popupError;
    }

    const user = userCredential.user;
    signedInUser = user;

    securityContext = await verifyPostGoogleSecurity(user, token, "google_login");

    await ensureUserProfile(user);
    await reload(user);

    await safeSecurityLog({
      type: "google_login_success",
      message: "User logged in with Google",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    redirectToHome();
  } catch (error) {
    console.error("Google login failed:", error);

    if (signedInUser) {
      try {
        await signOut(auth);
      } catch (signOutError) {
        console.warn("Google login cleanup sign-out failed:", signOutError);
      }
    }

    await safeSecurityLog({
      type: "google_login_failed",
      message: error?.message || "Google login failed",
      email: signedInUser?.email || "google-login",
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    showFormError(getFriendlyAuthMessage(error));
    resetTurnstile();
    setTemporaryCooldown(googleBtn, 3000);
  } finally {
    clearLoading(googleBtn);
    isSubmitting = false;
  }
}

async function handleForgotPassword() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  if (isReadOnlyMode(containmentState)) {
    showFormError("This action is temporarily unavailable. Please try again later.");
    isSubmitting = false;
    return;
  }

  const email = normalizeEmail(emailInput?.value || "");
  if (emailInput) {
    emailInput.value = email;
  }

  if (!email) {
    setFieldError(emailInput, emailError, "Enter your email first to reset your password.");
    emailInput?.focus();
    isSubmitting = false;
    return;
  }

  if (!isValidEmail(email)) {
    setFieldError(emailInput, emailError, "Please enter a valid email address.");
    emailInput?.focus();
    isSubmitting = false;
    return;
  }

  const token = getTurnstileToken();
  let securityContext = {};

  try {
    setLoading(forgotPasswordBtn, "Sending...");
    clearCaptchaError();

    securityContext = await precheckSensitiveAction(email, token, "password_reset");

    await sendPasswordResetEmail(auth, email);

    await safeSecurityLog({
      type: "password_reset_requested",
      message: "Password reset requested",
      email,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    showFormSuccess("If this email is registered, a password reset link has been sent.");
  } catch (error) {
    console.error("Password reset failed:", error);

    await safeSecurityLog({
      type: "password_reset_failed",
      message: error?.message || "Password reset failed",
      email,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    if (isLockedMessage(error?.message)) {
      showFormError(error.message);
    } else {
      showFormError("Could not process the password reset request. Please try again.");
    }
  } finally {
    resetTurnstile();
    clearLoading(forgotPasswordBtn);
    isSubmitting = false;
  }
}

async function initTurnstile() {
  await waitForTurnstile();

  const container = document.getElementById("turnstile-container");
  if (!container) {
    throw new Error("Turnstile container not found.");
  }

  container.innerHTML = "";

  widgetId = window.turnstile.render("#turnstile-container", {
    sitekey: "0x4AAAAAACqA_Z98nhvcobbI",
    theme: "dark",
    size: "flexible",
    retry: "auto",
    "refresh-expired": "auto",
    callback() {
      clearCaptchaError();
    },
    "error-callback"() {
      showCaptchaError("Captcha failed to load. Please refresh and try again.");
    },
    "expired-callback"() {
      showCaptchaError("Captcha expired. Please complete it again.");
    }
  });
}

emailInput?.addEventListener("input", () => {
  clearFormError();
  clearCaptchaError();

  if (emailInput.value.trim()) {
    validateEmail(true);
  } else {
    clearFieldState(emailInput, emailError);
  }
});

passwordInput?.addEventListener("input", () => {
  clearFormError();

  if (passwordInput.value.trim()) {
    validatePassword(true);
  } else {
    clearFieldState(passwordInput, passwordError);
  }
});

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await handleEmailLogin();
});

googleBtn?.addEventListener("click", async () => {
  await handleGoogleLogin();
});

forgotPasswordBtn?.addEventListener("click", async () => {
  await handleForgotPassword();
});

window.addEventListener("load", async () => {
  try {
    setButtonsDisabled(true);

    containmentState = await fetchContainmentState();

    await initTurnstile();
    await handleRedirectResultIfAny();
  } catch (error) {
    console.error("Page init failed:", error);
    showFormError("Page failed to load properly. Please refresh and try again.");
  } finally {
    setButtonsDisabled(false);
  }
});
