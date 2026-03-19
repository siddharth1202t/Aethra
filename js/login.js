import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  sendPasswordResetEmail,
  signOut,
  onAuthStateChanged
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

const TURNSTILE_SITEKEY = "0x4AAAAAACqA_Z98nhvcobbI";
const TURNSTILE_WAIT_INTERVAL_MS = 250;
const TURNSTILE_MAX_WAIT_ATTEMPTS = 60;

const HOME_PAGE = "home.html";
const VERIFY_EMAIL_PAGE = "verify-email.html";

const ALLOWED_GOOGLE_AUTH_HOSTS = new Set([
  "aethra-hb2h.vercel.app",
  "aethra-gules.vercel.app"
]);

const form = document.getElementById("loginForm");
const googleBtn =
  document.getElementById("googleLoginBtn") ||
  document.getElementById("googleSignInBtn");
const loginBtn =
  document.getElementById("loginBtn") || document.querySelector(".login-btn");
const forgotPasswordBtn = document.getElementById("forgotPasswordBtn");

const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");

const emailError = document.getElementById("emailError");
const passwordError = document.getElementById("passwordError");
const captchaError = document.getElementById("captchaError");
const formError = document.getElementById("formError");

const touchedFields = {
  email: false,
  password: false
};

let isSubmitting = false;
let containmentState = null;
let eventsBound = false;
let authFallbackHandled = false;

/* ---------------- BASIC HELPERS ---------------- */

function safeString(value, maxLength = 500) {
  return String(value || "").trim().slice(0, maxLength);
}

function goTo(page) {
  window.location.replace(page);
}

function redirectToHome() {
  goTo(HOME_PAGE);
}

function redirectToVerifyEmail() {
  goTo(VERIFY_EMAIL_PAGE);
}

function redirectSignedInUser(user) {
  if (!user) {
    return false;
  }

  if (!user.emailVerified) {
    redirectToVerifyEmail();
    return true;
  }

  redirectToHome();
  return true;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(
    navigator.userAgent
  );
}

function isAllowedGoogleAuthHost() {
  return ALLOWED_GOOGLE_AUTH_HOSTS.has(window.location.hostname);
}

function isLockedMessage(message) {
  return String(message || "").toLowerCase().includes("temporarily locked");
}

function formatRemainingMinutes(ms) {
  const minutes = Math.ceil(Number(ms || 0) / 60000);
  return minutes <= 1 ? "1 minute" : `${minutes} minutes`;
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

/* ---------------- UI HELPERS ---------------- */

function setButtonsDisabled(disabled) {
  if (loginBtn) loginBtn.disabled = disabled;
  if (googleBtn) googleBtn.disabled = disabled;
  if (forgotPasswordBtn) forgotPasswordBtn.disabled = disabled;
}

function setTemporaryCooldown(button, ms = 3000) {
  if (!button) {
    return;
  }

  const originalText = button.dataset.originalText || button.textContent;
  button.dataset.originalText = originalText;
  button.disabled = true;
  button.textContent = "Please wait...";
  button.classList.add("is-loading");

  window.setTimeout(() => {
    button.disabled = false;
    button.textContent = originalText;
    button.classList.remove("is-loading");
  }, ms);
}

function setLoading(button, loadingText = "Please wait...") {
  if (!button) {
    return;
  }

  if (!button.dataset.originalText) {
    button.dataset.originalText = button.textContent;
  }

  button.disabled = true;
  button.textContent = loadingText;
  button.classList.add("is-loading");
}

function clearLoading(button) {
  if (!button) {
    return;
  }

  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
  button.classList.remove("is-loading");
}

function clearFieldState(input, errorEl) {
  if (!input || !errorEl) {
    return;
  }

  errorEl.textContent = "";
  input.classList.remove("input-invalid", "input-valid");
  input.removeAttribute("aria-invalid");
}

function setFieldError(input, errorEl, message) {
  if (!input || !errorEl) {
    return;
  }

  errorEl.textContent = String(message || "").trim();
  input.classList.add("input-invalid");
  input.classList.remove("input-valid");
  input.setAttribute("aria-invalid", "true");
}

function setFieldValid(input, errorEl) {
  if (!input || !errorEl) {
    return;
  }

  errorEl.textContent = "";
  input.classList.remove("input-invalid");
  input.classList.add("input-valid");
  input.setAttribute("aria-invalid", "false");
}

function setFormMessage(message = "", type = "error") {
  if (!formError) {
    return;
  }

  const safeMessage = String(message || "").trim();

  if (!safeMessage) {
    formError.textContent = "";
    formError.classList.remove(
      "show",
      "form-error--success",
      "form-error--danger"
    );
    return;
  }

  formError.textContent = safeMessage;
  formError.classList.add("show");
  formError.classList.remove("form-error--success", "form-error--danger");
  formError.classList.add(
    type === "success" ? "form-error--success" : "form-error--danger"
  );
}

function showFormError(message) {
  setFormMessage(message, "error");
}

function showFormSuccess(message) {
  setFormMessage(message, "success");
}

function clearFormError() {
  setFormMessage("");
}

function showCaptchaError(message) {
  if (captchaError) {
    captchaError.textContent = String(message || "").trim();
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

/* ---------------- SECURITY LOGGING ---------------- */

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

/* ---------------- SECURITY / API ---------------- */

async function fetchContainmentState() {
  try {
    const response = await fetch("/api/security-containment-state", {
      method: "GET",
      headers: {
        "Content-Type": "application/json"
      },
      cache: "no-store"
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
  const response = await fetch("/api/verify-turnstile", {
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

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.success) {
    throw new Error(
      data?.message || "Captcha verification failed. Please try again."
    );
  }

  return data;
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
    throw new Error(data?.message || "Login security check failed.");
  }

  return data;
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

/* ---------------- TURNSTILE MANAGER ---------------- */

window.aethraLoginTurnstile = {
  widgetId: null,
  token: "",
  rendered: false,
  renderRequested: false,
  isWaitingForApi: false,

  setToken(token) {
    this.token = token || "";

    const hiddenInput = document.getElementById("turnstileToken");
    if (hiddenInput) {
      hiddenInput.value = this.token;
    }

    if (this.token) {
      clearCaptchaError();
    }
  },

  clearToken() {
    this.setToken("");
  },

  getToken() {
    if (this.token) {
      return this.token;
    }

    const hiddenInput = document.getElementById("turnstileToken");
    return hiddenInput?.value || "";
  },

  reset() {
    this.clearToken();

    if (
      this.widgetId !== null &&
      window.turnstile &&
      typeof window.turnstile.reset === "function"
    ) {
      window.turnstile.reset(this.widgetId);
    }
  },

  render() {
    const container = document.getElementById("turnstile-container");

    if (!container || this.rendered) {
      return;
    }

    if (!window.turnstile || typeof window.turnstile.render !== "function") {
      return;
    }

    container.replaceChildren();

    this.widgetId = window.turnstile.render(container, {
      sitekey: TURNSTILE_SITEKEY,
      theme: "dark",
      size: "flexible",
      retry: "auto",
      "refresh-expired": "auto",
      callback: (token) => {
        this.setToken(token);
      },
      "error-callback": () => {
        this.clearToken();
        showCaptchaError("Captcha failed to load. Please refresh and try again.");
      },
      "expired-callback": () => {
        this.clearToken();
        showCaptchaError("Captcha expired. Please complete it again.");
      },
      "timeout-callback": () => {
        this.clearToken();
        showCaptchaError("Captcha timed out. Please try again.");
      }
    });

    this.rendered = true;
    this.renderRequested = true;
    clearCaptchaError();
  },

  waitForApiAndRender() {
    if (this.isWaitingForApi) {
      return;
    }

    this.isWaitingForApi = true;
    let attempts = 0;

    const timer = window.setInterval(() => {
      attempts += 1;

      if (window.turnstile && typeof window.turnstile.render === "function") {
        window.clearInterval(timer);
        this.isWaitingForApi = false;
        this.render();
        return;
      }

      if (attempts >= TURNSTILE_MAX_WAIT_ATTEMPTS) {
        window.clearInterval(timer);
        this.isWaitingForApi = false;
        this.renderRequested = false;
        showCaptchaError("Captcha could not be loaded. Please refresh the page.");
      }
    }, TURNSTILE_WAIT_INTERVAL_MS);
  },

  ensureRendered() {
    if (this.rendered || this.renderRequested) {
      return;
    }

    this.renderRequested = true;

    if (window.turnstile && typeof window.turnstile.render === "function") {
      this.render();
      return;
    }

    this.waitForApiAndRender();
  }
};

function getTurnstileManager() {
  return window.aethraLoginTurnstile || null;
}

function getTurnstileToken() {
  const manager = getTurnstileManager();

  if (manager && typeof manager.getToken === "function") {
    return manager.getToken();
  }

  const hiddenInput = document.getElementById("turnstileToken");
  return hiddenInput?.value || "";
}

function resetTurnstile() {
  const manager = getTurnstileManager();

  if (manager && typeof manager.reset === "function") {
    manager.reset();
    return;
  }

  const hiddenInput = document.getElementById("turnstileToken");
  if (hiddenInput) {
    hiddenInput.value = "";
  }
}

function triggerTurnstileRender() {
  const manager = getTurnstileManager();

  if (manager && typeof manager.ensureRendered === "function") {
    manager.ensureRendered();
  }
}

function bindTurnstileLazyRender() {
  const interactionElements = [emailInput, passwordInput].filter(Boolean);

  interactionElements.forEach((element) => {
    element.addEventListener(
      "focus",
      () => {
        triggerTurnstileRender();
      },
      { once: true }
    );

    element.addEventListener(
      "pointerdown",
      () => {
        triggerTurnstileRender();
      },
      { once: true }
    );
  });

  loginBtn?.addEventListener("pointerdown", triggerTurnstileRender);
  forgotPasswordBtn?.addEventListener("pointerdown", triggerTurnstileRender);
}

async function ensureCaptchaSolved(
  message = "Please complete the captcha first."
) {
  triggerTurnstileRender();

  const token = getTurnstileToken();
  if (token) {
    return token;
  }

  showCaptchaError(message);

  const container = document.getElementById("turnstile-container");
  if (container) {
    container.scrollIntoView({
      behavior: "smooth",
      block: "center"
    });
  }

  throw new Error("Captcha missing");
}

/* ---------------- VALIDATION ---------------- */

function validateEmail(showUI = true) {
  const email = normalizeEmail(emailInput?.value || "");

  if (emailInput) {
    emailInput.value = email;
  }

  if (!email) {
    if (showUI) {
      setFieldError(emailInput, emailError, "Please enter your email.");
    }
    return false;
  }

  if (!isValidEmail(email)) {
    if (showUI) {
      setFieldError(
        emailInput,
        emailError,
        "Please enter a valid email address."
      );
    }
    return false;
  }

  if (showUI) {
    setFieldValid(emailInput, emailError);
  }

  return true;
}

function validatePassword(showUI = true) {
  const password = passwordInput?.value || "";

  if (!password) {
    if (showUI) {
      setFieldError(passwordInput, passwordError, "Please enter your password.");
    }
    return false;
  }

  if (showUI) {
    setFieldValid(passwordInput, passwordError);
  }

  return true;
}

function getFriendlyAuthMessage(error) {
  const code = error?.code || "";
  const message = String(error?.message || "");

  if (message.toLowerCase().includes("captcha")) {
    return "Captcha verification failed. Please complete it again.";
  }

  if (message.toLowerCase().includes("timed out")) {
    return "Google sign-in took too long. Please try again.";
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

async function precheckSensitiveAction(email, actionLabel = "login_check") {
  const securityContext = getClientSecurityContext();

  const checkResult = await callLoginAttemptApi(email, "check", {
    actionLabel,
    ...securityContext
  });

  if (checkResult?.isLocked) {
    throw new Error(
      `This account is temporarily locked. Please try again in ${formatRemainingMinutes(
        checkResult.remainingMs
      )}.`
    );
  }

  const token = await ensureCaptchaSolved("Please complete the captcha first.");
  await verifyTurnstileToken(token, securityContext.behavior || {});

  return securityContext;
}

/* ---------------- GOOGLE REDIRECT HANDLING ---------------- */

async function handleRedirectResultIfAny() {
  try {
    const result = await getRedirectResult(auth);

    if (!result?.user) {
      return false;
    }

    const user = result.user;
    const securityContext = getClientSecurityContext();

    const checkResult = await callLoginAttemptApi(
      normalizeEmail(user?.email || "google-login"),
      "check",
      {
        actionLabel: "google_login_redirect",
        ...securityContext
      }
    );

    if (checkResult?.isLocked) {
      throw new Error(
        `This account is temporarily locked. Please try again in ${formatRemainingMinutes(
          checkResult.remainingMs
        )}.`
      );
    }

    await ensureUserProfile(user);

    fireAndForgetSecurityLog({
      type: "google_login_success",
      message: "User logged in with Google via redirect",
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

    console.warn("[Google Login] Redirect sign-in warning:", error);

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
        "[Google Login] Redirect cleanup sign-out failed:",
        signOutError
      );
    }

    fireAndForgetSecurityLog({
      type: "google_login_failed",
      message: error?.message || "Google redirect login failed",
      email: ""
    });

    showFormError(getFriendlyAuthMessage(error));
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
          normalizeEmail(user?.email || "google-login"),
          "check",
          {
            actionLabel: "google_login_auth_state",
            ...securityContext
          }
        );

        if (checkResult?.isLocked) {
          await signOut(auth);
          showFormError(
            `This account is temporarily locked. Please try again in ${formatRemainingMinutes(
              checkResult.remainingMs
            )}.`
          );
          resolve(true);
          return;
        }

        await ensureUserProfile(user);

        fireAndForgetSecurityLog({
          type: "google_login_success",
          message: "User logged in with Google via auth state fallback",
          email: user.email || "",
          userId: user.uid,
          metadata: {
            behavior: securityContext.behavior || {}
          }
        });

        resolve(redirectSignedInUser(user));
      } catch (error) {
        console.error("[Google Login] auth-state fallback failed:", error);
        showFormError(getFriendlyAuthMessage(error));
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

/* ---------------- EMAIL LOGIN ---------------- */

async function handleEmailLogin() {
  if (isSubmitting) {
    return;
  }

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

  if (emailInput) {
    emailInput.value = email;
  }

  let securityContext = {};

  try {
    setLoading(loginBtn, "Logging in...");
    clearCaptchaError();

    securityContext = await precheckSensitiveAction(email, "email_login");

    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    await ensureUserProfile(user);

    fireAndForgetSecurityLog({
      type: "login_success",
      message: "User logged in successfully",
      email,
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    redirectSignedInUser(user);
  } catch (error) {
    console.error("Email login failed:", error);

    fireAndForgetSecurityLog({
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
            `Too many failed attempts. This account is locked for ${formatRemainingMinutes(
              failStatus.remainingMs
            )}.`
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

/* ---------------- GOOGLE LOGIN ---------------- */

async function handleGoogleLogin() {
  if (isSubmitting) {
    return;
  }

  isSubmitting = true;
  clearAllErrors();

  let securityContext = {};
  let signedInUser = null;

  try {
    setLoading(googleBtn, "Please wait...");
    clearCaptchaError();

    if (!isAllowedGoogleAuthHost()) {
      showFormError("Google sign-in is only available on the official Aethra domains.");
      return;
    }

    if (isMobileDevice()) {
      fireAndForgetSecurityLog({
        type: "google_login_redirect_started",
        message: "Google redirect sign-in started",
        email: "google-login"
      });

      await signInWithRedirect(auth, provider);
      return;
    }

    let userCredential;

    try {
      userCredential = await withTimeout(
        signInWithPopup(auth, provider),
        90000,
        "Google sign-in timed out."
      );
    } catch (popupError) {
      console.error("[Google Login] popup failed", popupError);

      if (
        popupError?.code === "auth/popup-blocked" ||
        popupError?.code === "auth/cancelled-popup-request"
      ) {
        fireAndForgetSecurityLog({
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
    securityContext = getClientSecurityContext();

    const checkResult = await callLoginAttemptApi(
      normalizeEmail(user?.email || "google-login"),
      "check",
      {
        actionLabel: "google_login",
        ...securityContext
      }
    );

    if (checkResult?.isLocked) {
      throw new Error(
        `This account is temporarily locked. Please try again in ${formatRemainingMinutes(
          checkResult.remainingMs
        )}.`
      );
    }

    await ensureUserProfile(user);

    fireAndForgetSecurityLog({
      type: "google_login_success",
      message: "User logged in with Google",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    redirectSignedInUser(user);
  } catch (error) {
    console.error("[Google Login] failed", error);

    if (signedInUser) {
      try {
        await signOut(auth);
      } catch (signOutError) {
        console.warn("[Google Login] cleanup signOut failed:", signOutError);
      }
    }

    fireAndForgetSecurityLog({
      type: "google_login_failed",
      message: error?.message || "Google login failed",
      email: signedInUser?.email || "google-login",
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    showFormError(getFriendlyAuthMessage(error));
    setTemporaryCooldown(googleBtn, 2000);
  } finally {
    clearLoading(googleBtn);
    isSubmitting = false;
  }
}

/* ---------------- FORGOT PASSWORD ---------------- */

async function handleForgotPassword() {
  if (isSubmitting) {
    return;
  }

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
    setFieldError(
      emailInput,
      emailError,
      "Enter your email first to reset your password."
    );
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

  let securityContext = {};

  try {
    setLoading(forgotPasswordBtn, "Sending...");
    clearCaptchaError();

    securityContext = await precheckSensitiveAction(email, "password_reset");

    await sendPasswordResetEmail(auth, email);

    fireAndForgetSecurityLog({
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

    fireAndForgetSecurityLog({
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

/* ---------------- EVENTS ---------------- */

function bindEvents() {
  if (eventsBound) {
    return;
  }

  bindTurnstileLazyRender();

  emailInput?.addEventListener("focus", () => {
    touchedFields.email = true;
  });

  passwordInput?.addEventListener("focus", () => {
    touchedFields.password = true;
  });

  emailInput?.addEventListener("input", () => {
    clearFormError();
    clearCaptchaError();

    if (touchedFields.email) {
      validateEmail(true);
    }
  });

  passwordInput?.addEventListener("input", () => {
    clearFormError();

    if (touchedFields.password) {
      validatePassword(true);
    }
  });

  emailInput?.addEventListener("blur", () => {
    touchedFields.email = true;
    validateEmail(true);
  });

  passwordInput?.addEventListener("blur", () => {
    touchedFields.password = true;
    validatePassword(true);
  });

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    await handleEmailLogin();
  });

  googleBtn?.addEventListener("click", async () => {
    await handleGoogleLogin();
  });

  forgotPasswordBtn?.addEventListener("click", async () => {
    await handleForgotPassword();
  });

  eventsBound = true;
}

/* ---------------- PAGE INIT ---------------- */

async function initLoginPage() {
  try {
    setButtonsDisabled(true);
    bindEvents();

    if (auth.currentUser) {
      redirectSignedInUser(auth.currentUser);
      return;
    }

    containmentState = await fetchContainmentState();

    const handledRedirect = await handleRedirectResultIfAny();

    if (!handledRedirect) {
      await handleAuthenticatedUserFallback();
    }
  } catch (error) {
    console.error("Page init failed:", error);
    showFormError("Page failed to load properly. Please refresh and try again.");
  } finally {
    setButtonsDisabled(false);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initLoginPage, { once: true });
} else {
  initLoginPage();
}
