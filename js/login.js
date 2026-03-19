import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  sendPasswordResetEmail,
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

const TURNSTILE_SITEKEY = "0x4AAAAAACqA_Z98nhvcobbI";
const TURNSTILE_WAIT_INTERVAL_MS = 250;
const TURNSTILE_MAX_WAIT_ATTEMPTS = 60;

const HOME_PAGE = "home.html";
const VERIFY_EMAIL_PAGE = "verify-email.html";

const REQUEST_TIMEOUT_MS = 10000;
const GOOGLE_POPUP_TIMEOUT_MS = 90000;

const EMAIL_MAX_LENGTH = 120;
const PASSWORD_MAX_LENGTH = 128;

const EMAIL_LOGIN_COOLDOWN_MS = 2500;
const GOOGLE_LOGIN_COOLDOWN_MS = 2500;
const RESET_COOLDOWN_MS = 3000;

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
let persistenceReadyPromise = null;

let lastEmailLoginAt = 0;
let lastGoogleLoginAt = 0;
let lastResetAt = 0;

/* ---------------- BASIC HELPERS ---------------- */

function safeString(value, maxLength = 500) {
  return String(value || "").trim().slice(0, maxLength);
}

function now() {
  return Date.now();
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
  return String(email || "").trim().toLowerCase().slice(0, EMAIL_MAX_LENGTH);
}

function sanitizePassword(password) {
  return String(password || "").slice(0, PASSWORD_MAX_LENGTH);
}

function isValidEmail(email) {
  return (
    Boolean(email) &&
    email.length <= EMAIL_MAX_LENGTH &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
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

function hasSuspiciousLength(value, max) {
  return String(value || "").length > max;
}

function clearSensitiveInputs({ keepEmail = true } = {}) {
  if (!keepEmail && emailInput) {
    emailInput.value = "";
  }

  if (passwordInput) {
    passwordInput.value = "";
  }
}

function shouldThrottle(lastAt, cooldownMs) {
  return now() - lastAt < cooldownMs;
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

  errorEl.textContent = String(message || "").trim().slice(0, 200);
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

  const safeMessage = String(message || "").trim().slice(0, 300);

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
    captchaError.textContent = String(message || "").trim().slice(0, 200);
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

/* ---------------- FETCH HELPERS ---------------- */

async function fetchJson(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      },
      cache: options.cache || "no-store"
    });

    const data = await response.json().catch(() => ({}));
    return { response, data };
  } finally {
    window.clearTimeout(timeoutId);
  }
}

/* ---------------- SECURITY / API ---------------- */

async function fetchContainmentState() {
  try {
    const { response, data } = await fetchJson(
      "/api/security-containment-state",
      { method: "GET" }
    );

    if (!response.ok) {
      return null;
    }

    return data && typeof data === "object" ? data : null;
  } catch (error) {
    console.warn("Containment state fetch failed:", error);
    return null;
  }
}

function isReadOnlyMode(state) {
  return state?.flags?.readOnlyMode === true;
}

async function verifyTurnstileToken(token, securityContext = {}) {
  const { response, data } = await fetchJson("/api/verify-turnstile", {
    method: "POST",
    body: JSON.stringify({
      token,
      behavior: securityContext.behavior || {},
      sessionId: securityContext?.behavior?.sessionId || "",
      context: {
        language: securityContext.language || "",
        platform: securityContext.platform || "",
        timezone: securityContext.timezone || "unknown",
        webdriver: securityContext.webdriver === true
      }
    })
  });

  if (!response.ok || !data.success) {
    throw new Error(
      data?.message || "Captcha verification failed. Please try again."
    );
  }

  return data;
}

async function callLoginAttemptApi(email, action, extra = {}) {
  const { response, data } = await fetchJson("/api/login-attempt", {
    method: "POST",
    body: JSON.stringify({
      email,
      action,
      ...extra
    })
  });

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
    timezone: Intl.DateTimeFormat?.().resolvedOptions?.().timeZone || "unknown",
    webdriver: navigator.webdriver === true,
    screen: {
      width: window.screen?.width || 0,
      height: window.screen?.height || 0
    }
  };
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
  googleBtn?.addEventListener("pointerdown", triggerTurnstileRender);
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

  if (hasSuspiciousLength(email, EMAIL_MAX_LENGTH) || !isValidEmail(email)) {
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
  const password = sanitizePassword(passwordInput?.value || "");

  if (passwordInput && passwordInput.value !== password) {
    passwordInput.value = password;
  }

  if (!password) {
    if (showUI) {
      setFieldError(passwordInput, passwordError, "Please enter your password.");
    }
    return false;
  }

  if (hasSuspiciousLength(password, PASSWORD_MAX_LENGTH)) {
    if (showUI) {
      setFieldError(passwordInput, passwordError, "Password is too long.");
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
    return "The request took too long. Please try again.";
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
      return "This sign-in method is temporarily unavailable.";
    case "auth/internal-error":
      return "Sign-in could not be completed. Please try again.";
    default:
      return "Login failed. Please try again.";
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
  await verifyTurnstileToken(token, securityContext);

  return securityContext;
}

/* ---------------- GOOGLE REDIRECT HANDLING ---------------- */

async function processAuthenticatedGoogleUser(user, actionLabel, successMessage) {
  const securityContext = getClientSecurityContext();

  const checkResult = await callLoginAttemptApi(
    normalizeEmail(user?.email || "google-login"),
    "check",
    {
      actionLabel,
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
    message: successMessage,
    email: user.email || "",
    userId: user.uid,
    metadata: {
      behavior: securityContext.behavior || {},
      timezone: securityContext.timezone,
      webdriver: securityContext.webdriver === true
    }
  });

  authFallbackHandled = true;
  return redirectSignedInUser(user);
}

async function handleRedirectResultIfAny() {
  try {
    const result = await getRedirectResult(auth);

    if (!result?.user) {
      return false;
    }

    return await processAuthenticatedGoogleUser(
      result.user,
      "google_login_redirect",
      "User logged in with Google via redirect"
    );
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
      unsubscribe();

      try {
        const handled = await processAuthenticatedGoogleUser(
          user,
          "google_login_auth_state",
          "User logged in with Google via auth state fallback"
        );
        resolve(handled);
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
    }, 8000);
  });
}

/* ---------------- EMAIL LOGIN ---------------- */

async function handleEmailLogin() {
  if (isSubmitting) {
    return;
  }

  if (shouldThrottle(lastEmailLoginAt, EMAIL_LOGIN_COOLDOWN_MS)) {
    showFormError("Please wait a moment before trying again.");
    return;
  }

  lastEmailLoginAt = now();
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
  const password = sanitizePassword(passwordInput?.value || "");

  if (emailInput) {
    emailInput.value = email;
  }
  if (passwordInput) {
    passwordInput.value = password;
  }

  let securityContext = {};

  try {
    setLoading(loginBtn, "Logging in...");
    clearCaptchaError();
    await ensureAuthPersistence();

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
        behavior: securityContext.behavior || {},
        timezone: securityContext.timezone,
        webdriver: securityContext.webdriver === true
      }
    });

    clearSensitiveInputs({ keepEmail: true });
    redirectSignedInUser(user);
  } catch (error) {
    console.error("Email login failed:", error);

    fireAndForgetSecurityLog({
      type: "login_failed",
      message: error?.code || "login_failed",
      email,
      metadata: {
        behavior: securityContext.behavior || {},
        timezone: securityContext.timezone,
        webdriver: securityContext.webdriver === true
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

    clearSensitiveInputs({ keepEmail: true });
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

  if (shouldThrottle(lastGoogleLoginAt, GOOGLE_LOGIN_COOLDOWN_MS)) {
    showFormError("Please wait a moment before trying again.");
    return;
  }

  lastGoogleLoginAt = now();
  isSubmitting = true;
  clearAllErrors();

  let signedInUser = null;

  try {
    setLoading(googleBtn, "Please wait...");
    clearCaptchaError();

    if (!isAllowedGoogleAuthHost()) {
      fireAndForgetSecurityLog({
        type: "google_login_blocked_host",
        message: "Google sign-in blocked on unauthorized host",
        email: "",
        metadata: {
          hostname: window.location.hostname
        }
      });

      showFormError("Google sign-in is only available on the official Aethra domains.");
      return;
    }

    await ensureAuthPersistence();

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
        GOOGLE_POPUP_TIMEOUT_MS,
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

    await processAuthenticatedGoogleUser(
      user,
      "google_login",
      "User logged in with Google"
    );
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
      message: error?.code || "google_login_failed",
      email: signedInUser?.email || "google-login"
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

  if (shouldThrottle(lastResetAt, RESET_COOLDOWN_MS)) {
    showFormError("Please wait a moment before trying again.");
    return;
  }

  lastResetAt = now();
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
    await ensureAuthPersistence();

    securityContext = await precheckSensitiveAction(email, "password_reset");

    await sendPasswordResetEmail(auth, email);

    fireAndForgetSecurityLog({
      type: "password_reset_requested",
      message: "Password reset requested",
      email,
      metadata: {
        behavior: securityContext.behavior || {},
        timezone: securityContext.timezone,
        webdriver: securityContext.webdriver === true
      }
    });

    clearSensitiveInputs({ keepEmail: true });
    showFormSuccess("If this email is registered, a password reset link has been sent.");
  } catch (error) {
    console.error("Password reset failed:", error);

    fireAndForgetSecurityLog({
      type: "password_reset_failed",
      message: error?.code || "password_reset_failed",
      email,
      metadata: {
        behavior: securityContext.behavior || {},
        timezone: securityContext.timezone,
        webdriver: securityContext.webdriver === true
      }
    });

    if (isLockedMessage(error?.message)) {
      showFormError(error.message);
    } else {
      showFormError("Could not process the password reset request. Please try again.");
    }

    resetTurnstile();
  } finally {
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
    await ensureAuthPersistence();

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
