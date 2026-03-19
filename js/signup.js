import {
  getAuth,
  createUserWithEmailAndPassword,
  updateProfile,
  sendEmailVerification
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

import { app } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";
import { writeSecurityLog } from "./security-logger.js";
import { detectBotBehavior } from "./bot-detection.js";

const auth = getAuth(app);

const VERIFY_EMAIL_PAGE = "verify-email.html";
const TURNSTILE_MANAGER_TIMEOUT_MS = 10000;
const REQUEST_TIMEOUT_MS = 10000;
const SUBMIT_COOLDOWN_MS = 2500;

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 20;
const EMAIL_MAX_LENGTH = 120;
const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 128;

/* ---------------- DOM ---------------- */

const signupForm = document.getElementById("signupForm");
const signupBtn = document.querySelector(".signup-btn");

const nameInput = document.getElementById("name");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const confirmPasswordInput = document.getElementById("confirmPassword");

const nameError = document.getElementById("nameError");
const emailError = document.getElementById("emailError");
const passwordError = document.getElementById("passwordError");
const confirmPasswordError = document.getElementById("confirmPasswordError");
const captchaError = document.getElementById("captchaError");
const formError = document.getElementById("formError");

let isSubmitting = false;
let containmentState = null;
let lastSubmitAt = 0;

const touchedFields = {
  name: false,
  email: false,
  password: false,
  confirmPassword: false
};

/* ---------------- NAVIGATION ---------------- */

function goTo(page) {
  window.location.replace(page);
}

/* ---------------- UI HELPERS ---------------- */

function setFormMessage(message = "", type = "error") {
  if (!formError) {
    return;
  }

  const safeMessage = String(message || "").trim().slice(0, 300);
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

function setFormSuccess(message = "") {
  setFormMessage(message, "success");
}

function setFieldError(element, message = "") {
  if (!element) {
    return;
  }

  element.textContent = String(message || "").trim().slice(0, 200);
}

function clearFieldState(input) {
  if (!input) {
    return;
  }

  input.classList.remove("input-invalid", "input-valid");
  input.removeAttribute("aria-invalid");
}

function markFieldValid(input) {
  if (!input) {
    return;
  }

  input.classList.remove("input-invalid");
  input.classList.add("input-valid");
  input.setAttribute("aria-invalid", "false");
}

function markFieldInvalid(input) {
  if (!input) {
    return;
  }

  input.classList.remove("input-valid");
  input.classList.add("input-invalid");
  input.setAttribute("aria-invalid", "true");
}

function setBusyState(isBusy) {
  if (!signupBtn) {
    return;
  }

  if (!signupBtn.dataset.originalText) {
    signupBtn.dataset.originalText = signupBtn.textContent || "Create Account";
  }

  signupBtn.disabled = Boolean(isBusy);
  signupBtn.textContent = isBusy
    ? "Creating account..."
    : signupBtn.dataset.originalText;

  if (signupForm) {
    signupForm.setAttribute("aria-busy", isBusy ? "true" : "false");
  }
}

function clearAllErrors() {
  setFieldError(nameError);
  setFieldError(emailError);
  setFieldError(passwordError);
  setFieldError(confirmPasswordError);
  setFieldError(captchaError);
  setFormMessage("");

  clearFieldState(nameInput);
  clearFieldState(emailInput);
  clearFieldState(passwordInput);
  clearFieldState(confirmPasswordInput);
}

function clearSensitiveInputs({ keepEmail = true, keepName = true } = {}) {
  if (!keepName && nameInput) {
    nameInput.value = "";
  }

  if (!keepEmail && emailInput) {
    emailInput.value = "";
  }

  if (passwordInput) {
    passwordInput.value = "";
  }

  if (confirmPasswordInput) {
    confirmPasswordInput.value = "";
  }
}

function now() {
  return Date.now();
}

function shouldThrottleSubmission() {
  return now() - lastSubmitAt < SUBMIT_COOLDOWN_MS;
}

function recordSubmissionAttempt() {
  lastSubmitAt = now();
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

/* ---------------- CONTAINMENT STATE ---------------- */

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

function areRegistrationsFrozen(state) {
  return state?.flags?.freezeRegistrations === true;
}

function isReadOnlyMode(state) {
  return state?.flags?.readOnlyMode === true;
}

/* ---------------- CAPTCHA ---------------- */

async function verifyTurnstileToken(token, securityContext = {}) {
  const { response, data } = await fetchJson("/api/verify-turnstile", {
    method: "POST",
    body: JSON.stringify({
      token,
      context: {
        behavior: securityContext.behavior || {},
        language: securityContext.language || "",
        timezone:
          Intl.DateTimeFormat?.().resolvedOptions?.().timeZone || "unknown"
      }
    })
  });

  if (!response.ok || !data.success) {
    throw new Error(data?.message || "Captcha verification failed.");
  }

  return data;
}

function getTurnstileManager() {
  return window.aethraTurnstile || null;
}

function getTurnstileToken() {
  const manager = getTurnstileManager();

  if (manager && typeof manager.getToken === "function") {
    const managerToken = manager.getToken();
    if (managerToken) {
      return managerToken;
    }
  }

  const hiddenTokenInput = document.getElementById("turnstileToken");
  return hiddenTokenInput?.value || "";
}

function resetTurnstile() {
  const manager = getTurnstileManager();

  if (manager && typeof manager.reset === "function") {
    manager.reset();
    return;
  }

  const hiddenTokenInput = document.getElementById("turnstileToken");
  if (hiddenTokenInput) {
    hiddenTokenInput.value = "";
  }
}

async function waitForTurnstileManager(timeout = TURNSTILE_MANAGER_TIMEOUT_MS) {
  const start = now();

  while (now() - start < timeout) {
    const manager = getTurnstileManager();

    if (manager && typeof manager.getToken === "function") {
      return manager;
    }

    await new Promise((resolve) => window.setTimeout(resolve, 150));
  }

  throw new Error("Turnstile manager did not initialize.");
}

async function ensureTurnstileRendered() {
  const manager = await waitForTurnstileManager();

  if (typeof manager.ensureRendered === "function") {
    manager.ensureRendered();
  }

  return manager;
}

async function getVerifiedTurnstileToken() {
  setFieldError(captchaError, "");

  await ensureTurnstileRendered();
  const token = getTurnstileToken();

  if (token) {
    return token;
  }

  setFieldError(
    captchaError,
    "Please complete the captcha before creating your account."
  );

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

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase().slice(0, EMAIL_MAX_LENGTH);
}

function sanitizeUsername(value) {
  return String(value || "")
    .normalize("NFKC")
    .trim()
    .replace(/[^\w. ]/g, "")
    .replace(/\s+/g, " ")
    .replace(/\.+/g, ".")
    .trim()
    .slice(0, USERNAME_MAX_LENGTH);
}

function sanitizePassword(value) {
  return String(value || "").slice(0, PASSWORD_MAX_LENGTH);
}

function isValidEmail(email) {
  if (!email || email.length > EMAIL_MAX_LENGTH) {
    return false;
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hasUppercase(value) {
  return /[A-Z]/.test(value);
}

function hasLowercase(value) {
  return /[a-z]/.test(value);
}

function hasNumber(value) {
  return /\d/.test(value);
}

function hasSpecialCharacter(value) {
  return /[^A-Za-z0-9]/.test(value);
}

function hasSuspiciousLength(value, max) {
  return String(value || "").length > max;
}

function validateName() {
  const name = sanitizeUsername(nameInput?.value || "");

  if (nameInput) {
    nameInput.value = name;
  }

  if (!name) {
    setFieldError(nameError, "Please enter a username.");
    markFieldInvalid(nameInput);
    return false;
  }

  if (name.length < USERNAME_MIN_LENGTH || name.length > USERNAME_MAX_LENGTH) {
    setFieldError(
      nameError,
      `Username must be ${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} characters.`
    );
    markFieldInvalid(nameInput);
    return false;
  }

  setFieldError(nameError);
  markFieldValid(nameInput);
  return true;
}

function validateEmail() {
  const email = normalizeEmail(emailInput?.value || "");

  if (emailInput) {
    emailInput.value = email;
  }

  if (!email) {
    setFieldError(emailError, "Please enter your email.");
    markFieldInvalid(emailInput);
    return false;
  }

  if (!isValidEmail(email)) {
    setFieldError(emailError, "Please enter a valid email.");
    markFieldInvalid(emailInput);
    return false;
  }

  setFieldError(emailError);
  markFieldValid(emailInput);
  return true;
}

function validatePassword() {
  const password = sanitizePassword(passwordInput?.value || "");

  if (passwordInput && passwordInput.value !== password) {
    passwordInput.value = password;
  }

  if (!password) {
    setFieldError(passwordError, "Please enter a password.");
    markFieldInvalid(passwordInput);
    return false;
  }

  if (password.length < PASSWORD_MIN_LENGTH) {
    setFieldError(
      passwordError,
      `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`
    );
    markFieldInvalid(passwordInput);
    return false;
  }

  if (
    !hasUppercase(password) ||
    !hasLowercase(password) ||
    !hasNumber(password) ||
    !hasSpecialCharacter(password)
  ) {
    setFieldError(
      passwordError,
      "Password must include uppercase, lowercase, number, and special character."
    );
    markFieldInvalid(passwordInput);
    return false;
  }

  setFieldError(passwordError);
  markFieldValid(passwordInput);
  return true;
}

function validateConfirmPassword() {
  const password = passwordInput?.value || "";
  const confirmPassword = confirmPasswordInput?.value || "";

  if (!confirmPassword) {
    setFieldError(confirmPasswordError, "Please confirm your password.");
    markFieldInvalid(confirmPasswordInput);
    return false;
  }

  if (password !== confirmPassword) {
    setFieldError(confirmPasswordError, "Passwords do not match.");
    markFieldInvalid(confirmPasswordInput);
    return false;
  }

  setFieldError(confirmPasswordError);
  markFieldValid(confirmPasswordInput);
  return true;
}

function validateInputLengths() {
  if (hasSuspiciousLength(nameInput?.value || "", 100)) {
    setFieldError(nameError, "Username is too long.");
    markFieldInvalid(nameInput);
    return false;
  }

  if (hasSuspiciousLength(emailInput?.value || "", 200)) {
    setFieldError(emailError, "Email is too long.");
    markFieldInvalid(emailInput);
    return false;
  }

  if (hasSuspiciousLength(passwordInput?.value || "", PASSWORD_MAX_LENGTH)) {
    setFieldError(passwordError, "Password is too long.");
    markFieldInvalid(passwordInput);
    return false;
  }

  if (
    hasSuspiciousLength(
      confirmPasswordInput?.value || "",
      PASSWORD_MAX_LENGTH
    )
  ) {
    setFieldError(confirmPasswordError, "Password is too long.");
    markFieldInvalid(confirmPasswordInput);
    return false;
  }

  return true;
}

/* ---------------- SECURITY CONTEXT ---------------- */

function getClientSecurityContext() {
  let behavior = {};

  try {
    behavior =
      typeof detectBotBehavior === "function" ? detectBotBehavior() : {};
  } catch {
    behavior = {};
  }

  return {
    behavior,
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    timezone: Intl.DateTimeFormat?.().resolvedOptions?.().timeZone || "unknown",
    platform: navigator.platform || "",
    webdriver: navigator.webdriver === true
  };
}

/* ---------------- SIGNUP FLOW ---------------- */

async function precheckSensitiveAction() {
  const securityContext = getClientSecurityContext();
  const token = await getVerifiedTurnstileToken();

  await verifyTurnstileToken(token, securityContext);

  return { token, securityContext };
}

function mapSignupError(error) {
  const code = error?.code || "";

  switch (code) {
    case "auth/email-already-in-use":
      setFieldError(emailError, "This email is already in use.");
      markFieldInvalid(emailInput);
      return "This email is already in use.";

    case "auth/invalid-email":
      setFieldError(emailError, "Please enter a valid email.");
      markFieldInvalid(emailInput);
      return "Please enter a valid email.";

    case "auth/weak-password":
      setFieldError(passwordError, "Password does not meet requirements.");
      markFieldInvalid(passwordInput);
      return "Password does not meet requirements.";

    case "auth/network-request-failed":
      return "Network error. Please check your connection.";

    case "auth/too-many-requests":
      return "Too many attempts. Please wait and try again.";

    case "auth/operation-not-allowed":
      return "Account registration is temporarily unavailable.";

    default:
      return "Signup failed. Please try again.";
  }
}

async function handleEmailSignup() {
  if (isSubmitting) {
    return;
  }

  if (shouldThrottleSubmission()) {
    setFormError("Please wait a moment before trying again.");
    return;
  }

  recordSubmissionAttempt();
  isSubmitting = true;

  clearAllErrors();
  setBusyState(true);

  try {
    touchedFields.name = true;
    touchedFields.email = true;
    touchedFields.password = true;
    touchedFields.confirmPassword = true;

    const isValid =
      validateInputLengths() &&
      validateName() &&
      validateEmail() &&
      validatePassword() &&
      validateConfirmPassword();

    if (!isValid) {
      fireAndForgetSecurityLog({
        type: "signup_validation_failed",
        message: "Client-side signup validation failed",
        email: normalizeEmail(emailInput?.value || ""),
        metadata: {
          hasName: Boolean(nameInput?.value),
          hasEmail: Boolean(emailInput?.value),
          passwordLength: (passwordInput?.value || "").length
        }
      });
      return;
    }

    if (
      areRegistrationsFrozen(containmentState) ||
      isReadOnlyMode(containmentState)
    ) {
      setFormError("Account registration is temporarily disabled.");
      fireAndForgetSecurityLog({
        type: "signup_blocked_containment",
        message: "Signup blocked due to containment state",
        email: normalizeEmail(emailInput?.value || "")
      });
      return;
    }

    const email = normalizeEmail(emailInput?.value || "");
    const password = sanitizePassword(passwordInput?.value || "");
    const name = sanitizeUsername(nameInput?.value || "");

    const { securityContext } = await precheckSensitiveAction();

    if (securityContext.webdriver) {
      fireAndForgetSecurityLog({
        type: "signup_suspicious_automation_signal",
        message: "Navigator webdriver detected during signup attempt",
        email,
        metadata: {
          behavior: securityContext.behavior || {}
        }
      });
    }

    const credential = await createUserWithEmailAndPassword(
      auth,
      email,
      password
    );

    const user = credential.user;

    await updateProfile(user, { displayName: name });
    const profileResult = await ensureUserProfile(user);
    await sendEmailVerification(user);

    fireAndForgetSecurityLog({
      type: "signup_success",
      message: "User account created",
      email,
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {},
        profileResult: profileResult || {},
        timezone: securityContext.timezone,
        platform: securityContext.platform
      }
    });

    clearSensitiveInputs({ keepEmail: true, keepName: true });
    setFormSuccess("Account created. Redirecting...");
    goTo(VERIFY_EMAIL_PAGE);
  } catch (error) {
    console.error("Signup failed:", error);

    const email = normalizeEmail(emailInput?.value || "");
    const securityContext = getClientSecurityContext();

    fireAndForgetSecurityLog({
      type: "signup_failed",
      message: error?.code || "signup_failed",
      email,
      metadata: {
        code: error?.code || "unknown",
        behavior: securityContext.behavior || {},
        webdriver: securityContext.webdriver === true
      }
    });

    setFormError(mapSignupError(error));
    clearSensitiveInputs({ keepEmail: true, keepName: true });
    resetTurnstile();
  } finally {
    setBusyState(false);
    isSubmitting = false;
  }
}

/* ---------------- LIVE VALIDATION ---------------- */

nameInput?.addEventListener("focus", () => {
  touchedFields.name = true;
});

emailInput?.addEventListener("focus", () => {
  touchedFields.email = true;
});

passwordInput?.addEventListener("focus", () => {
  touchedFields.password = true;
});

confirmPasswordInput?.addEventListener("focus", () => {
  touchedFields.confirmPassword = true;
});

nameInput?.addEventListener("input", () => {
  if (touchedFields.name) {
    validateName();
  }
});

emailInput?.addEventListener("input", () => {
  if (touchedFields.email) {
    validateEmail();
  }
});

passwordInput?.addEventListener("input", () => {
  if (touchedFields.password) {
    validatePassword();
  }

  if (touchedFields.confirmPassword || confirmPasswordInput?.value) {
    validateConfirmPassword();
  }
});

confirmPasswordInput?.addEventListener("input", () => {
  if (touchedFields.confirmPassword || confirmPasswordInput?.value) {
    validateConfirmPassword();
  }
});

nameInput?.addEventListener("blur", () => {
  touchedFields.name = true;
  validateName();
});

emailInput?.addEventListener("blur", () => {
  touchedFields.email = true;
  validateEmail();
});

passwordInput?.addEventListener("blur", () => {
  touchedFields.password = true;
  validatePassword();
});

confirmPasswordInput?.addEventListener("blur", () => {
  touchedFields.confirmPassword = true;
  validateConfirmPassword();
});

/* ---------------- EVENTS ---------------- */

if (signupForm) {
  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();

    if (isSubmitting) {
      return;
    }

    await handleEmailSignup();
  });
} else {
  console.error("signupForm not found");
}

/* ---------------- PAGE INIT ---------------- */

async function initSignupPage() {
  try {
    if (
      !signupForm ||
      !signupBtn ||
      !nameInput ||
      !emailInput ||
      !passwordInput ||
      !confirmPasswordInput
    ) {
      throw new Error("Required signup elements are missing.");
    }

    containmentState = await fetchContainmentState();

    if (areRegistrationsFrozen(containmentState)) {
      setFormError("Registrations are temporarily disabled.");
    }

    console.log("signup.js loaded");
  } catch (error) {
    console.error("Signup page init failed:", error);
    setFormError("Page failed to load. Please refresh.");
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSignupPage, { once: true });
} else {
  initSignupPage();
}
