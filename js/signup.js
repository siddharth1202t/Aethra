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

function setFormSuccess(message = "") {
  setFormMessage(message, "success");
}

function setFieldError(element, message = "") {
  if (!element) {
    return;
  }

  element.textContent = String(message || "").trim();
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

/* ---------------- CONTAINMENT STATE ---------------- */

async function fetchContainmentState() {
  try {
    const response = await fetch("/api/security-containment-state", {
      method: "GET",
      headers: { "Content-Type": "application/json" },
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

function areRegistrationsFrozen(state) {
  return state?.flags?.freezeRegistrations === true;
}

function isReadOnlyMode(state) {
  return state?.flags?.readOnlyMode === true;
}

/* ---------------- CAPTCHA ---------------- */

async function verifyTurnstileToken(token) {
  const response = await fetch("/api/verify-turnstile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ token })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.success) {
    throw new Error(data?.message || "Captcha verification failed.");
  }
}

function getTurnstileToken() {
  const managerToken =
    window.aethraTurnstile &&
    typeof window.aethraTurnstile.getToken === "function"
      ? window.aethraTurnstile.getToken()
      : "";

  if (managerToken) {
    return managerToken;
  }

  const hiddenTokenInput = document.getElementById("turnstileToken");
  return hiddenTokenInput?.value || "";
}

function resetTurnstile() {
  if (
    window.aethraTurnstile &&
    typeof window.aethraTurnstile.reset === "function"
  ) {
    window.aethraTurnstile.reset();
    return;
  }

  const hiddenTokenInput = document.getElementById("turnstileToken");
  if (hiddenTokenInput) {
    hiddenTokenInput.value = "";
  }
}

async function ensureTurnstileReady(timeout = 12000) {
  const start = Date.now();

  while (Date.now() - start < timeout) {
    const managerReady =
      window.aethraTurnstile &&
      typeof window.aethraTurnstile.getToken === "function";

    if (managerReady) {
      return true;
    }

    await new Promise((resolve) => window.setTimeout(resolve, 150));
  }

  throw new Error("Turnstile manager did not initialize.");
}

/* ---------------- VALIDATION ---------------- */

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function sanitizeUsername(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._ ]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 30);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hasUppercase(value) {
  return /[A-Z]/.test(value);
}

function hasNumber(value) {
  return /\d/.test(value);
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

  if (name.length < 3 || name.length > 20) {
    setFieldError(nameError, "Username must be 3-20 characters.");
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
  const password = passwordInput?.value || "";

  if (!password) {
    setFieldError(passwordError, "Please enter a password.");
    markFieldInvalid(passwordInput);
    return false;
  }

  if (password.length < 8 || !hasUppercase(password) || !hasNumber(password)) {
    setFieldError(
      passwordError,
      "Password must be 8+ chars with uppercase & number."
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
    language: navigator.language || ""
  };
}

/* ---------------- SIGNUP FLOW ---------------- */

async function precheckSensitiveAction(token) {
  if (!token) {
    setFieldError(captchaError, "Please complete the captcha.");
    throw new Error("Captcha missing");
  }

  const securityContext = getClientSecurityContext();
  await verifyTurnstileToken(token);
  return securityContext;
}

function mapSignupError(error) {
  const code = error?.code || "";
  const message = error?.message || "";

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
      setFieldError(passwordError, "Password is too weak.");
      markFieldInvalid(passwordInput);
      return "Password is too weak.";

    case "auth/network-request-failed":
      return "Network error. Please check your connection.";

    case "auth/too-many-requests":
      return "Too many attempts. Please wait and try again.";

    default:
      return message || "Signup failed. Please try again.";
  }
}

async function handleEmailSignup() {
  if (isSubmitting) {
    return;
  }

  isSubmitting = true;
  clearAllErrors();
  setBusyState(true);

  try {
    touchedFields.name = true;
    touchedFields.email = true;
    touchedFields.password = true;
    touchedFields.confirmPassword = true;

    const isValid =
      validateName() &&
      validateEmail() &&
      validatePassword() &&
      validateConfirmPassword();

    if (!isValid) {
      return;
    }

    if (
      areRegistrationsFrozen(containmentState) ||
      isReadOnlyMode(containmentState)
    ) {
      setFormError("Account registration is temporarily disabled.");
      return;
    }

    const email = normalizeEmail(emailInput?.value || "");
    const password = passwordInput?.value || "";
    const name = sanitizeUsername(nameInput?.value || "");
    const token = getTurnstileToken();

    const securityContext = await precheckSensitiveAction(token);

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
        profileResult: profileResult || {}
      }
    });

    goTo(VERIFY_EMAIL_PAGE);
  } catch (error) {
    console.error("Signup failed:", error);

    const email = normalizeEmail(emailInput?.value || "");

    fireAndForgetSecurityLog({
      type: "signup_failed",
      message: error?.message || "Signup failed",
      email,
      metadata: {
        code: error?.code || "unknown"
      }
    });

    setFormError(mapSignupError(error));
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

    await ensureTurnstileReady();
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
