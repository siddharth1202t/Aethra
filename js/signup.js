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
const LOGIN_PAGE = "login.html"; // redirect after email verification
const TURNSTILE_MANAGER_TIMEOUT_MS = 10000;
const REQUEST_TIMEOUT_MS = 10000;
const SUBMIT_COOLDOWN_MS = 2500;

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 20;
const EMAIL_MAX_LENGTH = 120;
const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 128;

/* ---------------- DOM ELEMENTS ---------------- */

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

const goTo = (page) => window.location.replace(page);

/* ---------------- UI HELPERS ---------------- */

const setFormMessage = (message = "", type = "error") => {
  if (!formError) return;

  const safeMessage = String(message).trim().slice(0, 300);
  formError.textContent = safeMessage;
  formError.className = "show";
  formError.classList.toggle("form-error--success", type === "success");
  formError.classList.toggle("form-error--danger", type !== "success");
};

const setFormError = (message = "") => setFormMessage(message, "error");
const setFormSuccess = (message = "") => setFormMessage(message, "success");

const setFieldError = (element, message = "") => {
  if (!element) return;
  element.textContent = String(message).trim().slice(0, 200);
};

const clearFieldState = (input) => {
  if (!input) return;
  input.classList.remove("input-invalid", "input-valid");
  input.removeAttribute("aria-invalid");
};

const markFieldValid = (input) => {
  if (!input) return;
  input.classList.remove("input-invalid");
  input.classList.add("input-valid");
  input.setAttribute("aria-invalid", "false");
};

const markFieldInvalid = (input) => {
  if (!input) return;
  input.classList.remove("input-valid");
  input.classList.add("input-invalid");
  input.setAttribute("aria-invalid", "true");
};

const setBusyState = (isBusy) => {
  if (!signupBtn) return;

  if (!signupBtn.dataset.originalText) {
    signupBtn.dataset.originalText = signupBtn.textContent || "Create Account";
  }

  signupBtn.disabled = Boolean(isBusy);
  signupBtn.textContent = isBusy
    ? "Creating account..."
    : signupBtn.dataset.originalText;

  if (signupForm) signupForm.setAttribute("aria-busy", isBusy ? "true" : "false");
};

const clearAllErrors = () => {
  [nameError, emailError, passwordError, confirmPasswordError, captchaError].forEach(
    (el) => setFieldError(el)
  );
  clearFieldState(nameInput);
  clearFieldState(emailInput);
  clearFieldState(passwordInput);
  clearFieldState(confirmPasswordInput);
  setFormMessage("");
};

const clearSensitiveInputs = ({ keepEmail = true, keepName = true } = {}) => {
  if (!keepName && nameInput) nameInput.value = "";
  if (!keepEmail && emailInput) emailInput.value = "";
  if (passwordInput) passwordInput.value = "";
  if (confirmPasswordInput) confirmPasswordInput.value = "";
};

const now = () => Date.now();

const shouldThrottleSubmission = () => now() - lastSubmitAt < SUBMIT_COOLDOWN_MS;
const recordSubmissionAttempt = () => (lastSubmitAt = now());

/* ---------------- SECURITY LOGGING ---------------- */

const safeSecurityLog = async (payload) => {
  try {
    await writeSecurityLog(payload);
  } catch (error) {
    console.warn("Security log failed:", error);
  }
};

const fireAndForgetSecurityLog = (payload) => safeSecurityLog(payload).catch(() => {});

/* ---------------- FETCH HELPERS ---------------- */

const fetchJson = async (url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      cache: options.cache || "no-store"
    });
    const data = await response.json().catch(() => ({}));
    return { response, data };
  } finally {
    clearTimeout(timeoutId);
  }
};

/* ---------------- CONTAINMENT STATE ---------------- */

const fetchContainmentState = async () => {
  try {
    const { response, data } = await fetchJson("/api/security-containment-state", { method: "GET" });
    return response.ok && data ? data : null;
  } catch {
    return null;
  }
};

const areRegistrationsFrozen = (state) => state?.flags?.freezeRegistrations === true;
const isReadOnlyMode = (state) => state?.flags?.readOnlyMode === true;

/* ---------------- CAPTCHA ---------------- */

const getTurnstileManager = () => window.aethraTurnstile || null;
const getTurnstileToken = () => getTurnstileManager()?.getToken?.() || document.getElementById("turnstileToken")?.value || "";
const resetTurnstile = () => getTurnstileManager()?.reset?.() || (document.getElementById("turnstileToken") && (document.getElementById("turnstileToken").value = ""));

const waitForTurnstileManager = async (timeout = TURNSTILE_MANAGER_TIMEOUT_MS) => {
  const start = now();
  while (now() - start < timeout) {
    const manager = getTurnstileManager();
    if (manager?.getToken) return manager;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error("Turnstile manager did not initialize.");
};

const ensureTurnstileRendered = async () => {
  const manager = await waitForTurnstileManager();
  manager.ensureRendered?.();
  return manager;
};

const getVerifiedTurnstileToken = async () => {
  setFieldError(captchaError, "");
  await ensureTurnstileRendered();
  const token = getTurnstileToken();
  if (!token) {
    setFieldError(captchaError, "Please complete the captcha before creating your account.");
    document.getElementById("turnstile-container")?.scrollIntoView({ behavior: "smooth", block: "center" });
    throw new Error("Captcha missing");
  }
  return token;
};

/* ---------------- VALIDATION ---------------- */

const normalizeEmail = (email) => String(email || "").trim().toLowerCase().slice(0, EMAIL_MAX_LENGTH);
const sanitizeUsername = (value) =>
  String(value || "").normalize("NFKC").trim().replace(/[^\w. ]/g, "").replace(/\s+/g, " ").replace(/\.+/g, ".").trim().slice(0, USERNAME_MAX_LENGTH);
const sanitizePassword = (value) => String(value || "").slice(0, PASSWORD_MAX_LENGTH);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= EMAIL_MAX_LENGTH;

const hasUppercase = (v) => /[A-Z]/.test(v);
const hasLowercase = (v) => /[a-z]/.test(v);
const hasNumber = (v) => /\d/.test(v);
const hasSpecialCharacter = (v) => /[^A-Za-z0-9]/.test(v);
const hasSuspiciousLength = (v, max) => String(v || "").length > max;

/* ---------------- INPUT VALIDATION ---------------- */

const validateName = () => {
  const name = sanitizeUsername(nameInput?.value || "");
  if (nameInput) nameInput.value = name;

  if (!name) { setFieldError(nameError, "Please enter a username."); markFieldInvalid(nameInput); return false; }
  if (name.length < USERNAME_MIN_LENGTH || name.length > USERNAME_MAX_LENGTH) {
    setFieldError(nameError, `Username must be ${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} characters.`); markFieldInvalid(nameInput); return false;
  }
  setFieldError(nameError); markFieldValid(nameInput); return true;
};

const validateEmail = () => {
  const email = normalizeEmail(emailInput?.value || "");
  if (emailInput) emailInput.value = email;

  if (!email) { setFieldError(emailError, "Please enter your email."); markFieldInvalid(emailInput); return false; }
  if (!isValidEmail(email)) { setFieldError(emailError, "Please enter a valid email."); markFieldInvalid(emailInput); return false; }

  setFieldError(emailError); markFieldValid(emailInput); return true;
};

const validatePassword = () => {
  const pw = sanitizePassword(passwordInput?.value || "");
  if (passwordInput && passwordInput.value !== pw) passwordInput.value = pw;

  if (!pw) { setFieldError(passwordError, "Please enter a password."); markFieldInvalid(passwordInput); return false; }
  if (pw.length < PASSWORD_MIN_LENGTH) { setFieldError(passwordError, `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`); markFieldInvalid(passwordInput); return false; }
  if (!hasUppercase(pw) || !hasLowercase(pw) || !hasNumber(pw) || !hasSpecialCharacter(pw)) {
    setFieldError(passwordError, "Password must include uppercase, lowercase, number, and special character."); markFieldInvalid(passwordInput); return false;
  }

  setFieldError(passwordError); markFieldValid(passwordInput); return true;
};

const validateConfirmPassword = () => {
  const pw = passwordInput?.value || "";
  const cpw = confirmPasswordInput?.value || "";

  if (!cpw) { setFieldError(confirmPasswordError, "Please confirm your password."); markFieldInvalid(confirmPasswordInput); return false; }
  if (pw !== cpw) { setFieldError(confirmPasswordError, "Passwords do not match."); markFieldInvalid(confirmPasswordInput); return false; }

  setFieldError(confirmPasswordError); markFieldValid(confirmPasswordInput); return true;
};

const validateInputLengths = () => {
  if (hasSuspiciousLength(nameInput?.value || "", 100)) { setFieldError(nameError, "Username is too long."); markFieldInvalid(nameInput); return false; }
  if (hasSuspiciousLength(emailInput?.value || "", 200)) { setFieldError(emailError, "Email is too long."); markFieldInvalid(emailInput); return false; }
  if (hasSuspiciousLength(passwordInput?.value || "", PASSWORD_MAX_LENGTH)) { setFieldError(passwordError, "Password is too long."); markFieldInvalid(passwordInput); return false; }
  if (hasSuspiciousLength(confirmPasswordInput?.value || "", PASSWORD_MAX_LENGTH)) { setFieldError(confirmPasswordError, "Password is too long."); markFieldInvalid(confirmPasswordInput); return false; }
  return true;
};

/* ---------------- SECURITY CONTEXT ---------------- */

const getClientSecurityContext = () => {
  let behavior = {};
  try { behavior = typeof detectBotBehavior === "function" ? detectBotBehavior() : {}; } catch { behavior = {}; }
  return {
    behavior,
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    timezone: Intl.DateTimeFormat?.().resolvedOptions?.timeZone || "unknown",
    platform: navigator.platform || "",
    webdriver: navigator.webdriver === true
  };
};

/* ---------------- SIGNUP FLOW ---------------- */

const precheckSensitiveAction = async () => {
  const securityContext = getClientSecurityContext();
  const token = await getVerifiedTurnstileToken();
  await fetchJson("/api/verify-turnstile", { method: "POST", body: JSON.stringify({ token, context: securityContext }) });
  return { token, securityContext };
};

const mapSignupError = (error) => {
  const code = error?.code || "";
  switch (code) {
    case "auth/email-already-in-use": setFieldError(emailError, "This email is already in use."); markFieldInvalid(emailInput); return "This email is already in use.";
    case "auth/invalid-email": setFieldError(emailError, "Please enter a valid email."); markFieldInvalid(emailInput); return "Please enter a valid email.";
    case "auth/weak-password": setFieldError(passwordError, "Password does not meet requirements."); markFieldInvalid(passwordInput); return "Password does not meet requirements.";
    case "auth/network-request-failed": return "Network error. Please check your connection.";
    case "auth/too-many-requests": return "Too many attempts. Please wait and try again.";
    case "auth/operation-not-allowed": return "Account registration is temporarily unavailable.";
    default: return "Signup failed. Please try again.";
  }
};

const handleEmailSignup = async () => {
  if (isSubmitting) return;
  if (shouldThrottleSubmission()) { setFormError("Please wait a moment before trying again."); return; }
  recordSubmissionAttempt();
  isSubmitting = true;

  clearAllErrors(); setBusyState(true);

  try {
    Object.keys(touchedFields).forEach(k => touchedFields[k] = true);

    const isValid = validateInputLengths() && validateName() && validateEmail() && validatePassword() && validateConfirmPassword();
    if (!isValid) {
      fireAndForgetSecurityLog({ type: "signup_validation_failed", message: "Client-side signup validation failed", email: normalizeEmail(emailInput?.value || ""), metadata: { hasName: Boolean(nameInput?.value), hasEmail: Boolean(emailInput?.value), passwordLength: (passwordInput?.value || "").length } });
      return;
    }

    if (areRegistrationsFrozen(containmentState) || isReadOnlyMode(containmentState)) {
      setFormError("Account registration is temporarily disabled.");
      fireAndForgetSecurityLog({ type: "signup_blocked_containment", message: "Signup blocked due to containment state", email: normalizeEmail(emailInput?.value || "") });
      return;
    }

    const email = normalizeEmail(emailInput?.value || "");
    const password = sanitizePassword(passwordInput?.value || "");
    const name = sanitizeUsername(nameInput?.value || "");
    const { securityContext } = await precheckSensitiveAction();

    if (securityContext.webdriver) {
      fireAndForgetSecurityLog({ type: "signup_suspicious_automation_signal", message: "Navigator webdriver detected during signup attempt", email, metadata: { behavior: securityContext.behavior || {} } });
    }

    const credential = await createUserWithEmailAndPassword(auth, email, password);
    const user = credential.user;

    await updateProfile(user, { displayName: name });
    await ensureUserProfile(user);

    // ✅ Updated: Send verification email with redirect to login page
    await sendEmailVerification(user, { url: LOGIN_PAGE, handleCodeInApp: true });

    fireAndForgetSecurityLog({ type: "signup_success", message: "User account created", email, userId: user.uid, metadata: { behavior: securityContext.behavior || {}, timezone: securityContext.timezone, platform: securityContext.platform } });

    clearSensitiveInputs({ keepEmail: true, keepName: true });
    setFormSuccess("Account created. Redirecting...");
    goTo(VERIFY_EMAIL_PAGE);

  } catch (error) {
    console.error("Signup failed:", error);
    const email = normalizeEmail(emailInput?.value || "");
    fireAndForgetSecurityLog({ type: "signup_failed", message: error?.code || "signup_failed", email, metadata: { code: error?.code || "unknown", behavior: getClientSecurityContext().behavior || {}, webdriver: getClientSecurityContext().webdriver === true } });
    setFormError(mapSignupError(error));
    clearSensitiveInputs({ keepEmail: true, keepName: true });
    resetTurnstile();
  } finally {
    setBusyState(false);
    isSubmitting = false;
  }
};

/* ---------------- INPUT EVENTS ---------------- */

[nameInput, emailInput, passwordInput, confirmPasswordInput].forEach((input) => {
  if (!input) return;
  input.addEventListener("focus", () => touchedFields[input.id] = true);
  input.addEventListener("blur", () => { touchedFields[input.id] = true; validateName(); validateEmail(); validatePassword(); validateConfirmPassword(); });

  input.addEventListener("input", () => {
    if (input.id === "name" && touchedFields.name) validateName();
    if (input.id === "email" && touchedFields.email) validateEmail();
    if (input.id === "password" && touchedFields.password) { validatePassword(); if (touchedFields.confirmPassword || confirmPasswordInput?.value) validateConfirmPassword(); }
    if (input.id === "confirmPassword" && (touchedFields.confirmPassword || confirmPasswordInput?.value)) validateConfirmPassword();
  });
});

/* ---------------- FORM SUBMIT ---------------- */

signupForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  event.stopPropagation();
  await handleEmailSignup();
});

/* ---------------- PAGE INIT ---------------- */

const initSignupPage = async () => {
  try {
    if (!signupForm || !signupBtn || !nameInput || !emailInput || !passwordInput || !confirmPasswordInput) throw new Error("Required signup elements are missing.");
    containmentState = await fetchContainmentState();
    if (areRegistrationsFrozen(containmentState)) setFormError("Registrations are temporarily disabled.");
    console.log("signup.js loaded");
  } catch (error) {
    console.error("Signup page init failed:", error);
    setFormError("Page failed to load. Please refresh.");
  }
};

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSignupPage, { once: true });
} else {
  initSignupPage();
}
