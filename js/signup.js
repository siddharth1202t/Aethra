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

// Continue URL for verification email
const CONTINUE_URL =
  window.location.hostname.includes("localhost")
    ? "http://localhost:5173/login.html"
    : "https://YOUR_PRODUCTION_DOMAIN/login.html"; // replace with live domain

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

/* ---------------- FORM HELPERS ---------------- */
function setFormMessage(message = "", type = "error") {
  if (!formError) return;

  const safeMessage = String(message || "").trim().slice(0, 300);
  formError.textContent = safeMessage;
  formError.className = `form-error ${safeMessage ? "show" : ""} ${
    type === "success" ? "form-error--success" : "form-error--danger"
  }`;
}

function setFieldError(element, message = "") {
  if (!element) return;
  element.textContent = String(message || "").trim().slice(0, 200);
}

function clearFieldState(input) {
  if (!input) return;
  input.classList.remove("input-invalid", "input-valid");
  input.removeAttribute("aria-invalid");
}

function markFieldValid(input) {
  if (!input) return;
  input.classList.add("input-valid");
  input.classList.remove("input-invalid");
  input.setAttribute("aria-invalid", "false");
}

function markFieldInvalid(input) {
  if (!input) return;
  input.classList.add("input-invalid");
  input.classList.remove("input-valid");
  input.setAttribute("aria-invalid", "true");
}

function setBusyState(isBusy) {
  if (!signupBtn) return;
  if (!signupBtn.dataset.originalText) signupBtn.dataset.originalText = signupBtn.textContent || "Create Account";
  signupBtn.disabled = isBusy;
  signupBtn.textContent = isBusy ? "Creating account..." : signupBtn.dataset.originalText;
}

function clearAllErrors() {
  setFieldError(nameError);
  setFieldError(emailError);
  setFieldError(passwordError);
  setFieldError(confirmPasswordError);
  setFieldError(captchaError);
  setFormMessage();
  clearFieldState(nameInput);
  clearFieldState(emailInput);
  clearFieldState(passwordInput);
  clearFieldState(confirmPasswordInput);
}

function clearSensitiveInputs({ keepEmail = true, keepName = true } = {}) {
  if (!keepName && nameInput) nameInput.value = "";
  if (!keepEmail && emailInput) emailInput.value = "";
  if (passwordInput) passwordInput.value = "";
  if (confirmPasswordInput) confirmPasswordInput.value = "";
}

function now() { return Date.now(); }
function shouldThrottleSubmission() { return now() - lastSubmitAt < SUBMIT_COOLDOWN_MS; }
function recordSubmissionAttempt() { lastSubmitAt = now(); }

/* ---------------- SECURITY LOGGING ---------------- */
async function safeSecurityLog(payload) {
  try { await writeSecurityLog(payload); } 
  catch (error) { console.warn("Security log failed:", error); }
}

function fireAndForgetSecurityLog(payload) {
  safeSecurityLog(payload).catch((error) => console.warn("Async security log failed:", error));
}

/* ---------------- VALIDATION ---------------- */
function normalizeEmail(email) { return String(email || "").trim().toLowerCase().slice(0, EMAIL_MAX_LENGTH); }
function sanitizeUsername(value) { return String(value || "").normalize("NFKC").trim().replace(/[^\w. ]/g, "").replace(/\s+/g, " ").replace(/\.+/g, ".").trim().slice(0, USERNAME_MAX_LENGTH); }
function sanitizePassword(value) { return String(value || "").slice(0, PASSWORD_MAX_LENGTH); }

function isValidEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= EMAIL_MAX_LENGTH; }

function validateName() {
  const name = sanitizeUsername(nameInput?.value || "");
  if (nameInput) nameInput.value = name;
  if (!name) { setFieldError(nameError, "Please enter a username."); markFieldInvalid(nameInput); return false; }
  if (name.length < USERNAME_MIN_LENGTH || name.length > USERNAME_MAX_LENGTH) { setFieldError(nameError, `Username must be ${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} characters.`); markFieldInvalid(nameInput); return false; }
  setFieldError(nameError); markFieldValid(nameInput); return true;
}

function validateEmail() {
  const email = normalizeEmail(emailInput?.value || "");
  if (emailInput) emailInput.value = email;
  if (!email) { setFieldError(emailError, "Please enter your email."); markFieldInvalid(emailInput); return false; }
  if (!isValidEmail(email)) { setFieldError(emailError, "Please enter a valid email."); markFieldInvalid(emailInput); return false; }
  setFieldError(emailError); markFieldValid(emailInput); return true;
}

function validatePassword() {
  const password = sanitizePassword(passwordInput?.value || "");
  if (passwordInput && passwordInput.value !== password) passwordInput.value = password;
  if (!password) { setFieldError(passwordError, "Please enter a password."); markFieldInvalid(passwordInput); return false; }
  if (password.length < PASSWORD_MIN_LENGTH) { setFieldError(passwordError, `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`); markFieldInvalid(passwordInput); return false; }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || /[^A-Za-z0-9]/.test(password)) {
    setFieldError(passwordError, "Password must include uppercase, lowercase, number, and special character."); markFieldInvalid(passwordInput); return false;
  }
  setFieldError(passwordError); markFieldValid(passwordInput); return true;
}

function validateConfirmPassword() {
  const password = passwordInput?.value || "";
  const confirmPassword = confirmPasswordInput?.value || "";
  if (!confirmPassword) { setFieldError(confirmPasswordError, "Please confirm your password."); markFieldInvalid(confirmPasswordInput); return false; }
  if (password !== confirmPassword) { setFieldError(confirmPasswordError, "Passwords do not match."); markFieldInvalid(confirmPasswordInput); return false; }
  setFieldError(confirmPasswordError); markFieldValid(confirmPasswordInput); return true;
}

function validateInputLengths() {
  if ((nameInput?.value || "").length > 100) { setFieldError(nameError, "Username is too long."); markFieldInvalid(nameInput); return false; }
  if ((emailInput?.value || "").length > 200) { setFieldError(emailError, "Email is too long."); markFieldInvalid(emailInput); return false; }
  if ((passwordInput?.value || "").length > PASSWORD_MAX_LENGTH) { setFieldError(passwordError, "Password is too long."); markFieldInvalid(passwordInput); return false; }
  if ((confirmPasswordInput?.value || "").length > PASSWORD_MAX_LENGTH) { setFieldError(confirmPasswordError, "Password is too long."); markFieldInvalid(confirmPasswordInput); return false; }
  return true;
}

/* ---------------- SIGNUP FLOW ---------------- */

async function handleEmailSignup() {
  if (isSubmitting) return;
  if (shouldThrottleSubmission()) { setFormMessage("Please wait a moment before trying again.", "error"); return; }
  recordSubmissionAttempt(); isSubmitting = true;
  clearAllErrors(); setBusyState(true);

  try {
    touchedFields.name = touchedFields.email = touchedFields.password = touchedFields.confirmPassword = true;
    const isValid = validateInputLengths() && validateName() && validateEmail() && validatePassword() && validateConfirmPassword();
    if (!isValid) { fireAndForgetSecurityLog({ type: "signup_validation_failed", message: "Client-side signup validation failed" }); return; }

    const email = normalizeEmail(emailInput?.value || "");
    const password = sanitizePassword(passwordInput?.value || "");
    const name = sanitizeUsername(nameInput?.value || "");

    const credential = await createUserWithEmailAndPassword(auth, email, password);
    const user = credential.user;
    await updateProfile(user, { displayName: name });
    await ensureUserProfile(user);

    await sendEmailVerification(user, { url: CONTINUE_URL });

    fireAndForgetSecurityLog({ type: "signup_success", message: "User account created", email, userId: user.uid });

    clearSensitiveInputs({ keepEmail: true, keepName: true });
    setFormMessage("Account created. Redirecting to verification page...", "success");
    goTo(VERIFY_EMAIL_PAGE);

  } catch (error) {
    console.error("Signup failed:", error);
    setFormMessage(error?.message || "Signup failed. Please try again.", "error");
    clearSensitiveInputs({ keepEmail: true, keepName: true });
  } finally {
    setBusyState(false);
    isSubmitting = false;
  }
}

/* ---------------- EVENTS ---------------- */
if (signupForm) {
  signupForm.addEventListener("submit", async (e) => {
    e.preventDefault(); e.stopPropagation();
    await handleEmailSignup();
  });
}

/* ---------------- PAGE INIT ---------------- */
document.addEventListener("DOMContentLoaded", () => {
  console.log("signup.js loaded");
});
