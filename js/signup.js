import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  GoogleAuthProvider,
  updateProfile,
  sendEmailVerification,
  reload
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

import { app } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";
import { writeSecurityLog } from "./security-logger.js";
import { detectBotBehavior } from "./bot-detection.js";

const auth = getAuth(app);
const provider = new GoogleAuthProvider();
provider.setCustomParameters({
  prompt: "select_account"
});

const signupForm = document.getElementById("signupForm");
const googleBtn = document.getElementById("googleSignInBtn");
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

/* ---------------- NAVIGATION ---------------- */

function goTo(page) {
  window.location.replace(page);
}

/* ---------------- UI HELPERS ---------------- */

function setFormError(message = "") {
  if (!formError) return;
  formError.textContent = message;
  formError.classList.toggle("show", Boolean(message));
}

function setFieldError(element, message = "") {
  if (!element) return;
  element.textContent = message;
}

function clearFieldState(input) {
  if (!input) return;
  input.classList.remove("input-invalid", "input-valid");
}

function markFieldValid(input) {
  if (!input) return;
  input.classList.remove("input-invalid");
  input.classList.add("input-valid");
}

function markFieldInvalid(input) {
  if (!input) return;
  input.classList.remove("input-valid");
  input.classList.add("input-invalid");
}

function setBusyState(isBusy) {
  if (signupBtn) {
    signupBtn.disabled = isBusy;
    signupBtn.textContent = isBusy ? "Creating account..." : "Create Account";
  }

  if (googleBtn) {
    googleBtn.disabled = isBusy;
  }
}

function clearAllErrors() {
  setFieldError(nameError);
  setFieldError(emailError);
  setFieldError(passwordError);
  setFieldError(confirmPasswordError);
  setFieldError(captchaError);
  setFormError("");

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

/* ---------------- CONTAINMENT STATE ---------------- */

async function fetchContainmentState() {
  try {
    const res = await fetch("/api/security-containment-state", {
      method: "GET",
      headers: { "Content-Type": "application/json" }
    });

    if (!res.ok) return null;

    const data = await res.json().catch(() => null);
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
  const res = await fetch("/api/verify-turnstile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ token })
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok || !data.success) {
    throw new Error(data?.message || "Captcha verification failed.");
  }
}

function getTurnstileToken() {
  const managerToken =
    window.aethraTurnstile &&
    typeof window.aethraTurnstile.getToken === "function"
      ? window.aethraTurnstile.getToken()
      : "";

  if (managerToken) return managerToken;

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
  if (hiddenTokenInput) hiddenTokenInput.value = "";
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

    await new Promise((resolve) => setTimeout(resolve, 150));
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
  if (nameInput) nameInput.value = name;

  if (!name || name.length < 3 || name.length > 20) {
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
  if (emailInput) emailInput.value = email;

  if (!email || !isValidEmail(email)) {
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
    userAgent: navigator.userAgent,
    language: navigator.language
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
      return "This email is already in use.";
    case "auth/invalid-email":
      return "Please enter a valid email.";
    case "auth/weak-password":
      return "Password is too weak.";
    case "auth/popup-closed-by-user":
      return "Google sign-in was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser.";
    case "auth/cancelled-popup-request":
      return "Another sign-in popup was already open.";
    case "auth/unauthorized-domain":
      return "This domain is not authorized in Firebase.";
    case "auth/operation-not-allowed":
      return "Google sign-in is not enabled in Firebase Authentication.";
    case "auth/network-request-failed":
      return "Network error. Please check your connection.";
    default:
      return message || "Signup failed. Please try again.";
  }
}

async function handleEmailSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  if (
    !validateName() ||
    !validateEmail() ||
    !validatePassword() ||
    !validateConfirmPassword()
  ) {
    isSubmitting = false;
    return;
  }

  if (
    areRegistrationsFrozen(containmentState) ||
    isReadOnlyMode(containmentState)
  ) {
    setFormError("Account registration is temporarily disabled.");
    isSubmitting = false;
    return;
  }

  const email = normalizeEmail(emailInput?.value || "");
  const password = passwordInput?.value || "";
  const name = sanitizeUsername(nameInput?.value || "");
  const token = getTurnstileToken();

  try {
    setBusyState(true);

    const securityContext = await precheckSensitiveAction(token);

    const credential = await createUserWithEmailAndPassword(
      auth,
      email,
      password
    );

    const user = credential.user;

    await updateProfile(user, { displayName: name });
    await ensureUserProfile(user);
    await sendEmailVerification(user);
    await reload(user);

    await safeSecurityLog({
      type: "signup_success",
      message: "User account created",
      email,
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    goTo("verify-email.html");
  } catch (error) {
    console.error("Signup failed:", error);

    await safeSecurityLog({
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

/* ---------------- GOOGLE SIGNUP ---------------- */

async function handleGoogleSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  try {
    setBusyState(true);

    if (
      areRegistrationsFrozen(containmentState) ||
      isReadOnlyMode(containmentState)
    ) {
      setFormError("Account registration is temporarily disabled.");
      return;
    }

    const token = getTurnstileToken();

    if (!token) {
      setFieldError(captchaError, "Please complete the captcha.");
      throw new Error("Captcha missing");
    }

    await verifyTurnstileToken(token);

    const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

    if (isMobile) {
      await signInWithRedirect(auth, provider);
      return;
    }

    const credential = await signInWithPopup(auth, provider);
    const user = credential.user;

    await ensureUserProfile(user);
    await reload(user);

    await safeSecurityLog({
      type: "google_signup_success",
      message: "Google signup completed",
      email: user?.email || "",
      userId: user?.uid || ""
    });

    goTo("home.html");
  } catch (error) {
    console.error("Google signup failed:", error);

    await safeSecurityLog({
      type: "google_signup_failed",
      message: error?.message || "Google signup failed",
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

nameInput?.addEventListener("blur", validateName);
emailInput?.addEventListener("blur", validateEmail);
passwordInput?.addEventListener("blur", validatePassword);
confirmPasswordInput?.addEventListener("blur", validateConfirmPassword);

nameInput?.addEventListener("input", () => {
  if (nameError?.textContent) validateName();
});

emailInput?.addEventListener("input", () => {
  if (emailError?.textContent) validateEmail();
});

passwordInput?.addEventListener("input", () => {
  if (passwordError?.textContent) validatePassword();
  if (confirmPasswordInput?.value) validateConfirmPassword();
});

confirmPasswordInput?.addEventListener("input", () => {
  if (confirmPasswordError?.textContent) validateConfirmPassword();
});

/* ---------------- EVENTS ---------------- */

signupForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  await handleEmailSignup();
});

googleBtn?.addEventListener("click", async () => {
  await handleGoogleSignup();
});

/* ---------------- PAGE INIT ---------------- */

window.addEventListener("load", async () => {
  try {
    containmentState = await fetchContainmentState();

    if (areRegistrationsFrozen(containmentState)) {
      setFormError("Registrations are temporarily disabled.");
    }

    const redirected = await getRedirectResult(auth);

    if (redirected?.user) {
      await ensureUserProfile(redirected.user);
      await reload(redirected.user);
      goTo("home.html");
      return;
    }

    await ensureTurnstileReady();
  } catch (error) {
    console.error("Signup page init failed:", error);
    setFormError("Page failed to load. Please refresh.");
  }
});
