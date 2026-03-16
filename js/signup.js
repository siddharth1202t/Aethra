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

let widgetId = null;
let isSubmitting = false;
let containmentState = null;

function goTo(page) {
  window.location.replace(page);
}

function waitForTurnstile(timeout = 10000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    const check = () => {
      if (window.turnstile) resolve();
      else if (Date.now() - start > timeout)
        reject(new Error("Turnstile script did not load."));
      else setTimeout(check, 100);
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
  if (!window.turnstile || widgetId === null) return "";
  return window.turnstile.getResponse(widgetId) || "";
}

function resetTurnstile() {
  if (widgetId !== null && window.turnstile) {
    window.turnstile.reset(widgetId);
  }
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
    nameError.textContent = "Username must be 3-20 characters.";
    return false;
  }

  nameError.textContent = "";
  return true;
}

function validateEmail() {
  const email = normalizeEmail(emailInput?.value || "");
  if (emailInput) emailInput.value = email;

  if (!email || !isValidEmail(email)) {
    emailError.textContent = "Please enter a valid email.";
    return false;
  }

  emailError.textContent = "";
  return true;
}

function validatePassword() {
  const password = passwordInput?.value || "";

  if (password.length < 8 || !hasUppercase(password) || !hasNumber(password)) {
    passwordError.textContent =
      "Password must be 8+ chars with uppercase & number.";
    return false;
  }

  passwordError.textContent = "";
  return true;
}

function validateConfirmPassword() {
  if ((passwordInput?.value || "") !== (confirmPasswordInput?.value || "")) {
    confirmPasswordError.textContent = "Passwords do not match.";
    return false;
  }

  confirmPasswordError.textContent = "";
  return true;
}

function clearAllErrors() {
  nameError.textContent = "";
  emailError.textContent = "";
  passwordError.textContent = "";
  confirmPasswordError.textContent = "";
  captchaError.textContent = "";
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

async function precheckSensitiveAction(email, token) {
  if (!token) {
    captchaError.textContent = "Please complete the captcha.";
    throw new Error("Captcha missing");
  }

  const securityContext = getClientSecurityContext();

  await verifyTurnstileToken(token);

  return securityContext;
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
    formError.textContent =
      "Account registration is temporarily disabled.";
    isSubmitting = false;
    return;
  }

  const token = getTurnstileToken();
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  const name = sanitizeUsername(nameInput.value);

  let securityContext = {};

  try {
    signupBtn.disabled = true;
    signupBtn.textContent = "Creating account...";

    securityContext = await precheckSensitiveAction(email, token);

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
      email
    });

    formError.textContent = "Signup failed. Please try again.";

    resetTurnstile();
  } finally {
    signupBtn.disabled = false;
    signupBtn.textContent = "Sign Up";
    isSubmitting = false;
  }
}

/* ---------------- GOOGLE SIGNUP ---------------- */

async function handleGoogleSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  try {
    const token = getTurnstileToken();
    await verifyTurnstileToken(token);

    if (/Android|iPhone|iPad/i.test(navigator.userAgent)) {
      await signInWithRedirect(auth, provider);
      return;
    }

    const credential = await signInWithPopup(auth, provider);

    const user = credential.user;

    await ensureUserProfile(user);
    await reload(user);

    goTo("home.html");
  } catch (error) {
    console.error("Google signup failed:", error);
    formError.textContent = "Google signup failed.";
    resetTurnstile();
  } finally {
    isSubmitting = false;
  }
}

/* ---------------- TURNSTILE ---------------- */

async function initTurnstile() {
  await waitForTurnstile();

  const container = document.getElementById("turnstile-container");

  widgetId = window.turnstile.render("#turnstile-container", {
    sitekey: "0x4AAAAAACqA_Z98nhvcobbI",
    theme: "dark",
    size: "flexible"
  });
}

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
      formError.textContent = "Registrations are temporarily disabled.";
    }

    const redirected = await getRedirectResult(auth);

    if (!redirected) {
      await initTurnstile();
    }
  } catch (error) {
    console.error("Signup page init failed:", error);
    formError.textContent = "Page failed to load. Please refresh.";
  }
});
