import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  GoogleAuthProvider,
  updateProfile,
  sendEmailVerification
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

import { app } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";

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

async function verifyTurnstileToken(token) {
  const res = await fetch("/api/verify-turnstile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ token })
  });

  const data = await res.json();

  if (!res.ok || !data.success) {
    throw new Error("Captcha verification failed.");
  }
}

function getTurnstileToken() {
  if (!window.turnstile || widgetId === null) return "";
  return window.turnstile.getResponse(widgetId);
}

function resetTurnstile() {
  if (widgetId !== null && window.turnstile) {
    window.turnstile.reset(widgetId);
  }
}

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(
    navigator.userAgent
  );
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function sanitizeUsername(value) {
  return value
    .trim()
    .replace(/[^a-zA-Z0-9._ ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function setLoading(button, text = "Please wait...") {
  if (!button) return;
  button.dataset.originalText ??= button.textContent;
  button.disabled = true;
  button.textContent = text;
}

function clearLoading(button) {
  if (!button) return;
  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
}

function setTemporaryCooldown(button, ms = 3000) {
  if (!button) return;

  const original = button.dataset.originalText || button.textContent;

  button.dataset.originalText = original;
  button.disabled = true;
  button.textContent = "Please wait...";

  setTimeout(() => {
    button.disabled = false;
    button.textContent = original;
  }, ms);
}

function clearFormError() {
  if (!formError) return;
  formError.textContent = "";
  formError.classList.remove("show");
}

function showFormError(message) {
  if (!formError) return;
  formError.textContent = message;
  formError.classList.add("show");
}

function showCaptchaError(message) {
  if (captchaError) captchaError.textContent = message;
}

function clearCaptchaError() {
  if (captchaError) captchaError.textContent = "";
}

function clearAllErrors() {
  clearCaptchaError();
  clearFormError();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hasUppercase(v) {
  return /[A-Z]/.test(v);
}

function hasNumber(v) {
  return /\d/.test(v);
}

function validateName() {
  const name = sanitizeUsername(nameInput.value);
  nameInput.value = name;

  if (!name || name.length < 3 || name.length > 20) {
    nameError.textContent = "Username must be 3-20 characters.";
    return false;
  }

  nameError.textContent = "";
  return true;
}

function validateEmail() {
  const email = normalizeEmail(emailInput.value);
  emailInput.value = email;

  if (!isValidEmail(email)) {
    emailError.textContent = "Please enter a valid email address.";
    return false;
  }

  emailError.textContent = "";
  return true;
}

function validatePassword() {
  const password = passwordInput.value;

  if (
    password.length < 8 ||
    !hasUppercase(password) ||
    !hasNumber(password)
  ) {
    passwordError.textContent =
      "Password must be 8+ chars, include uppercase & number.";
    return false;
  }

  passwordError.textContent = "";
  return true;
}

function validateConfirmPassword() {
  if (passwordInput.value !== confirmPasswordInput.value) {
    confirmPasswordError.textContent = "Passwords do not match.";
    return false;
  }

  confirmPasswordError.textContent = "";
  return true;
}

async function handleRedirectResult() {
  try {
    const result = await getRedirectResult(auth);

    if (result?.user) {
      await ensureUserProfile(result.user);
      goTo("home.html");
      return true;
    }

    return false;
  } catch (error) {
    console.error(error);
    showFormError("Google signup failed.");
    return false;
  }
}

async function handleEmailSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const valid =
    validateName() &&
    validateEmail() &&
    validatePassword() &&
    validateConfirmPassword();

  const token = getTurnstileToken();

  if (!valid || !token) {
    if (!token) showCaptchaError("Please complete captcha.");
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  const name = sanitizeUsername(nameInput.value);
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;

  try {
    setLoading(signupBtn, "Creating account...");
    await verifyTurnstileToken(token);

    const cred = await createUserWithEmailAndPassword(auth, email, password);

    await updateProfile(cred.user, { displayName: name });

    await ensureUserProfile(cred.user);

    await sendEmailVerification(cred.user);

    goTo("verify-email.html");
  } catch (error) {
    console.error(error);
    showFormError("Signup failed. Please try again.");
    resetTurnstile();
  } finally {
    clearLoading(signupBtn);
    isSubmitting = false;
  }
}

async function handleGoogleSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const token = getTurnstileToken();

  if (!token) {
    showCaptchaError("Please complete captcha.");
    isSubmitting = false;
    return;
  }

  try {
    setLoading(googleBtn);

    await verifyTurnstileToken(token);

    if (isMobileDevice()) {
      await signInWithRedirect(auth, provider);
    } else {
      const cred = await signInWithPopup(auth, provider);
      await ensureUserProfile(cred.user);
      goTo("home.html");
    }
  } catch (error) {
    console.error(error);
    showFormError("Google signup failed.");
    resetTurnstile();
  } finally {
    clearLoading(googleBtn);
    isSubmitting = false;
  }
}

async function initTurnstile() {
  await waitForTurnstile();

  widgetId = window.turnstile.render("#turnstile-container", {
    sitekey: "0x4AAAAAACqA_Z98nhvcobbI",
    theme: "dark",
    size: "flexible",
    retry: "auto",
    "refresh-expired": "auto"
  });
}

signupForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  await handleEmailSignup();
});

googleBtn?.addEventListener("click", async () => {
  await handleGoogleSignup();
});

window.addEventListener("load", async () => {
  try {
    const redirected = await handleRedirectResult();
    if (!redirected) await initTurnstile();
  } catch (error) {
    console.error(error);
    showFormError("Page failed to load.");
  }
});
