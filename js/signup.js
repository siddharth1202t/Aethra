import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
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
import { ensureUserProfile } from "./user-profile.js";

const firebaseConfig = {
  apiKey: "AIzaSyCbfEQyTwry7qNOluYqlHUZuU8AF3bkpgQ",
  authDomain: "aethra-web.firebaseapp.com",
  projectId: "aethra-web",
  storageBucket: "aethra-web.firebasestorage.app",
  messagingSenderId: "280560043528",
  appId: "1:280560043528:web:a6c2e485c8da32c9dab3bd"
};

const app = initializeApp(firebaseConfig);
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

function waitForTurnstile(timeout = 10000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    const check = () => {
      if (window.turnstile) {
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
    throw new Error("Captcha verification failed. Please try again.");
  }
}

function getTurnstileToken() {
  if (widgetId === null || !window.turnstile) return "";
  return window.turnstile.getResponse(widgetId);
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
  return email.trim().toLowerCase();
}

function sanitizeUsername(value) {
  return value
    .trim()
    .replace(/[^a-zA-Z0-9._ ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
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

function redirectToVerifyEmail() {
  window.location.href = "verify-email.html";
}

function redirectToHome() {
  window.location.href = "home.html";
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
}

function clearFormError() {
  if (!formError) return;
  formError.textContent = "";
  formError.classList.remove("show");
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
  clearFieldState(nameInput, nameError);
  clearFieldState(emailInput, emailError);
  clearFieldState(passwordInput, passwordError);
  clearFieldState(confirmPasswordInput, confirmPasswordError);
  clearCaptchaError();
  clearFormError();
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

function validateName(showUI = true) {
  const name = sanitizeUsername(nameInput.value);
  nameInput.value = name;

  if (!name) {
    if (showUI) setFieldError(nameInput, nameError, "Please enter a username.");
    return false;
  }

  if (name.length < 3) {
    if (showUI) setFieldError(nameInput, nameError, "Username must be at least 3 characters.");
    return false;
  }

  if (name.length > 20) {
    if (showUI) setFieldError(nameInput, nameError, "Username must be 20 characters or less.");
    return false;
  }

  if (showUI) setFieldValid(nameInput, nameError);
  return true;
}

function validateEmail(showUI = true) {
  const email = normalizeEmail(emailInput.value);
  emailInput.value = email;

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
  const password = passwordInput.value;

  if (!password) {
    if (showUI) setFieldError(passwordInput, passwordError, "Please enter your password.");
    return false;
  }

  if (password.length < 8) {
    if (showUI) setFieldError(passwordInput, passwordError, "Password must be at least 8 characters.");
    return false;
  }

  if (!hasUppercase(password)) {
    if (showUI) setFieldError(passwordInput, passwordError, "Password must contain at least 1 uppercase letter.");
    return false;
  }

  if (!hasNumber(password)) {
    if (showUI) setFieldError(passwordInput, passwordError, "Password must contain at least 1 number.");
    return false;
  }

  if (showUI) setFieldValid(passwordInput, passwordError);
  return true;
}

function validateConfirmPassword(showUI = true) {
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  if (!confirmPassword) {
    if (showUI) {
      setFieldError(confirmPasswordInput, confirmPasswordError, "Please confirm your password.");
    }
    return false;
  }

  if (password !== confirmPassword) {
    if (showUI) {
      setFieldError(confirmPasswordInput, confirmPasswordError, "Passwords do not match.");
    }
    return false;
  }

  if (showUI) setFieldValid(confirmPasswordInput, confirmPasswordError);
  return true;
}

function mapSignupErrorToField(error) {
  const code = error?.code || "";

  if (code === "auth/email-already-in-use") {
    setFieldError(emailInput, emailError, "This email is already in use.");
    emailInput.focus();
    return;
  }

  if (code === "auth/invalid-email") {
    setFieldError(emailInput, emailError, "Please enter a valid email address.");
    emailInput.focus();
    return;
  }

  if (code === "auth/weak-password" || code === "auth/password-does-not-meet-requirements") {
    setFieldError(passwordInput, passwordError, "Password does not meet the required rules.");
    passwordInput.focus();
    return;
  }

  if (code === "auth/network-request-failed") {
    showFormError("Network error. Please check your internet connection and try again.");
    return;
  }

  showFormError("Signup failed. Please try again.");
}

function getFriendlyGoogleError(error) {
  const code = error?.code || "";

  switch (code) {
    case "auth/popup-closed-by-user":
      return "Google sign-up was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser. Please allow popups and try again.";
    case "auth/network-request-failed":
      return "Network error. Please check your internet connection.";
    default:
      return "Google sign-up failed. Please try again.";
  }
}

async function handleRedirectResult() {
  try {
    const result = await getRedirectResult(auth);

    if (result?.user) {
      await ensureUserProfile(result.user);
      redirectToHome();
      return true;
    }

    return false;
  } catch (error) {
    console.error("Signup redirect error:", error);
    showFormError(getFriendlyGoogleError(error));
    return false;
  }
}

async function handleEmailSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const isNameValid = validateName(true);
  const isEmailValid = validateEmail(true);
  const isPasswordValid = validatePassword(true);
  const isConfirmPasswordValid = validateConfirmPassword(true);
  const token = getTurnstileToken();

  if (!isNameValid || !isEmailValid || !isPasswordValid || !isConfirmPasswordValid) {
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1200);
    return;
  }

  if (!token) {
    showCaptchaError("Please complete the captcha first.");
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  const name = sanitizeUsername(nameInput.value);
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;

  try {
    setLoading(signupBtn, "Creating account...");
    clearCaptchaError();

    await verifyTurnstileToken(token);

    const userCredential = await createUserWithEmailAndPassword(auth, email, password);

    await updateProfile(userCredential.user, {
      displayName: name
    });

    await ensureUserProfile(userCredential.user);
    await sendEmailVerification(userCredential.user);

    redirectToVerifyEmail();
  } catch (error) {
    console.error("Signup error:", error);
    mapSignupErrorToField(error);
    resetTurnstile();
    setTemporaryCooldown(signupBtn, 3000);
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
    showCaptchaError("Please complete the captcha first.");
    isSubmitting = false;
    setTemporaryCooldown(googleBtn, 1500);
    return;
  }

  try {
    setLoading(googleBtn, "Please wait...");
    clearCaptchaError();

    await verifyTurnstileToken(token);

    if (isMobileDevice()) {
      await signInWithRedirect(auth, provider);
      return;
    } else {
      const userCredential = await signInWithPopup(auth, provider);
      await ensureUserProfile(userCredential.user);
      redirectToHome();
    }
  } catch (error) {
    console.error("Google signup error:", error);
    showFormError(getFriendlyGoogleError(error));
    resetTurnstile();
    setTemporaryCooldown(googleBtn, 3000);
  } finally {
    clearLoading(googleBtn);
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
    "error-callback": function () {
      showCaptchaError("Captcha failed to load. Please refresh and try again.");
    },
    "expired-callback": function () {
      showCaptchaError("Captcha expired. Please complete it again.");
    }
  });
}

nameInput?.addEventListener("input", () => {
  clearFormError();
  if (nameInput.value.trim()) validateName(true);
  else clearFieldState(nameInput, nameError);
});

emailInput?.addEventListener("input", () => {
  clearFormError();
  if (emailInput.value.trim()) validateEmail(true);
  else clearFieldState(emailInput, emailError);
});

passwordInput?.addEventListener("input", () => {
  clearFormError();
  if (passwordInput.value.trim()) validatePassword(true);
  else clearFieldState(passwordInput, passwordError);

  if (confirmPasswordInput.value.trim()) {
    validateConfirmPassword(true);
  }
});

confirmPasswordInput?.addEventListener("input", () => {
  clearFormError();
  if (confirmPasswordInput.value.trim()) validateConfirmPassword(true);
  else clearFieldState(confirmPasswordInput, confirmPasswordError);
});

if (signupForm) {
  signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    await handleEmailSignup();
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    await handleGoogleSignup();
  });
}

window.addEventListener("load", async () => {
  try {
    const redirected = await handleRedirectResult();

    if (!redirected) {
      await initTurnstile();
    }
  } catch (error) {
    console.error("Page init failed:", error);
    showFormError("Page failed to load properly. Please refresh and try again.");
  }
});
