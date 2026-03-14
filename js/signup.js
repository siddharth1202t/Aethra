import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  GoogleAuthProvider,
  updateProfile
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

const nameError = document.getElementById("nameError");
const emailError = document.getElementById("emailError");
const passwordError = document.getElementById("passwordError");

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

function clearAllErrors() {
  clearFieldState(nameInput, nameError);
  clearFieldState(emailInput, emailError);
  clearFieldState(passwordInput, passwordError);
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

function mapSignupErrorToField(error) {
  const code = error?.code || "";
  const message = error?.message || "";

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

  if (code === "auth/password-does-not-meet-requirements" || code === "auth/weak-password") {
    if (message.toLowerCase().includes("upper")) {
      setFieldError(passwordInput, passwordError, "Password must contain at least 1 uppercase letter.");
    } else if (message.toLowerCase().includes("number")) {
      setFieldError(passwordInput, passwordError, "Password must contain at least 1 number.");
    } else {
      setFieldError(passwordInput, passwordError, "Password does not meet the required rules.");
    }
    passwordInput.focus();
    return;
  }

  if (code === "auth/network-request-failed") {
    setFieldError(emailInput, emailError, "Network error. Please check your internet connection.");
    emailInput.focus();
    return;
  }

  alert(`Message: ${message || "none"}\nCode: ${code || "none"}`);
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
    alert(`Message: ${error?.message || "none"}\nCode: ${error?.code || "none"}`);
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
  const token = getTurnstileToken();

  if (!isNameValid || !isEmailValid || !isPasswordValid) {
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1200);
    return;
  }

  if (!token) {
    alert("Please complete the captcha first.");
    isSubmitting = false;
    return;
  }

  const name = sanitizeUsername(nameInput.value);
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;

  try {
    setLoading(signupBtn, "Creating account...");
    await verifyTurnstileToken(token);

    const userCredential = await createUserWithEmailAndPassword(auth, email, password);

    await updateProfile(userCredential.user, {
      displayName: name
    });

    await ensureUserProfile(userCredential.user);

    redirectToHome();
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
    alert("Please complete the captcha first.");
    isSubmitting = false;
    return;
  }

  try {
    setLoading(googleBtn, "Please wait...");
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
    alert(`Message: ${error?.message || "none"}\nCode: ${error?.code || "none"}`);
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
    size: "flexible"
  });
}

nameInput?.addEventListener("input", () => {
  if (nameInput.value.trim()) validateName(true);
  else clearFieldState(nameInput, nameError);
});

emailInput?.addEventListener("input", () => {
  if (emailInput.value.trim()) validateEmail(true);
  else clearFieldState(emailInput, emailError);
});

passwordInput?.addEventListener("input", () => {
  if (passwordInput.value.trim()) validatePassword(true);
  else clearFieldState(passwordInput, passwordError);
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
  const redirected = await handleRedirectResult();

  if (!redirected) {
    await initTurnstile();
  }
});
