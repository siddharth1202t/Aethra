import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  sendPasswordResetEmail,
  reload
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";

const auth = getAuth(app);
const provider = new GoogleAuthProvider();

const form = document.getElementById("loginForm");
const googleBtn = document.getElementById("googleLoginBtn");
const loginBtn = document.querySelector(".login-btn");
const forgotPasswordBtn = document.getElementById("forgotPasswordBtn");

const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");

const emailError = document.getElementById("emailError");
const passwordError = document.getElementById("passwordError");
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

async function callLoginAttemptApi(email, action) {
  const res = await fetch("/api/login-attempt", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ email, action })
  });

  const data = await res.json();

  if (!res.ok || !data.success) {
    throw new Error(data?.message || "Login security check failed.");
  }

  return data;
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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

function formatRemainingMinutes(ms) {
  const minutes = Math.ceil(ms / 60000);
  return minutes <= 1 ? "1 minute" : `${minutes} minutes`;
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
  formError.style.background = "rgba(255, 102, 102, 0.12)";
  formError.style.borderColor = "rgba(255, 102, 102, 0.2)";
  formError.style.color = "#ffd0d0";
}

function showFormSuccess(message) {
  if (!formError) return;
  formError.textContent = message;
  formError.classList.add("show");
  formError.style.background = "rgba(125, 255, 179, 0.12)";
  formError.style.borderColor = "rgba(125, 255, 179, 0.2)";
  formError.style.color = "#d4ffe6";
}

function clearFormError() {
  if (!formError) return;
  formError.textContent = "";
  formError.classList.remove("show");
  formError.style.background = "";
  formError.style.borderColor = "";
  formError.style.color = "";
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
  clearFieldState(emailInput, emailError);
  clearFieldState(passwordInput, passwordError);
  clearCaptchaError();
  clearFormError();
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

  if (showUI) setFieldValid(passwordInput, passwordError);
  return true;
}

function getFriendlyAuthMessage(error) {
  const code = error?.code || "";

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
    default:
      return "Login failed. Please try again.";
  }
}

function redirectToHome() {
  goTo("home.html");
}

function redirectToVerifyEmail() {
  goTo("verify-email.html");
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
    console.error("Redirect sign-in failed:", error);
    showFormError(getFriendlyAuthMessage(error));
    return false;
  }
}

async function handleEmailLogin() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const isEmailValid = validateEmail(true);
  const isPasswordValid = validatePassword(true);
  const token = getTurnstileToken();

  if (!isEmailValid || !isPasswordValid) {
    isSubmitting = false;
    setTemporaryCooldown(loginBtn, 1200);
    return;
  }

  if (!token) {
    showCaptchaError("Please complete the captcha first.");
    isSubmitting = false;
    setTemporaryCooldown(loginBtn, 1500);
    return;
  }

  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  emailInput.value = email;

  try {
    setLoading(loginBtn, "Logging in...");
    clearCaptchaError();

    const lockStatus = await callLoginAttemptApi(email, "check");
    if (lockStatus.isLocked) {
      showFormError(
        `This account is temporarily locked. Please try again in ${formatRemainingMinutes(lockStatus.remainingMs)}.`
      );
      resetTurnstile();
      setTemporaryCooldown(loginBtn, 3000);
      return;
    }

    await verifyTurnstileToken(token);

    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    await ensureUserProfile(user);
    await reload(user);

    if (!auth.currentUser?.emailVerified) {
      redirectToVerifyEmail();
      return;
    }

    redirectToHome();
  } catch (error) {
    console.error(error);

    const authCode = error?.code || "";
    const isFailedLogin =
      authCode === "auth/invalid-credential" ||
      authCode === "auth/wrong-password" ||
      authCode === "auth/user-not-found" ||
      authCode === "auth/invalid-email";

    if (authCode === "auth/invalid-email") {
      setFieldError(emailInput, emailError, "Please enter a valid email address.");
    }

    if (isFailedLogin) {
      try {
        const failStatus = await callLoginAttemptApi(email, "fail");

        if (failStatus.isLocked) {
          showFormError(
            `Too many failed attempts. This account is locked for ${formatRemainingMinutes(failStatus.remainingMs)}.`
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

    resetTurnstile();
    setTemporaryCooldown(loginBtn, 3000);
  } finally {
    clearLoading(loginBtn);
    isSubmitting = false;
  }
}

async function handleGoogleLogin() {
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
    console.error(error);
    showFormError(getFriendlyAuthMessage(error));
    resetTurnstile();
    setTemporaryCooldown(googleBtn, 3000);
  } finally {
    clearLoading(googleBtn);
    isSubmitting = false;
  }
}

async function handleForgotPassword() {
  clearAllErrors();

  const email = normalizeEmail(emailInput.value);
  emailInput.value = email;

  if (!email) {
    setFieldError(emailInput, emailError, "Enter your email first to reset your password.");
    emailInput.focus();
    return;
  }

  if (!isValidEmail(email)) {
    setFieldError(emailInput, emailError, "Please enter a valid email address.");
    emailInput.focus();
    return;
  }

  try {
    setLoading(forgotPasswordBtn, "Sending...");
    await sendPasswordResetEmail(auth, email);
    showFormSuccess("Password reset email sent. Please check your inbox.");
  } catch (error) {
    console.error("Password reset failed:", error);
    showFormError("Could not send reset email. Please check the email address and try again.");
  } finally {
    clearLoading(forgotPasswordBtn);
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

emailInput?.addEventListener("input", () => {
  clearFormError();
  clearCaptchaError();
  if (emailInput.value.trim()) validateEmail(true);
  else clearFieldState(emailInput, emailError);
});

passwordInput?.addEventListener("input", () => {
  clearFormError();
  if (passwordInput.value.trim()) validatePassword(true);
  else clearFieldState(passwordInput, passwordError);
});

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await handleEmailLogin();
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    await handleGoogleLogin();
  });
}

if (forgotPasswordBtn) {
  forgotPasswordBtn.addEventListener("click", async () => {
    await handleForgotPassword();
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
