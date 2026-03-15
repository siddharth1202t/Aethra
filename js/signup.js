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

async function safeSecurityLog(payload) {
  try {
    await writeSecurityLog(payload);
  } catch (error) {
    console.warn("Security log failed:", error);
  }
}

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

async function callSignupAttemptApi(email, action, extra = {}) {
  const res = await fetch("/api/signup-attempt", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email,
      action,
      ...extra
    })
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok || !data.success) {
    throw new Error(data?.message || "Signup security check failed.");
  }

  return data;
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

function isMobileDevice() {
  return /Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(
    navigator.userAgent
  );
}

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

function isLockedMessage(message) {
  return String(message || "").toLowerCase().includes("temporarily locked");
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

function clearFieldError(errorEl) {
  if (errorEl) errorEl.textContent = "";
}

function clearFormError() {
  if (!formError) return;
  formError.textContent = "";
  formError.classList.remove("show");
  formError.style.background = "";
  formError.style.borderColor = "";
  formError.style.color = "";
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

function showCaptchaError(message) {
  if (captchaError) captchaError.textContent = message;
}

function clearCaptchaError() {
  if (captchaError) captchaError.textContent = "";
}

function clearAllErrors() {
  clearFieldError(nameError);
  clearFieldError(emailError);
  clearFieldError(passwordError);
  clearFieldError(confirmPasswordError);
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

function getFriendlyAuthMessage(error) {
  const code = error?.code || "";
  const message = String(error?.message || "");

  if (message.toLowerCase().includes("captcha")) {
    return "Captcha verification failed. Please complete it again.";
  }

  if (isLockedMessage(message)) {
    return message;
  }

  switch (code) {
    case "auth/email-already-in-use":
      return "This email is already registered.";
    case "auth/invalid-email":
      return "Please enter a valid email address.";
    case "auth/weak-password":
      return "Password is too weak.";
    case "auth/network-request-failed":
      return "Network error. Please check your internet connection.";
    case "auth/popup-closed-by-user":
      return "Google sign-up was closed before completion.";
    case "auth/popup-blocked":
      return "Popup was blocked by the browser. Please allow popups or try again.";
    case "auth/cancelled-popup-request":
      return "Another sign-up request is already in progress.";
    default:
      return "Signup failed. Please try again.";
  }
}

function validateName(showUI = true) {
  const name = sanitizeUsername(nameInput?.value || "");
  if (nameInput) nameInput.value = name;

  if (!name || name.length < 3 || name.length > 20) {
    if (showUI) {
      nameError.textContent = "Username must be 3-20 characters.";
    }
    return false;
  }

  if (showUI) {
    nameError.textContent = "";
  }

  return true;
}

function validateEmail(showUI = true) {
  const email = normalizeEmail(emailInput?.value || "");
  if (emailInput) emailInput.value = email;

  if (!email || !isValidEmail(email)) {
    if (showUI) {
      emailError.textContent = "Please enter a valid email address.";
    }
    return false;
  }

  if (showUI) {
    emailError.textContent = "";
  }

  return true;
}

function validatePassword(showUI = true) {
  const password = passwordInput?.value || "";

  if (password.length < 8 || !hasUppercase(password) || !hasNumber(password)) {
    if (showUI) {
      passwordError.textContent =
        "Password must be 8+ chars, include uppercase & number.";
    }
    return false;
  }

  if (showUI) {
    passwordError.textContent = "";
  }

  return true;
}

function validateConfirmPassword(showUI = true) {
  if ((passwordInput?.value || "") !== (confirmPasswordInput?.value || "")) {
    if (showUI) {
      confirmPasswordError.textContent = "Passwords do not match.";
    }
    return false;
  }

  if (showUI) {
    confirmPasswordError.textContent = "";
  }

  return true;
}

function getClientSecurityContext() {
  let behavior = {};

  try {
    behavior = typeof detectBotBehavior === "function" ? detectBotBehavior() : {};
  } catch (error) {
    console.warn("Bot behavior detection failed:", error);
    behavior = {};
  }

  return {
    behavior,
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    platform: navigator.platform || "",
    screen: {
      width: window.screen?.width || 0,
      height: window.screen?.height || 0
    }
  };
}

async function precheckSensitiveAction(email, token, actionLabel = "signup_check") {
  if (!token) {
    await safeSecurityLog({
      type: "captcha_missing",
      message: `User attempted ${actionLabel} without captcha`,
      email
    });

    showCaptchaError("Please complete the captcha first.");
    throw new Error("Captcha missing");
  }

  const securityContext = getClientSecurityContext();

  const checkResult = await callSignupAttemptApi(email, "check", {
    actionLabel,
    ...securityContext
  });

  if (checkResult?.isLocked) {
    throw new Error(
      `This account is temporarily locked. Please try again in ${Math.max(
        1,
        Math.ceil(Number(checkResult.remainingMs || 0) / 60000)
      )} minute(s).`
    );
  }

  await verifyTurnstileToken(token);

  return securityContext;
}

async function handleRedirectResult() {
  try {
    const result = await getRedirectResult(auth);

    if (!result?.user) {
      return false;
    }

    const user = result.user;

    await ensureUserProfile(user);
    await reload(user);

    await safeSecurityLog({
      type: "google_signup_success",
      message: "User signed up with Google via redirect",
      email: user.email || "",
      userId: user.uid
    });

    if (!user.emailVerified) {
      goTo("verify-email.html");
      return true;
    }

    goTo("home.html");
    return true;
  } catch (error) {
    console.error("Google redirect signup failed:", error);

    await safeSecurityLog({
      type: "google_signup_failed",
      message: error?.message || "Google redirect signup failed"
    });

    showFormError(getFriendlyAuthMessage(error));
    return false;
  }
}

async function handleEmailSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  clearAllErrors();

  const valid =
    validateName(true) &&
    validateEmail(true) &&
    validatePassword(true) &&
    validateConfirmPassword(true);

  if (!valid) {
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  const token = getTurnstileToken();
  const name = sanitizeUsername(nameInput?.value || "");
  const email = normalizeEmail(emailInput?.value || "");
  const password = passwordInput?.value || "";

  let securityContext = {};

  try {
    setLoading(signupBtn, "Creating account...");

    securityContext = await precheckSensitiveAction(email, token, "email_signup");

    const credential = await createUserWithEmailAndPassword(auth, email, password);
    const user = credential.user;

    await updateProfile(user, { displayName: name });
    await ensureUserProfile(user);
    await sendEmailVerification(user);
    await reload(user);

    await safeSecurityLog({
      type: "signup_success",
      message: "User account created successfully",
      email,
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    goTo("verify-email.html");
  } catch (error) {
    console.error("Email signup failed:", error);

    await safeSecurityLog({
      type: "signup_failed",
      message: error?.message || "Email signup failed",
      email,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    const authCode = error?.code || "";
    const isFailedSignup =
      authCode === "auth/email-already-in-use" ||
      authCode === "auth/invalid-email" ||
      authCode === "auth/weak-password";

    if (authCode === "auth/invalid-email") {
      emailError.textContent = "Please enter a valid email address.";
    }

    if (isLockedMessage(error?.message)) {
      showFormError(error.message);
    } else if (isFailedSignup) {
      try {
        const failStatus = await callSignupAttemptApi(email, "fail", {
          actionLabel: "email_signup_fail",
          ...securityContext
        });

        if (failStatus?.isLocked) {
          showFormError("Too many signup attempts. Please try again later.");
        } else {
          showFormError(getFriendlyAuthMessage(error));
        }
      } catch (attemptError) {
        console.error("Failed to record signup attempt:", attemptError);
        showFormError(getFriendlyAuthMessage(error));
      }
    } else {
      showFormError(getFriendlyAuthMessage(error));
    }

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

  const email = normalizeEmail(emailInput?.value || "google-signup");
  const token = getTurnstileToken();
  let securityContext = {};

  try {
    setLoading(googleBtn, "Please wait...");

    securityContext = await precheckSensitiveAction(email, token, "google_signup");

    if (isMobileDevice()) {
      await safeSecurityLog({
        type: "google_signup_redirect_started",
        message: "Google redirect sign-up started",
        email,
        metadata: {
          behavior: securityContext.behavior || {}
        }
      });

      await signInWithRedirect(auth, provider);
      return;
    }

    const credential = await signInWithPopup(auth, provider);
    const user = credential.user;

    await ensureUserProfile(user);
    await reload(user);

    await safeSecurityLog({
      type: "google_signup_success",
      message: "User signed up with Google",
      email: user.email || "",
      userId: user.uid,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    if (!user.emailVerified) {
      goTo("verify-email.html");
      return;
    }

    goTo("home.html");
  } catch (error) {
    console.error("Google signup failed:", error);

    await safeSecurityLog({
      type: "google_signup_failed",
      message: error?.message || "Google signup failed",
      email,
      metadata: {
        behavior: securityContext.behavior || {}
      }
    });

    showFormError(getFriendlyAuthMessage(error));
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
    callback() {
      clearCaptchaError();
    },
    "error-callback"() {
      showCaptchaError("Captcha failed to load. Please refresh and try again.");
    },
    "expired-callback"() {
      showCaptchaError("Captcha expired. Please complete it again.");
    }
  });
}

nameInput?.addEventListener("input", () => {
  clearFormError();

  if (nameInput.value.trim()) {
    validateName(true);
  } else {
    clearFieldError(nameError);
  }
});

emailInput?.addEventListener("input", () => {
  clearFormError();
  clearCaptchaError();

  if (emailInput.value.trim()) {
    validateEmail(true);
  } else {
    clearFieldError(emailError);
  }
});

passwordInput?.addEventListener("input", () => {
  clearFormError();

  if (passwordInput.value.trim()) {
    validatePassword(true);
  } else {
    clearFieldError(passwordError);
  }

  if (confirmPasswordInput?.value.trim()) {
    validateConfirmPassword(true);
  }
});

confirmPasswordInput?.addEventListener("input", () => {
  clearFormError();

  if (confirmPasswordInput.value.trim()) {
    validateConfirmPassword(true);
  } else {
    clearFieldError(confirmPasswordError);
  }
});

signupForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await handleEmailSignup();
});

googleBtn?.addEventListener("click", async () => {
  await handleGoogleSignup();
});

window.addEventListener("load", async () => {
  try {
    const redirected = await handleRedirectResult();

    if (!redirected) {
      await initTurnstile();
    }
  } catch (error) {
    console.error("Signup page init failed:", error);
    showFormError("Page failed to load properly. Please refresh and try again.");
  }
});
