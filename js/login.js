import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect
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

const form = document.getElementById("loginForm");
const googleBtn = document.getElementById("googleLoginBtn");
const loginBtn = document.querySelector(".login-btn");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");

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

function getFriendlyAuthMessage(error) {
  const code = error?.code || "";

  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
    case "auth/invalid-email":
      return "Invalid email or password.";
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
  window.location.href = "home.html";
}

async function handleEmailLogin() {
  if (isSubmitting) return;
  isSubmitting = true;

  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  const token = getTurnstileToken();

  emailInput.value = email;

  if (!email) {
    alert("Please enter your email.");
    emailInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(loginBtn, 1500);
    return;
  }

  if (!password) {
    alert("Please enter your password.");
    passwordInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(loginBtn, 1500);
    return;
  }

  if (!token) {
    alert("Please complete the captcha first.");
    isSubmitting = false;
    setTemporaryCooldown(loginBtn, 1500);
    return;
  }

  try {
    setLoading(loginBtn, "Logging in...");
    await verifyTurnstileToken(token);
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    await ensureUserProfile(userCredential.user);
    redirectToHome();
  } catch (error) {
    console.error(error);
    alert(getFriendlyAuthMessage(error));
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

  const token = getTurnstileToken();

  if (!token) {
    alert("Please complete the captcha first.");
    isSubmitting = false;
    setTemporaryCooldown(googleBtn, 1500);
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
    console.error(error);
    alert(getFriendlyAuthMessage(error));
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
    "error-callback": function (code) {
      console.error("Turnstile error code:", code);
      alert("Captcha failed to load. Error code: " + code);
    },
    "expired-callback": function () {
      console.warn("Turnstile expired.");
    }
  });
}

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

window.addEventListener("load", async () => {
  try {
    await initTurnstile();
  } catch (error) {
    console.error("Turnstile init failed:", error);
    alert("Turnstile init failed: " + error.message);
  }
});
