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
    console.error("Signup debug error:", error);
    alert(`Message: ${error?.message || "none"}\nCode: ${error?.code || "none"}`);
    return false;
  }
}

async function handleEmailSignup() {
  if (isSubmitting) return;
  isSubmitting = true;

  const name = sanitizeUsername(nameInput.value);
  const email = normalizeEmail(emailInput.value);
  const password = passwordInput.value;
  const token = getTurnstileToken();

  nameInput.value = name;
  emailInput.value = email;

  if (!name) {
    alert("Please enter a username.");
    nameInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  if (name.length < 3) {
    alert("Username must be at least 3 characters.");
    nameInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  if (name.length > 20) {
    alert("Username must be 20 characters or less.");
    nameInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  if (!email) {
    alert("Please enter your email.");
    emailInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  if (!password) {
    alert("Please enter your password.");
    passwordInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  if (password.length < 8) {
    alert("Password must be at least 8 characters.");
    passwordInput.focus();
    isSubmitting = false;
    setTemporaryCooldown(signupBtn, 1500);
    return;
  }

  if (!token) {
    alert("Please complete the captcha first.");
    isSubmitting = false;
    return;
  }

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
    console.error("Signup debug error:", error);
    alert(`Message: ${error?.message || "none"}\nCode: ${error?.code || "none"}`);
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
    console.error("Google signup debug error:", error);
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
