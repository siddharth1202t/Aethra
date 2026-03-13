import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

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

const form = document.getElementById("loginForm");
const googleBtn = document.getElementById("googleLoginBtn");

let widgetId = null;

function waitForTurnstile() {
  return new Promise((resolve) => {
    const check = () => {
      if (window.turnstile) {
        resolve();
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

async function handleEmailLogin() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const token = getTurnstileToken();

  if (!email) {
    alert("Please enter your email.");
    return;
  }

  if (!password) {
    alert("Please enter your password.");
    return;
  }

  if (!token) {
    alert("Please complete the captcha first.");
    return;
  }

  try {
    await verifyTurnstileToken(token);
    await signInWithEmailAndPassword(auth, email, password);
    window.location.href = "home.html";
  } catch (error) {
    alert(error.message);
    console.error(error);
    resetTurnstile();
  }
}

async function handleGoogleLogin() {
  const token = getTurnstileToken();

  if (!token) {
    alert("Please complete the captcha first.");
    return;
  }

  try {
    await verifyTurnstileToken(token);

    const provider = new GoogleAuthProvider();

    if (isMobileDevice()) {
      await signInWithRedirect(auth, provider);
      return;
    } else {
      await signInWithPopup(auth, provider);
    }

    window.location.href = "home.html";
  } catch (error) {
    alert(error.message);
    console.error(error);
    resetTurnstile();
  }
}

async function initTurnstile() {
  await waitForTurnstile();

  widgetId = window.turnstile.render("#turnstile-container", {
    sitekey: "0x4AAAAAACpvKyzO0FiDW0v2",
    theme: "dark",
    size: "flexible",
    retry: "auto",
    "refresh-expired": "auto",
    "error-callback": function (code) {
      console.error("Turnstile error code:", code);
      alert("Captcha failed to load. Error code: " + code);
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
  }
});
