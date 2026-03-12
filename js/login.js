import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup
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
let currentAction = null;

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

async function handleEmailLogin() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  if (!email) {
    alert("Please enter your email.");
    return;
  }

  if (!password) {
    alert("Please enter your password.");
    return;
  }

  currentAction = "email";

  if (widgetId !== null) {
    window.turnstile.reset(widgetId);
    window.turnstile.execute(widgetId);
  }
}

async function handleGoogleLogin() {
  currentAction = "google";

  if (widgetId !== null) {
    window.turnstile.reset(widgetId);
    window.turnstile.execute(widgetId);
  }
}

async function onTurnstileSuccess(token) {
  try {
    await verifyTurnstileToken(token);

    if (currentAction === "email") {
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      await signInWithEmailAndPassword(auth, email, password);
    } else if (currentAction === "google") {
      const provider = new GoogleAuthProvider();
      await signInWithPopup(auth, provider);
    } else {
      return;
    }

    window.location.href = "home.html";
  } catch (error) {
    alert(error.message);
    console.error(error);
  } finally {
    currentAction = null;
    if (widgetId !== null && window.turnstile) {
      window.turnstile.reset(widgetId);
    }
  }
}

async function initTurnstile() {
  await waitForTurnstile();

  widgetId = window.turnstile.render("#turnstile-container", {
    sitekey: "0x4AAAAAACpvKyzO0FiDW0v2",
    theme: "dark",
    execution: "execute",
    appearance: "interaction-only",
    callback: onTurnstileSuccess,
    "error-callback": function () {
      alert("Captcha failed to load. Please refresh and try again.");
    }
  });
}

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    handleEmailLogin();
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    handleGoogleLogin();
  });
}

initTurnstile();
