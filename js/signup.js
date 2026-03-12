import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithPopup,
  GoogleAuthProvider,
  updateProfile
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
const provider = new GoogleAuthProvider();

const signupForm = document.getElementById("signupForm");
const googleBtn = document.getElementById("googleSignInBtn");

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

async function handleEmailSignup() {
  const nameInput = document.getElementById("name");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");

  const name = nameInput.value.trim();
  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (!name) {
    alert("Please enter a username.");
    nameInput.focus();
    return;
  }

  if (!email) {
    alert("Please enter your email.");
    emailInput.focus();
    return;
  }

  if (!password) {
    alert("Please enter your password.");
    passwordInput.focus();
    return;
  }

  if (password.length < 6) {
    alert("Password must be at least 6 characters.");
    passwordInput.focus();
    return;
  }

  currentAction = "email";

  if (widgetId !== null) {
    window.turnstile.reset(widgetId);
    window.turnstile.execute(widgetId);
  }
}

async function handleGoogleSignup() {
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
      const name = document.getElementById("name").value.trim();
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;

      const userCredential = await createUserWithEmailAndPassword(auth, email, password);

      await updateProfile(userCredential.user, {
        displayName: name
      });
    } else if (currentAction === "google") {
      await signInWithPopup(auth, provider);
    } else {
      return;
    }

    window.location.href = "home.html";
  } catch (error) {
    console.error(error);
    alert(error.message);
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
    "error-callback": function (code) {
      console.error("Turnstile error code:", code);
      alert("Captcha failed to load. Error code: " + code);
    }
  });
}

if (signupForm) {
  signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    handleEmailSignup();
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    handleGoogleSignup();
  });
}

initTurnstile();
