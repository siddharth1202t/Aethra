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

function getTurnstileToken() {
  const tokenInput = document.querySelector('input[name="cf-turnstile-response"]');
  return tokenInput ? tokenInput.value : "";
}

async function verifyTurnstileToken(token) {
  const res = await fetch("/api/verify-turnstile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ token })
  });

  if (!res.ok) {
    throw new Error("Captcha verification request failed.");
  }

  const data = await res.json();

  if (!data.success) {
    throw new Error("Captcha verification failed. Please try again.");
  }

  return true;
}

function resetTurnstileWidget() {
  if (window.turnstile) {
    window.turnstile.reset();
  }
}

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const token = getTurnstileToken();
    if (!token) {
      alert("Please complete the captcha.");
      return;
    }

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    try {
      await verifyTurnstileToken(token);
      await signInWithEmailAndPassword(auth, email, password);
      window.location.href = "home.html";
    } catch (error) {
      alert(error.message);
      console.error(error);
      resetTurnstileWidget();
    }
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    const token = getTurnstileToken();
    if (!token) {
      alert("Please complete the captcha.");
      return;
    }

    const provider = new GoogleAuthProvider();

    try {
      await verifyTurnstileToken(token);
      await signInWithPopup(auth, provider);
      window.location.href = "home.html";
    } catch (error) {
      alert(error.message);
      console.error(error);
      resetTurnstileWidget();
    }
  });
}
