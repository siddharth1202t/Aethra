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

let turnstileWidgetId = null;
let turnstileToken = "";

window.onload = () => {
  if (window.turnstile) {
    turnstileWidgetId = window.turnstile.render("#turnstile-container", {
      sitekey: "0x4AAAAAACpvKyzO0FiDW0v2",
      theme: "dark",
      callback: function (token) {
        turnstileToken = token;
      }
    });
  }
};

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
}

function resetTurnstileWidget() {
  turnstileToken = "";
  if (window.turnstile && turnstileWidgetId !== null) {
    window.turnstile.reset(turnstileWidgetId);
  }
}

if (signupForm) {
  signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const nameInput = document.getElementById("name");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");

    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!name) {
      alert("Please enter a username.");
      return;
    }

    if (!email) {
      alert("Please enter your email.");
      return;
    }

    if (!password) {
      alert("Please enter your password.");
      return;
    }

    if (password.length < 6) {
      alert("Password must be at least 6 characters.");
      return;
    }

    if (!turnstileToken) {
      alert("Please complete the captcha.");
      return;
    }

    try {
      await verifyTurnstileToken(turnstileToken);

      const userCredential = await createUserWithEmailAndPassword(auth, email, password);

      await updateProfile(userCredential.user, {
        displayName: name
      });

      window.location.href = "home.html";
    } catch (error) {
      console.error(error);
      alert(error.message);
      resetTurnstileWidget();
    }
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {
    if (!turnstileToken) {
      alert("Please complete the captcha.");
      return;
    }

    try {
      await verifyTurnstileToken(turnstileToken);
      await signInWithPopup(auth, provider);
      window.location.href = "home.html";
    } catch (error) {
      console.error(error);
      alert(error.message);
      resetTurnstileWidget();
    }
  });
}
