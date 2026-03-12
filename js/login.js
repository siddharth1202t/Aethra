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

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const captchaResponse = grecaptcha.getResponse();
    if (!captchaResponse) {
      alert("Please verify that you are not a robot.");
      return;
    }

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    try {
      await signInWithEmailAndPassword(auth, email, password);
      window.location.href = "home.html";
    } catch (error) {
      alert(error.message);
      console.error(error);
    } finally {
      grecaptcha.reset();
    }
  });
}

if (googleBtn) {
  googleBtn.addEventListener("click", async () => {

    const captchaResponse = grecaptcha.getResponse();
    if (!captchaResponse) {
      alert("Please verify that you are not a robot.");
      return;
    }

    const provider = new GoogleAuthProvider();

    try {
      await signInWithPopup(auth, provider);
      window.location.href = "home.html";
    } catch (error) {
      alert(error.message);
      console.error(error);
    } finally {
      grecaptcha.reset();
    }
  });
}
