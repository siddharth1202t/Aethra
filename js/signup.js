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

if (signupForm) {
  signupForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const nameInput = document.getElementById("name");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");

    if (!nameInput || !emailInput || !passwordInput) {
      alert("One or more form fields are missing.");
      return;
    }

    const captchaResponse = grecaptcha.getResponse();
    if (!captchaResponse) {
      alert("Please verify that you are not a robot.");
      return;
    }

    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    try {
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);

      if (name) {
        await updateProfile(userCredential.user, {
          displayName: name
        });
      }

      alert("Account created successfully!");
      window.location.href = "home.html";
    } catch (error) {
      console.error("Signup error:", error);
      alert(error.message);
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

    try {
      await signInWithPopup(auth, provider);
      alert("Google login successful!");
      window.location.href = "home.html";
    } catch (error) {
      console.error("Google login error:", error);
      alert(error.message);
    } finally {
      grecaptcha.reset();
    }
  });
}
