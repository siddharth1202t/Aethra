import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  GoogleAuthProvider,
  signInWithPopup
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCbFE0yTwrY7qN0IuU8AF3bkpq0",
  authDomain: "aethra-web.firebaseapp.com",
  projectId: "aethra-web",
  storageBucket: "aethra-web.firebasestorage.app",
  messagingSenderId: "280560043528",
  appId: "1:280560043528:web:a6c2e485c8da32c9dab3bd"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const form = document.getElementById("loginForm");

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  try {
    await signInWithEmailAndPassword(auth, email, password);
    window.location.href = "home.html";
  } catch (error) {
    alert(error.message);
  }
});

const googleBtn = document.getElementById("googleLoginBtn");

googleBtn.addEventListener("click", async () => {
  const provider = new GoogleAuthProvider();

  try {
    await signInWithPopup(auth, provider);
    window.location.href = "home.html";
  } catch (error) {
    alert(error.message);
  }
});
