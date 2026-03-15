import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, onAuthStateChanged, reload } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { doc, getDoc, getFirestore } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

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
const db = getFirestore(app);

function goTo(page) {
  window.location.replace(page);
}

export function requireAuth(callback) {
  onAuthStateChanged(auth, async (user) => {
    if (!user) {
      goTo("login.html");
      return;
    }

    try {
      await reload(user);

      if (!auth.currentUser?.emailVerified) {
        if (!window.location.pathname.endsWith("/verify-email.html") &&
            !window.location.pathname.endsWith("verify-email.html")) {
          goTo("verify-email.html");
        }
        return;
      }

      if (callback) callback(auth.currentUser);
    } catch (error) {
      console.error("Auth guard failed:", error);
      goTo("login.html");
    }
  });
}

export function requireDeveloper(callback) {
  onAuthStateChanged(auth, async (user) => {
    if (!user) {
      goTo("login.html");
      return;
    }

    try {
      await reload(user);

      if (!auth.currentUser?.emailVerified) {
        goTo("verify-email.html");
        return;
      }

      const userRef = doc(db, "users", user.uid);
      const userSnap = await getDoc(userRef);

      if (!userSnap.exists()) {
        goTo("home.html");
        return;
      }

      const userData = userSnap.data();

      if (userData.role !== "developer") {
        goTo("home.html");
        return;
      }

      if (callback) callback(auth.currentUser);
    } catch (error) {
      console.error("Developer guard failed:", error);
      goTo("home.html");
    }
  });
}

export { auth };
