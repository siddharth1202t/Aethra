import { getAuth, onAuthStateChanged, reload } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { doc, getDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { app, db } from "./firestore-config.js";

const auth = getAuth(app);

function goTo(page) {
  window.location.replace(page);
}

function isVerifyEmailPage() {
  const path = window.location.pathname;
  return path.endsWith("/verify-email.html") || path.endsWith("verify-email.html");
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
        if (!isVerifyEmailPage()) {
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
