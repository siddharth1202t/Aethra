import {
  getAuth,
  onAuthStateChanged,
  reload
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { app, db } from "./firestore-config.js";

const auth = getAuth(app);

function goTo(page) {
  const currentPath = window.location.pathname || "";
  if (!currentPath.endsWith(`/${page}`) && !currentPath.endsWith(page)) {
    window.location.replace(page);
  }
}

function getCurrentPath() {
  return window.location.pathname || "";
}

function isVerifyEmailPage() {
  const path = getCurrentPath();
  return path.endsWith("/verify-email.html") || path.endsWith("verify-email.html");
}

function isLoginPage() {
  const path = getCurrentPath();
  return path.endsWith("/login.html") || path.endsWith("login.html");
}

export function requireAuth(callback) {
  let handled = false;

  return onAuthStateChanged(auth, async (user) => {
    if (handled) return;

    if (!user) {
      handled = true;
      if (!isLoginPage()) {
        goTo("login.html");
      }
      return;
    }

    try {
      await reload(user);

      const currentUser = auth.currentUser;

      if (!currentUser) {
        handled = true;
        goTo("login.html");
        return;
      }

      if (!currentUser.emailVerified) {
        handled = true;
        if (!isVerifyEmailPage()) {
          goTo("verify-email.html");
        }
        return;
      }

      handled = true;

      if (typeof callback === "function") {
        callback(currentUser);
      }
    } catch (error) {
      console.error("Auth guard failed:", error);
      handled = true;
      goTo("login.html");
    }
  });
}

export function requireDeveloper(callback) {
  let handled = false;

  return onAuthStateChanged(auth, async (user) => {
    if (handled) return;

    if (!user) {
      handled = true;
      if (!isLoginPage()) {
        goTo("login.html");
      }
      return;
    }

    try {
      await reload(user);

      const currentUser = auth.currentUser;

      if (!currentUser) {
        handled = true;
        goTo("login.html");
        return;
      }

      if (!currentUser.emailVerified) {
        handled = true;
        if (!isVerifyEmailPage()) {
          goTo("verify-email.html");
        }
        return;
      }

      const userRef = doc(db, "users", currentUser.uid);
      const userSnap = await getDoc(userRef);

      if (!userSnap.exists()) {
        handled = true;
        goTo("home.html");
        return;
      }

      const userData = userSnap.data() || {};
      const role = String(userData.role || "").toLowerCase();

      if (role !== "developer") {
        handled = true;
        goTo("home.html");
        return;
      }

      handled = true;

      if (typeof callback === "function") {
        callback(currentUser);
      }
    } catch (error) {
      console.error("Developer guard failed:", error);
      handled = true;
      goTo("home.html");
    }
  });
}

export { auth };
