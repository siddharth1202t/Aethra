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

function getCurrentPath() {
  return window.location.pathname || "";
}

function isPage(page) {
  const path = getCurrentPath();
  return path.endsWith(`/${page}`) || path.endsWith(page);
}

function goTo(page) {
  if (!isPage(page)) {
    window.location.replace(page);
  }
}

async function resolveVerifiedUser(user) {
  if (!user) {
    return { ok: false, reason: "not-authenticated" };
  }

  await reload(user);

  const currentUser = auth.currentUser;

  if (!currentUser) {
    return { ok: false, reason: "missing-current-user" };
  }

  if (!currentUser.emailVerified) {
    return { ok: false, reason: "email-not-verified", user: currentUser };
  }

  return { ok: true, user: currentUser };
}

function handleUnauthedState() {
  if (!isPage("login.html")) {
    goTo("login.html");
  }
}

function handleUnverifiedState() {
  if (!isPage("verify-email.html")) {
    goTo("verify-email.html");
  }
}

export function requireAuth(callback) {
  let handled = false;

  return onAuthStateChanged(auth, async (user) => {
    if (handled) return;

    if (!user) {
      handled = true;
      handleUnauthedState();
      return;
    }

    try {
      const result = await resolveVerifiedUser(user);

      if (!result.ok) {
        handled = true;

        if (result.reason === "email-not-verified") {
          handleUnverifiedState();
        } else {
          handleUnauthedState();
        }

        return;
      }

      handled = true;

      if (typeof callback === "function") {
        await callback(result.user);
      }
    } catch (error) {
      console.error("Auth guard failed:", error);
      handled = true;
      handleUnauthedState();
    }
  });
}

export function requireDeveloper(callback) {
  let handled = false;

  return onAuthStateChanged(auth, async (user) => {
    if (handled) return;

    if (!user) {
      handled = true;
      handleUnauthedState();
      return;
    }

    try {
      const result = await resolveVerifiedUser(user);

      if (!result.ok) {
        handled = true;

        if (result.reason === "email-not-verified") {
          handleUnverifiedState();
        } else {
          handleUnauthedState();
        }

        return;
      }

      const currentUser = result.user;
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
        await callback(currentUser);
      }
    } catch (error) {
      console.error("Developer guard failed:", error);
      handled = true;
      goTo("home.html");
    }
  });
}

export { auth };
