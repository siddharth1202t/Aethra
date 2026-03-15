import {
  getAuth,
  onAuthStateChanged,
  reload,
  getIdTokenResult
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

function handleNonDeveloperState() {
  if (!isPage("home.html")) {
    goTo("home.html");
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

async function getUserRoleData(uid) {
  try {
    const userRef = doc(db, "users", uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) {
      return {
        exists: false,
        firestoreRole: ""
      };
    }

    const userData = userSnap.data() || {};
    return {
      exists: true,
      firestoreRole: String(userData.role || "").toLowerCase()
    };
  } catch (error) {
    console.error("Failed to read user role data:", error);
    return {
      exists: false,
      firestoreRole: ""
    };
  }
}

async function resolveDeveloperAccess(currentUser) {
  let claimsRole = "";
  let isDeveloperByClaims = false;

  try {
    const tokenResult = await getIdTokenResult(currentUser, true);
    const claims = tokenResult?.claims || {};

    if (claims.admin === true) {
      claimsRole = "admin";
      isDeveloperByClaims = true;
    } else if (claims.developer === true) {
      claimsRole = "developer";
      isDeveloperByClaims = true;
    }
  } catch (error) {
    console.error("Failed to read token claims:", error);
  }

  const roleData = await getUserRoleData(currentUser.uid);

  const isDeveloperByFirestore =
    roleData.exists && roleData.firestoreRole === "developer";

  return {
    isDeveloper: isDeveloperByClaims || isDeveloperByFirestore,
    claimsRole,
    firestoreRole: roleData.firestoreRole,
    userDocExists: roleData.exists
  };
}

function createSingleRunGuard(handler) {
  let handled = false;

  return onAuthStateChanged(auth, async (user) => {
    if (handled) return;

    try {
      const done = await handler(user);
      if (done) {
        handled = true;
      }
    } catch (error) {
      console.error("Auth guard failed:", error);
      handled = true;
      handleUnauthedState();
    }
  });
}

export function requireAuth(callback) {
  return createSingleRunGuard(async (user) => {
    if (!user) {
      handleUnauthedState();
      return true;
    }

    const result = await resolveVerifiedUser(user);

    if (!result.ok) {
      if (result.reason === "email-not-verified") {
        handleUnverifiedState();
      } else {
        handleUnauthedState();
      }

      return true;
    }

    if (typeof callback === "function") {
      await callback(result.user);
    }

    return true;
  });
}

export function requireDeveloper(callback) {
  return createSingleRunGuard(async (user) => {
    if (!user) {
      handleUnauthedState();
      return true;
    }

    const result = await resolveVerifiedUser(user);

    if (!result.ok) {
      if (result.reason === "email-not-verified") {
        handleUnverifiedState();
      } else {
        handleUnauthedState();
      }

      return true;
    }

    const currentUser = result.user;
    const access = await resolveDeveloperAccess(currentUser);

    if (!access.isDeveloper) {
      handleNonDeveloperState();
      return true;
    }

    if (typeof callback === "function") {
      await callback(currentUser, access);
    }

    return true;
  });
}

export { auth };
