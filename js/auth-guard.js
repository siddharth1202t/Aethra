import {
  getAuth,
  onAuthStateChanged,
  reload,
  getIdTokenResult
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";

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

async function getClaimsAccess(currentUser) {
  try {
    const tokenResult = await getIdTokenResult(currentUser, true);
    const claims = tokenResult?.claims || {};

    const isAdmin = claims.admin === true;
    const isDeveloper = claims.developer === true || isAdmin;

    let role = "";
    if (isAdmin) {
      role = "admin";
    } else if (claims.developer === true) {
      role = "developer";
    }

    return {
      ok: true,
      isDeveloper,
      isAdmin,
      role,
      claims
    };
  } catch (error) {
    console.error("Failed to read token claims:", error);
    return {
      ok: false,
      isDeveloper: false,
      isAdmin: false,
      role: "",
      claims: {}
    };
  }
}

function createSingleRunGuard(handler, onError) {
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

      if (typeof onError === "function") {
        onError(error);
      } else {
        handleUnauthedState();
      }
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
  return createSingleRunGuard(
    async (user) => {
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
      const access = await getClaimsAccess(currentUser);

      if (!access.ok || !access.isDeveloper) {
        handleNonDeveloperState();
        return true;
      }

      if (typeof callback === "function") {
        await callback(currentUser, access);
      }

      return true;
    },
    () => {
      handleNonDeveloperState();
    }
  );
}

export async function getFreshIdToken() {
  const currentUser = auth.currentUser;

  if (!currentUser) {
    return "";
  }

  try {
    return await currentUser.getIdToken(true);
  } catch (error) {
    console.error("Failed to get fresh ID token:", error);
    return "";
  }
}

export { auth };
