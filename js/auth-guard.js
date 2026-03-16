import {
  getAuth,
  onAuthStateChanged,
  reload,
  getIdTokenResult
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";

const auth = getAuth(app);

function safeString(value, maxLength = 300) {
  return String(value || "").trim().slice(0, maxLength);
}

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

async function fetchContainmentState() {
  try {
    const response = await fetch("/api/security-containment-state", {
      method: "GET",
      headers: {
        "Content-Type": "application/json"
      }
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json().catch(() => null);
    return data && typeof data === "object" ? data : null;
  } catch (error) {
    console.warn("Containment state fetch failed:", error);
    return null;
  }
}

function isDeveloperRestrictedByContainment(containmentState) {
  if (!containmentState || typeof containmentState !== "object") {
    return false;
  }

  const flags = containmentState.flags || {};
  return flags.readOnlyMode === true || flags.lockAdminWrites === true;
}

async function resolveVerifiedUser(user) {
  if (!user) {
    return { ok: false, reason: "not-authenticated" };
  }

  try {
    await reload(user);
  } catch (error) {
    console.error("Failed to reload auth user:", error);
  }

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

    let role = "user";
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
      role: "user",
      claims: {}
    };
  }
}

function createSingleRunGuard(handler, onError) {
  let handled = false;
  let unsubscribe = null;

  unsubscribe = onAuthStateChanged(auth, async (user) => {
    if (handled) {
      return;
    }

    try {
      const done = await handler(user);

      if (done) {
        handled = true;

        if (typeof unsubscribe === "function") {
          unsubscribe();
        }
      }
    } catch (error) {
      console.error("Auth guard failed:", error);
      handled = true;

      if (typeof unsubscribe === "function") {
        unsubscribe();
      }

      if (typeof onError === "function") {
        onError(error);
      } else {
        handleUnauthedState();
      }
    }
  });

  return unsubscribe;
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

      const containmentState = await fetchContainmentState();

      if (isDeveloperRestrictedByContainment(containmentState)) {
        handleNonDeveloperState();
        return true;
      }

      if (typeof callback === "function") {
        await callback(currentUser, access, containmentState);
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

export async function getCurrentAccessProfile() {
  const currentUser = auth.currentUser;

  if (!currentUser) {
    return {
      ok: false,
      reason: "not-authenticated",
      role: "guest",
      isDeveloper: false,
      isAdmin: false
    };
  }

  const verified = await resolveVerifiedUser(currentUser);

  if (!verified.ok) {
    return {
      ok: false,
      reason: safeString(verified.reason || "not-verified", 80),
      role: "user",
      isDeveloper: false,
      isAdmin: false
    };
  }

  const access = await getClaimsAccess(verified.user);

  if (!access.ok) {
    return {
      ok: false,
      reason: "claims-unavailable",
      role: "user",
      isDeveloper: false,
      isAdmin: false
    };
  }

  const containmentState = await fetchContainmentState();
  const containmentRestricted = isDeveloperRestrictedByContainment(containmentState);

  return {
    ok: true,
    role: access.role,
    isDeveloper: access.isDeveloper,
    isAdmin: access.isAdmin,
    containmentRestricted,
    claims: access.claims
  };
}

export { auth };
