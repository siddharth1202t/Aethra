import { getAuth, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { doc, getDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { app, db } from "./firestore-config.js";
import { requireAuth } from "./auth-guard.js";

const auth = getAuth(app);

const shell = document.querySelector(".shell");
const userRoleEl = document.getElementById("userRole");
const heroUsernameEl = document.getElementById("heroUsername");
const logoutBtn = document.getElementById("logoutBtn");
const devBtn = document.getElementById("devBtn");

let pageReady = false;
let logoutInProgress = false;

function goTo(page) {
  window.location.replace(page);
}

function setPageVisible() {
  if (!shell || pageReady) {
    return;
  }

  shell.style.visibility = "visible";
  shell.style.opacity = "1";
  shell.style.transform = "translateY(0)";
  pageReady = true;
}

function setPageLoadingState() {
  if (!shell) {
    return;
  }

  shell.style.visibility = "visible";
  shell.style.opacity = "0";
  shell.style.transform = "translateY(8px)";
  shell.style.transition = "opacity 260ms ease, transform 260ms ease";
}

function getBestDisplayName(user) {
  const directName = user?.displayName?.trim();
  const providerName = user?.providerData?.[0]?.displayName?.trim();
  const emailName = user?.email ? user.email.split("@")[0] : "";

  return directName || providerName || emailName || "Explorer";
}

function setDefaultUserUI(user) {
  if (heroUsernameEl) {
    heroUsernameEl.textContent = getBestDisplayName(user);
  }

  if (userRoleEl) {
    userRoleEl.textContent = "User";
  }

  if (devBtn) {
    devBtn.style.display = "none";
  }
}

async function hydrateRole(user) {
  if (!user?.uid) {
    return;
  }

  try {
    const userRef = doc(db, "users", user.uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) {
      return;
    }

    const userData = userSnap.data() || {};
    const role = String(userData.role || "").toLowerCase();
    const isDeveloper = role === "developer";

    if (userRoleEl) {
      userRoleEl.textContent = isDeveloper ? "Developer" : "User";
    }

    if (devBtn) {
      devBtn.style.display = isDeveloper ? "block" : "none";
    }
  } catch (error) {
    console.error("Role hydration failed:", error);
  }
}

function bindActions() {
  devBtn?.addEventListener("click", () => {
    goTo("developer.html");
  });

  logoutBtn?.addEventListener("click", async () => {
    if (logoutInProgress) {
      return;
    }

    logoutInProgress = true;

    try {
      if (logoutBtn) {
        logoutBtn.disabled = true;
        logoutBtn.textContent = "Logging out...";
      }

      await signOut(auth);
    } catch (error) {
      console.error("Logout failed:", error);
    } finally {
      goTo("login.html");
    }
  });
}

async function initHomePage() {
  setPageLoadingState();
  bindActions();

  requireAuth(async (user) => {
    try {
      setDefaultUserUI(user);
      setPageVisible();

      await hydrateRole(user);
    } catch (error) {
      console.error("Home auth setup failed:", error);
      setDefaultUserUI(user);
      setPageVisible();
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initHomePage, { once: true });
} else {
  initHomePage();
}
