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
const starsContainer = document.getElementById("stars");

function goTo(page) {
  window.location.replace(page);
}

function createStars() {
  if (!starsContainer || starsContainer.dataset.ready === "true") return;

  const fragment = document.createDocumentFragment();

  for (let i = 0; i < 90; i += 1) {
    const star = document.createElement("div");
    star.classList.add("star");

    const size = Math.random() * 2.2 + 1;
    star.style.width = `${size}px`;
    star.style.height = `${size}px`;
    star.style.left = `${Math.random() * 100}vw`;
    star.style.top = `${Math.random() * 100}vh`;
    star.style.animationDuration = `${Math.random() * 4 + 2}s`;
    star.style.animationDelay = `${Math.random() * 4}s`;

    fragment.appendChild(star);
  }

  starsContainer.appendChild(fragment);
  starsContainer.dataset.ready = "true";
}

function setPageVisible() {
  if (shell) {
    shell.style.visibility = "visible";
  }
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
  if (!user?.uid) return;

  try {
    const userRef = doc(db, "users", user.uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) {
      return;
    }

    const userData = userSnap.data() || {};
    const isDeveloper = String(userData.role || "").toLowerCase() === "developer";

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

requireAuth(async (user) => {
  try {
    // Show useful UI immediately after auth is confirmed.
    setDefaultUserUI(user);
    setPageVisible();

    // Load role in the background so the page feels instant.
    await hydrateRole(user);
  } catch (error) {
    console.error("Home auth setup failed:", error);
    setDefaultUserUI(user);
    setPageVisible();
  }
});

devBtn?.addEventListener("click", () => {
  goTo("developer.html");
});

logoutBtn?.addEventListener("click", async () => {
  try {
    logoutBtn.disabled = true;
    logoutBtn.textContent = "Logging out...";
    await signOut(auth);
  } catch (error) {
    console.error("Logout failed:", error);
  } finally {
    goTo("login.html");
  }
});

createStars();
