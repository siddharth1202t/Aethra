import { getAuth, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { doc, getDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { app, db } from "./firestore-config.js";
import { ensureUserProfile } from "./user-profile.js";
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
  if (!starsContainer) return;

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

    starsContainer.appendChild(star);
  }
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

requireAuth(async (user) => {
  try {
    await ensureUserProfile(user);

    if (heroUsernameEl) {
      heroUsernameEl.textContent = getBestDisplayName(user);
    }

    let isDeveloper = false;

    const userRef = doc(db, "users", user.uid);
    const userSnap = await getDoc(userRef);

    if (userSnap.exists()) {
      const userData = userSnap.data() || {};
      isDeveloper = String(userData.role || "").toLowerCase() === "developer";
    }

    if (userRoleEl) {
      userRoleEl.textContent = isDeveloper ? "Developer" : "User";
    }

    if (devBtn) {
      devBtn.style.display = isDeveloper ? "block" : "none";
    }

    setPageVisible();
  } catch (error) {
    console.error("Home auth setup failed:", error);

    if (heroUsernameEl) {
      heroUsernameEl.textContent = "Explorer";
    }

    if (userRoleEl) {
      userRoleEl.textContent = "User";
    }

    if (devBtn) {
      devBtn.style.display = "none";
    }

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
