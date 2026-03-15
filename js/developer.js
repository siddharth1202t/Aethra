import { getAuth, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";
import { requireDeveloper } from "./auth-guard.js";
import { logSecurityEvent } from "./security-logger.js";

const auth = getAuth(app);

const wrap = document.querySelector(".wrap");
const logoutBtn = document.getElementById("logoutBtn");
const backHomeBtn = document.getElementById("backHomeBtn");

let pageAuthorized = false;
let logoutInProgress = false;

function goTo(page) {
  window.location.replace(page);
}

function setPageVisible() {
  if (wrap) {
    wrap.style.visibility = "visible";
  }
}

function setPageHidden() {
  if (wrap) {
    wrap.style.visibility = "hidden";
  }
}

function setButtonsDisabled(disabled) {
  if (logoutBtn) {
    logoutBtn.disabled = disabled;
  }

  if (backHomeBtn) {
    backHomeBtn.disabled = disabled;
  }
}

async function handleUnauthorizedAccess(reason = "developer_access_denied") {
  setPageHidden();
  setButtonsDisabled(true);

  try {
    await logSecurityEvent({
      type: "client_security_event",
      level: "warning",
      message: "Unauthorized attempt to access developer page",
      metadata: {
        reason,
        page: "developer.html"
      }
    });
  } catch (error) {
    console.error("Failed to log unauthorized developer access:", error);
  }

  goTo("home.html");
}

async function initializeDeveloperPage() {
  setPageHidden();
  setButtonsDisabled(true);

  try {
    await requireDeveloper(async () => {
      pageAuthorized = true;
      setPageVisible();
      setButtonsDisabled(false);
    });

    if (!pageAuthorized) {
      await handleUnauthorizedAccess("developer_check_failed");
    }
  } catch (error) {
    console.error("Developer access check failed:", error);
    await handleUnauthorizedAccess("developer_check_error");
  }
}

backHomeBtn?.addEventListener("click", () => {
  if (!pageAuthorized) {
    goTo("home.html");
    return;
  }

  goTo("home.html");
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

initializeDeveloperPage();
