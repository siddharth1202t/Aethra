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
let pageInitializing = true;

function goTo(page) {
  window.location.replace(page);
}

function safeSetText(element, value) {
  if (element) {
    element.textContent = String(value || "");
  }
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

function isDeveloperAccessRestricted(containmentState) {
  if (!containmentState || typeof containmentState !== "object") {
    return false;
  }

  const flags = containmentState.flags || {};
  return flags.readOnlyMode === true || flags.lockAdminWrites === true;
}

async function handleUnauthorizedAccess(reason = "developer_access_denied") {
  pageAuthorized = false;
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

async function handleContainmentRestriction(reason = "developer_access_restricted") {
  pageAuthorized = false;
  setPageHidden();
  setButtonsDisabled(true);

  try {
    await logSecurityEvent({
      type: "client_security_event",
      level: "warning",
      message: "Developer page access restricted by containment policy",
      metadata: {
        reason,
        page: "developer.html"
      }
    });
  } catch (error) {
    console.error("Failed to log containment-restricted developer access:", error);
  }

  goTo("home.html");
}

async function initializeDeveloperPage() {
  setPageHidden();
  setButtonsDisabled(true);
  pageInitializing = true;

  try {
    const containmentState = await fetchContainmentState();

    if (isDeveloperAccessRestricted(containmentState)) {
      await handleContainmentRestriction("containment_lock_active");
      return;
    }

    await requireDeveloper(async () => {
      pageAuthorized = true;
      setPageVisible();
      setButtonsDisabled(false);
    });

    if (!pageAuthorized) {
      await handleUnauthorizedAccess("developer_check_failed");
      return;
    }

    try {
      await logSecurityEvent({
        type: "client_security_event",
        level: "info",
        message: "Developer page access granted",
        metadata: {
          page: "developer.html"
        }
      });
    } catch (error) {
      console.error("Failed to log developer access grant:", error);
    }
  } catch (error) {
    console.error("Developer access check failed:", error);
    await handleUnauthorizedAccess("developer_check_error");
  } finally {
    pageInitializing = false;
  }
}

backHomeBtn?.addEventListener("click", () => {
  if (pageInitializing) {
    return;
  }

  goTo("home.html");
});

logoutBtn?.addEventListener("click", async () => {
  if (logoutInProgress || pageInitializing) {
    return;
  }

  logoutInProgress = true;
  setButtonsDisabled(true);

  try {
    safeSetText(logoutBtn, "Logging out...");

    try {
      await logSecurityEvent({
        type: "client_security_event",
        level: "info",
        message: "Developer initiated logout",
        metadata: {
          page: "developer.html"
        }
      });
    } catch (error) {
      console.error("Failed to log developer logout:", error);
    }

    await signOut(auth);
  } catch (error) {
    console.error("Logout failed:", error);
  } finally {
    goTo("login.html");
  }
});

initializeDeveloperPage();
