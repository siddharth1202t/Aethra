import {
  getAuth,
  onAuthStateChanged,
  reload,
  sendEmailVerification,
  signOut
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";

const RESEND_COOLDOWN_SECONDS = 60;

const auth = getAuth(app);

const verifyCard = document.getElementById("verifyCard");
const resendBtn = document.getElementById("resendBtn");
const refreshBtn = document.getElementById("refreshBtn");
const logoutBtn = document.getElementById("logoutBtn");
const messageBox = document.getElementById("messageBox");

let resendCountdown = null;
let resendRemaining = 0;
let authHandled = false;
let resendInProgress = false;
let refreshInProgress = false;
let logoutInProgress = false;

/* ---------------- BASIC HELPERS ---------------- */

function goTo(page) {
  window.location.replace(page);
}

function setPageVisible() {
  if (!verifyCard) {
    return;
  }

  verifyCard.style.visibility = "visible";

  window.requestAnimationFrame(() => {
    verifyCard.style.opacity = "1";
    verifyCard.style.transform = "translateY(0)";
  });
}

function showMessage(text, type = "error") {
  if (!messageBox) {
    return;
  }

  messageBox.textContent = String(text || "").trim();
  messageBox.className = msg show ${type === "success" ? "success" : "error"};
}

function clearMessage() {
  if (!messageBox) {
    return;
  }

  messageBox.textContent = "";
  messageBox.className = "msg";
}

function setLoading(button, text) {
  if (!button) {
    return;
  }

  if (!button.dataset.originalText) {
    button.dataset.originalText = button.textContent;
  }

  button.disabled = true;
  button.textContent = text;
}

function clearLoading(button) {
  if (!button) {
    return;
  }

  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
}

function clearResendCountdown() {
  if (resendCountdown) {
    window.clearInterval(resendCountdown);
    resendCountdown = null;
  }
}

function setResendCooldown(seconds = RESEND_COOLDOWN_SECONDS) {
  if (!resendBtn) {
    return;
  }

  resendRemaining = Math.max(0, Number(seconds) || 0);
  resendBtn.disabled = true;
  resendBtn.textContent = Resend available in ${resendRemaining}s;

  clearResendCountdown();

  resendCountdown = window.setInterval(() => {
    resendRemaining -= 1;

    if (resendRemaining <= 0) {
      clearResendCountdown();
      resendBtn.disabled = false;
      resendBtn.textContent =
        resendBtn.dataset.originalText || "Resend Verification Email";
      return;
    }

    resendBtn.textContent = Resend available in ${resendRemaining}s;
  }, 1000);
}

async function refreshCurrentUser(user) {
  if (!user) {
    return null;
  }

  await reload(user);
  return auth.currentUser;
}

/* ---------------- AUTH GATE ---------------- */

onAuthStateChanged(auth, async (user) => {
  if (authHandled) {
    return;
  }

  if (!user) {
    authHandled = true;
    goTo("login.html");
    return;
  }

  try {
    const refreshedUser = await refreshCurrentUser(user);

    if (refreshedUser?.emailVerified) {
      authHandled = true;
      goTo("home.html");
      return;
    }

    authHandled = true;
    setPageVisible();
  } catch (error) {
    console.error("Verification page auth refresh failed:", error);
    authHandled = true;
    setPageVisible();
    showMessage(
      "Could not refresh your account status. Please try again.",
      "error"
    );
  }
});

/* ---------------- ACTIONS ---------------- */

resendBtn?.addEventListener("click", async () => {
  if (resendInProgress || resendRemaining > 0) {
    return;
  }

  const user = auth.currentUser;

  if (!user) {
    goTo("login.html");
    return;
  }

  resendInProgress = true;

  try {
    clearMessage();
    setLoading(resendBtn, "Sending...");

    await sendEmailVerification(user);

    showMessage(
      "Verification email sent again. Please check your inbox.",
      "success"
    );

    clearLoading(resendBtn);
    setResendCooldown();
  } catch (error) {
    console.error("Resend verification failed:", error);
    clearLoading(resendBtn);
    showMessage(
      "Could not resend verification email right now. Please try again.",
      "error"
    );
  } finally {
    resendInProgress = false;
  }
});

refreshBtn?.addEventListener("click", async () => {
  if (refreshInProgress) {
    return;
  }

  const user = auth.currentUser;

  if (!user) {
    goTo("login.html");
    return;
  }

  refreshInProgress = true;

  try {
    clearMessage();
    setLoading(refreshBtn, "Checking...");

    const refreshedUser = await refreshCurrentUser(user);

    if (refreshedUser?.emailVerified) {
      goTo("home.html");
      return;
    }

    showMessage(
      "Your email is still not verified yet. Please verify it first, then try again.",
      "error"
    );
  } catch (error) {
    console.error("Verification refresh failed:", error);
    showMessage(
      "Could not refresh your verification status. Please try again.",
      "error"
    );
  } finally {
    clearLoading(refreshBtn);
    refreshInProgress = false;
  }
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

    if (refreshBtn) {
      refreshBtn.disabled = true;
    }

    if (resendBtn) {
      resendBtn.disabled = true;
    }

    await signOut(auth);
  } catch (error) {
    console.error("Logout failed:", error);
  } finally {
    goTo("login.html");
  }
});

/* ---------------- CLEANUP ---------------- */

window.addEventListener("beforeunload", () => {
  clearResendCountdown();
});
 = 5000;
