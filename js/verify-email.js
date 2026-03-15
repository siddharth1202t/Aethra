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

function goTo(page) {
  window.location.replace(page);
}

function setPageVisible() {
  if (verifyCard) {
    verifyCard.style.visibility = "visible";
  }
}

function showMessage(text, type = "error") {
  if (!messageBox) return;
  messageBox.textContent = text;
  messageBox.className = `msg show ${type}`;
}

function clearMessage() {
  if (!messageBox) return;
  messageBox.textContent = "";
  messageBox.className = "msg";
}

function setLoading(button, text) {
  if (!button) return;
  button.dataset.originalText = button.dataset.originalText || button.textContent;
  button.disabled = true;
  button.textContent = text;
}

function clearLoading(button) {
  if (!button) return;
  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
}

function clearResendCountdown() {
  if (resendCountdown) {
    clearInterval(resendCountdown);
    resendCountdown = null;
  }
}

function setResendCooldown(seconds = RESEND_COOLDOWN_SECONDS) {
  if (!resendBtn) return;

  resendRemaining = seconds;
  resendBtn.disabled = true;
  resendBtn.textContent = `Resend available in ${resendRemaining}s`;

  clearResendCountdown();

  resendCountdown = setInterval(() => {
    resendRemaining -= 1;

    if (resendRemaining <= 0) {
      clearResendCountdown();
      resendBtn.disabled = false;
      resendBtn.textContent = "Resend Verification Email";
      return;
    }

    resendBtn.textContent = `Resend available in ${resendRemaining}s`;
  }, 1000);
}

onAuthStateChanged(auth, async (user) => {
  if (authHandled) return;

  if (!user) {
    authHandled = true;
    goTo("login.html");
    return;
  }

  try {
    await reload(user);

    if (auth.currentUser?.emailVerified) {
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
    showMessage("Could not refresh your account status. Please try again.", "error");
  }
});

resendBtn?.addEventListener("click", async () => {
  const user = auth.currentUser;

  if (!user) {
    goTo("login.html");
    return;
  }

  if (resendRemaining > 0) {
    return;
  }

  try {
    clearMessage();
    setLoading(resendBtn, "Sending...");
    await sendEmailVerification(user);
    showMessage("Verification email sent again. Please check your inbox.", "success");
    clearLoading(resendBtn);
    setResendCooldown();
  } catch (error) {
    console.error("Resend verification failed:", error);
    clearLoading(resendBtn);
    showMessage("Could not resend verification email right now. Please try again.", "error");
  }
});

refreshBtn?.addEventListener("click", async () => {
  const user = auth.currentUser;

  if (!user) {
    goTo("login.html");
    return;
  }

  try {
    clearMessage();
    setLoading(refreshBtn, "Checking...");
    await reload(user);

    if (auth.currentUser?.emailVerified) {
      goTo("home.html");
      return;
    }

    showMessage("Your email is still not verified yet. Please verify it first, then try again.", "error");
  } catch (error) {
    console.error("Verification refresh failed:", error);
    showMessage("Could not refresh your verification status. Please try again.", "error");
  } finally {
    clearLoading(refreshBtn);
  }
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

window.addEventListener("beforeunload", () => {
  clearResendCountdown();
});
