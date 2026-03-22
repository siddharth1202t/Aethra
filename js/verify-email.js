import {
  getAuth,
  onAuthStateChanged,
  reload,
  sendEmailVerification,
  signOut
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";

const RESEND_COOLDOWN_SECONDS = 60;
const AUTO_CHECK_INTERVAL_MS = 5000;

const auth = getAuth(app);

const verifyCard = document.getElementById("verifyCard");
const resendBtn = document.getElementById("resendBtn");
const logoutBtn = document.getElementById("logoutBtn");
const messageBox = document.getElementById("messageBox");

let resendCountdown = null;
let resendRemaining = 0;
let authHandled = false;
let resendInProgress = false;
let logoutInProgress = false;
let autoCheckInterval = null;

/* ---------------- NAVIGATION ---------------- */
const goTo = (page) => window.location.replace(page);

/* ---------------- UI HELPERS ---------------- */
const setPageVisible = () => {
  if (!verifyCard) return;
  verifyCard.style.visibility = "visible";
  window.requestAnimationFrame(() => {
    verifyCard.style.opacity = "1";
    verifyCard.style.transform = "translateY(0)";
  });
};

const showMessage = (text, type = "error") => {
  if (!messageBox) return;
  messageBox.textContent = String(text || "").trim();
  messageBox.className = `msg show ${type === "success" ? "success" : "error"}`;
};

const clearMessage = () => {
  if (!messageBox) return;
  messageBox.textContent = "";
  messageBox.className = "msg";
};

const setLoading = (button, text) => {
  if (!button) return;
  if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
  button.disabled = true;
  button.textContent = text;
};

const clearLoading = (button) => {
  if (!button) return;
  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
};

const clearResendCountdown = () => {
  if (resendCountdown) {
    clearInterval(resendCountdown);
    resendCountdown = null;
  }
};

const setResendCooldown = (seconds = RESEND_COOLDOWN_SECONDS) => {
  if (!resendBtn) return;
  resendRemaining = Math.max(0, Number(seconds));
  resendBtn.disabled = true;
  resendBtn.textContent = `Resend in ${resendRemaining}s`;
  clearResendCountdown();
  resendCountdown = setInterval(() => {
    resendRemaining -= 1;
    if (resendRemaining <= 0) {
      clearResendCountdown();
      resendBtn.disabled = false;
      resendBtn.textContent = resendBtn.dataset.originalText || "Resend Verification Email";
      return;
    }
    resendBtn.textContent = `Resend in ${resendRemaining}s`;
  }, 1000);
};

const refreshCurrentUser = async (user) => {
  if (!user) return null;
  await reload(user);
  return auth.currentUser;
};

/* ---------------- AUTO-CHECK VERIFICATION ---------------- */
const startAutoCheck = (user) => {
  autoCheckInterval = setInterval(async () => {
    try {
      const refreshedUser = await refreshCurrentUser(user);
      if (refreshedUser?.emailVerified) {
        clearInterval(autoCheckInterval);
        goTo("login.html");
      }
    } catch (error) {
      console.error("Auto verification check failed:", error);
    }
  }, AUTO_CHECK_INTERVAL_MS);
};

/* ---------------- AUTH GATE ---------------- */
onAuthStateChanged(auth, async (user) => {
  if (authHandled) return;
  if (!user) { authHandled = true; goTo("login.html"); return; }

  try {
    const refreshedUser = await refreshCurrentUser(user);
    if (refreshedUser?.emailVerified) {
      authHandled = true;
      goTo("login.html");
      return;
    }
    authHandled = true;
    setPageVisible();
    startAutoCheck(user);
  } catch (error) {
    console.error("Verification page auth refresh failed:", error);
    authHandled = true;
    setPageVisible();
    showMessage("Could not refresh your account status. Please try again.", "error");
  }
});

/* ---------------- ACTIONS ---------------- */
resendBtn?.addEventListener("click", async () => {
  if (resendInProgress || resendRemaining > 0) return;
  const user = auth.currentUser;
  if (!user) { goTo("login.html"); return; }

  resendInProgress = true;
  try {
    clearMessage();
    setLoading(resendBtn, "Sending...");
    await sendEmailVerification(user);
    showMessage("Verification email sent again. Check your inbox.", "success");
    setResendCooldown();
  } catch (error) {
    console.error("Resend verification failed:", error);
    showMessage("Could not resend verification email. Try again.", "error");
  } finally {
    clearLoading(resendBtn);
    resendInProgress = false;
  }
});

logoutBtn?.addEventListener("click", async () => {
  if (logoutInProgress) return;
  logoutInProgress = true;
  try {
    setLoading(logoutBtn, "Logging out...");
    if (resendBtn) resendBtn.disabled = true;
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
  if (autoCheckInterval) clearInterval(autoCheckInterval);
});
