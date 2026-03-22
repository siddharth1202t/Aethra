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

/* ---------------- DOM ---------------- */
const verifyCard = document.getElementById("verifyCard");
const resendBtn = document.getElementById("resendBtn");
const refreshBtn = document.getElementById("refreshBtn");
const logoutBtn = document.getElementById("logoutBtn");
const messageBox = document.getElementById("messageBox");

let resendCountdown = null;
let resendRemaining = 0;
let authHandled = false;
let actionInProgress = false;

/* ---------------- HELPERS ---------------- */
function goTo(page) { window.location.replace(page); }

function showMessage(text, type = "error") {
  if (!messageBox) return;
  messageBox.textContent = String(text || "").trim();
  messageBox.className = `msg show ${type === "success" ? "success" : "error"}`;
}

function clearMessage() {
  if (!messageBox) return;
  messageBox.textContent = "";
  messageBox.className = "msg";
}

function setLoading(button, text) {
  if (!button) return;
  if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
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
  resendRemaining = Math.max(0, Number(seconds) || 0);
  resendBtn.disabled = true;
  resendBtn.textContent = `Resend in ${resendRemaining}s`;

  clearResendCountdown();
  resendCountdown = setInterval(() => {
    resendRemaining--;
    if (resendRemaining <= 0) {
      clearResendCountdown();
      resendBtn.disabled = false;
      resendBtn.textContent = resendBtn.dataset.originalText || "Resend Verification Email";
      return;
    }
    resendBtn.textContent = `Resend in ${resendRemaining}s`;
  }, 1000);
}

async function refreshCurrentUser(user) {
  if (!user) return null;
  await reload(user);
  return auth.currentUser;
}

/* ---------------- AUTH CHECK ---------------- */
onAuthStateChanged(auth, async (user) => {
  if (authHandled) return;

  if (!user) { authHandled = true; goTo("login.html"); return; }

  try {
    const refreshedUser = await refreshCurrentUser(user);
    if (refreshedUser?.emailVerified) { authHandled = true; goTo("home.html"); return; }
    authHandled = true;
    if (verifyCard) verifyCard.style.visibility = "visible";
  } catch {
    authHandled = true;
    if (verifyCard) verifyCard.style.visibility = "visible";
    showMessage("Could not refresh account status. Try again.", "error");
  }
});

/* ---------------- ACTIONS ---------------- */
resendBtn?.addEventListener("click", async () => {
  if (actionInProgress || resendRemaining > 0) return;
  const user = auth.currentUser;
  if (!user) { goTo("login.html"); return; }

  actionInProgress = true;
  clearMessage();
  setLoading(resendBtn, "Sending...");

  try {
    await sendEmailVerification(user);
    showMessage("Verification email sent. Check your inbox.", "success");
    setResendCooldown();
  } catch {
    showMessage("Failed to resend email. Try again.", "error");
  } finally {
    clearLoading(resendBtn);
    actionInProgress = false;
  }
});

refreshBtn?.addEventListener("click", async () => {
  if (actionInProgress) return;
  const user = auth.currentUser;
  if (!user) { goTo("login.html"); return; }

  actionInProgress = true;
  clearMessage();
  setLoading(refreshBtn, "Checking...");

  try {
    const refreshedUser = await refreshCurrentUser(user);
    if (refreshedUser?.emailVerified) { goTo("home.html"); return; }
    showMessage("Email not verified yet. Please check your inbox.", "error");
  } catch {
    showMessage("Failed to refresh status. Try again.", "error");
  } finally {
    clearLoading(refreshBtn);
    actionInProgress = false;
  }
});

logoutBtn?.addEventListener("click", async () => {
  if (actionInProgress) return;
  actionInProgress = true;

  try {
    [logoutBtn, resendBtn, refreshBtn].forEach(b => b && (b.disabled = true));
    await signOut(auth);
  } catch {}
  finally { goTo("login.html"); }
});

/* ---------------- CLEANUP ---------------- */
window.addEventListener("beforeunload", clearResendCountdown);
