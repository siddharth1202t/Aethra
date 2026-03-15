import { getAuth, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";
import { requireDeveloper } from "./auth-guard.js";

const auth = getAuth(app);

const wrap = document.querySelector(".wrap");
const logoutBtn = document.getElementById("logoutBtn");
const backHomeBtn = document.getElementById("backHomeBtn");

function goTo(page) {
  window.location.replace(page);
}

function setPageVisible() {
  if (wrap) {
    wrap.style.visibility = "visible";
  }
}

requireDeveloper(() => {
  setPageVisible();
});

backHomeBtn?.addEventListener("click", () => {
  goTo("home.html");
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
