const TURNSTILE_SITEKEY = "0x4AAAAAACqA_Z98nhvcobbI";

const TURNSTILE_WAIT_INTERVAL_MS = 250;
const TURNSTILE_MAX_WAIT_ATTEMPTS = 60;

window.aethraTurnstile = {
  widgetId: null,
  token: "",
  rendered: false,
  renderRequested: false,
  isWaitingForApi: false,

  setToken(token) {
    this.token = token || "";

    const tokenInput = document.getElementById("turnstileToken");
    if (tokenInput) {
      tokenInput.value = this.token;
    }

    const captchaError = document.getElementById("captchaError");
    if (captchaError && this.token) {
      captchaError.textContent = "";
    }
  },

  clearToken() {
    this.setToken("");
  },

  getToken() {
    return this.token || "";
  },

  showCaptchaError(message) {
    const captchaError = document.getElementById("captchaError");
    if (captchaError) {
      captchaError.textContent = message || "";
    }
  },

  reset() {
    this.clearToken();

    if (
      this.widgetId !== null &&
      window.turnstile &&
      typeof window.turnstile.reset === "function"
    ) {
      window.turnstile.reset(this.widgetId);
    }
  },

  render() {
    const container = document.getElementById("turnstile-container");

    if (!container || this.rendered) {
      return;
    }

    if (!window.turnstile || typeof window.turnstile.render !== "function") {
      return;
    }

    this.widgetId = window.turnstile.render(container, {
      sitekey: TURNSTILE_SITEKEY,
      theme: "dark",
      callback: (token) => {
        this.setToken(token);
      },
      "expired-callback": () => {
        this.clearToken();
      },
      "timeout-callback": () => {
        this.clearToken();
        this.showCaptchaError("Captcha timed out. Please try again.");
      },
      "error-callback": () => {
        this.clearToken();
        this.showCaptchaError(
          "Captcha failed to load. Refresh the page and try again."
        );
      }
    });

    this.rendered = true;
    this.renderRequested = true;
    this.showCaptchaError("");
  },

  ensureRendered() {
    if (this.rendered || this.renderRequested) {
      return;
    }

    this.renderRequested = true;

    if (window.turnstile && typeof window.turnstile.render === "function") {
      this.render();
      return;
    }

    this.waitForApiAndRender();
  },

  waitForApiAndRender() {
    if (this.isWaitingForApi) {
      return;
    }

    this.isWaitingForApi = true;
    let attempts = 0;

    const timer = window.setInterval(() => {
      attempts += 1;

      if (window.turnstile && typeof window.turnstile.render === "function") {
        window.clearInterval(timer);
        this.isWaitingForApi = false;
        this.render();
        return;
      }

      if (attempts >= TURNSTILE_MAX_WAIT_ATTEMPTS) {
        window.clearInterval(timer);
        this.isWaitingForApi = false;
        this.renderRequested = false;
        this.showCaptchaError(
          "Captcha could not be loaded. Please refresh the page."
        );
      }
    }, TURNSTILE_WAIT_INTERVAL_MS);
  }
};

function triggerTurnstileRender() {
  window.aethraTurnstile.ensureRendered();
}

function bindTurnstileLazyRender() {
  const form = document.getElementById("signupForm");
  const createAccountBtn = document.getElementById("createAccountBtn");

  const interactionSelectors = [
    "#name",
    "#email",
    "#password",
    "#confirmPassword"
  ];

  interactionSelectors.forEach((selector) => {
    const element = document.querySelector(selector);
    if (!element) return;

    element.addEventListener(
      "focus",
      () => {
        triggerTurnstileRender();
      },
      { once: true }
    );

    element.addEventListener(
      "pointerdown",
      () => {
        triggerTurnstileRender();
      },
      { once: true }
    );
  });

  if (createAccountBtn) {
    createAccountBtn.addEventListener("pointerdown", triggerTurnstileRender);
  }

  if (form) {
    form.addEventListener("submit", () => {
      triggerTurnstileRender();
    });
  }
}

document.addEventListener("DOMContentLoaded", bindTurnstileLazyRender);
