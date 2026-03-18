const TURNSTILE_SITEKEY = "0x4AAAAAACqA_Z98nhvcobbI";

window.aethraTurnstile = {
  widgetId: null,
  token: "",
  rendered: false,

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
        const captchaError = document.getElementById("captchaError");
        if (captchaError) {
          captchaError.textContent = "Captcha timed out. Please try again.";
        }
      },
      "error-callback": () => {
        this.clearToken();
        const captchaError = document.getElementById("captchaError");
        if (captchaError) {
          captchaError.textContent =
            "Captcha failed to load. Refresh the page and try again.";
        }
      }
    });

    this.rendered = true;
  }
};

function waitForTurnstileAndRender() {
  let attempts = 0;
  const maxAttempts = 60;

  const timer = window.setInterval(() => {
    attempts += 1;

    if (window.turnstile && typeof window.turnstile.render === "function") {
      window.clearInterval(timer);
      window.aethraTurnstile.render();
      return;
    }

    if (attempts >= maxAttempts) {
      window.clearInterval(timer);
      const captchaError = document.getElementById("captchaError");
      if (captchaError) {
        captchaError.textContent =
          "Captcha could not be loaded. Please refresh the page.";
      }
    }
  }, 250);
}

document.addEventListener("DOMContentLoaded", waitForTurnstileAndRender);
