function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

export async function writeSecurityLog(data = {}) {
  try {
    const payload = {
      type: safeString(data.type || "unknown", 50),
      message: safeString(data.message || "", 500),
      email: safeString(data.email || "", 200),
      userId: safeString(data.userId || "", 200),

      metadata: data.metadata || {},

      client: {
        userAgent: safeString(navigator.userAgent || "", 300),
        language: safeString(navigator.language || "", 40),
        platform: safeString(navigator.platform || "", 100),

        screenWidth: safeNumber(window.screen?.width),
        screenHeight: safeNumber(window.screen?.height),

        url: safeString(window.location.href || "", 500),
        referrer: safeString(document.referrer || "", 500)
      }
    };

    await fetch("/api/security-log", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

  } catch (error) {
    console.warn("Security log failed:", error);
  }
}
