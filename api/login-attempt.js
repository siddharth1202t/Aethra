import { writeSecurityLog } from "./_security-log.js";

const loginAttemptStore = new Map();

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return "unknown";
}

function getKey(email, ip) {
  return `${email}::${ip}`;
}

function getRecord(key) {
  const now = Date.now();
  const record = loginAttemptStore.get(key);

  if (!record) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now
    };
  }

  if (record.lockUntil && now > record.lockUntil) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now
    };
  }

  return record;
}

function saveRecord(key, record) {
  loginAttemptStore.set(key, record);
}

function isAllowedOrigin(origin) {
  const allowedOrigins = [
    "https://aethra-gules.vercel.app",
    "https://aethra-hb2h.vercel.app"
  ];
  return allowedOrigins.includes(origin);
}

function isTrustedSuccessReset(req) {
  const incomingSecret = req.headers["x-login-reset-secret"];
  const expectedSecret = process.env.LOGIN_RESET_SECRET;
  return Boolean(expectedSecret && incomingSecret && incomingSecret === expectedSecret);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }

  try {
    const origin = req.headers.origin || "";
    const ip = getClientIp(req);

    if (!isAllowedOrigin(origin)) {
      await writeSecurityLog({
        type: "forbidden_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on login-attempt API",
        ip,
        route: "/api/login-attempt",
        metadata: { origin }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin"
      });
    }

    const { email, action } = req.body || {};
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail) {
      await writeSecurityLog({
        type: "invalid_login_attempt_request",
        level: "warning",
        message: "Missing email in login-attempt API request",
        ip,
        route: "/api/login-attempt",
        metadata: { action: action || "" }
      });

      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    if (!isValidEmail(normalizedEmail)) {
      await writeSecurityLog({
        type: "invalid_login_attempt_email",
        level: "warning",
        message: "Invalid email format sent to login-attempt API",
        email: normalizedEmail,
        ip,
        route: "/api/login-attempt",
        metadata: { action: action || "" }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid email format"
      });
    }

    if (!action || !["check", "fail", "success"].includes(action)) {
      await writeSecurityLog({
        type: "invalid_login_attempt_action",
        level: "warning",
        message: "Invalid action sent to login-attempt API",
        email: normalizedEmail,
        ip,
        route: "/api/login-attempt",
        metadata: { action: action || "" }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid action"
      });
    }

    const key = getKey(normalizedEmail, ip);
    const now = Date.now();
    let record = getRecord(key);

    if (action === "check") {
      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      return res.status(200).json({
        success: true,
        isLocked,
        remainingMs
      });
    }

    if (action === "fail") {
      record.count += 1;
      record.lastAttempt = now;

      if (record.count >= 5) {
        record.lockUntil = now + 15 * 60 * 1000;

        await writeSecurityLog({
          type: "login_lockout",
          level: "critical",
          message: "Too many failed login attempts triggered temporary lock",
          email: normalizedEmail,
          ip,
          route: "/api/login-attempt",
          metadata: {
            attempts: record.count,
            lockUntil: record.lockUntil
          }
        });
      } else {
        await writeSecurityLog({
          type: "login_failed_attempt",
          level: "warning",
          message: "Failed login attempt recorded",
          email: normalizedEmail,
          ip,
          route: "/api/login-attempt",
          metadata: {
            attempts: record.count
          }
        });
      }

      saveRecord(key, record);

      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      return res.status(200).json({
        success: true,
        isLocked,
        remainingMs,
        attempts: record.count
      });
    }

    if (action === "success") {
      if (!isTrustedSuccessReset(req)) {
        await writeSecurityLog({
          type: "unauthorized_login_success_reset",
          level: "critical",
          message: "Blocked unauthorized login success reset attempt",
          email: normalizedEmail,
          ip,
          route: "/api/login-attempt",
          metadata: {}
        });

        return res.status(403).json({
          success: false,
          message: "Unauthorized reset attempt"
        });
      }

      loginAttemptStore.delete(key);

      await writeSecurityLog({
        type: "login_attempt_reset",
        level: "info",
        message: "Login attempt counter reset after trusted success flow",
        email: normalizedEmail,
        ip,
        route: "/api/login-attempt",
        metadata: {}
      });

      return res.status(200).json({
        success: true,
        reset: true
      });
    }

    return res.status(400).json({
      success: false,
      message: "Unhandled action"
    });
  } catch (error) {
    console.error("Login attempt API error:", error);

    await writeSecurityLog({
      type: "login_attempt_api_error",
      level: "error",
      message: "Unhandled server error in login-attempt API",
      ip: getClientIp(req),
      route: "/api/login-attempt",
      metadata: {
        error: error?.message || "Unknown error"
      }
    });

    return res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
}
