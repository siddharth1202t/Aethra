import { writeSecurityLog } from "./_security-log.js";
import { checkApiRateLimit } from "./_rate-limit.js";
import { analyzeBotBehavior } from "./_bot-detection.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";

const loginAttemptStore = new Map();
const ipAttemptStore = new Map();

const MAX_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;

const LOCK_WINDOW_MS = 15 * 60 * 1000;
const IP_LOCK_WINDOW_MS = 10 * 60 * 1000;
const STALE_RECORD_TTL_MS = 24 * 60 * 60 * 1000;

const ROUTE = "/api/login-attempt";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_ACTIONS = new Set(["check", "fail"]);
const GOOGLE_PLACEHOLDER_EMAIL = "google-login";

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safePositiveInt(value, fallback = 0) {
  const num = Math.floor(safeNumber(value, fallback));
  return num >= 0 ? num : fallback;
}

function safeMetadata(metadata = {}) {
  try {
    return JSON.parse(JSON.stringify(metadata || {}));
  } catch {
    return {};
  }
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (typeof forwarded === "string") {
    const parts = forwarded.split(",");
    const ip = parts[0]?.trim();

    if (ip && ip.length < 60) {
      return ip;
    }
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length < 60) {
    return realIp.trim();
  }

  return safeString(req.socket?.remoteAddress || "unknown", 100);
}

function getKey(email, ip) {
  return `${email}::${ip}`;
}

function cleanupStaleRecords() {
  const now = Date.now();

  for (const [key, record] of loginAttemptStore.entries()) {
    if (!record || now - safeNumber(record.lastAttempt) > STALE_RECORD_TTL_MS) {
      loginAttemptStore.delete(key);
    }
  }

  for (const [ip, record] of ipAttemptStore.entries()) {
    if (!record || now - safeNumber(record.lastAttempt) > STALE_RECORD_TTL_MS) {
      ipAttemptStore.delete(ip);
    }
  }
}

function getRecord(store, key) {
  const now = Date.now();
  const record = store.get(key);

  if (!record) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now,
      escalationCount: 0
    };
  }

  const normalized = {
    count: safePositiveInt(record.count, 0),
    lockUntil: safePositiveInt(record.lockUntil, 0),
    lastAttempt: safePositiveInt(record.lastAttempt, now),
    escalationCount: safePositiveInt(record.escalationCount, 0)
  };

  if (normalized.lockUntil && now > normalized.lockUntil) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now,
      escalationCount: normalized.escalationCount
    };
  }

  return normalized;
}

function saveRecord(store, key, record) {
  store.set(key, {
    count: safePositiveInt(record.count, 0),
    lockUntil: safePositiveInt(record.lockUntil, 0),
    lastAttempt: safePositiveInt(record.lastAttempt, Date.now()),
    escalationCount: safePositiveInt(record.escalationCount, 0)
  });
}

function isAllowedOrigin(origin) {
  return ALLOWED_ORIGINS.has(origin);
}

function isGooglePlaceholderEmail(email) {
  return email === GOOGLE_PLACEHOLDER_EMAIL;
}

function buildRiskPayload(botAnalysis, abuseAnalysis, combinedRisk, finalAction) {
  return {
    botLevel: botAnalysis.level,
    abuseLevel: abuseAnalysis.level,
    botRecommendedAction: botAnalysis.recommendedAction,
    abuseRecommendedAction: abuseAnalysis.recommendedAction,
    combinedRisk,
    finalAction
  };
}

function buildSuspiciousResponse(
  message = "Suspicious activity detected. Please try again later.",
  extra = {}
) {
  return {
    success: false,
    message,
    ...extra
  };
}

function buildLockResponse(isLocked, remainingMs = 0, extra = {}) {
  return {
    success: true,
    isLocked,
    remainingMs: isLocked ? Math.max(0, safePositiveInt(remainingMs, 0)) : 0,
    ...extra
  };
}

function getCombinedRisk(botAnalysis, abuseAnalysis) {
  let score = 0;

  score += safePositiveInt(botAnalysis.riskScore, 0);
  score += safePositiveInt(abuseAnalysis.abuseScore, 0);

  if (botAnalysis.recommendedAction === "block") {
    score += 25;
  } else if (botAnalysis.recommendedAction === "challenge") {
    score += 15;
  }

  if (abuseAnalysis.recommendedAction === "block") {
    score += 25;
  } else if (abuseAnalysis.recommendedAction === "challenge") {
    score += 15;
  }

  if (safePositiveInt(abuseAnalysis.snapshot?.suspiciousEvents, 0) >= 3) {
    score += 10;
  }

  return Math.min(100, score);
}

function getFinalSecurityAction({ botAnalysis, abuseAnalysis, combinedRisk }) {
  if (
    botAnalysis.recommendedAction === "block" ||
    abuseAnalysis.recommendedAction === "block" ||
    combinedRisk >= 90
  ) {
    return "block";
  }

  if (
    botAnalysis.recommendedAction === "challenge" ||
    abuseAnalysis.recommendedAction === "challenge" ||
    combinedRisk >= 60
  ) {
    return "challenge";
  }

  if (
    botAnalysis.recommendedAction === "throttle" ||
    abuseAnalysis.recommendedAction === "throttle" ||
    combinedRisk >= 40
  ) {
    return "throttle";
  }

  return "allow";
}

function getEscalatedLockMs(baseMs, escalationCount) {
  const multiplier = Math.min(4, 1 + safePositiveInt(escalationCount, 0) * 0.5);
  return Math.floor(baseMs * multiplier);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed."
    });
  }

  try {
    cleanupStaleRecords();

    const origin = safeString(req.headers.origin || "", 200);
    const ip = getClientIp(req);
    const body = req.body && typeof req.body === "object" ? req.body : {};

    const rawEmail = normalizeEmail(body.email);
    const action = safeString(body.action, 50).toLowerCase();
    const actionLabel = safeString(body.actionLabel, 100);
    const behavior = body.behavior && typeof body.behavior === "object" ? body.behavior : {};
    const sessionId = safeString(behavior.sessionId || body.sessionId || "", 120);

    if (!isAllowedOrigin(origin)) {
      await writeSecurityLog({
        type: "forbidden_origin",
        level: "warning",
        message: "Blocked request from forbidden origin",
        ip,
        route: ROUTE,
        metadata: { origin, source: "server_enforced" }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin."
      });
    }

    const rateLimitResult = checkApiRateLimit({
      key: `login-attempt:${ip}`,
      limit: 40,
      windowMs: 10 * 60 * 1000,
      route: ROUTE
    });

    if (!rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "login_attempt_rate_limited",
        level: "warning",
        message: "Rate limit exceeded for login attempt API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: rateLimitResult.recommendedAction,
          remainingMs: rateLimitResult.remainingMs,
          violations: rateLimitResult.violations || 0
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later.",
        action: rateLimitResult.recommendedAction,
        remainingMs: rateLimitResult.remainingMs || 0
      });
    }

    if (!ALLOWED_ACTIONS.has(action)) {
      await writeSecurityLog({
        type: "invalid_login_action",
        level: "warning",
        message: "Invalid action sent",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: { action, source: "server_enforced" }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid action."
      });
    }

    const emailIsAllowed = isValidEmail(rawEmail) || isGooglePlaceholderEmail(rawEmail);

    if (!rawEmail || !emailIsAllowed) {
      await writeSecurityLog({
        type: "invalid_login_request",
        level: "warning",
        message: "Invalid email sent to login attempt API",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: { source: "server_enforced" }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid email."
      });
    }

    const now = Date.now();

    const botAnalysis = analyzeBotBehavior(
      { ...behavior, route: ROUTE },
      req
    );

    const abuseAnalysis = trackApiAbuse({
      ip,
      sessionId,
      route: `${ROUTE}:${action}${actionLabel ? `:${actionLabel}` : ""}`,
      success: action !== "fail"
    });

    const combinedRisk = getCombinedRisk(botAnalysis, abuseAnalysis);
    const finalAction = getFinalSecurityAction({
      botAnalysis,
      abuseAnalysis,
      combinedRisk
    });

    if (finalAction === "block") {
      await writeSecurityLog({
        type: "blocked_suspicious_request",
        level: "critical",
        message: "Blocked login attempt API request due to suspicious behavior",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: safeMetadata({
          source: "server_enforced",
          action,
          actionLabel,
          botAnalysis,
          abuseAnalysis,
          combinedRisk,
          finalAction
        })
      });

      return res.status(429).json(
        buildSuspiciousResponse("Suspicious activity detected. Please try again later.", {
          action: finalAction
        })
      );
    }

    if (finalAction === "challenge" || finalAction === "throttle") {
      await writeSecurityLog({
        type: "temporary_security_challenge",
        level: "warning",
        message: "Suspicious login behavior detected",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: safeMetadata({
          source: "server_enforced",
          action,
          actionLabel,
          botAnalysis,
          abuseAnalysis,
          combinedRisk,
          finalAction
        })
      });
    }

    const ipRecord = getRecord(ipAttemptStore, ip);

    if (ipRecord.lockUntil > now) {
      return res.status(200).json(
        buildLockResponse(true, ipRecord.lockUntil - now, {
          risk: buildRiskPayload(botAnalysis, abuseAnalysis, combinedRisk, finalAction)
        })
      );
    }

    const key = getKey(rawEmail, ip);
    const record = getRecord(loginAttemptStore, key);

    if (action === "check") {
      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          risk: buildRiskPayload(botAnalysis, abuseAnalysis, combinedRisk, finalAction)
        })
      );
    }

    if (action === "fail") {
      record.count += 1;
      record.lastAttempt = now;

      ipRecord.count += 1;
      ipRecord.lastAttempt = now;

      if (finalAction === "challenge" || finalAction === "throttle") {
        record.escalationCount += 1;
        ipRecord.escalationCount += 1;
      }

      if (record.count >= MAX_ATTEMPTS) {
        record.escalationCount += 1;
        record.lockUntil = now + getEscalatedLockMs(LOCK_WINDOW_MS, record.escalationCount);

        await writeSecurityLog({
          type: "login_lockout",
          level: "critical",
          message: "Too many login attempts",
          email: rawEmail,
          ip,
          route: ROUTE,
          metadata: safeMetadata({
            source: "server_enforced",
            attempts: record.count,
            escalationCount: record.escalationCount,
            actionLabel,
            botAnalysis,
            abuseAnalysis,
            combinedRisk,
            finalAction
          })
        });
      }

      if (ipRecord.count >= MAX_IP_ATTEMPTS) {
        ipRecord.escalationCount += 1;
        ipRecord.lockUntil = now + getEscalatedLockMs(IP_LOCK_WINDOW_MS, ipRecord.escalationCount);

        await writeSecurityLog({
          type: "ip_login_lock",
          level: "critical",
          message: "IP temporarily blocked due to excessive login attempts",
          ip,
          route: ROUTE,
          metadata: safeMetadata({
            source: "server_enforced",
            attempts: ipRecord.count,
            escalationCount: ipRecord.escalationCount,
            actionLabel,
            combinedRisk,
            finalAction
          })
        });
      }

      saveRecord(loginAttemptStore, key, record);
      saveRecord(ipAttemptStore, ip, ipRecord);

      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          attempts: record.count,
          risk: buildRiskPayload(botAnalysis, abuseAnalysis, combinedRisk, finalAction)
        })
      );
    }

    return res.status(400).json({
      success: false,
      message: "Invalid request."
    });
  } catch (error) {
    console.error("Login attempt API error:", error);

    try {
      await writeSecurityLog({
        type: "login_attempt_api_error",
        level: "error",
        message: "Unhandled server error",
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          error: safeString(error?.message || "Unknown error", 500)
        }
      });
    } catch (logError) {
      console.error("Security log write failed:", logError);
    }

    return res.status(500).json({
      success: false,
      message: "Internal server error."
    });
  }
}
