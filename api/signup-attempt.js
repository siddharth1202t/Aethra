import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  safeNumber,
  safePositiveInt,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse,
  runRouteSecurity
} from "./_api-security.js";

const signupAttemptStore = new Map();
const ipAttemptStore = new Map();

const MAX_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;

const LOCK_WINDOW_MS = 15 * 60 * 1000;
const IP_LOCK_WINDOW_MS = 10 * 60 * 1000;
const STALE_RECORD_TTL_MS = 24 * 60 * 60 * 1000;

const ROUTE = "/api/signup-attempt";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_ACTIONS = new Set(["check", "fail"]);
const GOOGLE_PLACEHOLDER_EMAIL = "google-signup";

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getKey(email, ip) {
  return `${email}::${ip}`;
}

function cleanupStaleRecords() {
  const now = Date.now();

  for (const [key, record] of signupAttemptStore.entries()) {
    if (!record || now - safeNumber(record.lastAttempt) > STALE_RECORD_TTL_MS) {
      signupAttemptStore.delete(key);
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

function isGooglePlaceholderEmail(email) {
  return email === GOOGLE_PLACEHOLDER_EMAIL;
}

function buildLockResponse(isLocked, remainingMs = 0, extra = {}) {
  return {
    success: true,
    isLocked,
    remainingMs: isLocked ? Math.max(0, safePositiveInt(remainingMs, 0)) : 0,
    ...extra
  };
}

function getEscalatedLockMs(baseMs, escalationCount) {
  const multiplier = Math.min(4, 1 + safePositiveInt(escalationCount, 0) * 0.5);
  return Math.floor(baseMs * multiplier);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json(buildMethodNotAllowedResponse());
  }

  try {
    cleanupStaleRecords();

    const body = sanitizeBody(req.body, 20);

    const rawEmail = normalizeEmail(body.email);
    const action = safeString(body.action, 50).toLowerCase();
    const actionLabel = safeString(body.actionLabel, 100);
    const behavior =
      body.behavior && typeof body.behavior === "object" && !Array.isArray(body.behavior)
        ? body.behavior
        : {};
    const sessionId = safeString(behavior.sessionId || body.sessionId || "", 120);

    const security = runRouteSecurity({
      req,
      route: `${ROUTE}:${action || "unknown"}${actionLabel ? `:${actionLabel}` : ""}`,
      allowedOrigins: ALLOWED_ORIGINS,
      rateLimit: {
        key: `signup-attempt:${safeString(req?.headers?.["x-forwarded-for"] || req?.headers?.["x-real-ip"] || req?.socket?.remoteAddress || "unknown", 100)}`,
        limit: 35,
        windowMs: 10 * 60 * 1000
      },
      body,
      behavior,
      sessionId,
      abuseSuccess: action !== "fail"
    });

    const ip = security.ip;
    const origin = security.origin;

    if (!security.originAllowed) {
      await writeSecurityLog({
        type: "forbidden_signup_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on signup-attempt API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          origin,
          requestUserAgent: security.requestUserAgent
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden origin.", { action: "block" })
      );
    }

    if (security.rateLimitResult && !security.rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "signup_attempt_rate_limited",
        level: "warning",
        message: "Rate limit exceeded for signup attempt API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: security.rateLimitResult.recommendedAction,
          remainingMs: security.rateLimitResult.remainingMs || 0,
          violations: security.rateLimitResult.violations || 0
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later.",
        action: security.rateLimitResult.recommendedAction,
        remainingMs: security.rateLimitResult.remainingMs || 0
      });
    }

    if (!ALLOWED_ACTIONS.has(action)) {
      await writeSecurityLog({
        type: "invalid_signup_action",
        level: "warning",
        message: "Invalid action sent to signup-attempt API",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action
        }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid action."
      });
    }

    const emailIsAllowed = isValidEmail(rawEmail) || isGooglePlaceholderEmail(rawEmail);

    if (!rawEmail || !emailIsAllowed) {
      await writeSecurityLog({
        type: "invalid_signup_request",
        level: "warning",
        message: "Invalid email sent to signup-attempt API",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced"
        }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid email."
      });
    }

    const now = Date.now();
    const combinedRisk = security.combinedRisk;
    const finalAction = security.finalAction;

    if (finalAction === "block") {
      await writeSecurityLog({
        type: "blocked_suspicious_signup_request",
        level: "critical",
        message: "Blocked signup attempt API request due to suspicious behavior",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          action,
          actionLabel,
          botAnalysis: security.botAnalysis,
          abuseAnalysis: security.abuseAnalysis,
          combinedRisk,
          finalAction
        })
      });

      return res.status(429).json(
        buildBlockedResponse("Suspicious activity detected. Please try again later.", {
          action: finalAction
        })
      );
    }

    if (finalAction === "challenge" || finalAction === "throttle") {
      await writeSecurityLog({
        type: "temporary_signup_security_challenge",
        level: "warning",
        message: "Suspicious signup behavior detected",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          action,
          actionLabel,
          botAnalysis: security.botAnalysis,
          abuseAnalysis: security.abuseAnalysis,
          combinedRisk,
          finalAction
        })
      });
    }

    const ipRecord = getRecord(ipAttemptStore, ip);

    if (ipRecord.lockUntil > now) {
      return res.status(200).json(
        buildLockResponse(true, ipRecord.lockUntil - now, {
          risk: security.riskPayload
        })
      );
    }

    const key = getKey(rawEmail, ip);
    const record = getRecord(signupAttemptStore, key);

    if (action === "check") {
      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          risk: security.riskPayload
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
          type: "signup_lockout",
          level: "critical",
          message: "Too many signup attempts",
          email: rawEmail,
          ip,
          route: ROUTE,
          metadata: sanitizeMetadata({
            source: "server_enforced",
            attempts: record.count,
            escalationCount: record.escalationCount,
            actionLabel,
            botAnalysis: security.botAnalysis,
            abuseAnalysis: security.abuseAnalysis,
            combinedRisk,
            finalAction
          })
        });
      }

      if (ipRecord.count >= MAX_IP_ATTEMPTS) {
        ipRecord.escalationCount += 1;
        ipRecord.lockUntil = now + getEscalatedLockMs(IP_LOCK_WINDOW_MS, ipRecord.escalationCount);

        await writeSecurityLog({
          type: "ip_signup_lock",
          level: "critical",
          message: "IP temporarily blocked due to excessive signup attempts",
          ip,
          route: ROUTE,
          metadata: sanitizeMetadata({
            source: "server_enforced",
            attempts: ipRecord.count,
            escalationCount: ipRecord.escalationCount,
            actionLabel,
            combinedRisk,
            finalAction
          })
        });
      }

      saveRecord(signupAttemptStore, key, record);
      saveRecord(ipAttemptStore, ip, ipRecord);

      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          attempts: record.count,
          risk: security.riskPayload
        })
      );
    }

    return res.status(400).json({
      success: false,
      message: "Invalid request."
    });
  } catch (error) {
    console.error("Signup attempt API error:", error);

    try {
      await writeSecurityLog({
        type: "signup_attempt_api_error",
        level: "error",
        message: "Unhandled server error in signup-attempt API",
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
