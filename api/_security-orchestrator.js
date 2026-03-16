import { redis } from "./_redis.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  safeString,
  safePositiveInt,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse
} from "./_api-security.js";

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

function buildSignupAttemptKey(email, ip) {
  return `signup-attempt:${safeString(getKey(email, ip), 260)}`;
}

function buildIpAttemptKey(ip) {
  return `signup-attempt-ip:${safeString(ip, 120)}`;
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(safeString(origin, 200).trim().toLowerCase());
}

async function getStoredRecord(redisKey) {
  const now = Date.now();

  try {
    const raw = await redis.get(redisKey);

    if (!raw) {
      return {
        count: 0,
        lockUntil: 0,
        lastAttempt: now,
        escalationCount: 0
      };
    }

    const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;

    const normalized = {
      count: safePositiveInt(parsed?.count, 0),
      lockUntil: safePositiveInt(parsed?.lockUntil, 0),
      lastAttempt: safePositiveInt(parsed?.lastAttempt, now),
      escalationCount: safePositiveInt(parsed?.escalationCount, 0)
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
  } catch (error) {
    console.error("Redis signup-attempt read failed:", error);

    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now,
      escalationCount: 0
    };
  }
}

async function saveStoredRecord(redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(STALE_RECORD_TTL_MS / 1000));

    await redis.set(
      redisKey,
      JSON.stringify({
        count: safePositiveInt(record.count, 0),
        lockUntil: safePositiveInt(record.lockUntil, 0),
        lastAttempt: safePositiveInt(record.lastAttempt, Date.now()),
        escalationCount: safePositiveInt(record.escalationCount, 0)
      }),
      { ex: ttlSeconds }
    );

    return true;
  } catch (error) {
    console.error("Redis signup-attempt write failed:", error);
    return false;
  }
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
    const body = sanitizeBody(req.body, 20);

    const rawEmail = normalizeEmail(body.email);
    const action = safeString(body.action, 50).toLowerCase();
    const actionLabel = safeString(body.actionLabel, 100);
    const behavior =
      body.behavior && typeof body.behavior === "object" && !Array.isArray(body.behavior)
        ? body.behavior
        : {};

    const actor = createActorContext({
      req,
      body,
      behavior,
      context: {
        email: rawEmail
      },
      route: `${ROUTE}:${action || "unknown"}${actionLabel ? `:${actionLabel}` : ""}`
    });

    if (!isOriginAllowed(actor.origin)) {
      await writeSecurityLog({
        type: "forbidden_signup_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on signup-attempt API",
        ip: actor.ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          origin: actor.origin,
          requestUserAgent: actor.userAgent
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden origin.", { action: "block" })
      );
    }

    const security = await runSecurityOrchestrator({
      req,
      body,
      behavior,
      route: actor.route,
      context: {
        ip: actor.ip,
        sessionId: actor.sessionId,
        userId: actor.userId,
        email: rawEmail
      },
      rateLimitConfig: {
        key: `signup-attempt:${actor.ip}`,
        limit: 35,
        windowMs: 10 * 60 * 1000
      },
      abuseSuccess: action !== "fail",
      containmentConfig: {
        isAdminRoute: false,
        isWriteAction: action === "fail",
        actionType: "signup"
      }
    });

    const ip = security.actor.ip;

    if (security.signals.containmentResult?.blocked) {
      await writeSecurityLog({
        type: "signup_containment_block",
        level: "critical",
        message: "Signup request blocked by containment policy",
        email: rawEmail,
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          containmentResult: security.signals.containmentResult,
          risk: security.risk
        })
      });

      return res.status(403).json(
        buildBlockedResponse("Registrations are temporarily unavailable.", {
          action: "block"
        })
      );
    }

    if (security.signals.rateLimitResult && !security.signals.rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "signup_attempt_rate_limited",
        level: "warning",
        message: "Rate limit exceeded for signup attempt API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: security.signals.rateLimitResult.recommendedAction,
          remainingMs: security.signals.rateLimitResult.remainingMs || 0,
          violations: security.signals.rateLimitResult.violations || 0,
          riskScore: security.risk.riskScore,
          riskLevel: security.risk.level
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later.",
        action: security.signals.rateLimitResult.recommendedAction,
        remainingMs: security.signals.rateLimitResult.remainingMs || 0
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

    if (security.risk.finalAction === "block") {
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
          risk: security.risk,
          botResult: security.signals.botResult,
          abuseResult: security.signals.abuseResult,
          threatResult: security.signals.threatResult,
          containmentResult: security.signals.containmentResult
        })
      });

      return res.status(429).json(
        buildBlockedResponse("Suspicious activity detected. Please try again later.", {
          action: security.risk.finalAction
        })
      );
    }

    if (security.risk.finalAction === "challenge" || security.risk.finalAction === "throttle") {
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
          risk: security.risk,
          botResult: security.signals.botResult,
          abuseResult: security.signals.abuseResult,
          threatResult: security.signals.threatResult,
          containmentResult: security.signals.containmentResult
        })
      });
    }

    const ipRedisKey = buildIpAttemptKey(ip);
    const ipRecord = await getStoredRecord(ipRedisKey);

    if (ipRecord.lockUntil > now) {
      return res.status(200).json(
        buildLockResponse(true, ipRecord.lockUntil - now, {
          risk: security.risk
        })
      );
    }

    const userRedisKey = buildSignupAttemptKey(rawEmail, ip);
    const record = await getStoredRecord(userRedisKey);

    if (action === "check") {
      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          risk: security.risk
        })
      );
    }

    if (action === "fail") {
      record.count += 1;
      record.lastAttempt = now;

      ipRecord.count += 1;
      ipRecord.lastAttempt = now;

      if (security.risk.finalAction === "challenge" || security.risk.finalAction === "throttle") {
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
            risk: security.risk,
            threatResult: security.signals.threatResult
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
            risk: security.risk
          })
        });
      }

      await saveStoredRecord(userRedisKey, record);
      await saveStoredRecord(ipRedisKey, ipRecord);

      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          attempts: record.count,
          risk: security.risk
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
