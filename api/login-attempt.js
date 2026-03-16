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

const ROUTE = "/api/login-attempt";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_ACTIONS = new Set(["check", "fail"]);
const GOOGLE_PLACEHOLDER_EMAIL = "google-login";

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function normalizeEmail(email) {
  return safeString(email || "", 200).trim().toLowerCase();
}

function normalizeIp(ip) {
  let value = safeString(ip || "unknown", 100);

  if (!value) return "unknown";

  if (value.startsWith("::ffff:")) {
    value = value.slice(7);
  }

  value = value.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return value || "unknown";
}

function normalizeKeyPart(value, fallback = "", maxLength = 160) {
  const cleaned = safeString(value || "", maxLength).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return cleaned || fallback;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getKey(email, ip) {
  return `${normalizeKeyPart(email, "unknown-email", 220)}::${normalizeKeyPart(ip, "unknown-ip", 120)}`;
}

function buildLoginAttemptKey(email, ip) {
  return `login-attempt:${safeString(getKey(email, ip), 260)}`;
}

function buildIpAttemptKey(ip) {
  return `login-attempt-ip:${normalizeKeyPart(ip, "unknown-ip", 120)}`;
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(safeString(origin, 200).trim().toLowerCase());
}

function createDefaultRecord(now = Date.now()) {
  return {
    count: 0,
    lockUntil: 0,
    lastAttempt: now,
    escalationCount: 0
  };
}

function normalizeRecord(record, now = Date.now()) {
  const normalized = {
    count: safePositiveInt(record?.count, 0),
    lockUntil: safePositiveInt(record?.lockUntil, 0),
    lastAttempt: safePositiveInt(record?.lastAttempt, now),
    escalationCount: safePositiveInt(record?.escalationCount, 0)
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

async function getStoredRecord(redisKey) {
  const now = Date.now();

  try {
    const raw = await redis.get(redisKey);

    if (!raw) {
      return createDefaultRecord(now);
    }

    const parsed =
      typeof raw === "string"
        ? safeJsonParse(raw, null)
        : typeof raw === "object"
          ? raw
          : null;

    if (!parsed || typeof parsed !== "object") {
      return createDefaultRecord(now);
    }

    return normalizeRecord(parsed, now);
  } catch (error) {
    console.error("Redis login-attempt read failed:", error);
    return createDefaultRecord(now);
  }
}

async function saveStoredRecord(redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(STALE_RECORD_TTL_MS / 1000));
    const normalized = normalizeRecord(record, Date.now());

    await redis.set(redisKey, JSON.stringify(normalized), { ex: ttlSeconds });

    return true;
  } catch (error) {
    console.error("Redis login-attempt write failed:", error);
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

function pickSecurityAction(security) {
  return safeString(
    security?.risk?.finalAction || security?.risk?.action || "allow",
    20
  ).toLowerCase();
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
        type: "forbidden_origin",
        level: "warning",
        message: "Blocked request from forbidden origin",
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
        key: `login-attempt:${normalizeIp(actor.ip)}`,
        limit: 40,
        windowMs: 10 * 60 * 1000
      },
      abuseSuccess: action !== "fail"
    });

    const ip = normalizeIp(security.actor.ip);
    const securityAction = pickSecurityAction(security);

    if (security.signals.rateLimitResult && !security.signals.rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "login_attempt_rate_limited",
        level: "warning",
        message: "Rate limit exceeded for login attempt API",
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
        type: "invalid_login_action",
        level: "warning",
        message: "Invalid action sent",
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
        type: "invalid_login_request",
        level: "warning",
        message: "Invalid email sent to login attempt API",
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

    if (securityAction === "block") {
      await writeSecurityLog({
        type: "blocked_suspicious_request",
        level: "critical",
        message: "Blocked login attempt API request due to suspicious behavior",
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
          threatResult: security.signals.threatResult
        })
      });

      return res.status(429).json(
        buildBlockedResponse("Suspicious activity detected. Please try again later.", {
          action: "block"
        })
      );
    }

    if (securityAction === "challenge" || securityAction === "throttle") {
      await writeSecurityLog({
        type: "temporary_security_challenge",
        level: "warning",
        message: "Suspicious login behavior detected",
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
          threatResult: security.signals.threatResult
        })
      });
    }

    const ipRedisKey = buildIpAttemptKey(ip);
    const ipRecord = await getStoredRecord(ipRedisKey);

    if (ipRecord.lockUntil > now) {
      return res.status(200).json(
        buildLockResponse(true, ipRecord.lockUntil - now, {
          lockType: "ip",
          risk: security.risk
        })
      );
    }

    const userRedisKey = buildLoginAttemptKey(rawEmail, ip);
    const record = await getStoredRecord(userRedisKey);

    if (action === "check") {
      const isLocked = record.lockUntil > now;

      return res.status(200).json(
        buildLockResponse(isLocked, record.lockUntil - now, {
          lockType: isLocked ? "user" : "none",
          risk: security.risk
        })
      );
    }

    if (action === "fail") {
      record.count += 1;
      record.lastAttempt = now;

      ipRecord.count += 1;
      ipRecord.lastAttempt = now;

      if (securityAction === "challenge" || securityAction === "throttle") {
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
          type: "ip_login_lock",
          level: "critical",
          message: "IP temporarily blocked due to excessive login attempts",
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
          lockType: isLocked ? "user" : (ipRecord.lockUntil > now ? "ip" : "none"),
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
