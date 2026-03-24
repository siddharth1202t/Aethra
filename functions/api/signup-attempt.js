import { getRedis } from "./_redis.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  safeString,
  safePositiveInt,
  sanitizeBody,
  buildMethodNotAllowedResponse
} from "./_api-security.js";

const ROUTE = "/api/signup-attempt";

const MAX_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;

const LOCK_WINDOW_MS = 15 * 60 * 1000;
const IP_LOCK_WINDOW_MS = 10 * 60 * 1000;
const STALE_RECORD_TTL_MS = 24 * 60 * 60 * 1000;

const MAX_BODY_KEYS = 20;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

const ALLOWED_ACTIONS = new Set(["check", "fail", "success"]);
const GOOGLE_PLACEHOLDER_EMAIL = "google-signup";

/* ---------------- RESPONSE HELPERS ---------------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store"
    }
  });
}

/* ---------------- NORMALIZATION ---------------- */

function normalizeEmail(email) {
  return safeString(email || "", 200).trim().toLowerCase();
}

function normalizeIp(ip) {
  let value = safeString(ip || "unknown", 100).trim();

  if (value.startsWith("::ffff:")) value = value.slice(7);

  value = value.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return value || "unknown";
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isGooglePlaceholderEmail(email) {
  return email === GOOGLE_PLACEHOLDER_EMAIL;
}

function buildSignupAttemptKey(email, ip) {
  return `signup-attempt:${email}::${ip}`;
}

function buildIpAttemptKey(ip) {
  return `signup-attempt-ip:${ip}`;
}

/* ---------------- RECORD HELPERS ---------------- */

function createDefaultRecord(now = Date.now()) {
  return {
    count: 0,
    lockUntil: 0,
    lastAttempt: now,
    escalationCount: 0
  };
}

function normalizeRecord(raw, now = Date.now()) {
  const record = raw && typeof raw === "object" ? raw : {};
  return {
    count: safePositiveInt(record.count, 0),
    lockUntil: safePositiveInt(record.lockUntil, 0),
    lastAttempt: safePositiveInt(record.lastAttempt, now),
    escalationCount: safePositiveInt(record.escalationCount, 0)
  };
}

async function getStoredRecord(redis, key) {
  const now = Date.now();

  try {
    const raw = await redis.get(key);

    if (!raw) return createDefaultRecord(now);

    if (typeof raw === "string") {
      return normalizeRecord(JSON.parse(raw), now);
    }

    if (typeof raw === "object") {
      return normalizeRecord(raw, now);
    }

    return createDefaultRecord(now);
  } catch {
    return createDefaultRecord(now);
  }
}

async function saveStoredRecord(redis, key, record) {
  const ttlSeconds = Math.max(1, Math.ceil(STALE_RECORD_TTL_MS / 1000));
  await redis.set(key, JSON.stringify(normalizeRecord(record)), { ex: ttlSeconds });
}

function getEscalatedLockMs(baseMs, escalationCount) {
  const multiplier = Math.min(4, 1 + safePositiveInt(escalationCount, 0) * 0.5);
  return Math.floor(baseMs * multiplier);
}

/* ---------------- LOGGING HELPERS ---------------- */

async function logSignupAttempt({
  env,
  type,
  level,
  message,
  actor,
  ip,
  email,
  action,
  metadata = {}
}) {
  await writeSecurityLog({
    env,
    type,
    level,
    message,
    ip: ip || actor?.ip || "unknown",
    route: ROUTE,
    userId: actor?.userId || null,
    sessionId: actor?.sessionId || null,
    metadata: {
      actorKey: actor?.actorKey || null,
      routeKey: actor?.routeKey || null,
      email: safeString(email || "", 200),
      action: safeString(action || "", 50),
      ...metadata
    }
  });
}

function buildLockResponse({
  isLocked,
  remainingMs = 0,
  lockType = "none",
  attempts = 0,
  action = "allow",
  message = null
}) {
  return {
    success: true,
    action,
    isLocked: Boolean(isLocked),
    remainingMs: Math.max(0, safePositiveInt(remainingMs, 0)),
    lockType,
    attempts: safePositiveInt(attempts, 0),
    ...(message ? { message } : {})
  };
}

/* ---------------- MAIN HANDLER ---------------- */

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return json(buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json(
      {
        success: false,
        action: "deny",
        message: "Unsupported content type."
      },
      415
    );
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return json(
      {
        success: false,
        action: "deny",
        message: "Request body too large."
      },
      413
    );
  }

  let redis;
  try {
    redis = getRedis(env);
  } catch (error) {
    await writeSecurityLog({
      env,
      type: "signup_attempt_redis_unavailable",
      level: "critical",
      message: "Redis unavailable during signup-attempt processing",
      route: ROUTE,
      metadata: {
        error: safeString(error?.message || "Redis init failed", 300)
      }
    });

    return json(
      {
        success: false,
        action: "deny",
        message: "Service temporarily unavailable."
      },
      503
    );
  }

  try {
    const bodyRaw = await request.json();
    const body = sanitizeBody(bodyRaw, MAX_BODY_KEYS);

    const rawEmail = normalizeEmail(body.email);
    const action = safeString(body.action, 50).toLowerCase();

    if (!ALLOWED_ACTIONS.has(action)) {
      return json(
        {
          success: false,
          action: "deny",
          message: "Invalid action."
        },
        400
      );
    }

    const emailAllowed =
      isValidEmail(rawEmail) || isGooglePlaceholderEmail(rawEmail);

    if (!rawEmail || !emailAllowed) {
      return json(
        {
          success: false,
          action: "deny",
          message: "Invalid email."
        },
        400
      );
    }

    const actor = createActorContext({
      req: request,
      body,
      route: `${ROUTE}:${action || "unknown"}`
    });

    const security = await runSecurityOrchestrator({
      env,
      req: request,
      body,
      route: actor.route,
      context: {
        ip: actor.ip,
        sessionId: actor.sessionId,
        userId: actor.userId,
        email: rawEmail
      },
      rateLimitConfig: {
        key: `signup-attempt:${normalizeIp(actor.ip)}`,
        limit: 35,
        windowMs: 10 * 60 * 1000
      },
      abuseSuccess: action !== "fail",
      containmentConfig: {
        isWriteAction: true,
        actionType: "auth_attempt",
        routeSensitivity: "critical"
      }
    });

    const ip = normalizeIp(security?.actor?.ip || actor.ip);
    const securityAction = safeString(
      security?.risk?.finalAction || "allow",
      50
    ).toLowerCase();
    const riskScore = safePositiveInt(security?.risk?.riskScore, 0);

    if (securityAction === "block") {
      await logSignupAttempt({
        env,
        type: "signup_attempt_blocked",
        level: "warning",
        message: "Signup attempt request blocked by security orchestrator",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          riskScore,
          finalAction: securityAction
        }
      });

      return json(
        {
          success: false,
          action: "block",
          message: "Request blocked."
        },
        403
      );
    }

    if (securityAction === "challenge") {
      await logSignupAttempt({
        env,
        type: "signup_attempt_challenged",
        level: "warning",
        message: "Signup attempt requires additional verification",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          riskScore,
          finalAction: securityAction
        }
      });

      return json(
        {
          success: false,
          action: "challenge",
          message: "Verification required."
        },
        403
      );
    }

    const now = Date.now();

    const ipKey = buildIpAttemptKey(ip);
    const userKey = buildSignupAttemptKey(rawEmail, ip);

    const [ipRecord, record] = await Promise.all([
      getStoredRecord(redis, ipKey),
      getStoredRecord(redis, userKey)
    ]);

    if (ipRecord.lockUntil > now) {
      const remainingMs = ipRecord.lockUntil - now;

      await logSignupAttempt({
        env,
        type: "signup_ip_lock_enforced",
        level: "warning",
        message: "Signup attempt denied due to active IP lock",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          remainingMs,
          ipAttempts: ipRecord.count,
          escalationCount: ipRecord.escalationCount
        }
      });

      return json(
        buildLockResponse({
          isLocked: true,
          remainingMs,
          lockType: "ip",
          attempts: ipRecord.count,
          action: "deny",
          message: "Too many attempts. Please try again later."
        }),
        200
      );
    }

    if (record.lockUntil > now && action !== "success") {
      const remainingMs = record.lockUntil - now;

      await logSignupAttempt({
        env,
        type: "signup_user_lock_enforced",
        level: "warning",
        message: "Signup attempt denied due to active user lock",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          remainingMs,
          attempts: record.count,
          escalationCount: record.escalationCount
        }
      });

      return json(
        buildLockResponse({
          isLocked: true,
          remainingMs,
          lockType: "user",
          attempts: record.count,
          action: "deny",
          message: "Too many attempts. Please try again later."
        }),
        200
      );
    }

    if (action === "check") {
      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      await logSignupAttempt({
        env,
        type: "signup_attempt_checked",
        level: "info",
        message: "Signup attempt lock state checked",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          isLocked,
          remainingMs,
          attempts: record.count
        }
      });

      return json(
        buildLockResponse({
          isLocked,
          remainingMs,
          lockType: isLocked ? "user" : "none",
          attempts: record.count,
          action: "allow"
        }),
        200
      );
    }

    if (action === "success") {
      record.count = 0;
      record.lockUntil = 0;
      record.lastAttempt = now;

      await saveStoredRecord(redis, userKey, record);

      await logSignupAttempt({
        env,
        type: "signup_attempt_reset",
        level: "info",
        message: "Signup attempt counters reset after success",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          attempts: 0
        }
      });

      return json(
        buildLockResponse({
          isLocked: false,
          remainingMs: 0,
          lockType: "none",
          attempts: 0,
          action: "allow"
        }),
        200
      );
    }

    if (action === "fail") {
      record.count += 1;
      ipRecord.count += 1;

      record.lastAttempt = now;
      ipRecord.lastAttempt = now;

      if (record.count >= MAX_ATTEMPTS) {
        record.escalationCount += 1;
        record.lockUntil =
          now + getEscalatedLockMs(LOCK_WINDOW_MS, record.escalationCount);
      }

      if (ipRecord.count >= MAX_IP_ATTEMPTS) {
        ipRecord.escalationCount += 1;
        ipRecord.lockUntil =
          now + getEscalatedLockMs(IP_LOCK_WINDOW_MS, ipRecord.escalationCount);
      }

      await Promise.all([
        saveStoredRecord(redis, userKey, record),
        saveStoredRecord(redis, ipKey, ipRecord)
      ]);

      const isUserLocked = record.lockUntil > now;
      const isIpLocked = ipRecord.lockUntil > now;
      const lockType = isUserLocked ? "user" : isIpLocked ? "ip" : "none";
      const remainingMs = Math.max(
        isUserLocked ? record.lockUntil - now : 0,
        isIpLocked ? ipRecord.lockUntil - now : 0
      );

      await logSignupAttempt({
        env,
        type: isUserLocked || isIpLocked
          ? "signup_lockout_triggered"
          : "signup_attempt_failed",
        level: isUserLocked || isIpLocked ? "warning" : "info",
        message: isUserLocked || isIpLocked
          ? "Signup lockout triggered after repeated failed attempts"
          : "Signup failure recorded",
        actor,
        ip,
        email: rawEmail,
        action,
        metadata: {
          attempts: record.count,
          ipAttempts: ipRecord.count,
          lockType,
          remainingMs,
          userEscalationCount: record.escalationCount,
          ipEscalationCount: ipRecord.escalationCount
        }
      });

      return json(
        buildLockResponse({
          isLocked: isUserLocked || isIpLocked,
          remainingMs,
          lockType,
          attempts: record.count,
          action: isUserLocked || isIpLocked ? "deny" : "allow",
          message:
            isUserLocked || isIpLocked
              ? "Too many attempts. Please try again later."
              : null
        }),
        200
      );
    }

    return json(
      {
        success: false,
        action: "deny",
        message: "Invalid request."
      },
      400
    );
  } catch (error) {
    console.error("Signup attempt API error:", error);

    await writeSecurityLog({
      env,
      type: "signup_attempt_api_error",
      level: "error",
      message: "Unhandled server error in signup-attempt API",
      route: ROUTE,
      metadata: {
        error: safeString(error?.message || "Unknown error", 500)
      }
    });

    return json(
      {
        success: false,
        action: "deny",
        message: "Internal server error."
      },
      500
    );
  }
}
