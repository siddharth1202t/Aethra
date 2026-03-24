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

const MAX_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;

const LOCK_WINDOW_MS = 15 * 60 * 1000;
const IP_LOCK_WINDOW_MS = 10 * 60 * 1000;
const STALE_RECORD_TTL_MS = 24 * 60 * 60 * 1000;

const ROUTE = "/api/signup-attempt";

const ALLOWED_ACTIONS = new Set(["check", "fail", "success"]);
const GOOGLE_PLACEHOLDER_EMAIL = "google-signup";

const MAX_BODY_KEYS = 20;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

/* ---------- helpers ---------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store"
    }
  });
}

function normalizeEmail(email) {
  return safeString(email || "", 200).trim().toLowerCase();
}

function normalizeIp(ip) {
  let value = safeString(ip || "unknown", 100);

  if (value.startsWith("::ffff:")) value = value.slice(7);

  value = value.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return value || "unknown";
}

function buildSignupAttemptKey(email, ip) {
  return `signup-attempt:${email}::${ip}`;
}

function buildIpAttemptKey(ip) {
  return `signup-attempt-ip:${ip}`;
}

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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isGooglePlaceholderEmail(email) {
  return email === GOOGLE_PLACEHOLDER_EMAIL;
}

function getEscalatedLockMs(baseMs, escalationCount) {
  const multiplier = Math.min(
    4,
    1 + safePositiveInt(escalationCount, 0) * 0.5
  );
  return Math.floor(baseMs * multiplier);
}

/* ---------- main handler ---------- */

export async function onRequest(context) {
  const { request, env } = context;
  const redis = getRedis(env);

  if (request.method !== "POST") {
    return json(buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.startsWith("application/json")) {
    return json({
      success: false,
      message: "Unsupported content type."
    }, 415);
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return json({
      success: false,
      message: "Request body too large."
    }, 413);
  }

  try {
    const bodyRaw = await request.json();
    const body = sanitizeBody(bodyRaw, MAX_BODY_KEYS);

    const rawEmail = normalizeEmail(body.email);
    const action = safeString(body.action, 50).toLowerCase();

    if (!ALLOWED_ACTIONS.has(action)) {
      return json({
        success: false,
        message: "Invalid action."
      }, 400);
    }

    const emailAllowed =
      isValidEmail(rawEmail) || isGooglePlaceholderEmail(rawEmail);

    if (!rawEmail || !emailAllowed) {
      return json({
        success: false,
        message: "Invalid email."
      }, 400);
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
    const securityAction = security?.risk?.finalAction || "allow";

    if (securityAction === "block") {
      await writeSecurityLog({
        env,
        type: "signup_attempt_blocked",
        level: "warning",
        message: "Signup attempt request blocked by security orchestrator",
        ip,
        route: ROUTE,
        metadata: {
          riskScore: security?.risk?.riskScore || 0,
          finalAction: securityAction
        }
      });

      return json({
        success: false,
        message: "Request blocked."
      }, 403);
    }

    if (securityAction === "challenge") {
      return json({
        success: false,
        message: "Verification required."
      }, 403);
    }

    const now = Date.now();

    const ipKey = buildIpAttemptKey(ip);
    const ipRecord = await getStoredRecord(redis, ipKey);

    if (ipRecord.lockUntil > now) {
      return json({
        success: true,
        isLocked: true,
        remainingMs: ipRecord.lockUntil - now,
        lockType: "ip"
      });
    }

    const userKey = buildSignupAttemptKey(rawEmail, ip);
    const record = await getStoredRecord(redis, userKey);

    if (record.lockUntil > now && action !== "success") {
      return json({
        success: true,
        isLocked: true,
        remainingMs: record.lockUntil - now,
        lockType: "user"
      });
    }

    if (action === "check") {
      const isLocked = record.lockUntil > now;

      return json({
        success: true,
        isLocked,
        remainingMs: isLocked ? record.lockUntil - now : 0,
        lockType: isLocked ? "user" : "none"
      });
    }

    if (action === "success") {
      record.count = 0;
      record.lockUntil = 0;
      record.lastAttempt = now;

      await saveStoredRecord(redis, userKey, record);

      return json({
        success: true,
        isLocked: false,
        remainingMs: 0,
        lockType: "none"
      });
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

      await saveStoredRecord(redis, userKey, record);
      await saveStoredRecord(redis, ipKey, ipRecord);

      const isUserLocked = record.lockUntil > now;
      const isIpLocked = ipRecord.lockUntil > now;

      if (isUserLocked || isIpLocked) {
        await writeSecurityLog({
          env,
          type: "signup_lockout_triggered",
          level: "warning",
          message: "Signup lockout triggered after repeated failed attempts",
          ip,
          route: ROUTE,
          metadata: {
            lockType: isUserLocked ? "user" : "ip",
            attempts: record.count,
            ipAttempts: ipRecord.count
          }
        });
      }

      return json({
        success: true,
        isLocked: isUserLocked || isIpLocked,
        remainingMs: Math.max(
          isUserLocked ? record.lockUntil - now : 0,
          isIpLocked ? ipRecord.lockUntil - now : 0
        ),
        lockType: isUserLocked ? "user" : isIpLocked ? "ip" : "none",
        attempts: record.count
      });
    }

    return json({
      success: false,
      message: "Invalid request."
    }, 400);
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

    return json({
      success: false,
      message: "Internal server error."
    }, 500);
  }
}
