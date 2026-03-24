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

const ROUTE = "/api/login-attempt";
const MAX_BODY_KEYS = 25;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

async function buildAttemptFingerprint({ email, ip, action, actionLabel }) {
  const encoder = new TextEncoder();

  const data = encoder.encode(
    [
      safeString(email, 200),
      safeString(ip, 100),
      safeString(action, 50),
      safeString(actionLabel, 100)
    ].join("|")
  );

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  return hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function normalizeEmail(email) {
  return safeString(email || "", 200).trim().toLowerCase();
}

function normalizeIp(ip) {
  let value = safeString(ip || "unknown", 100);

  if (value.startsWith("::ffff:")) {
    value = value.slice(7);
  }

  value = value.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return value || "unknown";
}

function getEscalatedLockMs(baseMs, escalationCount) {
  const multiplier = Math.min(
    4,
    1 + safePositiveInt(escalationCount, 0) * 0.5
  );
  return Math.floor(baseMs * multiplier);
}

function buildLoginAttemptKey(email, ip) {
  return `login-attempt:${email}::${ip}`;
}

function buildIpAttemptKey(ip) {
  return `login-attempt-ip:${ip}`;
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

export async function onRequest(context) {
  const { request, env } = context;
  const redis = getRedis(env);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

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
    const actionLabel = safeString(body.actionLabel, 100);

    const actor = createActorContext({
      req: request,
      body,
      route: `${ROUTE}:${action || "unknown"}`
    });

    const ip = normalizeIp(actor.ip);
    const now = Date.now();

    const security = await runSecurityOrchestrator({
      env,
      req: request,
      body,
      route: `${ROUTE}:${action || "unknown"}`,
      abuseSuccess: action !== "fail",
      containmentConfig: {
        isWriteAction: true,
        actionType: "auth_attempt",
        routeSensitivity: "critical"
      },
      rateLimitConfig: {
        key: `login-attempt:${actor.actorKey}`,
        limit: 20,
        windowMs: 60 * 1000
      }
    });

    if (security?.risk?.finalAction === "block") {
      await writeSecurityLog({
        env,
        type: "login_attempt_blocked",
        level: "warning",
        message: "Login attempt request blocked by security orchestrator",
        ip,
        route: ROUTE,
        metadata: {
          finalAction: security?.risk?.finalAction,
          riskScore: security?.risk?.riskScore
        }
      });

      return json({
        success: false,
        message: "Request blocked."
      }, 403);
    }

    const fingerprint = await buildAttemptFingerprint({
      email: rawEmail,
      ip,
      action,
      actionLabel
    });

    const ipRedisKey = buildIpAttemptKey(ip);
    const userRedisKey = buildLoginAttemptKey(rawEmail || "anon", ip);

    const ipRecord = await getStoredRecord(redis, ipRedisKey);
    const record = await getStoredRecord(redis, userRedisKey);

    if (ipRecord.lockUntil > now) {
      return json({
        success: true,
        isLocked: true,
        remainingMs: ipRecord.lockUntil - now,
        lockType: "ip"
      });
    }

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

      await saveStoredRecord(redis, userRedisKey, record);

      return json({
        success: true,
        isLocked: false,
        remainingMs: 0,
        lockType: "none",
        fingerprint
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

      await saveStoredRecord(redis, userRedisKey, record);
      await saveStoredRecord(redis, ipRedisKey, ipRecord);

      const isUserLocked = record.lockUntil > now;
      const isIpLocked = ipRecord.lockUntil > now;

      if (isUserLocked || isIpLocked) {
        await writeSecurityLog({
          env,
          type: "login_lockout_triggered",
          level: "warning",
          message: "Login lockout triggered after repeated failed attempts",
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
        attempts: record.count,
        fingerprint
      });
    }

    return json({
      success: false,
      message: "Invalid request."
    }, 400);
  } catch (error) {
    console.error("Login attempt API error:", error);

    try {
      await writeSecurityLog({
        env,
        type: "login_attempt_api_error",
        level: "error",
        message: "Unhandled server error",
        route: ROUTE,
        metadata: {
          error: safeString(error?.message || "Unknown error", 500)
        }
      });
    } catch {}

    return json({
      success: false,
      message: "Internal server error."
    }, 500);
  }
}
