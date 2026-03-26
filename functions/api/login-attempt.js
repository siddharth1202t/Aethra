import { getRedis, isRedisAvailable } from "./_redis.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  safeString,
  safePositiveInt,
  sanitizeBody,
  buildMethodNotAllowedResponse,
  buildDeniedResponse,
  buildChallengeResponse,
  buildBlockedResponse
} from "./_api-security.js";

const ROUTE = "/api/login-attempt";

const MAX_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;

const LOCK_WINDOW_MS = 15 * 60 * 1000;
const IP_LOCK_WINDOW_MS = 10 * 60 * 1000;
const STALE_RECORD_TTL_MS = 24 * 60 * 60 * 1000;

const MAX_BODY_KEYS = 25;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

const ALLOWED_ACTIONS = new Set(["check", "fail", "success"]);

/* ---------------- RESPONSE ---------------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "pragma": "no-cache",
      "x-content-type-options": "nosniff"
    }
  });
}

function buildAttemptResponse({
  isLocked,
  remainingMs = 0,
  lockType = "none",
  attempts = 0,
  action = "allow",
  fingerprint = null,
  message = null,
  degraded = false
}) {
  return {
    success: true,
    action,
    isLocked: Boolean(isLocked),
    remainingMs: Math.max(0, safePositiveInt(remainingMs, 0)),
    lockType,
    attempts: safePositiveInt(attempts, 0),
    degraded: degraded === true,
    ...(fingerprint ? { fingerprint } : {}),
    ...(message ? { message } : {})
  };
}

/* ---------------- NORMALIZATION ---------------- */

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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getEscalatedLockMs(baseMs, escalationCount) {
  const multiplier = Math.min(
    4,
    1 + safePositiveInt(escalationCount, 0) * 0.5
  );
  return Math.floor(baseMs * multiplier);
}

/* ---------------- KEYS ---------------- */

function buildLoginAttemptKey(email, ip) {
  return `login-attempt:${email}::${ip}`;
}

function buildIpAttemptKey(ip) {
  return `login-attempt-ip:${ip}`;
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

/* ---------------- FINGERPRINT ---------------- */

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

/* ---------------- LOGGING ---------------- */

async function logLoginAttempt({
  env,
  type,
  level,
  actor,
  ip,
  email,
  action,
  message,
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

function debugLoginAttempt(label, data = {}) {
  try {
    console.log(
      "LOGIN_ATTEMPT_DEBUG",
      JSON.stringify(
        {
          label,
          ...data
        },
        null,
        2
      )
    );
  } catch (error) {
    console.error("LOGIN_ATTEMPT_DEBUG_ERROR", error);
  }
}

/* ---------------- MAIN HANDLER ---------------- */

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  if (request.method !== "POST") {
    return json(buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json(
      buildDeniedResponse("Unsupported content type.", {
        action: "deny"
      }),
      415
    );
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return json(
      buildDeniedResponse("Request body too large.", {
        action: "deny"
      }),
      413
    );
  }

  if (!isRedisAvailable(env)) {
    await writeSecurityLog({
      env,
      type: "login_attempt_redis_unavailable",
      level: "critical",
      message: "Redis unavailable during login-attempt processing",
      route: ROUTE,
      metadata: {
        degraded: true
      }
    });

    return json(
      buildDeniedResponse("Service temporarily unavailable.", {
        action: "deny",
        degraded: true
      }),
      503
    );
  }

  let redis;
  try {
    redis = getRedis(env);
  } catch (error) {
    await writeSecurityLog({
      env,
      type: "login_attempt_redis_unavailable",
      level: "critical",
      message: "Redis unavailable during login-attempt processing",
      route: ROUTE,
      metadata: {
        error: safeString(error?.message || "Redis init failed", 300)
      }
    });

    return json(
      buildDeniedResponse("Service temporarily unavailable.", {
        action: "deny",
        degraded: true
      }),
      503
    );
  }

  try {
    const bodyRaw = await request.json();
    const body = sanitizeBody(bodyRaw, MAX_BODY_KEYS);

    const rawEmail = normalizeEmail(body.email);
    const action = safeString(body.action, 50).toLowerCase();
    const actionLabel = safeString(body.actionLabel, 100);

    if (!ALLOWED_ACTIONS.has(action)) {
      return json(
        buildDeniedResponse("Invalid action.", {
          action: "deny"
        }),
        400
      );
    }

    if (!rawEmail || !isValidEmail(rawEmail)) {
      return json(
        buildDeniedResponse("Invalid email.", {
          action: "deny"
        }),
        400
      );
    }

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
      behavior: body,
      route: `${ROUTE}:${action || "unknown"}`,
      context: {
        ip: actor.ip,
        sessionId: actor.sessionId,
        userId: actor.userId,
        email: rawEmail
      },
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

    try {
      console.log(
        "LOGIN_ATTEMPT_SECURITY",
        JSON.stringify(
          {
            route: `${ROUTE}:${action || "unknown"}`,
            actor: {
              ip: actor?.ip || null,
              sessionId: actor?.sessionId || null,
              userId: actor?.userId || null,
              actorKey: actor?.actorKey || null,
              routeKey: actor?.routeKey || null,
              deviceKey: actor?.deviceKey || null,
              userAgent: actor?.userAgent || null,
              origin: actor?.origin || null,
              referer: actor?.referer || null
            },
            risk: {
              finalAction: security?.risk?.finalAction || null,
              action: security?.risk?.action || null,
              containmentAction: security?.risk?.containmentAction || null,
              finalContainmentAction:
                security?.risk?.finalContainmentAction || null,
              riskScore: security?.risk?.riskScore ?? null,
              level: security?.risk?.level || null,
              routeSensitivity: security?.risk?.routeSensitivity || null,
              criticalAttackLikely:
                security?.risk?.criticalAttackLikely === true,
              degraded: security?.risk?.degraded === true,
              degradedReasons: security?.risk?.degradedReasons || [],
              reasons: Array.isArray(security?.risk?.reasons)
                ? security.risk.reasons
                : [],
              events: security?.risk?.events || {}
            },
            enforcement: security?.enforcement || {},
            botResult: security?.signals?.botResult || null,
            abuseResult: security?.signals?.abuseResult || null,
            rateLimitResult: security?.signals?.rateLimitResult || null,
            freshnessResult: security?.signals?.freshnessResult || null,
            threatResult: security?.signals?.threatResult || null,
            containmentResult: security?.signals?.containmentResult || null,
            adaptiveModeResult: security?.signals?.adaptiveModeResult || null,
            anomalyResult: security?.signals?.anomalyResult || null,
            securityState: security?.signals?.securityState || null,
            persistentRiskState: security?.signals?.persistentRiskState || null,
            alertsResult: security?.signals?.alertsResult || null
          },
          null,
          2
        )
      );
    } catch (logError) {
      console.error("LOGIN_ATTEMPT_SECURITY_LOG_ERROR", logError);
    }

    const finalAction = safeString(
      security?.risk?.finalAction || "allow",
      50
    ).toLowerCase();
    const riskScore = safePositiveInt(security?.risk?.riskScore, 0);
    const degraded = security?.risk?.degraded === true;

    if (finalAction === "block") {
      await logLoginAttempt({
        env,
        type: "login_attempt_blocked",
        level: "warning",
        actor,
        ip,
        email: rawEmail,
        action,
        message: "Login attempt request blocked by security orchestrator",
        metadata: {
          finalAction,
          riskScore,
          degraded
        }
      });

      return json(
        buildBlockedResponse("Request blocked.", {
          action: "block",
          degraded
        }),
        403
      );
    }

    if (finalAction === "challenge") {
      await logLoginAttempt({
        env,
        type: "login_attempt_challenged",
        level: "warning",
        actor,
        ip,
        email: rawEmail,
        action,
        message: "Login attempt requires additional verification",
        metadata: {
          finalAction,
          riskScore,
          degraded
        }
      });

      return json(
        buildChallengeResponse("Verification required.", {
          action: "challenge",
          degraded
        }),
        403
      );
    }

    const fingerprint = await buildAttemptFingerprint({
      email: rawEmail,
      ip,
      action,
      actionLabel
    });

    const ipRedisKey = buildIpAttemptKey(ip);
    const userRedisKey = buildLoginAttemptKey(rawEmail, ip);

    const [ipRecord, record] = await Promise.all([
      getStoredRecord(redis, ipRedisKey),
      getStoredRecord(redis, userRedisKey)
    ]);

    debugLoginAttempt("records_loaded", {
      action,
      email: rawEmail,
      ip,
      now,
      userRedisKey,
      ipRedisKey,
      userRecord: record,
      ipRecord
    });

    if (ipRecord.lockUntil > now) {
      const remainingMs = ipRecord.lockUntil - now;

      debugLoginAttempt("ip_lock_enforced", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        userRecord: record,
        ipRecord,
        computed: {
          remainingMs
        }
      });

      await logLoginAttempt({
        env,
        type: "login_ip_lock_enforced",
        level: "warning",
        actor,
        ip,
        email: rawEmail,
        action,
        message: "Login attempt denied due to active IP lock",
        metadata: {
          remainingMs,
          ipAttempts: ipRecord.count,
          escalationCount: ipRecord.escalationCount,
          fingerprint
        }
      });

      return json(
        buildAttemptResponse({
          isLocked: true,
          remainingMs,
          lockType: "ip",
          attempts: ipRecord.count,
          action: "deny",
          fingerprint,
          message: "Too many attempts. Please try again later.",
          degraded
        }),
        200
      );
    }

    if (record.lockUntil > now && action !== "success") {
      const remainingMs = record.lockUntil - now;

      debugLoginAttempt("user_lock_enforced", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        userRecord: record,
        ipRecord,
        computed: {
          remainingMs
        }
      });

      await logLoginAttempt({
        env,
        type: "login_user_lock_enforced",
        level: "warning",
        actor,
        ip,
        email: rawEmail,
        action,
        message: "Login attempt denied due to active user lock",
        metadata: {
          remainingMs,
          attempts: record.count,
          escalationCount: record.escalationCount,
          fingerprint
        }
      });

      return json(
        buildAttemptResponse({
          isLocked: true,
          remainingMs,
          lockType: "user",
          attempts: record.count,
          action: "deny",
          fingerprint,
          message: "Too many attempts. Please try again later.",
          degraded
        }),
        200
      );
    }

    if (action === "check") {
      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      debugLoginAttempt("check_evaluated", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        userRecord: record,
        ipRecord,
        computed: {
          isLocked,
          remainingMs
        }
      });

      await logLoginAttempt({
        env,
        type: "login_attempt_checked",
        level: "info",
        actor,
        ip,
        email: rawEmail,
        action,
        message: "Login attempt lock state checked",
        metadata: {
          isLocked,
          remainingMs,
          attempts: record.count,
          fingerprint
        }
      });

      return json(
        buildAttemptResponse({
          isLocked,
          remainingMs,
          lockType: isLocked ? "user" : "none",
          attempts: record.count,
          action: "allow",
          fingerprint,
          degraded
        }),
        200
      );
    }

    if (action === "success") {
      debugLoginAttempt("success_before_reset", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        userRecord: record,
        ipRecord
      });

      record.count = 0;
      record.lockUntil = 0;
      record.lastAttempt = now;

      await saveStoredRecord(redis, userRedisKey, record);

      const savedSuccessRecord = await getStoredRecord(redis, userRedisKey);

      debugLoginAttempt("success_after_reset", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        savedUserRecord: savedSuccessRecord
      });

      await logLoginAttempt({
        env,
        type: "login_attempt_reset",
        level: "info",
        actor,
        ip,
        email: rawEmail,
        action,
        message: "Login attempt counters reset after success",
        metadata: {
          fingerprint
        }
      });

      return json(
        buildAttemptResponse({
          isLocked: false,
          remainingMs: 0,
          lockType: "none",
          attempts: 0,
          action: "allow",
          fingerprint,
          degraded
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

      debugLoginAttempt("fail_before_save", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        userRecord: record,
        ipRecord
      });

      await Promise.all([
        saveStoredRecord(redis, userRedisKey, record),
        saveStoredRecord(redis, ipRedisKey, ipRecord)
      ]);

      const [savedIpRecord, savedUserRecord] = await Promise.all([
        getStoredRecord(redis, ipRedisKey),
        getStoredRecord(redis, userRedisKey)
      ]);

      debugLoginAttempt("fail_after_save", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        savedUserRecord,
        savedIpRecord
      });

      const isUserLocked = record.lockUntil > now;
      const isIpLocked = ipRecord.lockUntil > now;
      const lockType = isUserLocked ? "user" : isIpLocked ? "ip" : "none";
      const remainingMs = Math.max(
        isUserLocked ? record.lockUntil - now : 0,
        isIpLocked ? ipRecord.lockUntil - now : 0
      );

      debugLoginAttempt("fail_evaluated", {
        action,
        email: rawEmail,
        ip,
        now,
        userRedisKey,
        ipRedisKey,
        userRecord: record,
        ipRecord,
        computed: {
          isUserLocked,
          isIpLocked,
          lockType,
          remainingMs
        }
      });

      await logLoginAttempt({
        env,
        type: isUserLocked || isIpLocked
          ? "login_lockout_triggered"
          : "login_attempt_failed",
        level: isUserLocked || isIpLocked ? "warning" : "info",
        actor,
        ip,
        email: rawEmail,
        action,
        message: isUserLocked || isIpLocked
          ? "Login lockout triggered after repeated failed attempts"
          : "Login failure recorded",
        metadata: {
          lockType,
          attempts: record.count,
          ipAttempts: ipRecord.count,
          remainingMs,
          userEscalationCount: record.escalationCount,
          ipEscalationCount: ipRecord.escalationCount,
          fingerprint,
          degraded
        }
      });

      return json(
        buildAttemptResponse({
          isLocked: isUserLocked || isIpLocked,
          remainingMs,
          lockType,
          attempts: record.count,
          action: isUserLocked || isIpLocked ? "deny" : "allow",
          fingerprint,
          message:
            isUserLocked || isIpLocked
              ? "Too many attempts. Please try again later."
              : null,
          degraded
        }),
        200
      );
    }

    return json(
      buildDeniedResponse("Invalid request.", {
        action: "deny"
      }),
      400
    );
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
