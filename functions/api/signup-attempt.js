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
      "cache-control": "no-store",
      "pragma": "no-cache",
      "x-content-type-options": "nosniff"
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

function safeTimestamp(value, fallback = 0) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num) || num < 0) return fallback;
  return Math.min(num, Date.now() + 7 * 24 * 60 * 60 * 1000);
}

function normalizeRecord(raw, now = Date.now()) {
  const record = raw && typeof raw === "object" ? raw : {};
  return {
    count: safePositiveInt(record.count, 0),
    lockUntil: safeTimestamp(record.lockUntil, 0),
    lastAttempt: safeTimestamp(record.lastAttempt, now),
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
    ...(message ? { message } : {})
  };
}

function debugSignupAttempt(label, data = {}) {
  try {
    console.log(
      "SIGNUP_ATTEMPT_DEBUG",
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
    console.error("SIGNUP_ATTEMPT_DEBUG_ERROR", error);
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
      type: "signup_attempt_redis_unavailable",
      level: "critical",
      message: "Redis unavailable during signup-attempt processing",
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
      type: "signup_attempt_redis_unavailable",
      level: "critical",
      message: "Redis unavailable during signup-attempt processing",
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
    const securityRoute = `${ROUTE}:${action || "unknown"}`;

    if (!ALLOWED_ACTIONS.has(action)) {
      return json(
        buildDeniedResponse("Invalid action.", {
          action: "deny"
        }),
        400
      );
    }

    const emailAllowed =
      isValidEmail(rawEmail) || isGooglePlaceholderEmail(rawEmail);

    if (!rawEmail || !emailAllowed) {
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
      route: securityRoute
    });

    const security = await runSecurityOrchestrator({
      env,
      req: request,
      body,
      behavior: body,
      route: securityRoute,
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

    try {
      console.log(
        "SIGNUP_ATTEMPT_SECURITY",
        JSON.stringify(
          {
            route: securityRoute,
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
      console.error("SIGNUP_ATTEMPT_SECURITY_LOG_ERROR", logError);
    }

    const ip = normalizeIp(security?.actor?.ip || actor.ip);
    const securityAction = safeString(
      security?.risk?.finalAction || "allow",
      50
    ).toLowerCase();
    const riskScore = safePositiveInt(security?.risk?.riskScore, 0);
    const degraded = security?.risk?.degraded === true;

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
          finalAction: securityAction,
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
          finalAction: securityAction,
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

    const now = Date.now();

    const ipKey = buildIpAttemptKey(ip);
    const userKey = buildSignupAttemptKey(rawEmail, ip);

    const [ipRecord, record] = await Promise.all([
      getStoredRecord(redis, ipKey),
      getStoredRecord(redis, userKey)
    ]);

    debugSignupAttempt("records_loaded", {
      action,
      email: rawEmail,
      ip,
      now,
      userKey,
      ipKey,
      userRecord: record,
      ipRecord
    });

    if (ipRecord.lockUntil > now) {
      const remainingMs = ipRecord.lockUntil - now;

      debugSignupAttempt("ip_lock_enforced", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        userRecord: record,
        ipRecord,
        computed: {
          remainingMs
        }
      });

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
          message: "Too many attempts. Please try again later.",
          degraded
        }),
        200
      );
    }

    if (record.lockUntil > now && action !== "success") {
      const remainingMs = record.lockUntil - now;

      debugSignupAttempt("user_lock_enforced", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        userRecord: record,
        ipRecord,
        computed: {
          remainingMs
        }
      });

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
          message: "Too many attempts. Please try again later.",
          degraded
        }),
        200
      );
    }

    if (action === "check") {
      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      debugSignupAttempt("check_evaluated", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        userRecord: record,
        ipRecord,
        computed: {
          isLocked,
          remainingMs
        }
      });

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
          action: "allow",
          degraded
        }),
        200
      );
    }

    if (action === "success") {
      debugSignupAttempt("success_before_reset", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        userRecord: record,
        ipRecord
      });

      record.count = 0;
      record.lockUntil = 0;
      record.lastAttempt = now;

      await saveStoredRecord(redis, userKey, record);

      const savedSuccessRecord = await getStoredRecord(redis, userKey);

      debugSignupAttempt("success_after_reset", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        savedUserRecord: savedSuccessRecord
      });

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
          action: "allow",
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

      debugSignupAttempt("fail_before_save", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        userRecord: record,
        ipRecord
      });

      await Promise.all([
        saveStoredRecord(redis, userKey, record),
        saveStoredRecord(redis, ipKey, ipRecord)
      ]);

      const [savedIpRecord, savedUserRecord] = await Promise.all([
        getStoredRecord(redis, ipKey),
        getStoredRecord(redis, userKey)
      ]);

      debugSignupAttempt("fail_after_save", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
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

      debugSignupAttempt("fail_evaluated", {
        action,
        email: rawEmail,
        ip,
        now,
        userKey,
        ipKey,
        userRecord: record,
        ipRecord,
        computed: {
          isUserLocked,
          isIpLocked,
          lockType,
          remainingMs
        }
      });

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
          ipEscalationCount: ipRecord.escalationCount,
          degraded
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
      buildDeniedResponse("Internal server error.", {
        action: "deny"
      }),
      500
    );
  }
}
