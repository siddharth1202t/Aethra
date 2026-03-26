import { createActorContext } from "../_actor-context.js";
import { writeSecurityLog } from "../_security-log-writer.js";
import {
  buildDeniedResponse,
  buildMethodNotAllowedResponse
} from "../_api-security.js";

import { getRedis } from "../_redis.js";
import { clearBotBehaviorSnapshot } from "../_bot-detection.js";
import { clearApiAbuse } from "../_api-abuse-protection.js";
import { clearRiskState } from "../_security-risk-state.js";
import { resetAdaptiveThreatMode } from "../_adaptive-threat-mode.js";
import {
  clearContainmentState,
  clearActorContainment
} from "../_security-containment.js";

const ROUTE = "/api/admin/security-reset";

const NORMAL_ACTIONS = new Set([
  "clear_login_attempt_state",
  "clear_signup_attempt_state",
  "clear_bot_state",
  "clear_abuse_state",
  "clear_actor_risk"
]);

const ELEVATED_ACTIONS = new Set([
  "clear_lockdown",
  "clear_global_containment",
  "full_test_reset"
]);

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

function safeString(value, maxLength = 300) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", 100);
  if (!ip) return "unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return ip || "unknown";
}

function normalizeEmail(value = "") {
  return safeString(value || "", 200).trim().toLowerCase();
}

function isNormalAction(action) {
  return NORMAL_ACTIONS.has(action);
}

function isElevatedAction(action) {
  return ELEVATED_ACTIONS.has(action);
}

async function logSecurityReset({
  env,
  actor,
  action,
  reason,
  level = "warning",
  message = "Security reset endpoint invoked",
  metadata = {}
}) {
  try {
    await writeSecurityLog({
      env,
      type: "security_reset_invoked",
      level,
      message,
      ip: actor?.ip || "unknown",
      route: ROUTE,
      userId: actor?.userId || null,
      sessionId: actor?.sessionId || null,
      metadata: {
        action,
        reason,
        actorKey: actor?.actorKey || null,
        routeKey: actor?.routeKey || null,
        ...metadata
      }
    });
  } catch (error) {
    console.error("security-reset log failed:", error);
  }
}

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

  let body = {};
  try {
    body = await request.json();
  } catch {
    return json(
      buildDeniedResponse("Invalid JSON body.", {
        action: "deny"
      }),
      400
    );
  }

  const actor = createActorContext({
    req: request,
    body,
    route: ROUTE
  });

  const action = safeString(body?.action || "", 100).toLowerCase();
  const reason = safeString(body?.reason || "no_reason_provided", 300);

  if (!action) {
    return json(
      buildDeniedResponse("Missing action.", {
        action: "deny"
      }),
      400
    );
  }

  const providedNormalKey = safeString(
    request.headers.get("x-security-break-glass") || "",
    500
  );
  const providedElevatedKey = safeString(
    request.headers.get("x-security-break-glass-elevated") || "",
    500
  );

  const expectedNormalKey = safeString(
    env?.SECURITY_BREAK_GLASS_KEY || "",
    500
  );
  const expectedElevatedKey = safeString(
    env?.SECURITY_BREAK_GLASS_ELEVATED_KEY || "",
    500
  );

  const targetIp = normalizeIp(body?.ip || actor?.ip || "unknown");
  const targetSessionId = safeString(body?.sessionId || actor?.sessionId || "", 120);
  const targetUserId = safeString(body?.userId || actor?.userId || "", 128);
  const targetEmail = normalizeEmail(body?.email || "");

  const actionIsNormal = isNormalAction(action);
  const actionIsElevated = isElevatedAction(action);

  if (!actionIsNormal && !actionIsElevated) {
    return json(
      buildDeniedResponse("Invalid action.", {
        action: "deny"
      }),
      400
    );
  }

  if (actionIsElevated) {
    if (!expectedElevatedKey || providedElevatedKey !== expectedElevatedKey) {
      return json(
        buildDeniedResponse("Forbidden.", {
          action: "deny"
        }),
        403
      );
    }
  } else {
    if (!expectedNormalKey || providedNormalKey !== expectedNormalKey) {
      return json(
        buildDeniedResponse("Forbidden.", {
          action: "deny"
        }),
        403
      );
    }
  }

  try {
    const redis = getRedis(env);

    const results = {
      action,
      target: {
        ip: targetIp,
        sessionId: targetSessionId || null,
        userId: targetUserId || null,
        email: targetEmail || null
      },
      cleared: {}
    };

    if (action === "clear_login_attempt_state") {
      const deletedKeys = [];

      if (targetIp && targetIp !== "unknown") {
        deletedKeys.push(`login-attempt-ip:${targetIp}`);
      }

      if (targetEmail && targetIp && targetIp !== "unknown") {
        deletedKeys.push(`login-attempt:${targetEmail}::${targetIp}`);
      }

      if (deletedKeys.length) {
        results.cleared.loginAttemptKeysDeleted = await redis.del(...deletedKeys);
        results.cleared.loginAttemptKeys = deletedKeys;
      } else {
        results.cleared.loginAttemptKeysDeleted = 0;
        results.cleared.loginAttemptKeys = [];
      }

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        message: "Login attempt state cleared through break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Login attempt state cleared.",
        results
      });
    }

    if (action === "clear_signup_attempt_state") {
      const deletedKeys = [];

      if (targetIp && targetIp !== "unknown") {
        deletedKeys.push(`signup-attempt-ip:${targetIp}`);
      }

      if (targetEmail && targetIp && targetIp !== "unknown") {
        deletedKeys.push(`signup-attempt:${targetEmail}::${targetIp}`);
      }

      if (deletedKeys.length) {
        results.cleared.signupAttemptKeysDeleted = await redis.del(...deletedKeys);
        results.cleared.signupAttemptKeys = deletedKeys;
      } else {
        results.cleared.signupAttemptKeysDeleted = 0;
        results.cleared.signupAttemptKeys = [];
      }

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        message: "Signup attempt state cleared through break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Signup attempt state cleared.",
        results
      });
    }

    if (action === "clear_bot_state") {
      results.cleared.bot = await clearBotBehaviorSnapshot({
        env,
        ip: targetIp,
        sessionId: targetSessionId,
        userId: targetUserId
      });

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        message: "Bot state cleared through break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Bot state cleared.",
        results
      });
    }

    if (action === "clear_abuse_state") {
      results.cleared.abuse = await clearApiAbuse({
        env,
        ip: targetIp,
        sessionId: targetSessionId,
        userId: targetUserId
      });

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        message: "Abuse state cleared through break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Abuse state cleared.",
        results
      });
    }

    if (action === "clear_actor_risk") {
      const riskResults = [];

      if (targetSessionId) {
        riskResults.push(
          await clearRiskState({
            env,
            actorType: "session",
            actorId: targetSessionId,
            reason
          })
        );
      }

      if (targetUserId) {
        riskResults.push(
          await clearRiskState({
            env,
            actorType: "user",
            actorId: targetUserId,
            reason
          })
        );
      }

      if (targetIp && targetIp !== "unknown") {
        riskResults.push(
          await clearRiskState({
            env,
            actorType: "ip",
            actorId: targetIp,
            reason
          })
        );
      }

      results.cleared.risk = riskResults;

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        message: "Actor risk state cleared through break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Actor risk state cleared.",
        results
      });
    }

    if (action === "clear_lockdown") {
      results.cleared.adaptiveThreatMode = await resetAdaptiveThreatMode(env);
      results.cleared.globalContainment = await clearContainmentState(env);

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        level: "warning",
        message: "Lockdown state cleared through elevated break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Lockdown state cleared.",
        results
      });
    }

    if (action === "clear_global_containment") {
      results.cleared.globalContainment = await clearContainmentState(env);

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        level: "warning",
        message: "Global containment cleared through elevated break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Global containment cleared.",
        results
      });
    }

    if (action === "full_test_reset") {
      results.cleared.adaptiveThreatMode = await resetAdaptiveThreatMode(env);
      results.cleared.globalContainment = await clearContainmentState(env);

      if (targetSessionId) {
        results.cleared.sessionContainment = await clearActorContainment(env, {
          actorType: "session",
          actorId: targetSessionId,
          reason
        });
      }

      if (targetUserId) {
        results.cleared.userContainment = await clearActorContainment(env, {
          actorType: "user",
          actorId: targetUserId,
          reason
        });
      }

      if (targetIp && targetIp !== "unknown") {
        results.cleared.ipContainment = await clearActorContainment(env, {
          actorType: "ip",
          actorId: targetIp,
          reason
        });
      }

      results.cleared.bot = await clearBotBehaviorSnapshot({
        env,
        ip: targetIp,
        sessionId: targetSessionId,
        userId: targetUserId
      });

      results.cleared.abuse = await clearApiAbuse({
        env,
        ip: targetIp,
        sessionId: targetSessionId,
        userId: targetUserId
      });

      const riskResults = [];

      if (targetSessionId) {
        riskResults.push(
          await clearRiskState({
            env,
            actorType: "session",
            actorId: targetSessionId,
            reason
          })
        );
      }

      if (targetUserId) {
        riskResults.push(
          await clearRiskState({
            env,
            actorType: "user",
            actorId: targetUserId,
            reason
          })
        );
      }

      if (targetIp && targetIp !== "unknown") {
        riskResults.push(
          await clearRiskState({
            env,
            actorType: "ip",
            actorId: targetIp,
            reason
          })
        );
      }

      results.cleared.risk = riskResults;

      const deletedKeys = [];

      if (targetIp && targetIp !== "unknown") {
        deletedKeys.push(
          `login-attempt-ip:${targetIp}`,
          `signup-attempt-ip:${targetIp}`
        );
      }

      if (targetEmail && targetIp && targetIp !== "unknown") {
        deletedKeys.push(
          `login-attempt:${targetEmail}::${targetIp}`,
          `signup-attempt:${targetEmail}::${targetIp}`
        );
      }

      if (deletedKeys.length) {
        results.cleared.attemptKeysDeleted = await redis.del(...deletedKeys);
        results.cleared.attemptKeys = deletedKeys;
      } else {
        results.cleared.attemptKeysDeleted = 0;
        results.cleared.attemptKeys = [];
      }

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        level: "warning",
        message: "Full test reset executed through elevated break-glass endpoint",
        metadata: results.target
      });

      return json({
        success: true,
        action: "allow",
        message: "Full test reset completed.",
        results
      });
    }

    return json(
      buildDeniedResponse("Invalid action.", {
        action: "deny"
      }),
      400
    );
  } catch (error) {
    console.error("security-reset error:", error);

    await logSecurityReset({
      env,
      actor,
      action,
      reason,
      level: "error",
      message: "Security reset endpoint failed",
      metadata: {
        targetIp,
        targetSessionId,
        targetUserId,
        targetEmail,
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
