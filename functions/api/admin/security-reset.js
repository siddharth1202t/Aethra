import { createActorContext } from "../_actor-context.js";
import { writeSecurityLog } from "../_security-log-writer.js";
import {
  buildDeniedResponse,
  buildMethodNotAllowedResponse
} from "../_api-security.js";

import { clearBotBehaviorSnapshot } from "../_bot-detection.js";
import { clearApiAbuse } from "../_api-abuse-protection.js";
import { clearRiskState } from "../_security-risk-state.js";
import { resetAdaptiveThreatMode } from "../_adaptive-threat-mode.js";
import {
  clearContainmentState,
  clearActorContainment
} from "../_security-containment.js";

const ROUTE = "/api/admin/security-reset";

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

async function logSecurityReset({
  env,
  actor,
  action,
  reason,
  metadata = {},
  level = "warning",
  message = "Security reset endpoint invoked"
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

  const providedBreakGlassKey = safeString(
    request.headers.get("x-security-break-glass") || "",
    500
  );

  const expectedBreakGlassKey = safeString(
    env?.SECURITY_BREAK_GLASS_KEY || "",
    500
  );

  if (!expectedBreakGlassKey || providedBreakGlassKey !== expectedBreakGlassKey) {
    return json(
      buildDeniedResponse("Forbidden.", {
        action: "deny"
      }),
      403
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

  const targetIp = normalizeIp(body?.ip || actor?.ip || "unknown");
  const targetSessionId = safeString(body?.sessionId || actor?.sessionId || "", 120);
  const targetUserId = safeString(body?.userId || actor?.userId || "", 128);

  if (!action) {
    return json(
      buildDeniedResponse("Missing action.", {
        action: "deny"
      }),
      400
    );
  }

  try {
    const results = {
      action,
      target: {
        ip: targetIp,
        sessionId: targetSessionId || null,
        userId: targetUserId || null
      },
      cleared: {}
    };

    if (action === "clear_lockdown") {
      results.cleared.adaptiveThreatMode = await resetAdaptiveThreatMode(env);
      results.cleared.globalContainment = await clearContainmentState(env);

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        metadata: {
          targetIp,
          targetSessionId,
          targetUserId
        },
        level: "warning",
        message: "Lockdown state cleared through break-glass endpoint"
      });

      return json({
        success: true,
        action: "allow",
        message: "Lockdown state cleared.",
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

      await logSecurityReset({
        env,
        actor,
        action,
        reason,
        metadata: {
          targetIp,
          targetSessionId,
          targetUserId
        },
        level: "warning",
        message: "Full test reset executed through break-glass endpoint"
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
      metadata: {
        targetIp,
        targetSessionId,
        targetUserId,
        error: safeString(error?.message || "Unknown error", 500)
      },
      level: "error",
      message: "Security reset endpoint failed"
    });

    return json(
      buildDeniedResponse("Internal server error.", {
        action: "deny"
      }),
      500
    );
  }
}
