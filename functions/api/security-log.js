import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  sanitizeBody,
  buildMethodNotAllowedResponse,
  runRouteSecurity
} from "./_api-security.js";
import { validateFreshRequest } from "./_request-freshness.js";

const ROUTE = "/api/security-log";
const MAX_BODY_KEYS = 20;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return jsonResponse(buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.startsWith("application/json")) {
    return jsonResponse(
      {
        success: false,
        message: "Unsupported content type"
      },
      415
    );
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return jsonResponse(
      {
        success: false,
        message: "Request body too large"
      },
      413
    );
  }

  try {
    let rawBody = {};

    try {
      rawBody = await request.json();
    } catch {
      return jsonResponse(
        {
          success: false,
          message: "Invalid JSON body"
        },
        400
      );
    }

    const body = sanitizeBody(rawBody, MAX_BODY_KEYS);

    const security = await runRouteSecurity({
      env,
      req: request,
      route: ROUTE,
      body,
      abuseSuccess: true,
      containmentConfig: {
        isWriteAction: true,
        actionType: "security_log",
        routeSensitivity: "critical"
      },
      rateLimitConfig: {
        key: `security-log:${request.headers.get("cf-connecting-ip") || "unknown"}`,
        limit: 20,
        windowMs: 60 * 1000
      }
    });

    if (security?.risk?.finalAction === "block") {
      return jsonResponse(
        {
          success: false,
          message: "Request blocked"
        },
        403
      );
    }

    const freshness = await validateFreshRequest({
      env,
      requestAt: body.eventAt || body.requestAt || body.timestamp,
      nonce: safeString(body.nonce || "", 200),
      scope: "security-log",
      requireNonce: Boolean(body.nonce),
      requireNonceStorage: true,
      maxAgeMs: 2 * 60 * 1000,
      futureToleranceMs: 15 * 1000,
      nonceTtlMs: 10 * 60 * 1000
    });

    if (!freshness.ok) {
      return jsonResponse(
        {
          success: false,
          message: "Invalid telemetry request"
        },
        400
      );
    }

    const ok = await writeSecurityLog({
      env,
      ...(body && typeof body === "object" ? body : {})
    });

    return jsonResponse({
      success: true,
      logged: ok === true
    });
  } catch (error) {
    console.error("security-log route error:", error);

    return jsonResponse(
      {
        success: false,
        message: "Internal server error"
      },
      500
    );
  }
}
