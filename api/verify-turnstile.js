import { writeSecurityLog } from "./_security-log.js";
import { checkApiRateLimit } from "./_rate-limit.js";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_HOSTNAMES = new Set([
  "aethra-gules.vercel.app",
  "aethra-hb2h.vercel.app"
]);

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    const ip = forwarded.split(",")[0]?.trim();
    if (ip) return ip;
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0) {
    return realIp.trim();
  }

  return req.socket?.remoteAddress || "unknown";
}

function isAllowedOrigin(origin) {
  return ALLOWED_ORIGINS.has(origin);
}

function isExpectedHostname(hostname = "") {
  return ALLOWED_HOSTNAMES.has(hostname);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed."
    });
  }

  try {
    const origin = safeString(req.headers.origin || "", 200);
    const ip = getClientIp(req);
    const token = safeString(req.body?.token || "", 5000);
    const secret = process.env.TURNSTILE_SECRET_KEY;

    if (!isAllowedOrigin(origin)) {
      await writeSecurityLog({
        type: "forbidden_turnstile_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on verify-turnstile API",
        ip,
        route: "/api/verify-turnstile",
        metadata: { origin }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin."
      });
    }

    const rateLimitResult = checkApiRateLimit({
      key: `verify-turnstile:${ip}`,
      limit: 10,
      windowMs: 60 * 1000
    });

    if (!rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "turnstile_rate_limited",
        level: "warning",
        message: "Rate limit exceeded on verify-turnstile API",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          remainingMs: rateLimitResult.remainingMs
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later.",
        remainingMs: rateLimitResult.remainingMs || 0
      });
    }

    if (!token || !secret) {
      await writeSecurityLog({
        type: "turnstile_missing_token_or_secret",
        level: "error",
        message: "Missing token or server secret in verify-turnstile API",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          hasToken: Boolean(token),
          hasSecret: Boolean(secret)
        }
      });

      return res.status(400).json({
        success: false,
        message: "Missing token or secret."
      });
    }

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          secret,
          response: token,
          remoteip: ip
        })
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      await writeSecurityLog({
        type: "turnstile_upstream_error",
        level: "error",
        message: "Turnstile upstream verification request failed",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          status: response.status
        }
      });

      return res.status(502).json({
        success: false,
        message: "Captcha verification service failed."
      });
    }

    if (!data.success) {
      await writeSecurityLog({
        type: "turnstile_verification_failed",
        level: "warning",
        message: "Turnstile verification failed",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          errorCodes: Array.isArray(data["error-codes"])
            ? data["error-codes"].slice(0, 10)
            : []
        }
      });

      return res.status(400).json({
        success: false,
        message: "Captcha verification failed."
      });
    }

    if (data.hostname && !isExpectedHostname(data.hostname)) {
      await writeSecurityLog({
        type: "turnstile_hostname_mismatch",
        level: "critical",
        message: "Turnstile token hostname did not match allowed hostnames",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          hostname: safeString(data.hostname, 200)
        }
      });

      return res.status(400).json({
        success: false,
        message: "Captcha hostname validation failed."
      });
    }

    return res.status(200).json({
      success: true
    });
  } catch (error) {
    console.error("Turnstile API error:", error);

    try {
      await writeSecurityLog({
        type: "turnstile_api_error",
        level: "error",
        message: "Unhandled server error in verify-turnstile API",
        ip: getClientIp(req),
        route: "/api/verify-turnstile",
        metadata: {
          error: safeString(error?.message || "Unknown error", 500)
        }
      });
    } catch (logError) {
      console.error("Security log write failed:", logError);
    }

    return res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
}
