import { writeSecurityLog } from "./_security-log.js";

const rateLimitStore = new Map();

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return "unknown";
}

function isRateLimited(ip, limit = 10, windowMs = 60 * 1000) {
  const now = Date.now();
  const record = rateLimitStore.get(ip);

  if (!record) {
    rateLimitStore.set(ip, {
      count: 1,
      windowStart: now
    });
    return false;
  }

  if (now - record.windowStart > windowMs) {
    rateLimitStore.set(ip, {
      count: 1,
      windowStart: now
    });
    return false;
  }

  if (record.count >= limit) {
    return true;
  }

  record.count += 1;
  rateLimitStore.set(ip, record);
  return false;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ success: false });
  }

  try {
    const allowedOrigins = [
      "https://aethra-gules.vercel.app",
      "https://aethra-hb2h.vercel.app"
    ];

    const origin = req.headers.origin || "";
    const ip = getClientIp(req);

    if (!allowedOrigins.includes(origin)) {
      await writeSecurityLog({
        type: "forbidden_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on Turnstile verify API",
        ip,
        route: "/api/verify-turnstile",
        metadata: { origin }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin"
      });
    }

    if (isRateLimited(ip, 10, 60 * 1000)) {
      await writeSecurityLog({
        type: "rate_limit_hit",
        level: "warning",
        message: "Turnstile verify endpoint rate limit exceeded",
        ip,
        route: "/api/verify-turnstile",
        metadata: {}
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later."
      });
    }

    const { token } = req.body || {};
    const secret = process.env.TURNSTILE_SECRET_KEY;

    if (!token || !secret) {
      await writeSecurityLog({
        type: "invalid_turnstile_request",
        level: "warning",
        message: "Missing Turnstile token or secret during verification",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          hasToken: Boolean(token),
          hasSecret: Boolean(secret)
        }
      });

      return res.status(400).json({ success: false });
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
          response: token
        })
      }
    );

    const data = await response.json();

    if (!data.success) {
      await writeSecurityLog({
        type: "turnstile_failed",
        level: "warning",
        message: "Turnstile verification failed",
        ip,
        route: "/api/verify-turnstile",
        metadata: {
          hostname: data.hostname || "",
          errorCodes: data["error-codes"] || []
        }
      });

      return res.status(400).json({ success: false });
    }

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Turnstile API error:", error);

    await writeSecurityLog({
      type: "turnstile_api_error",
      level: "error",
      message: "Unhandled server error in Turnstile verify API",
      ip: getClientIp(req),
      route: "/api/verify-turnstile",
      metadata: {
        error: error?.message || "Unknown error"
      }
    });

    return res.status(500).json({ success: false });
  }
}
