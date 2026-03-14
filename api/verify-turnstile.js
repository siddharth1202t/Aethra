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
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }

  try {
    const allowedOrigins = [
      "https://aethra-gules.vercel.app",
      "https://aethra-hb2h.vercel.app"
    ];

    const origin = req.headers.origin || "";
    const ip = getClientIp(req);

    if (!allowedOrigins.includes(origin)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden origin"
      });
    }

    if (isRateLimited(ip, 10, 60 * 1000)) {
      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later."
      });
    }

    const { token } = req.body || {};
    const secret = process.env.TURNSTILE_SECRET_KEY;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Missing token"
      });
    }

    if (!secret) {
      return res.status(500).json({
        success: false,
        message: "TURNSTILE_SECRET_KEY is missing"
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
          response: token
        })
      }
    );

    const data = await response.json();

    if (!data.success) {
      return res.status(400).json({
        success: false,
        message: "Turnstile verification failed",
        errorCodes: data["error-codes"] || []
      });
    }

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Turnstile API error:", error);
    return res.status(500).json({
      success: false,
      message: error?.message || "Internal server error"
    });
  }
}
