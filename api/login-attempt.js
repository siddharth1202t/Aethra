const loginAttemptStore = new Map();

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return "unknown";
}

function getKey(email, ip) {
  return `${email}::${ip}`;
}

function getRecord(key) {
  const now = Date.now();
  const record = loginAttemptStore.get(key);

  if (!record) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now
    };
  }

  if (record.lockUntil && now > record.lockUntil) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now
    };
  }

  return record;
}

function saveRecord(key, record) {
  loginAttemptStore.set(key, record);
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
    if (!allowedOrigins.includes(origin)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden origin"
      });
    }

    const { email, action } = req.body || {};
    const normalizedEmail = normalizeEmail(email);
    const ip = getClientIp(req);

    if (!normalizedEmail) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    if (!action || !["check", "fail", "reset"].includes(action)) {
      return res.status(400).json({
        success: false,
        message: "Invalid action"
      });
    }

    const key = getKey(normalizedEmail, ip);
    const now = Date.now();
    let record = getRecord(key);

    if (action === "check") {
      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      return res.status(200).json({
        success: true,
        isLocked,
        remainingMs
      });
    }

    if (action === "fail") {
      record.count += 1;
      record.lastAttempt = now;

      if (record.count >= 5) {
        record.lockUntil = now + 15 * 60 * 1000;
      }

      saveRecord(key, record);

      const isLocked = record.lockUntil > now;
      const remainingMs = isLocked ? record.lockUntil - now : 0;

      return res.status(200).json({
        success: true,
        isLocked,
        remainingMs,
        attempts: record.count
      });
    }

    if (action === "reset") {
      loginAttemptStore.delete(key);

      return res.status(200).json({
        success: true,
        reset: true
      });
    }

    return res.status(400).json({
      success: false,
      message: "Unhandled action"
    });
  } catch (error) {
    console.error("Login attempt API error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
}
