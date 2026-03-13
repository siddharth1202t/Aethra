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

    if (!allowedOrigins.includes(origin)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden origin"
      });
    }

    const { token } = req.body;
    const secret = process.env.TURNSTILE_SECRET_KEY;

    if (!token || !secret) {
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
      return res.status(400).json({ success: false });
    }

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Turnstile API error:", error);
    return res.status(500).json({ success: false });
  }
}
