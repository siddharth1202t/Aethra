import { writeSecurityLog } from "./_security-log-writer.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    const ok = await writeSecurityLog(req.body || {});

    return res.status(200).json({
      success: true,
      logged: ok === true
    });
  } catch (error) {
    console.error("security-log route error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
}
