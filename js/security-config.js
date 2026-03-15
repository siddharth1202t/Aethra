export const SECURITY_CONFIG = {
  developerEmail:
    typeof process !== "undefined" && process.env.DEVELOPER_EMAIL
      ? process.env.DEVELOPER_EMAIL
      : "siddharthkumar9127@gmail.com",

  allowedOrigins: [
    "https://aethra-gules.vercel.app",
    "https://aethra-hb2h.vercel.app"
  ],

  allowedHostnames: [
    "aethra-gules.vercel.app",
    "aethra-hb2h.vercel.app"
  ]
};
