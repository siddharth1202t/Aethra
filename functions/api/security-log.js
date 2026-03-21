import { writeSecurityLog } from "./_security-log-writer.js";

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
    return jsonResponse(
      {
        success: false,
        message: "Method not allowed"
      },
      405
    );
  }

  try {
    let body = {};

    try {
      body = await request.json();
    } catch {
      return jsonResponse(
        {
          success: false,
          message: "Invalid JSON body"
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
