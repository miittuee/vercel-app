export const config = { runtime: "edge" };

const TARGET_BASE = (process.env.T_DOMAIN || "").replace(/\/$/, "");
const API_KEY = process.env.P_KEY;

// Explicit allowlist (IMPORTANT)
const ALLOWED_PATHS = new Set([
  "/vercel",
  "/api/status",
]);

export default async function handler(req) {
  if (!TARGET_BASE) {
    return new Response("Server misconfigured", { status: 500 });
  }

  // ---- Auth layer (critical) ----
  const key = req.headers.get("x-api-key");
  if (!API_KEY || key !== API_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    const url = new URL(req.url);
    const path = url.pathname;

    // ---- Restrict routes ----
    if (!ALLOWED_PATHS.has(path)) {
      return new Response("Forbidden", { status: 403 });
    }

    const targetUrl = TARGET_BASE + path + url.search;

    // ---- Controlled headers (not pass-through) ----
    const headers = new Headers({
      "content-type": req.headers.get("content-type") || "application/json",
    });

    // Optional: pass identity safely
    const clientIp =
      req.headers.get("x-forwarded-for") ||
      req.headers.get("x-real-ip");

    if (clientIp) {
      headers.set("x-forwarded-for", clientIp);
    }

    const method = req.method;
    const hasBody = method !== "GET" && method !== "HEAD";

    const res = await fetch(targetUrl, {
      method,
      headers,
      body: hasBody ? req.body : undefined,
    });

    // ---- Return sanitized response ----
    return new Response(res.body, {
      status: res.status,
      headers: {
        "content-type": res.headers.get("content-type") || "text/plain",
      },
    });

  } catch (err) {
    console.error("proxy error:", err);
    return new Response("Upstream error", { status: 502 });
  }
}
