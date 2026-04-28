export const config = { runtime: "edge" };

// Required env vars
const TARGET_BASE = (process.env.TARGET_DOMAIN || "").replace(/\/$/, "");
const API_KEY = process.env.API_KEY;

// Only allow specific API routes
const ALLOWED_PREFIXES = ["/vercel/"];

// Only allow safe methods
const ALLOWED_METHODS = new Set(["GET", "POST"]);

// Max body size (1MB)
const MAX_BODY_SIZE = 1 * 1024 * 1024;

export default async function handler(req) {
  if (!TARGET_BASE || !API_KEY) {
    return new Response("Server misconfigured", { status: 500 });
  }

  const url = new URL(req.url);

  // 🔒 1. Authentication
  const key = req.headers.get("x-api-key");
  if (key !== API_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }

  // 🔒 2. Restrict path
  if (!ALLOWED_PREFIXES.some(p => url.pathname.startsWith(p))) {
    return new Response("Forbidden", { status: 403 });
  }

  // 🔒 3. Restrict method
  if (!ALLOWED_METHODS.has(req.method)) {
    return new Response("Method Not Allowed", { status: 405 });
  }

  // Build target URL safely
  let targetUrl;
  try {
    targetUrl = new URL(url.pathname + url.search, TARGET_BASE);
  } catch {
    return new Response("Bad Request", { status: 400 });
  }

  try {
    let body = undefined;

    // 🔒 4. Controlled body handling
    if (req.method === "POST") {
      const contentType = req.headers.get("content-type") || "";

      if (!contentType.includes("application/json")) {
        return new Response("Unsupported Media Type", { status: 415 });
      }

      const raw = await req.text();

      if (raw.length > MAX_BODY_SIZE) {
        return new Response("Payload too large", { status: 413 });
      }

      body = raw;
    }

    // 🔒 5. Minimal, clean headers (no proxy impersonation)
    const headers = new Headers();
    headers.set("content-type", "application/json");

    // Optional: pass user agent if present
    const ua = req.headers.get("user-agent");
    if (ua) headers.set("user-agent", ua);

    // 🚀 6. Fetch to backend
    const res = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body,
      redirect: "follow",
    });

    // 🔒 7. Clean response
    const responseHeaders = new Headers();
    const contentType = res.headers.get("content-type");

    if (contentType) {
      responseHeaders.set("content-type", contentType);
    }

    return new Response(res.body, {
      status: res.status,
      headers: responseHeaders,
    });

  } catch (err) {
    console.error("relay error:", err);
    return new Response("Bad Gateway", { status: 502 });
  }
}
