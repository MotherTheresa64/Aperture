import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { hashPassword, verifyPassword, totp, verifyTotp, SessionStore } from "./auth.ts";

const STEP_SECONDS = 30;

let cachedPage: string | null = null;

function indexHtml(): string {
  if (cachedPage === null) {
    cachedPage = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
  }
  return cachedPage;
}

function send(res: ServerResponse, status: number, body: unknown, type = "application/json; charset=utf-8"): void {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": type,
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (raw === "") return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("request body must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    throw new Error(err instanceof Error && err.message.startsWith("request body") ? err.message : "request body is not valid JSON");
  }
}

export function createApp(): Server {
  const sessions = new SessionStore();

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return send(res, 200, indexHtml(), "text/html; charset=utf-8");
      }

      if (req.method === "GET" && url.pathname === "/health") {
        return send(res, 200, { status: "ok" });
      }

      if (req.method === "POST" && url.pathname === "/hash") {
        const body = await readJson(req);
        const password = String(body.password ?? "");
        if (password.length < 8) {
          return send(res, 400, { error: "invalid", message: "password must be at least 8 characters" });
        }
        return send(res, 200, { stored: hashPassword(password) });
      }

      if (req.method === "POST" && url.pathname === "/verify") {
        const body = await readJson(req);
        return send(res, 200, {
          valid: verifyPassword(String(body.password ?? ""), String(body.stored ?? "")),
        });
      }

      if (req.method === "GET" && url.pathname === "/totp") {
        const secret = url.searchParams.get("secret") ?? "";
        if (!secret) return send(res, 400, { error: "invalid", message: "secret is required" });
        const now = Date.now();
        const seconds = Math.floor(now / 1000);
        return send(res, 200, {
          code: totp(secret, now),
          remaining: STEP_SECONDS - (seconds % STEP_SECONDS),
        });
      }

      if (req.method === "POST" && url.pathname === "/verify-totp") {
        const body = await readJson(req);
        const secret = String(body.secret ?? "");
        const code = String(body.code ?? "");
        const valid = verifyTotp(secret, code, Date.now());
        return send(res, 200, valid ? { valid: true } : { valid: false, reason: "code does not match this time step" });
      }

      if (req.method === "POST" && url.pathname === "/session") {
        const body = await readJson(req);
        const userId = String(body.userId ?? "user");
        const issued = sessions.issue(userId, Date.now());
        return send(res, 200, { userId, token: issued.token });
      }

      if (req.method === "GET" && url.pathname === "/session") {
        const token = url.searchParams.get("token") ?? "";
        const session = sessions.resolve(token, Date.now());
        return send(res, 200, { userId: session?.userId ?? null });
      }

      if (req.method === "DELETE" && url.pathname === "/session") {
        sessions.revoke(url.searchParams.get("token") ?? "");
        return send(res, 204, "");
      }

      return send(res, 404, { error: "not_found", path: url.pathname });
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("request body")) {
        return send(res, 400, { error: "invalid", message: err.message });
      }
      return send(res, 500, { error: "internal", message: "unexpected failure" });
    }
  });
}

// pathToFileURL matters on Windows: argv[1] is a drive path there, which never
// equals the file:/// URL form.
const isMainModule =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  const port = Number(process.env.PORT ?? 4105);
  createApp().listen(port, () => {
    console.log(`aperture listening on http://localhost:${port}`);
  });
}
