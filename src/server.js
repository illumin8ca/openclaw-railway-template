import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import cookieParser from "cookie-parser";
import express from "express";
import httpProxy from "http-proxy";
import sendgrid from "@sendgrid/mail";
import * as tar from "tar";

// Restore Claude Code from persistent volume on container restart.
// The binary lives at /data/claude-code and config at /data/.claude — both on
// the Railway volume. The ephemeral root filesystem needs symlinks recreated
// after every boot so that `claude` is on PATH and settings/history persist.
{
  const home = os.homedir();

  // Claude Code binary: /root/.local/share/claude -> /data/claude-code
  // The bin symlink at /root/.local/bin/claude points through this.
  const localShare = path.join(home, ".local", "share");
  const localBin = path.join(home, ".local", "bin");
  const links = [
    [path.join(localShare, "claude"), "/data/claude-code"],
    [path.join(home, ".claude"), "/data/.claude"],
    [path.join(home, ".claude.json"), "/data/.claude.json"],
  ];

  // Ensure parent directories exist (ephemeral fs starts empty).
  for (const dir of [localShare, localBin]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  for (const [link, target] of links) {
    try {
      if (fs.existsSync(target) && !fs.existsSync(link)) {
        fs.symlinkSync(target, link);
        console.log(`[startup] symlinked ${link} -> ${target}`);
      }
    } catch (err) {
      console.warn(`[startup] could not symlink ${link}: ${err.message}`);
    }
  }

  // Ensure the claude bin symlink points at the latest persisted version.
  const binLink = path.join(localBin, "claude");
  const versionsDir = "/data/claude-code/versions";
  try {
    if (fs.existsSync(versionsDir)) {
      const versions = fs.readdirSync(versionsDir).sort();
      if (versions.length > 0) {
        const latest = path.join(versionsDir, versions[versions.length - 1]);
        // Recreate bin symlink if missing or stale.
        try { fs.unlinkSync(binLink); } catch {}
        fs.symlinkSync(latest, binLink);
        console.log(`[startup] symlinked ${binLink} -> ${latest}`);
      }
    }
  } catch (err) {
    console.warn(`[startup] could not link claude binary: ${err.message}`);
  }
}

// Railway commonly sets PORT=8080 for HTTP services.
const PORT = Number.parseInt(process.env.PORT ?? "8080", 10);
const STATE_DIR =
  process.env.OPENCLAW_STATE_DIR?.trim() ||
  path.join(os.homedir(), ".openclaw");
const WORKSPACE_DIR =
  process.env.OPENCLAW_WORKSPACE_DIR?.trim() ||
  path.join(STATE_DIR, "workspace");

// ── Auth Management ───────────────────────────────────────────────────────
// Magic link authentication with SendGrid

function parseCookiesFromString(cookieStr) {
  const cookies = {};
  if (!cookieStr) return cookies;
  cookieStr.split(';').forEach(pair => {
    const [key, ...val] = pair.trim().split('=');
    if (key) cookies[key] = decodeURIComponent(val.join('='));
  });
  return cookies;
}

function getAuthConfig() {
  try {
    const authPath = path.join(STATE_DIR, "auth.json");
    if (fs.existsSync(authPath)) {
      return JSON.parse(fs.readFileSync(authPath, "utf8"));
    }
  } catch (err) {
    console.error("[auth] Failed to read auth.json:", err);
  }
  return { allowedEmails: [], sessions: {}, magicLinks: {} };
}

function saveAuthConfig(config) {
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(STATE_DIR, "auth.json"),
      JSON.stringify(config, null, 2),
      { mode: 0o600 }
    );
  } catch (err) {
    console.error("[auth] Failed to save auth.json:", err);
  }
}

function getSendGridConfig() {
  try {
    const sgPath = path.join(STATE_DIR, "sendgrid.json");
    if (fs.existsSync(sgPath)) {
      return JSON.parse(fs.readFileSync(sgPath, "utf8"));
    }
  } catch (err) {
    console.error("[auth] Failed to read sendgrid.json:", err);
  }
  return null;
}

function isEmailAllowed(email) {
  const auth = getAuthConfig();
  const normalizedEmail = email.toLowerCase().trim();
  return auth.allowedEmails.some(
    (allowed) => allowed.toLowerCase().trim() === normalizedEmail
  );
}

function generateMagicToken() {
  return crypto.randomBytes(32).toString("hex");
}

function storeMagicLink(email, token) {
  const auth = getAuthConfig();
  if (!auth.magicLinks) auth.magicLinks = {};
  auth.magicLinks[token] = {
    email: email.toLowerCase().trim(),
    expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
    createdAt: Date.now(),
  };
  // Clean up expired tokens (older than 1 hour)
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const [key, value] of Object.entries(auth.magicLinks)) {
    if (value.expiresAt < oneHourAgo) {
      delete auth.magicLinks[key];
    }
  }
  saveAuthConfig(auth);
}

function verifyMagicLink(token) {
  const auth = getAuthConfig();
  if (!auth.magicLinks) return null;
  const link = auth.magicLinks[token];
  if (!link) return null;
  if (Date.now() > link.expiresAt) {
    delete auth.magicLinks[token];
    saveAuthConfig(auth);
    return null;
  }
  // Consume the token (one-time use)
  delete auth.magicLinks[token];
  saveAuthConfig(auth);
  return link.email;
}

function createSession(email) {
  const auth = getAuthConfig();
  if (!auth.sessions) auth.sessions = {};
  const sessionId = crypto.randomBytes(32).toString("hex");
  auth.sessions[sessionId] = {
    email: email.toLowerCase().trim(),
    createdAt: Date.now(),
    expiresAt: Date.now() + 72 * 60 * 60 * 1000, // 72 hours
  };
  saveAuthConfig(auth);
  return sessionId;
}

function getSession(sessionId) {
  if (!sessionId) return null;
  const auth = getAuthConfig();
  if (!auth.sessions) return null;
  const session = auth.sessions[sessionId];
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    delete auth.sessions[sessionId];
    saveAuthConfig(auth);
    return null;
  }
  return session;
}

function deleteSession(sessionId) {
  const auth = getAuthConfig();
  if (!auth.sessions) return;
  delete auth.sessions[sessionId];
  saveAuthConfig(auth);
}

async function sendMagicLinkEmail(email, token, host) {
  const sgConfig = getSendGridConfig();
  if (!sgConfig || !sgConfig.apiKey || !sgConfig.senderEmail) {
    throw new Error("SendGrid not configured");
  }

  sendgrid.setApiKey(sgConfig.apiKey);

  const magicLink = `https://${host}/api/auth/verify?token=${token}`;

  const msg = {
    to: email,
    from: sgConfig.senderEmail,
    subject: "Your Gerald Login Link",
    text: `Click this link to log in to Gerald Dashboard:\n\n${magicLink}\n\nThis link expires in 15 minutes.\n\nIf you didn't request this, please ignore this email.`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
          }
          .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .header h1 {
            color: #0a0a0f;
            font-size: 24px;
            margin: 0;
          }
          .accent {
            color: #00ff87;
          }
          .button {
            display: inline-block;
            padding: 14px 32px;
            background: linear-gradient(135deg, #00ff87 0%, #00b4d8 100%);
            color: #0a0a0f;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            text-align: center;
            margin: 20px 0;
          }
          .button:hover {
            opacity: 0.9;
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            font-size: 12px;
            color: #666;
            text-align: center;
          }
          .expiry {
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px;
            margin: 20px 0;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Gerald <span class="accent">Dashboard</span></h1>
          </div>
          <p>Hi there!</p>
          <p>You requested a login link for the Gerald Dashboard. Click the button below to sign in:</p>
          <p style="text-align: center;">
            <a href="${magicLink}" class="button">Sign In to Gerald</a>
          </p>
          <div class="expiry">
            ⏰ This link expires in <strong>15 minutes</strong> and can only be used once.
          </div>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="word-break: break-all; font-size: 12px; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">
            ${magicLink}
          </p>
          <div class="footer">
            <p>If you didn't request this login link, you can safely ignore this email.</p>
            <p>Gerald Dashboard • Powered by OpenClaw</p>
          </div>
        </div>
      </body>
      </html>
    `,
  };

  await sendgrid.send(msg);
}

// Illumin8 site directories
const SITE_DIR = path.join(WORKSPACE_DIR, 'site');
const PRODUCTION_DIR = path.join(SITE_DIR, 'production');
const DEV_DIR = path.join(SITE_DIR, 'dev');

// Gerald Dashboard
const DASHBOARD_PORT = 3003;
const DASHBOARD_TARGET = `http://127.0.0.1:${DASHBOARD_PORT}`;
const DASHBOARD_DIR = path.join(STATE_DIR || '/data', 'dashboard');
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY || 'xQQB2ppPNQ+Ruo1xgr5pIFSix+86prk02IRS1+2208RRuCFM';

// Read CLIENT_DOMAIN from env or from a persisted config file
function getClientDomain() {
  const envDomain = process.env.CLIENT_DOMAIN?.trim();
  if (envDomain) return envDomain;
  // Try reading from persisted config
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'illumin8.json'), 'utf8'));
    return cfg.clientDomain || null;
  } catch { return null; }
}

// Serve static files with SPA fallback
function serveStaticSite(dir, req, res) {
  const reqPath = decodeURIComponent(req.path);
  const filePath = path.join(dir, reqPath === '/' ? 'index.html' : reqPath);
  // Prevent directory traversal
  if (!filePath.startsWith(dir)) {
    return res.status(403).send('Forbidden');
  }
  // 1. Exact file match (e.g., /styles.css, /image.png)
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    return res.sendFile(filePath);
  }
  // 2. Directory with index.html (e.g., /about → /about/index.html) — Astro MPA pattern
  const dirIndexPath = path.join(filePath, 'index.html');
  if (fs.existsSync(dirIndexPath) && fs.statSync(dirIndexPath).isFile()) {
    return res.sendFile(dirIndexPath);
  }
  // 3. Try adding .html extension (e.g., /about → /about.html)
  const htmlPath = filePath + '.html';
  if (fs.existsSync(htmlPath) && fs.statSync(htmlPath).isFile()) {
    return res.sendFile(htmlPath);
  }
  // 4. 404 page if one exists
  const notFoundPath = path.join(dir, '404.html');
  if (fs.existsSync(notFoundPath)) {
    return res.status(404).sendFile(notFoundPath);
  }
  // 5. Show a "Coming Soon" placeholder if no site is built yet
  const placeholderPath = path.join(process.cwd(), 'src', 'public', 'placeholder.html');
  if (fs.existsSync(placeholderPath)) {
    return res.status(200).sendFile(placeholderPath);
  }
  return res.status(404).send('Not found');
}

// Protect /setup with a user-provided password.
const SETUP_PASSWORD = process.env.SETUP_PASSWORD?.trim();

// Debug logging helper
const DEBUG = process.env.OPENCLAW_TEMPLATE_DEBUG?.toLowerCase() === "true";
function debug(...args) {
  if (DEBUG) console.log(...args);
}

// Gateway admin token (protects Openclaw gateway + Control UI).
// Must be stable across restarts. If not provided via env, persist it in the state dir.
function resolveGatewayToken() {
  console.log(`[token] ========== SERVER STARTUP TOKEN RESOLUTION ==========`);
  const envTok = process.env.OPENCLAW_GATEWAY_TOKEN?.trim();
  console.log(`[token] ENV OPENCLAW_GATEWAY_TOKEN exists: ${!!process.env.OPENCLAW_GATEWAY_TOKEN}`);
  console.log(`[token] ENV value length: ${process.env.OPENCLAW_GATEWAY_TOKEN?.length || 0}`);
  console.log(`[token] After trim length: ${envTok?.length || 0}`);

  if (envTok) {
    console.log(`[token] ✓ Using token from OPENCLAW_GATEWAY_TOKEN env variable`);
    console.log(`[token]   First 16 chars: ${envTok.slice(0, 16)}...`);
    console.log(`[token]   Full token: ${envTok}`);
    return envTok;
  }

  console.log(`[token] Env variable not available, checking persisted file...`);
  const tokenPath = path.join(STATE_DIR, "gateway.token");
  console.log(`[token] Token file path: ${tokenPath}`);

  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) {
      console.log(`[token] ✓ Using token from persisted file`);
      console.log(`[token]   First 16 chars: ${existing.slice(0, 8)}...`);
      return existing;
    }
  } catch (err) {
    console.log(`[token] Could not read persisted file: ${err.message}`);
  }

  const generated = crypto.randomBytes(32).toString("hex");
  console.log(`[token] ⚠️  Generating new random token (${generated.slice(0, 8)}...)`);
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, generated, { encoding: "utf8", mode: 0o600 });
    console.log(`[token] Persisted new token to ${tokenPath}`);
  } catch (err) {
    console.warn(`[token] Could not persist token: ${err}`);
  }
  return generated;
}

const OPENCLAW_GATEWAY_TOKEN = resolveGatewayToken();
process.env.OPENCLAW_GATEWAY_TOKEN = OPENCLAW_GATEWAY_TOKEN;
console.log(`[token] Final resolved token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);
console.log(`[token] ========== TOKEN RESOLUTION COMPLETE ==========\n`);

// Where the gateway will listen internally (we proxy to it).
const INTERNAL_GATEWAY_PORT = Number.parseInt(
  process.env.INTERNAL_GATEWAY_PORT ?? "18789",
  10,
);
const INTERNAL_GATEWAY_HOST = process.env.INTERNAL_GATEWAY_HOST ?? "127.0.0.1";
const GATEWAY_TARGET = `http://${INTERNAL_GATEWAY_HOST}:${INTERNAL_GATEWAY_PORT}`;

// Always run the built-from-source CLI entry directly to avoid PATH/global-install mismatches.
const OPENCLAW_ENTRY =
  process.env.OPENCLAW_ENTRY?.trim() || "/openclaw/dist/entry.js";
const OPENCLAW_NODE = process.env.OPENCLAW_NODE?.trim() || "node";

function clawArgs(args) {
  return [OPENCLAW_ENTRY, ...args];
}

function configPath() {
  return (
    process.env.OPENCLAW_CONFIG_PATH?.trim() ||
    path.join(STATE_DIR, "openclaw.json")
  );
}

function isConfigured() {
  try {
    return fs.existsSync(configPath());
  } catch {
    return false;
  }
}

let gatewayProc = null;
let gatewayStarting = null;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const start = Date.now();
  const endpoints = ["/openclaw", "/openclaw", "/", "/health"];
  
  while (Date.now() - start < timeoutMs) {
    for (const endpoint of endpoints) {
      try {
        const res = await fetch(`${GATEWAY_TARGET}${endpoint}`, { method: "GET" });
        // Any HTTP response means the port is open.
        if (res) {
          console.log(`[gateway] ready at ${endpoint}`);
          return true;
        }
      } catch (err) {
        // not ready, try next endpoint
      }
    }
    await sleep(250);
  }
  console.error(`[gateway] failed to become ready after ${timeoutMs}ms`);
  return false;
}

async function startGateway() {
  if (gatewayProc) return;
  if (!isConfigured()) throw new Error("Gateway cannot start: not configured");

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  // Sync wrapper token to openclaw.json before every gateway start.
  // This ensures the gateway's config-file token matches what the wrapper injects via proxy.
  console.log(`[gateway] ========== GATEWAY START TOKEN SYNC ==========`);
  console.log(`[gateway] Syncing wrapper token to config: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);

  const syncResult = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]),
  );

  console.log(`[gateway] Sync result: exit code ${syncResult.code}`);
  if (syncResult.output?.trim()) {
    console.log(`[gateway] Sync output: ${syncResult.output}`);
  }

  if (syncResult.code !== 0) {
    console.error(`[gateway] ⚠️  WARNING: Token sync failed with code ${syncResult.code}`);
  }

  // Verify sync succeeded
  try {
    const config = JSON.parse(fs.readFileSync(configPath(), "utf8"));
    const configToken = config?.gateway?.auth?.token;

    console.log(`[gateway] Token verification:`);
    console.log(`[gateway]   Wrapper: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);
    console.log(`[gateway]   Config:  ${configToken?.slice(0, 16)}... (len: ${configToken?.length || 0})`);

    if (configToken !== OPENCLAW_GATEWAY_TOKEN) {
      console.error(`[gateway] ✗ Token mismatch detected!`);
      console.error(`[gateway]   Full wrapper: ${OPENCLAW_GATEWAY_TOKEN}`);
      console.error(`[gateway]   Full config:  ${configToken || 'null'}`);
      throw new Error(
        `Token mismatch: wrapper has ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... but config has ${(configToken || 'null')?.slice?.(0, 16)}...`
      );
    }
    console.log(`[gateway] ✓ Token verification PASSED`);
  } catch (err) {
    console.error(`[gateway] ERROR: Token verification failed: ${err}`);
    throw err; // Don't start gateway with mismatched token
  }

  console.log(`[gateway] ========== TOKEN SYNC COMPLETE ==========`);

  const args = [
    "gateway",
    "run",
    "--bind",
    "loopback",
    "--port",
    String(INTERNAL_GATEWAY_PORT),
    "--auth",
    "token",
    "--token",
    OPENCLAW_GATEWAY_TOKEN,
  ];

  gatewayProc = childProcess.spawn(OPENCLAW_NODE, clawArgs(args), {
    stdio: "inherit",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    },
  });

  console.log(`[gateway] starting with command: ${OPENCLAW_NODE} ${clawArgs(args).join(" ")}`);
  console.log(`[gateway] STATE_DIR: ${STATE_DIR}`);
  console.log(`[gateway] WORKSPACE_DIR: ${WORKSPACE_DIR}`);
  console.log(`[gateway] config path: ${configPath()}`);

  gatewayProc.on("error", (err) => {
    console.error(`[gateway] spawn error: ${String(err)}`);
    gatewayProc = null;
  });

  gatewayProc.on("exit", (code, signal) => {
    console.error(`[gateway] exited code=${code} signal=${signal}`);
    gatewayProc = null;
  });
}

async function ensureGatewayRunning() {
  if (!isConfigured()) return { ok: false, reason: "not configured" };
  if (gatewayProc) return { ok: true };
  if (!gatewayStarting) {
    gatewayStarting = (async () => {
      await startGateway();
      const ready = await waitForGatewayReady({ timeoutMs: 20_000 });
      if (!ready) {
        throw new Error("Gateway did not become ready in time");
      }
    })().finally(() => {
      gatewayStarting = null;
    });
  }
  await gatewayStarting;
  return { ok: true };
}

async function restartGateway() {
  console.log("[gateway] Restarting gateway...");

  // Kill gateway process tracked by wrapper
  if (gatewayProc) {
    console.log("[gateway] Killing wrapper-managed gateway process");
    try {
      gatewayProc.kill("SIGTERM");
    } catch {
      // ignore
    }
    gatewayProc = null;
  }

  // Also kill any other gateway processes (e.g., started by onboard command)
  // by finding processes listening on the gateway port
  console.log(`[gateway] Killing any other gateway processes on port ${INTERNAL_GATEWAY_PORT}`);
  try {
    const killResult = await runCmd("pkill", ["-f", "openclaw-gateway"]);
    console.log(`[gateway] pkill result: exit code ${killResult.code}`);
  } catch (err) {
    console.log(`[gateway] pkill failed: ${err.message}`);
  }

  // Give processes time to exit and release the port
  await sleep(1500);

  return ensureGatewayRunning();
}

function requireSetupAuth(req, res, next) {
  if (!SETUP_PASSWORD) {
    return res
      .status(500)
      .type("text/plain")
      .send(
        "SETUP_PASSWORD is not set. Set it in Railway Variables before using /setup.",
      );
  }

  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="Openclaw Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (password !== SETUP_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="Openclaw Setup"');
    return res.status(401).send("Invalid password");
  }
  return next();
}

// Auth middleware for dashboard and API routes
function requireAuth(req, res, next) {
  const sessionId = req.cookies.gerald_session;
  const session = getSession(sessionId);

  if (!session) {
    // For API calls, return 401
    if (req.path.startsWith("/api/") && !req.path.startsWith("/api/auth/")) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    // For HTML pages, redirect to login
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  // Attach user info to request
  req.user = { email: session.email };
  return next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// Minimal health endpoint for Railway.
app.get("/setup/healthz", (_req, res) => res.json({ ok: true }));

// Serve static files for setup wizard (no-cache to avoid stale JS/CSS)
app.get("/setup/app.js", requireSetupAuth, (_req, res) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.type("application/javascript");
  res.sendFile(path.join(process.cwd(), "src", "public", "setup-app.js"));
});

app.get("/setup/styles.css", requireSetupAuth, (_req, res) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.type("text/css");
  res.sendFile(path.join(process.cwd(), "src", "public", "styles.css"));
});

app.get("/setup", requireSetupAuth, (_req, res) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.sendFile(path.join(process.cwd(), "src", "public", "setup.html"));
});

// ── Auth Endpoints ─────────────────────────────────────────────────────────

// Login page
app.get("/login", (_req, res) => {
  const error = res.req.query?.error;
  const errorMessage = error === "expired" 
    ? "Your login link has expired. Please request a new one."
    : error === "invalid"
    ? "Invalid login link. Please request a new one."
    : "";

  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.type("text/html");
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Sign In - Gerald</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          background: #0a0a0f;
          color: #e2e8f0;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
        }
        .container {
          width: 100%;
          max-width: 400px;
          background: #111118;
          border-radius: 12px;
          padding: 48px 32px;
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
          border: 1px solid rgba(255, 255, 255, 0.06);
        }
        .logo {
          text-align: center;
          margin-bottom: 40px;
        }
        .bot-icon {
          width: 64px;
          height: 64px;
          margin: 0 auto 20px;
        }
        .logo h1 {
          font-size: 36px;
          font-weight: 700;
          margin-bottom: 8px;
          color: #e2e8f0;
        }
        .logo p {
          font-size: 15px;
          color: #94a3b8;
          font-weight: 400;
        }
        .form-group {
          margin-bottom: 24px;
        }
        label {
          display: block;
          font-size: 14px;
          font-weight: 500;
          margin-bottom: 8px;
          color: #e2e8f0;
        }
        input[type="email"] {
          width: 100%;
          padding: 14px 16px;
          font-size: 15px;
          background: #14141c;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 8px;
          color: #e2e8f0;
          transition: all 0.2s ease;
        }
        input[type="email"]:focus {
          outline: none;
          border-color: #00ff87;
          box-shadow: 0 0 0 3px rgba(0, 255, 135, 0.1);
        }
        input[type="email"]::placeholder {
          color: #64748b;
        }
        button {
          width: 100%;
          padding: 14px 24px;
          font-size: 15px;
          font-weight: 600;
          background: #00ff87;
          color: #0a0a0f;
          border: none;
          border-radius: 9999px;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        button:hover {
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(0, 255, 135, 0.3);
        }
        button:active {
          transform: translateY(0);
        }
        button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
          transform: none;
        }
        .message {
          padding: 14px 16px;
          border-radius: 8px;
          margin-bottom: 24px;
          font-size: 14px;
          line-height: 1.5;
          text-align: center;
        }
        .error {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.2);
          color: #fca5a5;
        }
        .success {
          background: rgba(0, 255, 135, 0.1);
          border: 1px solid rgba(0, 255, 135, 0.2);
          color: #00ff87;
        }
        .hidden {
          display: none;
        }
        .footer {
          margin-top: 32px;
          text-align: center;
          font-size: 13px;
          color: #64748b;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <svg class="bot-icon" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="8" y="16" width="48" height="40" rx="8" fill="#00ff87" opacity="0.1"/>
            <rect x="8" y="16" width="48" height="40" rx="8" stroke="#00ff87" stroke-width="2"/>
            <circle cx="22" cy="32" r="4" fill="#00ff87"/>
            <circle cx="42" cy="32" r="4" fill="#00ff87"/>
            <path d="M26 44 Q32 48 38 44" stroke="#00ff87" stroke-width="2" stroke-linecap="round"/>
            <circle cx="32" cy="8" r="3" fill="#00b4d8"/>
            <line x1="32" y1="11" x2="32" y2="16" stroke="#00b4d8" stroke-width="2"/>
          </svg>
          <h1>Gerald</h1>
          <p>At your service, Sir.</p>
        </div>

        ${errorMessage ? `<div class="message error">${errorMessage}</div>` : ''}
        
        <div id="successMessage" class="message success hidden">
          ✓ Check your email for a login link!
        </div>

        <div id="errorMessage" class="message error hidden"></div>

        <form id="loginForm">
          <div class="form-group">
            <label for="email">Email Address</label>
            <input 
              type="email" 
              id="email" 
              name="email" 
              placeholder="you@example.com" 
              required 
              autocomplete="email"
              autofocus
            />
          </div>
          <button type="submit" id="submitBtn">
            Send Magic Link
          </button>
        </form>

        <div class="footer">
          Powered by OpenClaw
        </div>
      </div>

      <script>
        const form = document.getElementById('loginForm');
        const emailInput = document.getElementById('email');
        const submitBtn = document.getElementById('submitBtn');
        const successMessage = document.getElementById('successMessage');
        const errorMessage = document.getElementById('errorMessage');

        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          
          const email = emailInput.value.trim();
          if (!email) return;

          // Disable form
          submitBtn.disabled = true;
          submitBtn.textContent = 'Sending...';
          successMessage.classList.add('hidden');
          errorMessage.classList.add('hidden');

          try {
            const response = await fetch('/api/auth/request', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email })
            });

            const data = await response.json();

            if (response.ok) {
              successMessage.classList.remove('hidden');
              emailInput.value = '';
              submitBtn.textContent = 'Link Sent!';
              setTimeout(() => {
                submitBtn.textContent = 'Send Magic Link';
                submitBtn.disabled = false;
              }, 3000);
            } else {
              errorMessage.textContent = data.error || 'Failed to send login link';
              errorMessage.classList.remove('hidden');
              submitBtn.textContent = 'Send Magic Link';
              submitBtn.disabled = false;
            }
          } catch (error) {
            errorMessage.textContent = 'Network error. Please try again.';
            errorMessage.classList.remove('hidden');
            submitBtn.textContent = 'Send Magic Link';
            submitBtn.disabled = false;
          }
        });
      </script>
    </body>
    </html>
  `);
});

// Request magic link
app.post("/api/auth/request", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== "string") {
      return res.status(400).json({ error: "Email is required" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check if email is allowed (but don't reveal this in the response)
    if (isEmailAllowed(normalizedEmail)) {
      const token = generateMagicToken();
      storeMagicLink(normalizedEmail, token);

      // Get the host for the magic link
      const host = req.get("host") || req.hostname || "localhost";

      try {
        await sendMagicLinkEmail(normalizedEmail, token, host);
      } catch (err) {
        console.error("[auth] Failed to send magic link email:", err);
        return res.status(500).json({ error: "Failed to send email" });
      }
    }

    // Always return success to avoid leaking which emails are valid
    res.json({
      message: "If your email is registered, you'll receive a login link",
    });
  } catch (err) {
    console.error("[auth] Error in /api/auth/request:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Verify magic link
app.get("/api/auth/verify", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token || typeof token !== "string") {
      return res.redirect("/login?error=invalid");
    }

    const email = verifyMagicLink(token);
    if (!email) {
      return res.redirect("/login?error=expired");
    }

    // Create session
    const sessionId = createSession(email);

    // Set session cookie
    res.cookie("gerald_session", sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 72 * 60 * 60 * 1000, // 72 hours
    });

    // Determine redirect destination
    let redirect = req.query.redirect || "/";
    if (!redirect.startsWith("/") || redirect.startsWith("//")) {
      redirect = "/";
    }

    // Also authenticate with the Gerald Dashboard (so user doesn't see Telegram login)
    try {
      const dashRes = await fetch(`${DASHBOARD_TARGET}/api/auth/magic/generate`, {
        method: 'POST',
        headers: { 'X-Api-Key': INTERNAL_API_KEY }
      });
      
      if (dashRes.ok) {
        const { code } = await dashRes.json();
        // Redirect to dashboard's magic link endpoint which will set the token cookie
        return res.redirect(`/api/auth/magic/${code}?redirect=${encodeURIComponent(redirect)}`);
      } else {
        console.error('[auth] Dashboard magic generate failed:', dashRes.status);
        // Fallback: just redirect to destination (user will see Telegram login)
        return res.redirect(redirect);
      }
    } catch (dashErr) {
      console.error('[auth] Dashboard magic auth failed:', dashErr);
      // Fallback: just redirect to destination (user will see Telegram login)
      return res.redirect(redirect);
    }
  } catch (err) {
    console.error("[auth] Error in /api/auth/verify:", err);
    res.redirect("/login?error=invalid");
  }
});

// Logout
app.get("/api/auth/logout", (req, res) => {
  const sessionId = req.cookies.gerald_session;
  if (sessionId) {
    deleteSession(sessionId);
  }
  res.clearCookie("gerald_session");
  res.redirect("/login");
});

// Check auth status
app.get("/api/auth/me", (req, res) => {
  const sessionId = req.cookies.gerald_session;
  const session = getSession(sessionId);

  if (!session) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  res.json({ email: session.email });
});

app.get("/setup/api/status", requireSetupAuth, async (_req, res) => {
  const version = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const channelsHelp = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["channels", "add", "--help"]),
  );

  // We reuse Openclaw's own auth-choice grouping logic indirectly by hardcoding the same group defs.
  // This is intentionally minimal; later we can parse the CLI help output to stay perfectly in sync.
  const authGroups = [
    {
      value: "openai",
      label: "OpenAI",
      hint: "Codex OAuth + API key",
      options: [
        { value: "codex-cli", label: "OpenAI Codex OAuth (Codex CLI)" },
        { value: "openai-codex", label: "OpenAI Codex (ChatGPT OAuth)" },
        { value: "openai-api-key", label: "OpenAI API key" },
      ],
    },
    {
      value: "anthropic",
      label: "Anthropic",
      hint: "Claude Code CLI + API key",
      options: [
        { value: "claude-cli", label: "Anthropic token (Claude Code CLI)" },
        { value: "token", label: "Anthropic token (paste setup-token)" },
        { value: "apiKey", label: "Anthropic API key" },
      ],
    },
    {
      value: "google",
      label: "Google",
      hint: "Gemini API key + OAuth",
      options: [
        { value: "gemini-api-key", label: "Google Gemini API key" },
        { value: "google-antigravity", label: "Google Antigravity OAuth" },
        { value: "google-gemini-cli", label: "Google Gemini CLI OAuth" },
      ],
    },
    {
      value: "openrouter",
      label: "OpenRouter",
      hint: "API key",
      options: [{ value: "openrouter-api-key", label: "OpenRouter API key" }],
    },
    {
      value: "ai-gateway",
      label: "Vercel AI Gateway",
      hint: "API key",
      options: [
        { value: "ai-gateway-api-key", label: "Vercel AI Gateway API key" },
      ],
    },
    {
      value: "moonshot",
      label: "Moonshot AI",
      hint: "Kimi K2 + Kimi Code",
      options: [
        { value: "moonshot-api-key", label: "Moonshot AI API key" },
        { value: "kimi-code-api-key", label: "Kimi Code API key" },
      ],
    },
    {
      value: "zai",
      label: "Z.AI (GLM 4.7)",
      hint: "API key",
      options: [{ value: "zai-api-key", label: "Z.AI (GLM 4.7) API key" }],
    },
    {
      value: "minimax",
      label: "MiniMax",
      hint: "M2.1 (recommended)",
      options: [
        { value: "minimax-api", label: "MiniMax M2.1" },
        { value: "minimax-api-lightning", label: "MiniMax M2.1 Lightning" },
      ],
    },
    {
      value: "qwen",
      label: "Qwen",
      hint: "OAuth",
      options: [{ value: "qwen-portal", label: "Qwen OAuth" }],
    },
    {
      value: "copilot",
      label: "Copilot",
      hint: "GitHub + local proxy",
      options: [
        {
          value: "github-copilot",
          label: "GitHub Copilot (GitHub device login)",
        },
        { value: "copilot-proxy", label: "Copilot Proxy (local)" },
      ],
    },
    {
      value: "synthetic",
      label: "Synthetic",
      hint: "Anthropic-compatible (multi-model)",
      options: [{ value: "synthetic-api-key", label: "Synthetic API key" }],
    },
    {
      value: "opencode-zen",
      label: "OpenCode Zen",
      hint: "API key",
      options: [
        { value: "opencode-zen", label: "OpenCode Zen (multi-model proxy)" },
      ],
    },
  ];

  // Check SendGrid configuration
  const sendgridConfig = getSendGridConfig();
  const authConfig = getAuthConfig();

  res.json({
    configured: isConfigured(),
    gatewayTarget: GATEWAY_TARGET,
    openclawVersion: version.output.trim(),
    channelsAddHelp: channelsHelp.output,
    authGroups,
    defaultAuthGroup: process.env.DEFAULT_MODEL?.includes('moonshot') ? 'moonshot' : null,
    defaultAuthChoice: process.env.DEFAULT_MODEL?.includes('moonshot') ? 'moonshot-api-key' : null,
    defaultAuthSecret: process.env.MOONSHOT_API_KEY?.trim() ? '••••••••' : null,
    hasDefaultApiKey: !!process.env.MOONSHOT_API_KEY?.trim(),
    defaultModel: process.env.DEFAULT_MODEL || null,
    defaultClientDomain: process.env.CLIENT_DOMAIN?.trim() || null,
    cloudflareConfigured: !!(process.env.CLOUDFLARE_API_KEY?.trim() && process.env.CLOUDFLARE_EMAIL?.trim()),
    sendgridConfigured: !!(sendgridConfig?.apiKey && sendgridConfig?.senderEmail),
    hasSendgridEnv: !!process.env.SENDGRID_API_KEY?.trim(),
    authConfigured: !!(authConfig?.allowedEmails?.length > 0),
  });
});

function buildOnboardArgs(payload) {
  const args = [
    "onboard",
    "--non-interactive",
    "--accept-risk",
    "--json",
    "--no-install-daemon",
    "--skip-health",
    "--workspace",
    WORKSPACE_DIR,
    // The wrapper owns public networking; keep the gateway internal.
    "--gateway-bind",
    "loopback",
    "--gateway-port",
    String(INTERNAL_GATEWAY_PORT),
    "--gateway-auth",
    "token",
    "--gateway-token",
    OPENCLAW_GATEWAY_TOKEN,
    "--flow",
    payload.flow || "quickstart",
  ];

  if (payload.authChoice) {
    args.push("--auth-choice", payload.authChoice);

    // Map secret to correct flag for common choices.
    // Fall back to env var API key if user didn't enter one manually
    let secret = (payload.authSecret || "").trim();
    if (!secret && payload.authChoice === "moonshot-api-key" && process.env.MOONSHOT_API_KEY?.trim()) {
      secret = process.env.MOONSHOT_API_KEY.trim();
    }
    const map = {
      "openai-api-key": "--openai-api-key",
      apiKey: "--anthropic-api-key",
      "openrouter-api-key": "--openrouter-api-key",
      "ai-gateway-api-key": "--ai-gateway-api-key",
      "moonshot-api-key": "--moonshot-api-key",
      "kimi-code-api-key": "--kimi-code-api-key",
      "gemini-api-key": "--gemini-api-key",
      "zai-api-key": "--zai-api-key",
      "minimax-api": "--minimax-api-key",
      "minimax-api-lightning": "--minimax-api-key",
      "synthetic-api-key": "--synthetic-api-key",
      "opencode-zen": "--opencode-zen-api-key",
    };
    const flag = map[payload.authChoice];
    if (flag && secret) {
      args.push(flag, secret);
    }

    if (payload.authChoice === "token" && secret) {
      // This is the Anthropics setup-token flow.
      args.push("--token-provider", "anthropic", "--token", secret);
    }
  }

  return args;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = childProcess.spawn(cmd, args, {
      ...opts,
      env: {
        ...process.env,
        ...(opts.env || {}),
        OPENCLAW_STATE_DIR: STATE_DIR,
        OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      },
    });

    let out = "";
    proc.stdout?.on("data", (d) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d) => (out += d.toString("utf8")));

    proc.on("error", (err) => {
      out += `\n[spawn error] ${String(err)}\n`;
      resolve({ code: 127, output: out });
    });

    proc.on("close", (code) => resolve({ code: code ?? 0, output: out }));
  });
}

async function setupCloudflareDNS(domain, railwayDomain) {
  const cfKey = process.env.CLOUDFLARE_API_KEY?.trim();
  const cfEmail = process.env.CLOUDFLARE_EMAIL?.trim();
  if (!cfKey || !cfEmail) {
    return { ok: false, output: 'Cloudflare API key or email not set in environment variables' };
  }

  const cfHeaders = {
    'X-Auth-Email': cfEmail,
    'X-Auth-Key': cfKey,
    'Content-Type': 'application/json',
  };

  let output = '';

  // 1. Look up zone ID
  const zoneRes = await fetch(`https://api.cloudflare.com/client/v4/zones?name=${domain}`, { headers: cfHeaders });
  const zoneData = await zoneRes.json();

  if (!zoneData.success || !zoneData.result?.length) {
    return { ok: false, output: `Domain ${domain} not found in Cloudflare account. Add it to Cloudflare first.` };
  }

  const zoneId = zoneData.result[0].id;
  output += `Zone found: ${zoneId}\n`;

  // 2. Get existing DNS records
  const existingRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, { headers: cfHeaders });
  const existingData = await existingRes.json();
  const existingRecords = existingData.result || [];

  // 3. Create/update CNAME records for root, dev, and gerald subdomains
  const records = [
    { name: domain, type: 'CNAME' },
    { name: `dev.${domain}`, type: 'CNAME' },
    { name: `gerald.${domain}`, type: 'CNAME' },
  ];

  // Also ensure www redirects to root
  records.push({ name: `www.${domain}`, type: 'CNAME', content: domain });

  for (const record of records) {
    const content = record.content || railwayDomain;
    const existing = existingRecords.find(r => r.name === record.name && r.type === record.type);

    if (existing) {
      // Update existing record
      const updateRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${existing.id}`, {
        method: 'PUT',
        headers: cfHeaders,
        body: JSON.stringify({
          type: record.type,
          name: record.name,
          content: content,
          proxied: true,
        }),
      });
      const updateData = await updateRes.json();
      output += `Updated ${record.name} → ${content} (${updateData.success ? 'OK' : JSON.stringify(updateData.errors)})\n`;
    } else {
      // Create new record
      const createRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
        method: 'POST',
        headers: cfHeaders,
        body: JSON.stringify({
          type: record.type,
          name: record.name,
          content: content,
          proxied: true,
        }),
      });
      const createData = await createRes.json();
      output += `Created ${record.name} → ${content} (${createData.success ? 'OK' : JSON.stringify(createData.errors)})\n`;
    }
  }

  return { ok: true, output, zoneId };
}

async function createTurnstileWidget(domain, zoneId) {
  const cfKey = process.env.CLOUDFLARE_API_KEY?.trim();
  const cfEmail = process.env.CLOUDFLARE_EMAIL?.trim();
  if (!cfKey || !cfEmail) {
    return { ok: false, output: 'Cloudflare credentials not available' };
  }

  const cfHeaders = {
    'X-Auth-Email': cfEmail,
    'X-Auth-Key': cfKey,
    'Content-Type': 'application/json',
  };

  // Get account ID from the zone
  const zoneRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}`, { headers: cfHeaders });
  const zoneData = await zoneRes.json();
  const accountId = zoneData.result?.account?.id;

  if (!accountId) {
    return { ok: false, output: 'Could not determine Cloudflare account ID' };
  }

  // Create Turnstile widget
  const turnstileRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/challenges/widgets`, {
    method: 'POST',
    headers: cfHeaders,
    body: JSON.stringify({
      name: `${domain} Contact Form`,
      domains: [domain, `dev.${domain}`, `gerald.${domain}`],
      mode: 'managed',
      bot_fight_mode: false,
    }),
  });

  const turnstileData = await turnstileRes.json();

  if (!turnstileData.success) {
    return { ok: false, output: `Turnstile creation failed: ${JSON.stringify(turnstileData.errors)}` };
  }

  const siteKey = turnstileData.result.sitekey;
  const secretKey = turnstileData.result.secret;

  return {
    ok: true,
    siteKey,
    secretKey,
    output: `Turnstile widget created: ${siteKey}`,
  };
}

async function setupSendGridDomainAuth(domain, sendgridApiKey) {
  const cfKey = process.env.CLOUDFLARE_API_KEY?.trim();
  const cfEmail = process.env.CLOUDFLARE_EMAIL?.trim();
  
  if (!cfKey || !cfEmail) {
    return { ok: false, output: '[sendgrid-domain] Cloudflare credentials not available' };
  }

  const sgHeaders = {
    'Authorization': `Bearer ${sendgridApiKey}`,
    'Content-Type': 'application/json',
  };

  const cfHeaders = {
    'X-Auth-Email': cfEmail,
    'X-Auth-Key': cfKey,
    'Content-Type': 'application/json',
  };

  let output = '';

  try {
    // 1. Check if domain auth already exists
    output += `[sendgrid-domain] Checking for existing domain authentication...\n`;
    const existingDomainsRes = await fetch('https://api.sendgrid.com/v3/whitelabel/domains', {
      headers: sgHeaders,
    });
    if (!existingDomainsRes.ok) {
      const errText = await existingDomainsRes.text();
      return { ok: false, output: `SendGrid API error (${existingDomainsRes.status}): ${errText}` };
    }
    const existingDomains = await existingDomainsRes.json();
    if (!Array.isArray(existingDomains)) {
      return { ok: false, output: `SendGrid API returned unexpected response: ${JSON.stringify(existingDomains)}` };
    }
    
    let domainId = null;
    let dnsRecords = null;

    const existing = existingDomains.find(d => d.domain === domain);
    if (existing) {
      output += `[sendgrid-domain] Found existing domain auth (ID: ${existing.id})\n`;
      domainId = existing.id;
      dnsRecords = existing.dns;
    } else {
      // 2. Create domain authentication
      output += `[sendgrid-domain] Creating domain authentication for ${domain}...\n`;
      const createRes = await fetch('https://api.sendgrid.com/v3/whitelabel/domains', {
        method: 'POST',
        headers: sgHeaders,
        body: JSON.stringify({
          domain: domain,
          automatic_security: true,
          default: true,
        }),
      });

      if (!createRes.ok) {
        const errorText = await createRes.text();
        return { ok: false, output: output + `[sendgrid-domain] Failed to create domain: ${errorText}` };
      }

      const createData = await createRes.json();
      domainId = createData.id;
      dnsRecords = createData.dns;
      output += `[sendgrid-domain] Domain auth created (ID: ${domainId})\n`;
    }

    // 3. Get Cloudflare zone ID
    output += `[sendgrid-domain] Looking up Cloudflare zone for ${domain}...\n`;
    const zoneRes = await fetch(`https://api.cloudflare.com/client/v4/zones?name=${domain}`, {
      headers: cfHeaders,
    });
    if (!zoneRes.ok) {
      const errText = await zoneRes.text();
      return { ok: false, output: output + `[sendgrid-domain] Cloudflare API error (${zoneRes.status}): ${errText}\n` };
    }
    const zoneData = await zoneRes.json();

    if (!zoneData.success || !zoneData.result?.length) {
      return { ok: false, output: output + `[sendgrid-domain] Domain ${domain} not found in Cloudflare account\n` };
    }

    const zoneId = zoneData.result[0].id;
    output += `[sendgrid-domain] Cloudflare zone found: ${zoneId}\n`;

    // 4. Get existing DNS records
    const existingDnsRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
      headers: cfHeaders,
    });
    if (!existingDnsRes.ok) {
      const errText = await existingDnsRes.text();
      return { ok: false, output: output + `[sendgrid-domain] Failed to fetch DNS records (${existingDnsRes.status}): ${errText}\n` };
    }
    const existingDnsData = await existingDnsRes.json();
    const existingRecords = existingDnsData.result || [];

    // 5. Create/update DNS records
    const recordsToCreate = [
      { key: 'mail_cname', record: dnsRecords.mail_cname },
      { key: 'dkim1', record: dnsRecords.dkim1 },
      { key: 'dkim2', record: dnsRecords.dkim2 },
    ];

    for (const { key, record } of recordsToCreate) {
      if (!record) {
        output += `[sendgrid-domain] Warning: ${key} record not provided by SendGrid\n`;
        continue;
      }

      const existing = existingRecords.find(r => 
        r.name === record.host && r.type.toUpperCase() === record.type.toUpperCase()
      );

      if (existing) {
        // Update existing record
        const updateRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${existing.id}`, {
          method: 'PUT',
          headers: cfHeaders,
          body: JSON.stringify({
            type: record.type.toUpperCase(),
            name: record.host,
            content: record.data,
            proxied: false, // CNAME records for email must not be proxied
          }),
        });
        const updateData = await updateRes.json();
        output += `[sendgrid-domain] Updated ${key}: ${record.host} → ${record.data} (${updateData.success ? 'OK' : 'FAILED'})\n`;
      } else {
        // Create new record
        const createRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`, {
          method: 'POST',
          headers: cfHeaders,
          body: JSON.stringify({
            type: record.type.toUpperCase(),
            name: record.host,
            content: record.data,
            proxied: false, // CNAME records for email must not be proxied
          }),
        });
        const createData = await createRes.json();
        output += `[sendgrid-domain] Created ${key}: ${record.host} → ${record.data} (${createData.success ? 'OK' : 'FAILED'})\n`;
      }
    }

    // 6. Wait for DNS propagation and validate (retry loop)
    output += `[sendgrid-domain] Waiting for DNS propagation...\n`;
    let validated = false;
    
    for (let attempt = 1; attempt <= 3; attempt++) {
      await sleep(5000); // Wait 5 seconds between attempts
      
      output += `[sendgrid-domain] Validation attempt ${attempt}/3...\n`;
      const validateRes = await fetch(`https://api.sendgrid.com/v3/whitelabel/domains/${domainId}/validate`, {
        method: 'POST',
        headers: sgHeaders,
      });

      if (!validateRes.ok) {
        const errorText = await validateRes.text();
        output += `[sendgrid-domain] Validation API error (${validateRes.status}): ${errorText}\n`;
        continue;
      }

      const validateData = await validateRes.json();
      
      if (validateData.valid) {
        validated = true;
        output += `[sendgrid-domain] ✓ Domain validation successful!\n`;
        break;
      } else {
        output += `[sendgrid-domain] Validation pending (DNS may need more time to propagate)\n`;
        if (validateData.validation_results) {
          output += `[sendgrid-domain] Details: ${JSON.stringify(validateData.validation_results)}\n`;
        }
      }
    }

    if (!validated) {
      output += `[sendgrid-domain] ⚠️  Domain not yet validated - DNS records created but may need more time to propagate\n`;
    }

    // 7. Register verified sender as backup
    output += `[sendgrid-domain] Registering verified sender...\n`;
    const senderEmail = `noreply@${domain}`;
    
    const verifiedSenderRes = await fetch('https://api.sendgrid.com/v3/verified_senders', {
      method: 'POST',
      headers: sgHeaders,
      body: JSON.stringify({
        nickname: 'Gerald Dashboard',
        from_email: senderEmail,
        from_name: 'Gerald Dashboard',
        reply_to: senderEmail,
        reply_to_name: 'Gerald Dashboard',
        address: '123 Main St',
        city: 'Edmonton',
        state: 'AB',
        zip: 'T5A0A1',
        country: 'CA',
      }),
    });

    if (verifiedSenderRes.ok) {
      output += `[sendgrid-domain] ✓ Verified sender registered: ${senderEmail}\n`;
    } else {
      const errorText = await verifiedSenderRes.text();
      // Don't fail if sender already exists
      if (errorText.includes('already exists') || errorText.includes('duplicate')) {
        output += `[sendgrid-domain] Verified sender already exists: ${senderEmail}\n`;
      } else {
        output += `[sendgrid-domain] ⚠️  Failed to register verified sender (${verifiedSenderRes.status}): ${errorText}\n`;
      }
    }

    return {
      ok: true,
      validated,
      output,
    };

  } catch (err) {
    return {
      ok: false,
      output: output + `[sendgrid-domain] Error: ${err.message}\n`,
    };
  }
}

async function cloneAndBuild(repoUrl, branch, targetDir, token) {
  // Clean target dir
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.mkdirSync(targetDir, { recursive: true });

  // Clone with token auth
  const authUrl = token
    ? repoUrl.replace('https://', `https://x-access-token:${token}@`)
    : repoUrl;

  console.log(`[build] Cloning ${repoUrl} branch=${branch} into ${targetDir}`);
  let clone = await runCmd('git', ['clone', '--depth', '1', '--branch', branch, authUrl, targetDir]);
  if (clone.code !== 0) {
    // If branch doesn't exist, create it from the default branch
    if (clone.output.includes('not found') || clone.output.includes('Could not find remote branch')) {
      console.log(`[build] Branch '${branch}' not found, creating from default branch...`);
      fs.rmSync(targetDir, { recursive: true, force: true });
      fs.mkdirSync(targetDir, { recursive: true });
      
      // Clone default branch
      clone = await runCmd('git', ['clone', '--depth', '1', authUrl, targetDir]);
      if (clone.code === 0) {
        // Create and push the new branch
        await runCmd('git', ['checkout', '-b', branch], { cwd: targetDir });
        await runCmd('git', ['push', 'origin', branch], { cwd: targetDir });
        console.log(`[build] Created branch '${branch}' from default`);
      } else {
        console.error(`[build] Clone failed: ${clone.output}`);
        return { ok: false, output: clone.output };
      }
    } else {
      console.error(`[build] Clone failed: ${clone.output}`);
      return { ok: false, output: clone.output };
    }
  }

  // Detect build system and install deps
  const packageJson = path.join(targetDir, 'package.json');
  if (fs.existsSync(packageJson)) {
    console.log(`[build] Installing dependencies...`);
    // Use clean PATH to avoid esbuild version conflicts with openclaw's bundled version
    const cleanEnv = {
      ...process.env,
      PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/linuxbrew/.linuxbrew/bin',
      // Prevent esbuild from finding stale binaries during postinstall
      ESBUILD_BINARY_PATH: '',
    };
    
    // Step 1: Install without running postinstall scripts (avoids esbuild version conflicts)
    console.log(`[build] Installing dependencies (--ignore-scripts)...`);
    const install = await runCmd('npm', ['install', '--ignore-scripts'], { cwd: targetDir, env: cleanEnv });
    if (install.code !== 0) {
      console.error(`[build] npm install failed: ${install.output}`);
      return { ok: false, output: install.output };
    }
    
    // Step 2: Re-run esbuild's install to fetch correct platform-specific binary
    // Find all esbuild install.js files and run them individually
    const { execSync } = await import('child_process');
    try {
      const esbuildDirs = execSync(
        `find ${targetDir}/node_modules -name "install.js" -path "*/esbuild/*" -not -path "*/node_modules/*/node_modules/*/node_modules/*"`,
        { encoding: 'utf8', env: cleanEnv }
      ).trim().split('\n').filter(Boolean);
      
      for (const installScript of esbuildDirs) {
        const esbuildDir = path.dirname(installScript);
        console.log(`[build] Running esbuild install in ${path.relative(targetDir, esbuildDir)}...`);
        // Remove any cached/linked binary first
        const binPath = path.join(esbuildDir, 'bin', 'esbuild');
        try { fs.unlinkSync(binPath); } catch {}
        await runCmd('node', ['install.js'], { cwd: esbuildDir, env: cleanEnv });
      }
    } catch (e) {
      console.log(`[build] esbuild re-install: ${e.message || 'no esbuild found (OK)'}`);
    }

    // Build the site
    console.log(`[build] Running build...`);
    const build = await runCmd('npm', ['run', 'build'], { cwd: targetDir, env: cleanEnv });
    if (build.code !== 0) {
      console.error(`[build] Build failed: ${build.output}`);
      return { ok: false, output: build.output };
    }

    // Detect output directory (common static site generators)
    const possibleDirs = ['dist', 'build', 'out', '_site', '.output/public'];
    let outputDir = null;
    for (const dir of possibleDirs) {
      const fullPath = path.join(targetDir, dir);
      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
        outputDir = fullPath;
        break;
      }
    }

    if (outputDir && outputDir !== targetDir) {
      // Move build output to be the root of targetDir
      // First, move output to a temp location
      const tmpDir = targetDir + '_built';
      fs.rmSync(tmpDir, { recursive: true, force: true });
      fs.renameSync(outputDir, tmpDir);
      // Remove the cloned source
      fs.rmSync(targetDir, { recursive: true, force: true });
      // Move built output to target
      fs.renameSync(tmpDir, targetDir);
    }

    console.log(`[build] Build complete: ${targetDir}`);
    return { ok: true, output: `Built successfully from ${branch} branch` };
  }

  // No package.json — assume static site, already good
  return { ok: true, output: `Cloned static site from ${branch} branch` };
}

// ── Gerald Dashboard setup & lifecycle ────────────────────────────────
async function setupDashboard(token) {
  // Fall back to saved GitHub token if none provided
  if (!token) {
    try {
      const githubConfig = JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'github.json'), 'utf8'));
      token = githubConfig.token || '';
    } catch {}
  }
  if (!token) {
    token = process.env.GITHUB_TOKEN?.trim() || '';
  }

  const dashboardRepo = 'https://github.com/illumin8ca/gerald-dashboard';
  const authUrl = token
    ? dashboardRepo.replace('https://', `https://x-access-token:${token}@`)
    : dashboardRepo;

  console.log('[dashboard] Cloning Gerald Dashboard...');

  // Clone if not already present
  if (!fs.existsSync(path.join(DASHBOARD_DIR, 'package.json'))) {
    fs.rmSync(DASHBOARD_DIR, { recursive: true, force: true });
    fs.mkdirSync(DASHBOARD_DIR, { recursive: true });
    const clone = await runCmd('git', ['clone', '--depth', '1', authUrl, DASHBOARD_DIR]);
    if (clone.code !== 0) {
      console.error('[dashboard] Clone failed:', clone.output);
      return { ok: false, output: clone.output };
    }
  }

  // Install deps
  console.log('[dashboard] Installing dependencies...');
  const install = await runCmd('npm', ['install', '--production=false'], { cwd: DASHBOARD_DIR });
  if (install.code !== 0) {
    console.error('[dashboard] Install failed:', install.output);
    return { ok: false, output: install.output };
  }

  // Build frontend
  console.log('[dashboard] Building frontend...');
  const build = await runCmd('npm', ['run', 'build'], { cwd: DASHBOARD_DIR });
  if (build.code !== 0) {
    console.error('[dashboard] Build failed:', build.output);
    return { ok: false, output: build.output };
  }

  return { ok: true, output: 'Dashboard installed and built' };
}

let dashboardProcess = null;

async function startDashboard() {
  if (dashboardProcess) return;

  if (!fs.existsSync(path.join(DASHBOARD_DIR, 'package.json'))) {
    console.log('[dashboard] Not installed, attempting auto-setup...');
    const result = await setupDashboard(); // Will use saved token from github.json
    if (!result.ok) {
      console.error('[dashboard] Auto-setup failed:', result.output);
      return;
    }
    console.log('[dashboard] Auto-setup succeeded');
  }

  console.log('[dashboard] Starting on port ' + DASHBOARD_PORT);
  dashboardProcess = childProcess.spawn('node', ['server/index.js'], {
    cwd: DASHBOARD_DIR,
    env: {
      ...process.env,
      PORT: String(DASHBOARD_PORT),
      NODE_ENV: 'production',
      OPENCLAW_GATEWAY_URL: GATEWAY_TARGET,
      OPENCLAW_GATEWAY_TOKEN: OPENCLAW_GATEWAY_TOKEN,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  dashboardProcess.stdout.on('data', (d) => console.log('[dashboard]', d.toString().trim()));
  dashboardProcess.stderr.on('data', (d) => console.error('[dashboard]', d.toString().trim()));
  dashboardProcess.on('close', (code) => {
    console.log('[dashboard] Process exited with code', code);
    dashboardProcess = null;
  });

  // Wait for it to be ready (try /api/health first, fall back to / for older versions)
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000));
    try {
      const res = await fetch(`http://127.0.0.1:${DASHBOARD_PORT}/api/health`);
      if (res.ok) {
        console.log('[dashboard] Ready (health check)');
        return;
      }
    } catch {}
    // Fallback: any response from / means the server is up
    try {
      const res = await fetch(`http://127.0.0.1:${DASHBOARD_PORT}/`);
      if (res.status < 500) {
        console.log('[dashboard] Ready (root fallback)');
        return;
      }
    } catch {}
  }
  console.error('[dashboard] Failed to start within 30s');
}

app.post("/setup/api/run", requireSetupAuth, async (req, res) => {
  try {
    if (isConfigured()) {
      await ensureGatewayRunning();
      return res.json({
        ok: true,
        output:
          "Already configured.\nUse Reset setup if you want to rerun onboarding.\n",
      });
    }

    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

    const payload = req.body || {};
    const onboardArgs = buildOnboardArgs(payload);

    // DIAGNOSTIC: Log token we're passing to onboard
    console.log(`[onboard] ========== TOKEN DIAGNOSTIC START ==========`);
    console.log(`[onboard] Wrapper token (from env/file/generated): ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (length: ${OPENCLAW_GATEWAY_TOKEN.length})`);
    console.log(`[onboard] Onboard command args include: --gateway-token ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...`);
    console.log(`[onboard] Full onboard command: node ${clawArgs(onboardArgs).join(' ').replace(OPENCLAW_GATEWAY_TOKEN, OPENCLAW_GATEWAY_TOKEN.slice(0, 16) + '...')}`);

    const onboard = await runCmd(OPENCLAW_NODE, clawArgs(onboardArgs));

    let extra = "";

    const ok = onboard.code === 0 && isConfigured();

    // DIAGNOSTIC: Check what token onboard actually wrote to config
    if (ok) {
      try {
        const configAfterOnboard = JSON.parse(fs.readFileSync(configPath(), "utf8"));
        const tokenAfterOnboard = configAfterOnboard?.gateway?.auth?.token;
        console.log(`[onboard] Token in config AFTER onboard: ${tokenAfterOnboard?.slice(0, 16)}... (length: ${tokenAfterOnboard?.length || 0})`);
        console.log(`[onboard] Token match: ${tokenAfterOnboard === OPENCLAW_GATEWAY_TOKEN ? '✓ MATCHES' : '✗ MISMATCH!'}`);
        if (tokenAfterOnboard !== OPENCLAW_GATEWAY_TOKEN) {
          console.log(`[onboard] ⚠️  PROBLEM: onboard command ignored --gateway-token flag and wrote its own token!`);
          extra += `\n[WARNING] onboard wrote different token than expected\n`;
          extra += `  Expected: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...\n`;
          extra += `  Got:      ${tokenAfterOnboard?.slice(0, 16)}...\n`;
        }
      } catch (err) {
        console.error(`[onboard] Could not check config after onboard: ${err}`);
      }
    }

    // Optional channel setup (only after successful onboarding, and only if the installed CLI supports it).
    if (ok) {
      // Ensure gateway token is written into config so the browser UI can authenticate reliably.
      // (We also enforce loopback bind since the wrapper proxies externally.)
      console.log(`[onboard] Now syncing wrapper token to config (${OPENCLAW_GATEWAY_TOKEN.slice(0, 8)}...)`);

      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.mode", "local"]));
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.auth.mode", "token"]),
      );

      const setTokenResult = await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "gateway.auth.token",
          OPENCLAW_GATEWAY_TOKEN,
        ]),
      );

      console.log(`[onboard] config set gateway.auth.token result: exit code ${setTokenResult.code}`);
      if (setTokenResult.output?.trim()) {
        console.log(`[onboard] config set output: ${setTokenResult.output}`);
      }

      if (setTokenResult.code !== 0) {
        console.error(`[onboard] ⚠️  WARNING: config set gateway.auth.token failed with code ${setTokenResult.code}`);
        extra += `\n[WARNING] Failed to set gateway token in config: ${setTokenResult.output}\n`;
      }

      // Verify the token was actually written to config
      try {
        const configContent = fs.readFileSync(configPath(), "utf8");
        const config = JSON.parse(configContent);
        const configToken = config?.gateway?.auth?.token;

        console.log(`[onboard] Token verification after sync:`);
        console.log(`[onboard]   Wrapper token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);
        console.log(`[onboard]   Config token:  ${configToken?.slice(0, 16)}... (len: ${configToken?.length || 0})`);

        if (configToken !== OPENCLAW_GATEWAY_TOKEN) {
          console.error(`[onboard] ✗ ERROR: Token mismatch after config set!`);
          console.error(`[onboard]   Full wrapper token: ${OPENCLAW_GATEWAY_TOKEN}`);
          console.error(`[onboard]   Full config token:  ${configToken || 'null'}`);
          extra += `\n[ERROR] Token verification failed! Config has different token than wrapper.\n`;
          extra += `  Wrapper: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...\n`;
          extra += `  Config:  ${configToken?.slice(0, 16)}...\n`;
        } else {
          console.log(`[onboard] ✓ Token verification PASSED - tokens match!`);
          extra += `\n[onboard] ✓ Gateway token synced successfully\n`;
        }
      } catch (err) {
        console.error(`[onboard] ERROR: Could not verify token in config: ${err}`);
        extra += `\n[ERROR] Could not verify token: ${String(err)}\n`;
      }

      console.log(`[onboard] ========== TOKEN DIAGNOSTIC END ==========`);

      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.bind", "loopback"]),
      );
      await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "gateway.port",
          String(INTERNAL_GATEWAY_PORT),
        ]),
      );
      // Disable OpenClaw Control UI (Gerald Dashboard replaces it)
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.controlUi.enabled", "false"]),
      );
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "--json", "gateway.trustedProxies", '["127.0.0.1/8","::1/128","100.64.0.0/10","172.16.0.0/12"]']),
      );

      // Sync the gateway auth token to match the wrapper's OPENCLAW_GATEWAY_TOKEN env var
      // This ensures the proxy can authenticate WebSocket connections
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]),
      );

      const channelsHelp = await runCmd(
        OPENCLAW_NODE,
        clawArgs(["channels", "add", "--help"]),
      );
      const helpText = channelsHelp.output || "";

      const supports = (name) => helpText.includes(name);

      if (payload.telegramToken?.trim()) {
        if (!supports("telegram")) {
          extra +=
            "\n[telegram] skipped (this openclaw build does not list telegram in `channels add --help`)\n";
        } else {
          // Avoid `channels add` here (it has proven flaky across builds); write config directly.
          const token = payload.telegramToken.trim();
          const cfgObj = {
            enabled: true,
            dmPolicy: "pairing",
            botToken: token,
            groupPolicy: "allowlist",
            streamMode: "partial",
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs([
              "config",
              "set",
              "--json",
              "channels.telegram",
              JSON.stringify(cfgObj),
            ]),
          );
          const get = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "get", "channels.telegram"]),
          );
          extra += `\n[telegram config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[telegram verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      if (payload.discordToken?.trim()) {
        if (!supports("discord")) {
          extra +=
            "\n[discord] skipped (this openclaw build does not list discord in `channels add --help`)\n";
        } else {
          const token = payload.discordToken.trim();
          const cfgObj = {
            enabled: true,
            token,
            groupPolicy: "allowlist",
            dm: {
              policy: "pairing",
            },
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs([
              "config",
              "set",
              "--json",
              "channels.discord",
              JSON.stringify(cfgObj),
            ]),
          );
          const get = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "get", "channels.discord"]),
          );
          extra += `\n[discord config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[discord verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      if (payload.slackBotToken?.trim() || payload.slackAppToken?.trim()) {
        if (!supports("slack")) {
          extra +=
            "\n[slack] skipped (this openclaw build does not list slack in `channels add --help`)\n";
        } else {
          const cfgObj = {
            enabled: true,
            botToken: payload.slackBotToken?.trim() || undefined,
            appToken: payload.slackAppToken?.trim() || undefined,
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs([
              "config",
              "set",
              "--json",
              "channels.slack",
              JSON.stringify(cfgObj),
            ]),
          );
          const get = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "get", "channels.slack"]),
          );
          extra += `\n[slack config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[slack verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      // ── Illumin8 client configuration ──────────────────────────────────
      if (payload.clientDomain?.trim()) {
        const illumin8Config = {
          clientDomain: payload.clientDomain.trim().toLowerCase(),
          clientName: payload.clientName?.trim() || '',
          guardrailLevel: payload.guardrailLevel || 'standard',
          githubRepo: payload.githubRepo?.trim() || '',
          prodBranch: payload.prodBranch?.trim() || 'main',
          devBranch: payload.devBranch?.trim() || 'development',
          configuredAt: new Date().toISOString(),
        };

        fs.writeFileSync(
          path.join(STATE_DIR, 'illumin8.json'),
          JSON.stringify(illumin8Config, null, 2)
        );

        // Also set CLIENT_DOMAIN env for current process
        process.env.CLIENT_DOMAIN = illumin8Config.clientDomain;

        extra += `\n[illumin8] Client configured: ${illumin8Config.clientDomain}\n`;

        // Create site directories
        fs.mkdirSync(path.join(SITE_DIR, 'production'), { recursive: true });
        fs.mkdirSync(path.join(SITE_DIR, 'dev'), { recursive: true });

        // Create placeholder index.html for both
        const placeholder = `<!DOCTYPE html>
<html><head><title>Coming Soon</title></head>
<body style="display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;background:#0a0a0f;color:#fff;">
<h1>Site coming soon</h1>
</body></html>`;

        for (const dir of ['production', 'dev']) {
          const indexPath = path.join(SITE_DIR, dir, 'index.html');
          if (!fs.existsSync(indexPath)) {
            fs.writeFileSync(indexPath, placeholder);
          }
        }
        extra += `\n[illumin8] Site directories created\n`;

        // Write CLIENT-SKILLS.md to workspace
        try {
          const templatePath = path.join(process.cwd(), 'src', 'templates', 'CLIENT-SKILLS.md');
          let template = fs.readFileSync(templatePath, 'utf8');
          template = template.replaceAll('{{CLIENT_NAME}}', payload.clientName?.trim() || 'Client');
          template = template.replaceAll('{{CLIENT_DOMAIN}}', payload.clientDomain.trim().toLowerCase());

          const skillsPath = path.join(WORKSPACE_DIR, 'CLIENT-SKILLS.md');
          fs.writeFileSync(skillsPath, template);
          extra += `\n[illumin8] CLIENT-SKILLS.md written to workspace\n`;
        } catch (err) {
          console.error('[illumin8] Failed to write CLIENT-SKILLS.md:', err);
          extra += `\n[illumin8] Warning: Could not write CLIENT-SKILLS.md: ${err.message}\n`;
        }
      }

      // ── Auto-configure Cloudflare DNS ─────────────────────────────────────
      if (payload.clientDomain?.trim() && process.env.CLOUDFLARE_API_KEY?.trim()) {
        const domain = payload.clientDomain.trim().toLowerCase();

        // Determine Railway domain for CNAME target
        // IMPORTANT: Only use the *.up.railway.app domain, NOT custom domains (would be circular CNAME)
        const publicDomain = process.env.RAILWAY_PUBLIC_DOMAIN?.trim() || '';
        const staticUrl = process.env.RAILWAY_STATIC_URL?.replace('https://', '')?.trim() || '';
        const railwayDomain = (publicDomain.endsWith('.up.railway.app') ? publicDomain : '')
          || (staticUrl.endsWith('.up.railway.app') ? staticUrl : '')
          || `${(process.env.RAILWAY_SERVICE_NAME || 'gerald').toLowerCase()}-production.up.railway.app`;

        extra += `\n[dns] Configuring Cloudflare DNS for ${domain}...\n`;
        const dnsResult = await setupCloudflareDNS(domain, railwayDomain);
        extra += `[dns] ${dnsResult.output}\n`;

        // Auto-create Turnstile widget
        if (dnsResult.ok && dnsResult.zoneId) {
          extra += `[turnstile] Creating Turnstile widget...\n`;
          const turnstileResult = await createTurnstileWidget(domain, dnsResult.zoneId);
          extra += `[turnstile] ${turnstileResult.output}\n`;

          if (turnstileResult.ok) {
            // Auto-save Turnstile keys to services config
            const servicesPath = path.join(STATE_DIR, 'services.json');
            let services = {};
            try { services = JSON.parse(fs.readFileSync(servicesPath, 'utf8')); } catch {}
            services.turnstile = {
              siteKey: turnstileResult.siteKey,
              secretKey: turnstileResult.secretKey,
            };
            fs.writeFileSync(servicesPath, JSON.stringify(services, null, 2));
            extra += `[turnstile] Keys saved to services.json\n`;
          }
        }
      }

      // ── SendGrid configuration ─────────────────────────────────────────────
      const resolvedSendgridKey = payload.sendgridApiKey?.trim() || process.env.SENDGRID_API_KEY?.trim();
      if (resolvedSendgridKey && payload.sendgridSenderEmail?.trim()) {
        const sendgridConfig = {
          apiKey: resolvedSendgridKey,
          senderEmail: payload.sendgridSenderEmail.trim(),
        };
        fs.writeFileSync(
          path.join(STATE_DIR, 'sendgrid.json'),
          JSON.stringify(sendgridConfig, null, 2),
          { mode: 0o600 }
        );
        extra += `\n[sendgrid] Configuration saved\n`;

        // Auto-configure SendGrid domain authentication if client domain and Cloudflare are available
        const cfKey = process.env.CLOUDFLARE_API_KEY?.trim();
        const cfEmail = process.env.CLOUDFLARE_EMAIL?.trim();
        if (payload.clientDomain?.trim() && cfKey && cfEmail) {
          extra += `\n[sendgrid-domain] Configuring SendGrid domain authentication...\n`;
          const domainAuthResult = await setupSendGridDomainAuth(
            payload.clientDomain.trim().toLowerCase(),
            resolvedSendgridKey
          );
          extra += domainAuthResult.output;
        }
      }

      // ── Auth configuration ──────────────────────────────────────────────────
      if (payload.allowedEmails?.trim()) {
        const emails = payload.allowedEmails
          .split(/[\n,]/)
          .map(e => e.trim())
          .filter(e => e && e.includes('@'));
        
        if (emails.length > 0) {
          const authConfig = {
            allowedEmails: emails,
            sessions: {},
            magicLinks: {},
          };
          fs.writeFileSync(
            path.join(STATE_DIR, 'auth.json'),
            JSON.stringify(authConfig, null, 2),
            { mode: 0o600 }
          );
          extra += `\n[auth] Allowed emails configured: ${emails.join(', ')}\n`;
        }
      }

      // ── Services configuration ───────────────────────────────────────────
      const servicesConfig = {};
      const resolvedServiceSendgrid = payload.sendgridKey?.trim() || resolvedSendgridKey || process.env.SENDGRID_API_KEY?.trim();
      if (resolvedServiceSendgrid) servicesConfig.sendgridKey = resolvedServiceSendgrid;
      if (payload.twilioSid?.trim()) {
        servicesConfig.twilio = {
          accountSid: payload.twilioSid.trim(),
          authToken: payload.twilioToken?.trim() || '',
          phoneNumber: payload.twilioPhone?.trim() || '',
        };
      }
      if (payload.turnstileSiteKey?.trim()) {
        servicesConfig.turnstile = {
          siteKey: payload.turnstileSiteKey.trim(),
          secretKey: payload.turnstileSecretKey?.trim() || '',
        };
      }

      if (Object.keys(servicesConfig).length > 0) {
        fs.writeFileSync(
          path.join(STATE_DIR, 'services.json'),
          JSON.stringify(servicesConfig, null, 2)
        );
        extra += `\n[services] Configuration saved\n`;
      }

      // ── Clone and build website from GitHub ──────────────────────────────
      if (payload.githubRepo?.trim() && payload.clientDomain?.trim()) {
        const repoUrl = `https://github.com/${payload.githubRepo.trim()}`;
        const token = payload.githubToken?.trim() || process.env.GITHUB_TOKEN?.trim() || '';
        const prodBranch = payload.prodBranch?.trim() || 'main';
        const devBranch = payload.devBranch?.trim() || 'development';

        // Save GitHub config for future rebuilds
        const githubConfig = {
          repo: payload.githubRepo.trim(),
          prodBranch,
          devBranch,
          // Token is saved in the state dir (Railway volume)
          token: token,
        };
        fs.writeFileSync(
          path.join(STATE_DIR, 'github.json'),
          JSON.stringify(githubConfig, null, 2),
          { mode: 0o600 }
        );

        // Build production
        extra += `\n[build] Building production site from ${prodBranch}...\n`;
        const prodResult = await cloneAndBuild(repoUrl, prodBranch, PRODUCTION_DIR, token);
        extra += `[build] Production: ${prodResult.output}\n`;

        // Build development
        extra += `[build] Building dev site from ${devBranch}...\n`;
        const devResult = await cloneAndBuild(repoUrl, devBranch, DEV_DIR, token);
        extra += `[build] Dev: ${devResult.output}\n`;
      }

      // ── Clone and set up Gerald Dashboard ──────────────────────────────
      extra += '\n[dashboard] Setting up Gerald Dashboard...\n';
      const githubToken = payload.githubToken?.trim() || process.env.GITHUB_TOKEN?.trim() || '';
      const dashResult = await setupDashboard(githubToken);
      extra += `[dashboard] ${dashResult.output}\n`;

      // ── Default model configuration ──────────────────────────────────────
      if (process.env.DEFAULT_MODEL?.trim()) {
        await runCmd(OPENCLAW_NODE, clawArgs([
          'config', 'set', 'agents.defaults.model.primary', process.env.DEFAULT_MODEL.trim()
        ]));
        extra += `\n[model] Default model set: ${process.env.DEFAULT_MODEL}\n`;
      }

      if (process.env.MOONSHOT_API_KEY?.trim()) {
        await runCmd(OPENCLAW_NODE, clawArgs([
          'config', 'set', 'agents.defaults.model.primary',
          process.env.DEFAULT_MODEL?.trim() || 'moonshot/kimi-k2.5-preview'
        ]));
        extra += `\n[model] Moonshot configured\n`;
      }

      // Apply changes immediately.
      await restartGateway();
    }

    return res.status(ok ? 200 : 500).json({
      ok,
      output: `${onboard.output}${extra}`,
    });
  } catch (err) {
    console.error("[/setup/api/run] error:", err);
    return res
      .status(500)
      .json({ ok: false, output: `Internal error: ${String(err)}` });
  }
});

app.get("/setup/api/debug", requireSetupAuth, async (_req, res) => {
  const v = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const help = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["channels", "add", "--help"]),
  );
  res.json({
    wrapper: {
      node: process.version,
      port: PORT,
      stateDir: STATE_DIR,
      workspaceDir: WORKSPACE_DIR,
      configPath: configPath(),
      gatewayTokenFromEnv: Boolean(process.env.OPENCLAW_GATEWAY_TOKEN?.trim()),
      gatewayTokenPersisted: fs.existsSync(
        path.join(STATE_DIR, "gateway.token"),
      ),
      railwayCommit: process.env.RAILWAY_GIT_COMMIT_SHA || null,
    },
    openclaw: {
      entry: OPENCLAW_ENTRY,
      node: OPENCLAW_NODE,
      version: v.output.trim(),
      channelsAddHelpIncludesTelegram: help.output.includes("telegram"),
    },
  });
});

app.post("/setup/api/pairing/approve", requireSetupAuth, async (req, res) => {
  const { channel, code } = req.body || {};
  if (!channel || !code) {
    return res
      .status(400)
      .json({ ok: false, error: "Missing channel or code" });
  }
  const r = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["pairing", "approve", String(channel), String(code)]),
  );
  return res
    .status(r.code === 0 ? 200 : 500)
    .json({ ok: r.code === 0, output: r.output });
});

app.post("/setup/api/reset", requireSetupAuth, async (_req, res) => {
  // Minimal reset: delete the config file so /setup can rerun.
  // Keep credentials/sessions/workspace by default.
  try {
    fs.rmSync(configPath(), { force: true });
    res
      .type("text/plain")
      .send("OK - deleted config file. You can rerun setup now.");
  } catch (err) {
    res.status(500).type("text/plain").send(String(err));
  }
});

// Rebuild site from GitHub (can be triggered by Gerald or webhook)
app.post('/api/rebuild', requireSetupAuth, async (req, res) => {
  try {
    const githubConfigPath = path.join(STATE_DIR, 'github.json');
    if (!fs.existsSync(githubConfigPath)) {
      return res.status(400).json({ ok: false, error: 'No GitHub configuration found. Run setup first.' });
    }

    const githubConfig = JSON.parse(fs.readFileSync(githubConfigPath, 'utf8'));
    const repoUrl = `https://github.com/${githubConfig.repo}`;
    const token = githubConfig.token || process.env.GITHUB_TOKEN?.trim() || '';
    const target = req.body?.target || 'both'; // 'production', 'dev', or 'both'

    let output = '';

    if (target === 'production' || target === 'both') {
      const result = await cloneAndBuild(repoUrl, githubConfig.prodBranch, PRODUCTION_DIR, token);
      output += `Production (${githubConfig.prodBranch}): ${result.output}\n`;
    }

    if (target === 'dev' || target === 'both') {
      const result = await cloneAndBuild(repoUrl, githubConfig.devBranch, DEV_DIR, token);
      output += `Dev (${githubConfig.devBranch}): ${result.output}\n`;
    }

    res.json({ ok: true, output });
  } catch (err) {
    console.error('[rebuild]', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Rebuild Gerald Dashboard from GitHub
app.post('/api/rebuild-dashboard', requireSetupAuth, async (req, res) => {
  try {
    // Kill existing dashboard
    if (dashboardProcess) {
      dashboardProcess.kill('SIGTERM');
      dashboardProcess = null;
      await sleep(1000);
    }

    // Remove existing installation to force fresh clone
    fs.rmSync(DASHBOARD_DIR, { recursive: true, force: true });

    // Token from request body, github.json, or env
    const token = req.body?.token?.trim() || '';

    const result = await setupDashboard(token);
    if (!result.ok) {
      return res.status(500).json({ ok: false, output: result.output });
    }

    // Restart dashboard
    await startDashboard();
    res.json({ ok: true, output: result.output + '\nDashboard restarted.' });
  } catch (err) {
    console.error('[rebuild-dashboard]', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Manual SendGrid domain verification endpoint
app.post('/api/verify-sendgrid-domain', requireSetupAuth, async (req, res) => {
  try {
    // Read config from saved files
    const sendgridConfigPath = path.join(STATE_DIR, 'sendgrid.json');
    const illumin8ConfigPath = path.join(STATE_DIR, 'illumin8.json');

    if (!fs.existsSync(sendgridConfigPath)) {
      return res.status(400).json({ ok: false, error: 'SendGrid not configured. Run setup first.' });
    }

    if (!fs.existsSync(illumin8ConfigPath)) {
      return res.status(400).json({ ok: false, error: 'Client domain not configured. Run setup first.' });
    }

    const sendgridConfig = JSON.parse(fs.readFileSync(sendgridConfigPath, 'utf8'));
    const illumin8Config = JSON.parse(fs.readFileSync(illumin8ConfigPath, 'utf8'));

    const domain = illumin8Config.clientDomain;
    const apiKey = sendgridConfig.apiKey;

    if (!domain || !apiKey) {
      return res.status(400).json({ ok: false, error: 'Missing domain or API key in configuration.' });
    }

    const result = await setupSendGridDomainAuth(domain, apiKey);
    
    res.json({
      ok: result.ok,
      validated: result.validated,
      output: result.output,
    });
  } catch (err) {
    console.error('[verify-sendgrid-domain]', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Webhook for GitHub push events (auto-rebuild)
app.post('/api/webhook/github', express.json(), async (req, res) => {
  try {
    const githubConfigPath = path.join(STATE_DIR, 'github.json');
    if (!fs.existsSync(githubConfigPath)) {
      return res.status(200).json({ ok: true, skipped: true, reason: 'Not configured' });
    }

    const githubConfig = JSON.parse(fs.readFileSync(githubConfigPath, 'utf8'));
    const ref = req.body?.ref || '';
    const branch = ref.replace('refs/heads/', '');

    console.log(`[webhook] GitHub push to branch: ${branch}`);

    const repoUrl = `https://github.com/${githubConfig.repo}`;
    const token = githubConfig.token || process.env.GITHUB_TOKEN?.trim() || '';

    if (branch === githubConfig.prodBranch) {
      console.log(`[webhook] Rebuilding production...`);
      const result = await cloneAndBuild(repoUrl, branch, PRODUCTION_DIR, token);
      return res.json({ ok: true, target: 'production', output: result.output });
    }

    if (branch === githubConfig.devBranch) {
      console.log(`[webhook] Rebuilding dev...`);
      const result = await cloneAndBuild(repoUrl, branch, DEV_DIR, token);
      return res.json({ ok: true, target: 'dev', output: result.output });
    }

    res.json({ ok: true, skipped: true, reason: `Branch ${branch} not tracked` });
  } catch (err) {
    console.error('[webhook]', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get("/setup/export", requireSetupAuth, async (_req, res) => {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  res.setHeader("content-type", "application/gzip");
  res.setHeader(
    "content-disposition",
    `attachment; filename="openclaw-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.tar.gz"`,
  );

  // Prefer exporting from a common /data root so archives are easy to inspect and restore.
  // This preserves dotfiles like /data/.openclaw/openclaw.json.
  const stateAbs = path.resolve(STATE_DIR);
  const workspaceAbs = path.resolve(WORKSPACE_DIR);

  const dataRoot = "/data";
  const underData = (p) => p === dataRoot || p.startsWith(dataRoot + path.sep);

  let cwd = "/";
  let paths = [stateAbs, workspaceAbs].map((p) => p.replace(/^\//, ""));

  if (underData(stateAbs) && underData(workspaceAbs)) {
    cwd = dataRoot;
    // We export relative to /data so the archive contains: .openclaw/... and workspace/...
    paths = [
      path.relative(dataRoot, stateAbs) || ".",
      path.relative(dataRoot, workspaceAbs) || ".",
    ];
  }

  const stream = tar.c(
    {
      gzip: true,
      portable: true,
      noMtime: true,
      cwd,
      onwarn: () => {},
    },
    paths,
  );

  stream.on("error", (err) => {
    console.error("[export]", err);
    if (!res.headersSent) res.status(500);
    res.end(String(err));
  });

  stream.pipe(res);
});

// Proxy everything else to the gateway.
const proxy = httpProxy.createProxyServer({
  target: GATEWAY_TARGET,
  ws: true,
  xfwd: true,
});

proxy.on("error", (err, req, res) => {
  console.error("[proxy]", err.code || err.message);
  if (res && !res.headersSent && typeof res.writeHead === 'function') {
    res.writeHead(503, { 'Content-Type': 'text/html' });
    res.end('<html><body style="background:#0a0a0f;color:#94a3b8;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2 style="color:#00ff87">Gerald is starting up...</h2><p>Please refresh in a few seconds.</p></div></body></html>');
  }
});

// Inject auth token into HTTP proxy requests
proxy.on("proxyReq", (proxyReq, req, res) => {
  console.log(`[proxy] HTTP ${req.method} ${req.url} - injecting token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...`);
  proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
});

// Log WebSocket upgrade proxy events (token is injected via headers option in server.on("upgrade"))
proxy.on("proxyReqWs", (proxyReq, req, socket, options, head) => {
  console.log(`[proxy-event] WebSocket proxyReqWs event fired for ${req.url}`);
  console.log(`[proxy-event] Headers:`, JSON.stringify(proxyReq.getHeaders()));
});

app.use(async (req, res, next) => {
  // If not configured, force users to /setup for any non-setup routes.
  if (!isConfigured() && !req.path.startsWith("/setup")) {
    return res.redirect("/setup");
  }

  // ── Illumin8 host-based routing ─────────────────────────────────────
  const clientDomain = getClientDomain();
  if (clientDomain) {
    const host = req.hostname?.toLowerCase();

    // Production site: clientdomain.com or www.clientdomain.com
    if (host === clientDomain || host === `www.${clientDomain}`) {
      return serveStaticSite(PRODUCTION_DIR, req, res);
    }

    // Dev site: dev.clientdomain.com
    if (host === `dev.${clientDomain}`) {
      res.set('X-Robots-Tag', 'noindex, nofollow');
      return serveStaticSite(DEV_DIR, req, res);
    }

    // Gerald dashboard: gerald.clientdomain.com → Dashboard (except /openclaw → gateway)
    if (host === `gerald.${clientDomain}`) {
      // Auth routes are public (including magic link flow)
      if (req.path.startsWith('/api/auth/') || req.path === '/login') {
        // Magic link endpoint needs to be proxied to dashboard
        if (req.path.startsWith('/api/auth/magic/')) {
          return proxy.web(req, res, { target: DASHBOARD_TARGET });
        }
        // Other auth routes handled by wrapper
        return next();
      }
      
      if (req.path.startsWith('/openclaw')) {
        // Proxy /openclaw paths to OpenClaw gateway (dashboard API calls) - requires auth
        if (isConfigured()) {
          try { await ensureGatewayRunning(); } catch (err) {
            return res.status(503).type('text/plain').send(`Gateway not ready: ${String(err)}`);
          }
        }
        // Check auth before proxying to gateway
        const sessionId = req.cookies.gerald_session;
        const session = getSession(sessionId);
        if (!session) {
          return req.path.includes('api') 
            ? res.status(401).json({ error: 'Unauthorized' })
            : res.redirect('/login');
        }
        return proxy.web(req, res, { target: GATEWAY_TARGET });
      }
      
      // Everything else → Gerald Dashboard (requires auth)
      const sessionId = req.cookies.gerald_session;
      const session = getSession(sessionId);
      if (!session) {
        return req.path.startsWith('/api/')
          ? res.status(401).json({ error: 'Unauthorized' })
          : res.redirect('/login');
      }
      return proxy.web(req, res, { target: DASHBOARD_TARGET });
    }

    // All other hosts fall through to proxy (setup, healthz, etc.)
  }

  // ── Existing proxy logic ─────────────────────────────────────────────
  if (isConfigured()) {
    try {
      await ensureGatewayRunning();
    } catch (err) {
      return res
        .status(503)
        .type("text/plain")
        .send(`Gateway not ready: ${String(err)}`);
    }
  }

  // Proxy to gateway (auth token injected via proxyReq event)
  return proxy.web(req, res, { target: GATEWAY_TARGET });
});

// Create HTTP server from Express app
const server = app.listen(PORT, async () => {
  console.log(`[wrapper] listening on port ${PORT}`);
  console.log(`[wrapper] setup wizard: http://localhost:${PORT}/setup`);
  console.log(`[wrapper] configured: ${isConfigured()}`);

  // Auto-start the gateway so Telegram/Discord polling begins immediately
  // instead of waiting for the first inbound HTTP request.
  if (isConfigured()) {
    console.log(`[wrapper] auto-starting gateway...`);
    try {
      await ensureGatewayRunning();
      console.log(`[wrapper] gateway auto-started successfully`);
    } catch (err) {
      console.error(`[wrapper] gateway auto-start failed: ${err.message}`);
    }
  }

  // Start dashboard if installed
  startDashboard().catch(err => console.error('[dashboard] Auto-start failed:', err));
});

// Handle WebSocket upgrades
server.on("upgrade", async (req, socket, head) => {
  if (!isConfigured()) {
    socket.destroy();
    return;
  }

  // Only proxy WebSocket for gerald subdomain or when no client domain is set
  const clientDomain = getClientDomain();
  const wsHost = req.headers.host?.split(':')[0]?.toLowerCase();
  if (clientDomain && wsHost !== `gerald.${clientDomain}`) {
    socket.destroy();
    return;
  }

  // Parse the request path for routing
  const wsUrl = new URL(req.url, 'http://localhost');

  if (wsUrl.pathname.startsWith('/openclaw')) {
    // /openclaw paths → OpenClaw gateway WebSocket (chat, etc.)
    try {
      await ensureGatewayRunning();
    } catch {
      socket.destroy();
      return;
    }

    // Check session auth for gerald subdomain WebSocket upgrades
    if (clientDomain && wsHost === `gerald.${clientDomain}`) {
      const cookies = parseCookiesFromString(req.headers.cookie || '');
      const sessionId = cookies.gerald_session;
      if (!sessionId) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      const session = getSession(sessionId);
      if (!session) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
    }

    console.log(`[ws-upgrade] Proxying WebSocket to gateway: ${req.url}`);

    // Append token to the URL if not already present
    const url = new URL(req.url, GATEWAY_TARGET);
    if (!url.searchParams.has('token')) {
      url.searchParams.set('token', OPENCLAW_GATEWAY_TOKEN);
    }
    req.url = url.pathname + url.search;

    proxy.ws(req, socket, head, {
      target: GATEWAY_TARGET,
      headers: {
        Authorization: `Bearer ${OPENCLAW_GATEWAY_TOKEN}`,
      },
    });
  } else {
    // All other WebSocket paths → Gerald Dashboard
    console.log(`[ws-upgrade] Proxying WebSocket to dashboard: ${req.url}`);
    proxy.ws(req, socket, head, {
      target: DASHBOARD_TARGET,
    });
  }
});

process.on("SIGTERM", () => {
  // Best-effort shutdown
  try {
    if (gatewayProc) gatewayProc.kill("SIGTERM");
  } catch {
    // ignore
  }
  try {
    if (dashboardProcess) dashboardProcess.kill("SIGTERM");
  } catch {
    // ignore
  }
  process.exit(0);
});
