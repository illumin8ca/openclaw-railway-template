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
// The binary lives at /data/claude-code and config at /data/.claude - both on
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

// ── Tailscale Setup ───────────────────────────────────────────────────────
// Start tailscaled and authenticate if TAILSCALE_AUTHKEY is set
async function startTailscale() {
  const authKey = process.env.TAILSCALE_AUTHKEY?.trim();
  if (!authKey) {
    console.log('[tailscale] TAILSCALE_AUTHKEY not set, skipping Tailscale setup');
    return { ok: false, reason: 'no auth key' };
  }

  console.log('[tailscale] Starting tailscaled daemon...');

  // Start tailscaled in userspace networking mode (works in containers without TUN device)
  const tailscaled = childProcess.spawn('tailscaled', [
    '--state=/data/.tailscale/tailscaled.state',
    '--socket=/var/run/tailscale/tailscaled.sock',
    '--tun=userspace-networking',
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });

  tailscaled.stdout.on('data', (d) => console.log('[tailscaled]', d.toString().trim()));
  tailscaled.stderr.on('data', (d) => console.log('[tailscaled]', d.toString().trim()));
  tailscaled.unref();

  // Wait for tailscaled to be ready
  await new Promise(r => setTimeout(r, 2000));

  // Authenticate with the auth key
  console.log('[tailscale] Authenticating...');
  const hostname = process.env.TAILSCALE_HOSTNAME || 'cass-ai-railway';

  return new Promise((resolve) => {
    const up = childProcess.spawn('tailscale', [
      'up',
      '--authkey', authKey,
      '--hostname', hostname,
      '--accept-routes',
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let output = '';
    up.stdout.on('data', (d) => { output += d.toString(); console.log('[tailscale]', d.toString().trim()); });
    up.stderr.on('data', (d) => { output += d.toString(); console.log('[tailscale]', d.toString().trim()); });

    up.on('close', (code) => {
      if (code === 0) {
        console.log('[tailscale] ✓ Connected to tailnet');
        // Get and log the IP address
        childProcess.exec('tailscale ip -4', (err, stdout) => {
          if (!err && stdout.trim()) {
            console.log(`[tailscale] IP address: ${stdout.trim()}`);
          }
        });
        resolve({ ok: true });
      } else {
        console.error('[tailscale] Failed to connect:', output);
        resolve({ ok: false, reason: output });
      }
    });
  });
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

// Get Telegram bot username (for Login Widget)
let telegramBotUsername = null;
let telegramBotId = null;
async function getTelegramBotInfo() {
  if (telegramBotUsername && telegramBotId) return { username: telegramBotUsername, id: telegramBotId };
  try {
    const config = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    const botToken = config?.channels?.telegram?.botToken;
    if (!botToken) return { username: null, id: null };
    const res = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    const data = await res.json();
    if (data.ok) {
      telegramBotUsername = data.result.username;
      telegramBotId = String(data.result.id);
      return { username: telegramBotUsername, id: telegramBotId };
    }
  } catch (e) {
    console.error('[auth] Failed to get bot info:', e.message);
  }
  return { username: null, id: null };
}
async function getTelegramBotUsername() {
  const info = await getTelegramBotInfo();
  return info.username;
}

// Verify Telegram Login Widget data
function verifyTelegramWidget(data, botToken) {
  const { hash, ...rest } = data;
  if (!hash) return false;

  const dataCheckString = Object.keys(rest)
    .sort()
    .map(key => `${key}=${rest[key]}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(botToken).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  return hmac === hash;
}

function parseCookiesFromString(cookieStr) {
  const cookies = {};
  if (!cookieStr) return cookies;
  cookieStr.split(';').forEach(pair => {
    const [key, ...val] = pair.trim().split('=');
    if (key) cookies[key] = decodeURIComponent(val.join('='));
  });
  return cookies;
}

// Illumin8 site directories
const SITE_DIR = path.join(WORKSPACE_DIR, 'site');
const PRODUCTION_DIR = path.join(SITE_DIR, 'production');
const DEV_DIR = path.join(SITE_DIR, 'dev');

// Dev server
const DEV_SERVER_PORT = 4321;
const DEV_SERVER_TARGET = `http://127.0.0.1:${DEV_SERVER_PORT}`;
let devServerProcess = null;

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
  // 2. Directory with index.html (e.g., /about → /about/index.html) - Astro MPA pattern
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

  // Sync critical config before every gateway start.
  console.log(`[gateway] ========== GATEWAY START CONFIG SYNC ==========`);
  console.log(`[gateway] Syncing wrapper token to config: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);

  const syncResult = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]),
  );

  // Ensure OpenAI-compatible chat endpoint is enabled (required by Gerald Dashboard)
  await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "gateway.http.endpoints.chatCompletions.enabled", "true"]),
  );

  // Sync default model from env (ensures env var changes take effect without re-onboarding)
  const envModel = process.env.DEFAULT_MODEL?.trim();
  if (envModel) {
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "agents.defaults.model.primary", envModel]));
    console.log(`[gateway] Model synced: ${envModel}`);
  }

  // Sync Anthropic setup-token from env (persists Claude Max/Pro subscription through rebuilds)
  const anthropicToken = process.env.ANTHROPIC_SETUP_TOKEN?.trim();
  if (anthropicToken) {
    const agentDir = path.join(STATE_DIR, 'agents', 'main', 'agent');
    const authStorePath = path.join(agentDir, 'auth-profiles.json');
    try {
      fs.mkdirSync(agentDir, { recursive: true });
      let store = { version: 1, profiles: {}, order: [], lastGood: {}, usageStats: {} };
      if (fs.existsSync(authStorePath)) {
        try { store = JSON.parse(fs.readFileSync(authStorePath, 'utf8')); } catch {}
      }
      // Upsert the anthropic token profile
      const profileId = 'anthropic:default';
      store.profiles[profileId] = {
        credential: { type: 'token', provider: 'anthropic', token: anthropicToken },
      };
      if (!store.order?.includes(profileId)) {
        store.order = store.order || [];
        store.order.unshift(profileId);
      }
      store.lastGood = store.lastGood || {};
      store.lastGood.anthropic = profileId;
      fs.writeFileSync(authStorePath, JSON.stringify(store, null, 2), { mode: 0o600 });
      console.log(`[gateway] Anthropic token synced from ANTHROPIC_SETUP_TOKEN env`);

      // Also set the auth profile in config
      await runCmd(OPENCLAW_NODE, clawArgs([
        "config", "set", "auth.profiles.anthropic:default.provider", "anthropic",
      ]));
      await runCmd(OPENCLAW_NODE, clawArgs([
        "config", "set", "auth.profiles.anthropic:default.mode", "token",
      ]));
    } catch (err) {
      console.error(`[gateway] Failed to sync Anthropic token: ${err.message}`);
    }
  }

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
  // Skip auth for Gerald subdomain - Dashboard handles its own authentication
  const clientDomain = getClientDomain();
  const host = req.hostname?.toLowerCase();
  if (clientDomain && host === `gerald.${clientDomain}`) {
    return next();
  }

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

// requireAuth middleware removed - Dashboard handles its own authentication

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
// Wrapper auth removed - Dashboard handles its own authentication

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
  let sendgridConfig = null;
  try {
    const sgPath = path.join(STATE_DIR, "sendgrid.json");
    if (fs.existsSync(sgPath)) {
      sendgridConfig = JSON.parse(fs.readFileSync(sgPath, "utf8"));
    }
  } catch (err) {
    console.error("[setup/status] Failed to read sendgrid.json:", err);
  }

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
    defaultAllowedEmails: process.env.DEFAULT_ALLOWED_EMAILS?.trim() || null,
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

// Helper to safely remove directories (handles node_modules symlinks better than fs.rmSync)
async function safeRemoveDir(dir) {
  if (fs.existsSync(dir)) {
    await runCmd('rm', ['-rf', dir]);
  }
}

async function cloneAndBuild(repoUrl, branch, targetDir, token) {
  // Clean target dir (use shell rm -rf to handle node_modules properly)
  await safeRemoveDir(targetDir);
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
      await safeRemoveDir(targetDir);
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
      await safeRemoveDir(tmpDir);
      fs.renameSync(outputDir, tmpDir);
      // Remove the cloned source
      await safeRemoveDir(targetDir);
      // Move built output to target
      fs.renameSync(tmpDir, targetDir);
    }

    console.log(`[build] Build complete: ${targetDir}`);
    return { ok: true, output: `Built successfully from ${branch} branch` };
  }

  // No package.json - assume static site, already good
  return { ok: true, output: `Cloned static site from ${branch} branch` };
}

// ── Dev server lifecycle ──────────────────────────────────────────────
async function startDevServer() {
  if (devServerProcess) return;
  if (!fs.existsSync(path.join(DEV_DIR, 'package.json'))) {
    console.log('[dev-server] No package.json in dev dir, skipping');
    return;
  }

  console.log(`[dev-server] Starting on port ${DEV_SERVER_PORT}...`);

  // Install deps if needed
  if (!fs.existsSync(path.join(DEV_DIR, 'node_modules'))) {
    console.log('[dev-server] Installing dependencies...');
    await runCmd('npm', ['install'], { cwd: DEV_DIR });
  }

  devServerProcess = childProcess.spawn('npx', ['astro', 'dev', '--host', '0.0.0.0', '--port', String(DEV_SERVER_PORT)], {
    cwd: DEV_DIR,
    env: {
      ...process.env,
      PORT: String(DEV_SERVER_PORT),
      HOST: '0.0.0.0',
      NODE_ENV: 'development',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  devServerProcess.stdout.on('data', (d) => console.log('[dev-server]', d.toString().trim()));
  devServerProcess.stderr.on('data', (d) => console.error('[dev-server]', d.toString().trim()));
  devServerProcess.on('close', (code) => {
    console.log('[dev-server] Process exited with code', code);
    devServerProcess = null;
  });

  // Wait for it to be ready
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 1000));
    try {
      const res = await fetch(`http://127.0.0.1:${DEV_SERVER_PORT}/`);
      if (res.ok || res.status === 304) {
        console.log('[dev-server] Ready');
        return;
      }
    } catch {}
  }
  console.warn('[dev-server] Timed out waiting for dev server to start');
}

function stopDevServer() {
  if (!devServerProcess) return;
  console.log('[dev-server] Stopping...');
  devServerProcess.kill('SIGTERM');
  devServerProcess = null;
}

async function restartDevServer() {
  stopDevServer();
  await new Promise(r => setTimeout(r, 1000));
  await startDevServer();
}

// Pull latest code for dev branch (used by webhook - no full rebuild needed)
async function pullDevBranch() {
  const githubConfigPath = path.join(STATE_DIR, 'github.json');
  if (!fs.existsSync(githubConfigPath)) return { ok: false, output: 'No github config' };

  const githubConfig = JSON.parse(fs.readFileSync(githubConfigPath, 'utf8'));
  const token = getGitHubToken();
  const repoUrl = `https://github.com/${githubConfig.repo}`;
  const authUrl = token ? repoUrl.replace('https://', `https://x-access-token:${token}@`) : repoUrl;

  // If DEV_DIR has a .git, just pull. Otherwise clone fresh.
  if (fs.existsSync(path.join(DEV_DIR, '.git'))) {
    console.log('[dev-server] Pulling latest changes...');
    await runCmd('git', ['remote', 'set-url', 'origin', authUrl], { cwd: DEV_DIR });
    const pull = await runCmd('git', ['pull', '--ff-only', 'origin', githubConfig.devBranch], { cwd: DEV_DIR });
    if (pull.code !== 0) {
      // Pull failed - do a hard reset
      console.log('[dev-server] Pull failed, doing hard reset...');
      await runCmd('git', ['fetch', 'origin', githubConfig.devBranch], { cwd: DEV_DIR });
      await runCmd('git', ['reset', '--hard', `origin/${githubConfig.devBranch}`], { cwd: DEV_DIR });
    }
    // Reinstall deps if package.json changed
    await runCmd('npm', ['install'], { cwd: DEV_DIR });
    return { ok: true, output: 'Pulled and updated' };
  } else {
    // Fresh clone
    console.log('[dev-server] Fresh clone for dev server...');
    await safeRemoveDir(DEV_DIR);
    fs.mkdirSync(DEV_DIR, { recursive: true });
    const clone = await runCmd('git', ['clone', '--branch', githubConfig.devBranch, authUrl, DEV_DIR]);
    if (clone.code !== 0) return { ok: false, output: clone.output };
    await runCmd('npm', ['install'], { cwd: DEV_DIR });
    return { ok: true, output: 'Cloned fresh' };
  }
}

// ── Gerald Dashboard setup & lifecycle ────────────────────────────────
async function setupDashboard(token) {
  // Fall back to OAuth or saved GitHub token if none provided
  if (!token) {
    token = getGitHubToken();
  }

  const dashboardRepo = 'https://github.com/illumin8ca/gerald-dashboard';
  const authUrl = token
    ? dashboardRepo.replace('https://', `https://x-access-token:${token}@`)
    : dashboardRepo;

  // Clone if not present, otherwise pull latest
  if (!fs.existsSync(path.join(DASHBOARD_DIR, 'package.json'))) {
    console.log('[dashboard] Cloning Gerald Dashboard...');
    await safeRemoveDir(DASHBOARD_DIR);
    fs.mkdirSync(DASHBOARD_DIR, { recursive: true });
    const clone = await runCmd('git', ['clone', '--depth', '1', authUrl, DASHBOARD_DIR]);
    if (clone.code !== 0) {
      console.error('[dashboard] Clone failed:', clone.output);
      return { ok: false, output: clone.output };
    }
  } else {
    // Pull latest changes
    console.log('[dashboard] Updating Gerald Dashboard...');
    // Update remote URL in case token changed
    await runCmd('git', ['remote', 'set-url', 'origin', authUrl], { cwd: DASHBOARD_DIR });
    const pull = await runCmd('git', ['pull', '--ff-only', 'origin', 'main'], { cwd: DASHBOARD_DIR });
    if (pull.code !== 0) {
      // If pull fails (diverged history from shallow clone), do a fresh clone
      console.log('[dashboard] Pull failed, doing fresh clone...');
      await safeRemoveDir(DASHBOARD_DIR);
      fs.mkdirSync(DASHBOARD_DIR, { recursive: true });
      const clone = await runCmd('git', ['clone', '--depth', '1', authUrl, DASHBOARD_DIR]);
      if (clone.code !== 0) {
        console.error('[dashboard] Fresh clone failed:', clone.output);
        return { ok: false, output: clone.output };
      }
    } else {
      console.log('[dashboard] Updated:', pull.output.split('\n')[0]);
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

// ── Gerald Workspace setup ────────────────────────────────────────────
async function setupWorkspace(token) {
  // Fall back to OAuth or saved GitHub token if none provided
  if (!token) {
    token = getGitHubToken();
  }

  // Read workspace repo from illumin8.json config
  let workspaceRepo = null;
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'illumin8.json'), 'utf8'));
    workspaceRepo = cfg.workspaceRepo;
  } catch (e) {
    // Config doesn't exist yet
  }

  // Default to illumin8ca/gerald if not configured
  if (!workspaceRepo) {
    workspaceRepo = 'https://github.com/illumin8ca/gerald';
  }

  // Ensure it's a full URL
  if (!workspaceRepo.startsWith('http')) {
    workspaceRepo = `https://github.com/${workspaceRepo}`;
  }

  const authUrl = token
    ? workspaceRepo.replace('https://', `https://x-access-token:${token}@`)
    : workspaceRepo;

  // Check if workspace already has a git repo
  const hasGitRepo = fs.existsSync(path.join(WORKSPACE_DIR, '.git'));
  
  if (!hasGitRepo) {
    console.log(`[workspace] Cloning workspace from ${workspaceRepo}...`);
    // Don't remove existing workspace files, just init git
    // First try to clone into a temp dir, then move files
    const tempDir = path.join(STATE_DIR, 'workspace-temp');
    await safeRemoveDir(tempDir);
    
    const clone = await runCmd('git', ['clone', '--depth', '1', authUrl, tempDir]);
    if (clone.code !== 0) {
      console.error('[workspace] Clone failed:', clone.output);
      return { ok: false, output: clone.output };
    }
    
    // Move git repo and files to workspace dir (preserving existing non-conflicting files)
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });
    
    // Move .git directory
    if (fs.existsSync(path.join(tempDir, '.git'))) {
      fs.renameSync(path.join(tempDir, '.git'), path.join(WORKSPACE_DIR, '.git'));
    }
    
    // Copy files from temp to workspace (don't overwrite existing)
    // Note: cp -n doesn't work on Alpine, use rsync or manual copy
    try {
      const files = fs.readdirSync(tempDir);
      for (const file of files) {
        if (file === '.git') continue; // Already moved
        const src = path.join(tempDir, file);
        const dest = path.join(WORKSPACE_DIR, file);
        if (!fs.existsSync(dest)) {
          fs.cpSync(src, dest, { recursive: true });
        }
      }
    } catch (copyErr) {
      console.warn('[workspace] Copy warning:', copyErr.message);
    }
    
    await safeRemoveDir(tempDir);
    console.log('[workspace] Workspace initialized from', workspaceRepo);
  } else {
    // Pull latest changes
    console.log('[workspace] Updating workspace...');
    // Update remote URL in case token changed
    await runCmd('git', ['remote', 'set-url', 'origin', authUrl], { cwd: WORKSPACE_DIR });
    const pull = await runCmd('git', ['pull', '--ff-only', 'origin', 'main'], { cwd: WORKSPACE_DIR });
    if (pull.code !== 0) {
      // Don't do fresh clone for workspace - might have local changes
      console.log('[workspace] Pull failed (may have local changes):', pull.output.split('\n')[0]);
      // Try to at least fetch so we know what's available
      await runCmd('git', ['fetch', 'origin', 'main'], { cwd: WORKSPACE_DIR });
      return { ok: true, output: 'Workspace fetch complete (pull failed, may have local changes)' };
    } else {
      console.log('[workspace] Updated:', pull.output.split('\n')[0]);
    }
  }

  return { ok: true, output: 'Workspace ready' };
}

let dashboardProcess = null;

async function startDashboard() {
  if (dashboardProcess) return;

  // Setup workspace first (clone/pull Gerald repo with memories, skills, etc.)
  // Use timeout to prevent blocking startup
  console.log('[workspace] Checking workspace...');
  try {
    const wsPromise = setupWorkspace();
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Workspace setup timeout (30s)')), 30000)
    );
    const wsResult = await Promise.race([wsPromise, timeoutPromise]);
    if (!wsResult.ok) {
      console.warn('[workspace] Setup issue:', wsResult.output);
    }
  } catch (wsErr) {
    console.warn('[workspace] Setup skipped:', wsErr.message);
    // Continue anyway - workspace is optional
  }

  // Always run setup (which pulls latest + rebuilds) before starting
  console.log('[dashboard] Checking for updates...');
  const result = await setupDashboard();
  if (!result.ok) {
    // If setup/update failed but we have an existing install, try to start it anyway
    if (fs.existsSync(path.join(DASHBOARD_DIR, 'package.json'))) {
      console.log('[dashboard] Update failed, starting existing version:', result.output);
    } else {
      console.error('[dashboard] Setup failed, cannot start:', result.output);
      return;
    }
  }

  console.log('[dashboard] Starting on port ' + DASHBOARD_PORT);
  // Generate a stable JWT secret for the dashboard (persist in state dir)
  const jwtSecretPath = path.join(STATE_DIR, 'dashboard-jwt-secret');
  let dashboardJwtSecret;
  if (fs.existsSync(jwtSecretPath)) {
    dashboardJwtSecret = fs.readFileSync(jwtSecretPath, 'utf8').trim();
  } else {
    dashboardJwtSecret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(jwtSecretPath, dashboardJwtSecret, { mode: 0o600 });
    console.log('[dashboard] Generated new JWT secret');
  }

  // Read bot token from OpenClaw config for Dashboard's Telegram auth verification
  let telegramBotToken = '';
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    telegramBotToken = cfg?.channels?.telegram?.botToken || '';
  } catch {}

  dashboardProcess = childProcess.spawn('node', ['server/index.js'], {
    cwd: DASHBOARD_DIR,
    env: {
      ...process.env,
      PORT: String(DASHBOARD_PORT),
      NODE_ENV: 'production',
      OPENCLAW_GATEWAY_URL: GATEWAY_TARGET,
      OPENCLAW_GATEWAY_TOKEN: OPENCLAW_GATEWAY_TOKEN,
      INTERNAL_API_KEY: INTERNAL_API_KEY,
      JWT_SECRET: process.env.JWT_SECRET || dashboardJwtSecret,
      ALLOWED_TELEGRAM_IDS: process.env.ALLOWED_TELEGRAM_IDS || '511172388',
      TELEGRAM_BOT_ID: process.env.TELEGRAM_BOT_ID || '',
      TELEGRAM_BOT_TOKEN: telegramBotToken || process.env.TELEGRAM_BOT_TOKEN || '',
      SENDGRID_API_KEY: process.env.SENDGRID_API_KEY || '',
      SENDGRID_SENDER_EMAIL: process.env.SENDGRID_SENDER_EMAIL || '',
      CLIENT_DOMAIN: process.env.CLIENT_DOMAIN || '',
      ALLOWED_EMAILS: process.env.DEFAULT_ALLOWED_EMAILS || '',
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

// ── GitHub OAuth Device Flow Endpoints ────────────────────────────────
const GITHUB_CLIENT_ID = 'Ov23lihLeOlzBtN5di4E';
const GITHUB_CLIENT_SECRET = 'c593ee8eaeae73a1dca655bad285e7a2ff657261';

// Helper to get GitHub token (OAuth or manual)
function getGitHubToken() {
  // First check OAuth token
  const oauthPath = path.join(STATE_DIR, 'github-oauth.json');
  if (fs.existsSync(oauthPath)) {
    try {
      const oauth = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
      if (oauth.access_token) return oauth.access_token;
    } catch {}
  }

  // Fall back to manual token
  const configPath = path.join(STATE_DIR, 'github.json');
  if (fs.existsSync(configPath)) {
    try {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (config.token) return config.token;
    } catch {}
  }

  // Fall back to env var
  return process.env.GITHUB_TOKEN?.trim() || '';
}

app.post('/setup/api/github/start-auth', requireSetupAuth, async (req, res) => {
  try {
    const response = await fetch('https://github.com/login/device/code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        scope: 'repo read:user'
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        ok: false,
        error: `GitHub API error: ${errorText}`
      });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[github-auth] start-auth error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.post('/setup/api/github/poll-auth', requireSetupAuth, async (req, res) => {
  try {
    const { device_code } = req.body || {};
    if (!device_code) {
      return res.status(400).json({ ok: false, error: 'Missing device_code' });
    }

    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        device_code: device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        ok: false,
        error: `GitHub API error: ${errorText}`
      });
    }

    const data = await response.json();

    // Check for errors
    if (data.error) {
      if (data.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      }
      return res.json({ status: 'error', error: data.error });
    }

    // Success - fetch username
    const access_token = data.access_token;
    const userRes = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });

    if (!userRes.ok) {
      return res.json({
        status: 'error',
        error: 'Failed to fetch user info'
      });
    }

    const userData = await userRes.json();
    const username = userData.login;

    // Store token in github-oauth.json
    fs.mkdirSync(STATE_DIR, { recursive: true });
    const oauthData = {
      access_token: access_token,
      token_type: data.token_type || 'bearer',
      scope: data.scope || 'repo,read:user',
      username: username,
      connected_at: new Date().toISOString()
    };

    fs.writeFileSync(
      path.join(STATE_DIR, 'github-oauth.json'),
      JSON.stringify(oauthData, null, 2),
      { mode: 0o600 }
    );

    res.json({
      status: 'success',
      access_token: access_token,
      username: username
    });
  } catch (err) {
    console.error('[github-auth] poll-auth error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/setup/api/github/repos', requireSetupAuth, async (req, res) => {
  try {
    const token = getGitHubToken();
    if (!token) {
      return res.status(400).json({
        ok: false,
        error: 'No GitHub token available. Connect GitHub first.'
      });
    }

    // Try installation repos first (fine-grained PATs), fall back to user repos
    let repos = [];

    try {
      const installRes = await fetch('https://api.github.com/installation/repositories?per_page=100', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (installRes.ok) {
        const installData = await installRes.json();
        if (installData.repositories && installData.repositories.length > 0) {
          repos = installData.repositories;
        }
      }
    } catch {}

    // Fallback to user repos
    if (repos.length === 0) {
      const userRes = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!userRes.ok) {
        return res.status(userRes.status).json({
          ok: false,
          error: `GitHub API error: ${userRes.statusText}`
        });
      }

      repos = await userRes.json();
    }

    // Format repos for the frontend
    const formattedRepos = repos.map(repo => {
      // Ensure full_name is properly formatted
      const fullName = repo.full_name || `${repo.owner?.login}/${repo.name}`;
      return {
        id: repo.id,
        name: repo.name,
        full_name: fullName,
        owner: repo.owner?.login || '',
        private: repo.private,
        default_branch: repo.default_branch,
        html_url: repo.html_url,
        description: repo.description || '',
        language: repo.language || ''
      };
    });

    console.log(`[github-repos] Returning ${formattedRepos.length} repos`);
    res.json({ repos: formattedRepos });
  } catch (err) {
    console.error('[github-auth] repos error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/setup/api/github/status', requireSetupAuth, async (req, res) => {
  try {
    const oauthPath = path.join(STATE_DIR, 'github-oauth.json');
    if (fs.existsSync(oauthPath)) {
      const oauth = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
      if (oauth.access_token && oauth.username) {
        return res.json({
          connected: true,
          username: oauth.username
        });
      }
    }
    res.json({ connected: false });
  } catch (err) {
    console.error('[github-auth] status error:', err);
    res.json({ connected: false });
  }
});

app.post('/setup/api/github/disconnect', requireSetupAuth, async (req, res) => {
  try {
    const oauthPath = path.join(STATE_DIR, 'github-oauth.json');
    if (fs.existsSync(oauthPath)) {
      fs.unlinkSync(oauthPath);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[github-auth] disconnect error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// ==============================
// GitHub OAuth API Routes (Non-setup paths for Dashboard compatibility)
// ==============================
// These mirror the /setup/api/github/* routes for the Gerald Dashboard client
// which calls /api/github/* directly

app.post('/api/github/start-auth', requireSetupAuth, async (req, res) => {
  try {
    const response = await fetch('https://github.com/login/device/code', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        scope: 'repo read:user'
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        ok: false,
        error: `GitHub API error: ${errorText}`
      });
    }

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('[github-auth] start-auth error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.post('/api/github/poll-auth', requireSetupAuth, async (req, res) => {
  try {
    const { device_code } = req.body || {};
    if (!device_code) {
      return res.status(400).json({ ok: false, error: 'Missing device_code' });
    }

    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        device_code: device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        ok: false,
        error: `GitHub API error: ${errorText}`
      });
    }

    const data = await response.json();

    if (data.error) {
      if (data.error === 'authorization_pending') {
        return res.json({ status: 'pending' });
      }
      return res.json({ status: 'error', error: data.error });
    }

    const access_token = data.access_token;
    const userRes = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });

    if (!userRes.ok) {
      return res.json({
        status: 'error',
        error: 'Failed to fetch user info'
      });
    }

    const userData = await userRes.json();
    const username = userData.login;

    fs.mkdirSync(STATE_DIR, { recursive: true });
    const oauthData = {
      access_token: access_token,
      token_type: data.token_type || 'bearer',
      scope: data.scope || 'repo,read:user',
      username: username,
      connected_at: new Date().toISOString()
    };

    fs.writeFileSync(
      path.join(STATE_DIR, 'github-oauth.json'),
      JSON.stringify(oauthData, null, 2),
      { mode: 0o600 }
    );

    res.json({
      status: 'success',
      access_token: access_token,
      username: username
    });
  } catch (err) {
    console.error('[github-auth] poll-auth error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/api/github/repos', requireSetupAuth, async (req, res) => {
  try {
    const token = getGitHubToken();
    if (!token) {
      return res.status(400).json({
        ok: false,
        error: 'No GitHub token available. Connect GitHub first.'
      });
    }

    let repos = [];

    try {
      const installRes = await fetch('https://api.github.com/installation/repositories?per_page=100', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (installRes.ok) {
        const installData = await installRes.json();
        if (installData.repositories && installData.repositories.length > 0) {
          repos = installData.repositories;
        }
      }
    } catch {}

    if (repos.length === 0) {
      const userRes = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!userRes.ok) {
        return res.status(userRes.status).json({
          ok: false,
          error: `GitHub API error: ${userRes.statusText}`
        });
      }

      repos = await userRes.json();
    }

    const formattedRepos = repos.map(repo => ({
      id: repo.id,
      name: repo.name,
      full_name: repo.full_name,
      owner: repo.owner?.login || '',
      private: repo.private,
      default_branch: repo.default_branch,
      html_url: repo.html_url,
      description: repo.description || '',
      language: repo.language || ''
    }));

    res.json({ repos: formattedRepos });
  } catch (err) {
    console.error('[github-auth] repos error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/api/github/status', requireSetupAuth, async (req, res) => {
  try {
    const oauthPath = path.join(STATE_DIR, 'github-oauth.json');
    if (fs.existsSync(oauthPath)) {
      const oauth = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
      if (oauth.access_token && oauth.username) {
        return res.json({
          connected: true,
          username: oauth.username
        });
      }
    }
    res.json({ connected: false });
  } catch (err) {
    console.error('[github-auth] status error:', err);
    res.json({ connected: false });
  }
});

app.post('/api/github/disconnect', requireSetupAuth, async (req, res) => {
  try {
    const oauthPath = path.join(STATE_DIR, 'github-oauth.json');
    if (fs.existsSync(oauthPath)) {
      fs.unlinkSync(oauthPath);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[github-auth] disconnect error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// ==============================
// Push Notification API Routes
// ==============================
// These proxy to the Gerald Dashboard server which handles push notifications

app.get('/api/push/vapid-key', requireSetupAuth, async (req, res) => {
  try {
    // Forward to dashboard server
    const dashboardRes = await fetch(`http://127.0.0.1:${DASHBOARD_PORT}/api/push/vapid-key`);
    const data = await dashboardRes.json();
    res.status(dashboardRes.status).json(data);
  } catch (err) {
    console.error('[push] vapid-key error:', err);
    res.status(503).json({ error: 'Dashboard push service unavailable' });
  }
});

app.post('/api/push/subscribe', requireSetupAuth, async (req, res) => {
  try {
    const dashboardRes = await fetch(`http://127.0.0.1:${DASHBOARD_PORT}/api/push/subscribe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const data = await dashboardRes.json();
    res.status(dashboardRes.status).json(data);
  } catch (err) {
    console.error('[push] subscribe error:', err);
    res.status(503).json({ error: 'Dashboard push service unavailable' });
  }
});

app.post('/api/push/unsubscribe', requireSetupAuth, async (req, res) => {
  try {
    const dashboardRes = await fetch(`http://127.0.0.1:${DASHBOARD_PORT}/api/push/unsubscribe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const data = await dashboardRes.json();
    res.status(dashboardRes.status).json(data);
  } catch (err) {
    console.error('[push] unsubscribe error:', err);
    res.status(503).json({ error: 'Dashboard push service unavailable' });
  }
});

app.post('/api/push/test', requireSetupAuth, async (req, res) => {
  try {
    const dashboardRes = await fetch(`http://127.0.0.1:${DASHBOARD_PORT}/api/push/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await dashboardRes.json();
    res.status(dashboardRes.status).json(data);
  } catch (err) {
    console.error('[push] test error:', err);
    res.status(503).json({ error: 'Dashboard push service unavailable - is VAPID configured?' });
  }
});

// ==============================
// Codex CLI Authentication (Device Code Flow)
// ==============================
app.post('/setup/api/codex/start-auth', requireSetupAuth, async (req, res) => {
  try {
    // Codex CLI supports device code auth via `codex login --device-auth`
    // We'll initiate the flow by running the command and capturing the output
    const { stdout, stderr } = await new Promise((resolve, reject) => {
      const proc = childProcess.spawn('codex', ['login', '--device-auth'], {
        env: { ...process.env, HOME: '/data', CODEX_HOME: '/data/.codex' },
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let stdoutData = '';
      let stderrData = '';

      proc.stdout.on('data', (data) => {
        stdoutData += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderrData += data.toString();
      });

      proc.on('close', (code) => {
        resolve({ stdout: stdoutData, stderr: stderrData, code });
      });

      proc.on('error', (err) => {
        reject(err);
      });

      // Kill after 10 seconds if it hangs
      setTimeout(() => {
        proc.kill();
        reject(new Error('Codex login timeout'));
      }, 10000);
    });

    // Parse the output for device code and verification URL
    // Expected output format:
    // "Visit https://chatgpt.com/device and enter code: XXXX-XXXX"
    const output = stdout + stderr;
    const urlMatch = output.match(/Visit\s+(https:\/\/[^\s]+)/i);
    const codeMatch = output.match(/code:\s*([A-Z0-9-]+)/i);

    if (!urlMatch || !codeMatch) {
      console.error('[codex-auth] Could not parse device code:', output);
      return res.status(500).json({
        ok: false,
        error: 'Failed to parse device code from Codex CLI output',
        rawOutput: output
      });
    }

    res.json({
      verification_uri: urlMatch[1],
      user_code: codeMatch[1],
      message: 'Visit the URL and enter the code to authenticate'
    });
  } catch (err) {
    console.error('[codex-auth] start-auth error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/setup/api/codex/status', requireSetupAuth, async (req, res) => {
  try {
    const authPath = path.join('/data/.codex', 'auth.json');

    if (!fs.existsSync(authPath)) {
      return res.json({ authenticated: false });
    }

    const authData = JSON.parse(fs.readFileSync(authPath, 'utf8'));

    // Check if we have a valid token structure
    if (authData.access_token || authData.token) {
      return res.json({
        authenticated: true,
        // Don't expose full auth data, just confirmation
        provider: authData.provider || 'chatgpt'
      });
    }

    res.json({ authenticated: false });
  } catch (err) {
    console.error('[codex-auth] status error:', err);
    res.json({ authenticated: false, error: String(err) });
  }
});

app.post('/setup/api/codex/disconnect', requireSetupAuth, async (req, res) => {
  try {
    const authPath = path.join('/data/.codex', 'auth.json');
    if (fs.existsSync(authPath)) {
      fs.unlinkSync(authPath);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[codex-auth] disconnect error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// ==============================
// Codex CLI Authentication (SSH-based for Railway)
// ==============================
// Codex CLI requires browser auth which doesn't work on headless servers.
// Users must authenticate via SSH, then we detect the auth file.

// Check Codex auth status (reads auth file created by `codex login` via SSH)
app.get('/api/model-settings/openai-codex/status', async (req, res) => {
  try {
    // Check multiple possible auth file locations
    const possiblePaths = [
      '/data/.codex/auth.json',
      '/data/.codex/credentials.json',
      path.join('/data', '.codex', 'auth.json')
    ];
    
    let authData = null;
    let authPath = null;
    
    for (const p of possiblePaths) {
      if (fs.existsSync(p)) {
        authPath = p;
        try {
          authData = JSON.parse(fs.readFileSync(p, 'utf8'));
          break;
        } catch (e) {
          console.log('[codex-status] Failed to parse auth file:', p, e.message);
        }
      }
    }
    
    if (!authData) {
      return res.json({ 
        authenticated: false,
        instructions: 'Codex CLI is installed. SSH into your container and run: codex login'
      });
    }

    // Check for various auth formats
    const hasToken = authData.access_token || authData.token || authData.apiKey;
    const hasAccount = authData.account || authData.email || authData.user;
    
    if (hasToken || hasAccount) {
      return res.json({ 
        authenticated: true,
        method: authData.apiKey ? 'api_key' : 'subscription',
        account: authData.account?.email || authData.email || authData.user || 'Connected'
      });
    }

    res.json({ 
      authenticated: false,
      instructions: 'Codex CLI is installed. SSH into your container and run: codex login'
    });
  } catch (err) {
    console.error('[codex-status] error:', err);
    res.json({ 
      authenticated: false, 
      error: err.message,
      instructions: 'Codex CLI is installed. SSH into your container and run: codex login'
    });
  }
});

// Disconnect Codex auth
app.post('/api/model-settings/openai-codex/disconnect', async (req, res) => {
  try {
    const possiblePaths = [
      '/data/.codex/auth.json',
      '/data/.codex/credentials.json',
      path.join('/data', '.codex', 'auth.json')
    ];
    
    let deleted = false;
    for (const p of possiblePaths) {
      if (fs.existsSync(p)) {
        fs.unlinkSync(p);
        deleted = true;
        console.log('[codex-disconnect] Removed auth file:', p);
      }
    }
    
    // Also try running codex logout if available
    try {
      await runCmd('codex', ['logout']);
    } catch (e) {
      // Ignore errors from logout command
    }
    
    res.json({ ok: true, disconnected: deleted });
  } catch (err) {
    console.error('[codex-disconnect] error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// ==============================
// Claude Code CLI Authentication
// ==============================
// Note: Claude Code does not support device code flow.
// Users need to authenticate manually via SSH or provide instructions.
app.get('/setup/api/claude/status', requireSetupAuth, async (req, res) => {
  try {
    const authPath = path.join('/data', '.claude.json');

    if (!fs.existsSync(authPath)) {
      return res.json({ authenticated: false });
    }

    const authData = JSON.parse(fs.readFileSync(authPath, 'utf8'));

    // Check for oauthAccount field (indicates Claude Pro/Max subscription)
    if (authData.oauthAccount || authData.accessToken) {
      return res.json({
        authenticated: true,
        account: authData.oauthAccount?.email || 'authenticated'
      });
    }

    res.json({ authenticated: false });
  } catch (err) {
    console.error('[claude-auth] status error:', err);
    res.json({ authenticated: false, error: String(err) });
  }
});

app.post('/setup/api/claude/disconnect', requireSetupAuth, async (req, res) => {
  try {
    const authPath = path.join('/data', '.claude.json');
    if (fs.existsSync(authPath)) {
      fs.unlinkSync(authPath);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[claude-auth] disconnect error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

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
      // Enable OpenAI-compatible chat completions endpoint (required by Gerald Dashboard)
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.http.endpoints.chatCompletions.enabled", "true"]),
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
          workspaceRepo: payload.workspaceRepo?.trim() || '', // Gerald workspace repo (SOUL.md, memories, skills)
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
          contactFromName: payload.contactFromName?.trim() || '',
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
        // Prefer manual token from form, fall back to OAuth token, then env var
        let token = payload.githubToken?.trim() || '';
        if (!token) {
          token = getGitHubToken();
        }
        const prodBranch = payload.prodBranch?.trim() || 'main';
        const devBranch = payload.devBranch?.trim() || 'development';

        // Save GitHub config for future rebuilds (only save manual token, not OAuth token)
        const githubConfig = {
          repo: payload.githubRepo.trim(),
          prodBranch,
          devBranch,
          // Only save manual token (OAuth token is saved separately in github-oauth.json)
          token: payload.githubToken?.trim() || '',
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

        // Clone development branch and start dev server
        extra += `[build] Cloning dev branch (${devBranch}) for live dev server...\n`;
        const devResult = await cloneAndBuild(repoUrl, devBranch, DEV_DIR, token);
        extra += `[build] Dev: ${devResult.output}\n`;

        // Start dev server
        try {
          await startDevServer();
          extra += `[dev-server] ✓ Live dev server started on port ${DEV_SERVER_PORT}\n`;
        } catch (err) {
          extra += `[dev-server] ⚠️ Failed to start dev server: ${err.message}\n`;
        }

        // Auto-register GitHub webhook for push events (auto-rebuild on push)
        if (token && payload.clientDomain?.trim()) {
          try {
            const webhookUrl = `https://${payload.clientDomain.trim().toLowerCase()}/api/webhook/github`;
            const repo = payload.githubRepo.trim();

            // Check if webhook already exists
            const existingRes = await fetch(`https://api.github.com/repos/${repo}/hooks`, {
              headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json' },
            });
            const existing = existingRes.ok ? await existingRes.json() : [];
            const alreadyExists = existing.some(h => h.config?.url === webhookUrl);

            if (!alreadyExists) {
              const hookRes = await fetch(`https://api.github.com/repos/${repo}/hooks`, {
                method: 'POST',
                headers: { 'Authorization': `token ${token}`, 'Accept': 'application/vnd.github.v3+json', 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  name: 'web',
                  active: true,
                  events: ['push'],
                  config: { url: webhookUrl, content_type: 'json', insecure_ssl: '0' },
                }),
              });
              if (hookRes.ok) {
                extra += `[webhook] ✓ GitHub webhook registered: ${webhookUrl}\n`;
              } else {
                const err = await hookRes.text();
                extra += `[webhook] ⚠️ Failed to register webhook (${hookRes.status}): ${err}\n`;
              }
            } else {
              extra += `[webhook] ✓ GitHub webhook already exists\n`;
            }
          } catch (err) {
            extra += `[webhook] ⚠️ Could not register webhook: ${err.message}\n`;
          }
        }
      }

      // ── Clone and set up Gerald Dashboard ──────────────────────────────
      extra += '\n[dashboard] Setting up Gerald Dashboard...\n';
      const githubToken = payload.githubToken?.trim() || getGitHubToken();
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
          process.env.DEFAULT_MODEL?.trim() || 'moonshot/kimi-k2.5'
        ]));
        extra += `\n[model] Moonshot configured\n`;
      }

      // Apply changes immediately.
      await restartGateway();
    }

    // Build completion message with link to Gerald dashboard
    const clientDomain = getClientDomain();
    let completionMsg = '';
    if (ok && clientDomain) {
      completionMsg = `\n${'─'.repeat(50)}\n` +
        `✅ Setup complete!\n\n` +
        `🌐 Production site: https://${clientDomain}\n` +
        `🔧 Dev site: https://dev.${clientDomain}\n` +
        `🤖 Gerald Dashboard: https://gerald.${clientDomain}\n` +
        `\nYour Gerald deployment is ready to go!\n`;
    } else if (ok) {
      completionMsg = `\n${'─'.repeat(50)}\n✅ Setup complete!\n`;
    }

    return res.status(ok ? 200 : 500).json({
      ok,
      output: `${onboard.output}${extra}${completionMsg}`,
      clientDomain: clientDomain || null,
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
    const token = getGitHubToken();
    const target = req.body?.target || 'both'; // 'production', 'dev', or 'both'

    let output = '';

    if (target === 'production' || target === 'both') {
      const result = await cloneAndBuild(repoUrl, githubConfig.prodBranch, PRODUCTION_DIR, token);
      output += `Production (${githubConfig.prodBranch}): ${result.output}\n`;
    }

    if (target === 'dev' || target === 'both') {
      const result = await pullDevBranch();
      output += `Dev (${githubConfig.devBranch}): ${result.output}\n`;
      if (devServerProcess) {
        await restartDevServer();
        output += 'Dev server restarted.\n';
      } else {
        await startDevServer();
        output += 'Dev server started.\n';
      }
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
    await safeRemoveDir(DASHBOARD_DIR);

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

// Rebuild/Update Gerald Workspace from GitHub
app.post('/api/rebuild-workspace', requireSetupAuth, async (req, res) => {
  try {
    const token = req.body?.token?.trim() || '';
    const result = await setupWorkspace(token);
    res.json({ ok: result.ok, output: result.output });
  } catch (err) {
    console.error('[rebuild-workspace]', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Configure workspace repo URL
app.post('/api/config/workspace-repo', requireSetupAuth, async (req, res) => {
  try {
    const { repoUrl } = req.body;
    if (!repoUrl) {
      return res.status(400).json({ ok: false, error: 'repoUrl required' });
    }

    // Read existing config
    const configPath = path.join(STATE_DIR, 'illumin8.json');
    let config = {};
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) {}

    // Update workspace repo
    config.workspaceRepo = repoUrl;
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    res.json({ ok: true, message: `Workspace repo set to ${repoUrl}` });
  } catch (err) {
    console.error('[config/workspace-repo]', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Get workspace repo config
app.get('/api/config/workspace-repo', requireSetupAuth, (req, res) => {
  try {
    const configPath = path.join(STATE_DIR, 'illumin8.json');
    let config = {};
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) {}

    res.json({ 
      ok: true, 
      repoUrl: config.workspaceRepo || 'https://github.com/illumin8ca/gerald',
      isDefault: !config.workspaceRepo
    });
  } catch (err) {
    console.error('[config/workspace-repo]', err);
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
    const token = getGitHubToken();

    if (branch === githubConfig.prodBranch) {
      console.log(`[webhook] Rebuilding production...`);
      const result = await cloneAndBuild(repoUrl, branch, PRODUCTION_DIR, token);
      return res.json({ ok: true, target: 'production', output: result.output });
    }

    if (branch === githubConfig.devBranch) {
      console.log(`[webhook] Updating dev server...`);
      const result = await pullDevBranch();
      // Restart dev server if it was running, or start it
      if (devServerProcess) {
        await restartDevServer();
      } else {
        await startDevServer();
      }
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
  // Critical for streaming: don't buffer responses, pipe them immediately
  changeOrigin: true,
  // Increase timeout for long-running streaming responses (AI chat)
  timeout: 300000,      // 5 minutes for initial connection
  proxyTimeout: 300000, // 5 minutes for proxy response
});

proxy.on("error", (err, req, res) => {
  console.error("[proxy]", err.code || err.message);
  if (res && !res.headersSent && typeof res.writeHead === 'function') {
    res.writeHead(503, { 'Content-Type': 'text/html' });
    res.end('<html><body style="background:#0a0a0f;color:#94a3b8;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h2 style="color:#00ff87">Gerald is starting up...</h2><p>Please refresh in a few seconds.</p></div></body></html>');
  }
});

// Keep-alive for streaming connections
proxy.on('proxyRes', (proxyRes, req, res) => {
  // Disable buffering for SSE/streaming responses
  const contentType = proxyRes.headers['content-type'] || '';
  const isStreaming = contentType.includes('text/event-stream') ||
                      contentType.includes('application/octet-stream') ||
                      req.headers['accept']?.includes('text/event-stream');

  if (isStreaming) {
    // Ensure connection stays alive
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering if present

    // Log streaming connection
    console.log(`[proxy] Streaming response started: ${req.url}`);

    // Handle client disconnect
    req.on('close', () => {
      console.log(`[proxy] Client disconnected from stream: ${req.url}`);
    });
  }
});

// Log proxy timeout errors specifically
proxy.on('econnreset', (err, req, res) => {
  console.error('[proxy] Connection reset error:', err.message);
});

proxy.on('timeout', (req, res) => {
  console.error('[proxy] Timeout error on:', req.url);
});

// Inject auth token into HTTP proxy requests - only for gateway, not Dashboard
proxy.on("proxyReq", (proxyReq, req, res) => {
  if (req._proxyTarget === 'dashboard') {
    // Don't inject gateway token - Dashboard handles its own auth via cookies/JWT
  } else {
    console.log(`[proxy] HTTP ${req.method} ${req.url} - injecting token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...`);
    proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
  }

  // Re-inject body consumed by express.json() so http-proxy can forward it.
  // Without this, POST/PUT/PATCH requests hang because the stream is already drained.
  if (req.body && Object.keys(req.body).length > 0) {
    const bodyData = JSON.stringify(req.body);
    proxyReq.setHeader('Content-Type', 'application/json');
    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
    proxyReq.write(bodyData);
  }
});

// Inject X-Robots-Tag and meta tag into dev server responses
proxy.on("proxyRes", (proxyRes, req, res) => {
  // Only for dev-server target (set in routing middleware)
  if (req._proxyTarget === 'dev-server') {
    // Set X-Robots-Tag header on all proxied responses
    proxyRes.headers['x-robots-tag'] = 'noindex, nofollow';

    // Inject meta tag into HTML responses
    const contentType = proxyRes.headers['content-type'] || '';
    if (contentType.includes('text/html')) {
      const _write = res.write;
      const _end = res.end;
      const chunks = [];

      res.write = function(chunk, ...args) {
        chunks.push(Buffer.from(chunk));
        return true;
      };

      res.end = function(chunk, ...args) {
        if (chunk) {
          chunks.push(Buffer.from(chunk));
        }

        let body = Buffer.concat(chunks).toString('utf8');

        // Inject noindex meta tag if not already present
        if (!body.includes('name="robots"') && body.includes('<head>')) {
          body = body.replace(
            '<head>',
            '<head>\n  <meta name="robots" content="noindex, nofollow">'
          );
        }

        // Update Content-Length
        delete proxyRes.headers['content-length'];
        res.setHeader('Content-Length', Buffer.byteLength(body));

        res.write = _write;
        res.end = _end;
        res.end(body);
      };
    }
  }
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

    // Allow webhook and API rebuild endpoints through on any domain
    if (req.path === '/api/webhook/github' || req.path === '/api/rebuild') {
      return next();
    }

    // Production site: clientdomain.com or www.clientdomain.com
    if (host === clientDomain || host === `www.${clientDomain}`) {
      return serveStaticSite(PRODUCTION_DIR, req, res);
    }

    // Dev site: dev.clientdomain.com → live dev server (or static fallback)
    if (host === `dev.${clientDomain}`) {
      // Serve robots.txt that blocks all crawlers
      if (req.path === '/robots.txt') {
        res.set('X-Robots-Tag', 'noindex, nofollow');
        res.type('text/plain');
        return res.send('User-agent: *\nDisallow: /\nNoindex: /');
      }

      // Set X-Robots-Tag header on all dev subdomain responses
      res.set('X-Robots-Tag', 'noindex, nofollow');

      if (devServerProcess) {
        req._proxyTarget = 'dev-server'; // skip gateway token injection, enable meta tag injection
        return proxy.web(req, res, { target: DEV_SERVER_TARGET });
      }
      // Fallback to static files if dev server isn't running
      return serveStaticSite(DEV_DIR, req, res);
    }

    // Gerald dashboard: gerald.clientdomain.com → Dashboard (transparent proxy)
    if (host === `gerald.${clientDomain}`) {
      if (req.path.startsWith('/openclaw')) {
        // Proxy /openclaw paths to OpenClaw gateway (dashboard API calls)
        if (isConfigured()) {
          try { await ensureGatewayRunning(); } catch (err) {
            return res.status(503).type('text/plain').send(`Gateway not ready: ${String(err)}`);
          }
        }
        return proxy.web(req, res, { target: GATEWAY_TARGET });
      }

      // Everything else → Gerald Dashboard (Dashboard handles its own auth)
      req._proxyTarget = 'dashboard';
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
// Ensure tailscale directories exist
fs.mkdirSync('/data/.tailscale', { recursive: true });
fs.mkdirSync('/var/run/tailscale', { recursive: true });

// Start Tailscale before the HTTP server
startTailscale().catch(err => console.error('[tailscale] Startup error:', err));

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

  // Start dev server if dev site has been cloned
  if (fs.existsSync(path.join(DEV_DIR, 'package.json'))) {
    startDevServer().catch(err => console.error('[dev-server] Auto-start failed:', err));
  }
});

// Critical: Increase server timeouts for AI streaming (5 minutes)
// Default Node.js timeouts are too short for long LLM responses
server.timeout = 300000; // 5 minutes
server.keepAliveTimeout = 300000; // 5 minutes
server.headersTimeout = 301000; // Slightly longer than keepAliveTimeout

console.log(`[wrapper] Server timeouts set: timeout=${server.timeout}ms, keepAliveTimeout=${server.keepAliveTimeout}ms`);

// Handle WebSocket upgrades
server.on("upgrade", async (req, socket, head) => {
  if (!isConfigured()) {
    socket.destroy();
    return;
  }

  // Route WebSocket by subdomain
  const clientDomain = getClientDomain();
  const wsHost = req.headers.host?.split(':')[0]?.toLowerCase();

  // Dev subdomain WebSocket → dev server (HMR)
  if (clientDomain && wsHost === `dev.${clientDomain}` && devServerProcess) {
    console.log(`[ws-upgrade] Proxying WebSocket to dev server: ${req.url}`);
    proxy.ws(req, socket, head, { target: DEV_SERVER_TARGET });
    return;
  }

  // Only allow WebSocket for gerald subdomain (or no client domain set)
  if (clientDomain && wsHost !== `gerald.${clientDomain}`) {
    socket.destroy();
    return;
  }

  // Parse the request path for routing
  const wsUrl = new URL(req.url, 'http://localhost');

  if (wsUrl.pathname.startsWith('/openclaw') || wsUrl.pathname === '/') {
    // /openclaw paths OR root path → OpenClaw gateway WebSocket (chat, node connections, etc.)
    try {
      await ensureGatewayRunning();
    } catch {
      socket.destroy();
      return;
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
    // All other WebSocket paths → Gerald Dashboard (Dashboard handles its own auth)
    console.log(`[ws-upgrade] Proxying WebSocket to dashboard: ${req.url}`);
    proxy.ws(req, socket, head, {
      target: DASHBOARD_TARGET,
    });
  }
});

// ==============================
// Dashboard API Routes (proxied to Gerald Dashboard - no requireSetupAuth)
// ==============================

// Gerald Dashboard version check
app.get('/api/dashboard/gerald-version', async (req, res) => {
  try {
    // Use DASHBOARD_DIR constant (not hardcoded path)
    let currentCommit = 'unknown';
    let behindBy = 0;

    if (fs.existsSync(DASHBOARD_DIR)) {
      try {
        const { output: commit } = await runCmd('git', ['rev-parse', '--short', 'HEAD'], { cwd: DASHBOARD_DIR });
        currentCommit = commit.trim();

        // Check if behind origin/main
        await runCmd('git', ['fetch', 'origin', 'main'], { cwd: DASHBOARD_DIR });
        const { output: behind } = await runCmd('git', ['rev-list', '--count', 'HEAD..origin/main'], { cwd: DASHBOARD_DIR });
        behindBy = parseInt(behind.trim()) || 0;
      } catch (gitErr) {
        console.log('[gerald-version] git check failed:', gitErr.message);
      }
    }

    res.json({
      currentCommit,
      behindBy,
      canUpdate: behindBy > 0,
      updateAvailable: behindBy > 0,
      source: 'wrapper'
    });
  } catch (err) {
    console.error('[gerald-version] error:', err);
    res.status(500).json({ error: 'Failed to check version' });
  }
});

// Gerald Dashboard update
app.post('/api/dashboard/gerald-update', async (req, res) => {
  try {
    if (!fs.existsSync(DASHBOARD_DIR)) {
      return res.status(400).json({ success: false, error: 'Dashboard not installed' });
    }

    // Pull latest changes
    const { output: pullOutput } = await runCmd('git', ['pull', 'origin', 'main'], { cwd: DASHBOARD_DIR });

    // Rebuild the dashboard
    await runCmd('npm', ['run', 'build'], { cwd: DASHBOARD_DIR });

    // Restart dashboard process
    if (dashboardProcess) {
      dashboardProcess.kill('SIGTERM');
      await new Promise(r => setTimeout(r, 2000));
      await startDashboard();
    }

    res.json({
      success: true,
      message: `Updated and rebuilt. ${pullOutput}`,
      restarted: true
    });
  } catch (err) {
    console.error('[gerald-update] error:', err);
    res.status(500).json({ success: false, error: String(err) });
  }
});

// System health endpoint
app.get('/api/system/health', async (req, res) => {
  try {
    const status = {
      gateway: gatewayProc ? 'running' : 'stopped',
      dashboard: dashboardProcess ? 'running' : 'stopped',
      devServer: devServerProcess ? 'running' : 'stopped',
      timestamp: new Date().toISOString()
    };
    res.json(status);
  } catch (err) {
    console.error('[system-health] error:', err);
    res.status(500).json({ error: String(err) });
  }
});

// Health data endpoints (mock data for Railway template)
app.get('/api/health/summary', async (req, res) => {
  res.json({
    today: { step_count: 0, active_energy: 0, sleep_hours: 0, exercise_minutes: 0, stand_hours: 0 },
    goals: { step_count: 10000, active_energy: 500, sleep_hours: 8, exercise_minutes: 30, stand_hours: 12 }
  });
});

app.get('/api/health/history/:metric', async (req, res) => {
  res.json({ metric: req.params.metric, days: parseInt(req.query.days) || 7, data: [] });
});

app.get('/api/health/hourly/:metric', async (req, res) => {
  res.json({ metric: req.params.metric, date: req.query.date, data: [] });
});

app.get('/api/health/vitals', async (req, res) => {
  res.json({ vitals: [] });
});

app.get('/api/health/workouts/today', async (req, res) => {
  res.json({ workouts: [] });
});

// Note: Other Dashboard API routes (/api/health/*) are handled above
// The Dashboard server handles its own JWT authentication

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
  try {
    if (devServerProcess) devServerProcess.kill("SIGTERM");
  } catch {
    // ignore
  }
  process.exit(0);
});
