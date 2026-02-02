# OpenClaw Railway Template - Architecture

## Overview

The OpenClaw Railway Template is a multi-service wrapper that orchestrates **four distinct services** within a single Railway deployment:

1. **Express Wrapper** (port 8080) — Host-based routing, proxying, and lifecycle management
2. **OpenClaw Gateway** (port 18789) — AI agent runtime with WebSocket support
3. **Gerald Dashboard** (port 3003) — Web UI for managing the AI agent
4. **Dev Server** (port 4321) — Live Astro development server with HMR

The wrapper acts as the **single entry point** for all HTTP/WebSocket traffic and uses **host-based routing** to direct requests to the appropriate backend service.

## Port Allocation

| Service | Port | Bind | Purpose |
|---------|------|------|---------|
| **Wrapper** | 8080 | 0.0.0.0 | Public HTTP/WebSocket entry point |
| **Gateway** | 18789 | 127.0.0.1 | OpenClaw agent runtime (proxied) |
| **Dashboard** | 3003 | 127.0.0.1 | Gerald UI (proxied) |
| **Dev Server** | 4321 | 127.0.0.1 | Live Astro dev (proxied) |

Railway's `PORT` env var is always **8080** — the wrapper listens on this port and proxies internally to the other services.

## Host-Based Routing

All custom domains are routed through **Cloudflare → Railway → Wrapper**. The wrapper inspects `req.hostname` and routes requests:

| Hostname | Target | Description |
|----------|--------|-------------|
| `{domain}` | Static files (`/data/workspace/site/production/`) | Production website |
| `www.{domain}` | Static files (`/data/workspace/site/production/`) | Production website (www redirect) |
| `dev.{domain}` | Dev server (port 4321) → static fallback | Live development site with HMR |
| `gerald.{domain}` | Dashboard (port 3003) | Gerald web UI |
| `gerald.{domain}/openclaw/*` | Gateway (port 18789) | Gateway API calls from Dashboard |
| `*.up.railway.app` | Gateway (port 18789) | Direct access to OpenClaw gateway (setup wizard) |

### Exempted Routes

These routes bypass host-based routing and are available on **any domain**:

- `/api/webhook/github` — GitHub push webhook (auto-rebuild on push)
- `/api/rebuild` — Manual rebuild trigger
- `/setup/*` — Setup wizard (if not configured)

## Proxy System

The wrapper uses **http-proxy** to forward requests and WebSockets to backend services.

### HTTP Proxy

```javascript
const proxy = httpProxy.createProxyServer({
  target: GATEWAY_TARGET,
  ws: true,
  xfwd: true,
});
```

#### Token Injection (Gateway Only)

The `proxyReq` handler injects the gateway auth token **only for gateway requests** (not Dashboard):

```javascript
proxy.on("proxyReq", (proxyReq, req, res) => {
  if (req._proxyTarget === 'dashboard') {
    // Dashboard handles its own auth — don't inject gateway token
  } else {
    // Gateway requests get the token
    proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
  }

  // Re-inject body consumed by express.json()
  if (req.body && Object.keys(req.body).length > 0) {
    const bodyData = JSON.stringify(req.body);
    proxyReq.setHeader('Content-Type', 'application/json');
    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
    proxyReq.write(bodyData);
  }
});
```

**Critical gotcha:** Express's `express.json()` middleware consumes the request body stream, which breaks http-proxy. The `proxyReq` handler **re-injects** the parsed body so POST/PUT/PATCH requests work correctly.

### WebSocket Proxy

WebSocket upgrades are handled in `server.on("upgrade")`:

```javascript
server.on("upgrade", async (req, socket, head) => {
  const clientDomain = getClientDomain();
  const wsHost = req.headers.host?.split(':')[0]?.toLowerCase();

  // Dev subdomain WebSocket → dev server (HMR)
  if (clientDomain && wsHost === `dev.${clientDomain}` && devServerProcess) {
    proxy.ws(req, socket, head, { target: DEV_SERVER_TARGET });
    return;
  }

  // Parse path for routing
  const wsUrl = new URL(req.url, 'http://localhost');

  if (wsUrl.pathname.startsWith('/openclaw')) {
    // /openclaw paths → OpenClaw gateway
    const url = new URL(req.url, GATEWAY_TARGET);
    if (!url.searchParams.has('token')) {
      url.searchParams.set('token', OPENCLAW_GATEWAY_TOKEN);
    }
    req.url = url.pathname + url.search;
    proxy.ws(req, socket, head, {
      target: GATEWAY_TARGET,
      headers: { Authorization: `Bearer ${OPENCLAW_GATEWAY_TOKEN}` },
    });
  } else {
    // All other WebSocket paths → Dashboard
    proxy.ws(req, socket, head, { target: DASHBOARD_TARGET });
  }
});
```

#### HMR WebSocket Support

The dev server's **Hot Module Replacement (HMR)** uses WebSockets for live updates. The wrapper proxies `ws://dev.{domain}/*` to the dev server on port 4321, enabling real-time code updates without page refreshes.

## GitHub Integration

### Auto-Webhook Registration

On successful setup, the wrapper **auto-registers** a GitHub webhook:

```javascript
const webhookUrl = `https://${domain}/api/webhook/github`;
const hookRes = await fetch(`https://api.github.com/repos/${repo}/hooks`, {
  method: 'POST',
  headers: { 'Authorization': `token ${token}` },
  body: JSON.stringify({
    name: 'web',
    active: true,
    events: ['push'],
    config: { url: webhookUrl, content_type: 'json' },
  }),
});
```

### Webhook Handler (`/api/webhook/github`)

When GitHub pushes to the configured branches, the wrapper:

1. **Production branch** (`main`) → Full rebuild (`cloneAndBuild()`)
2. **Dev branch** (`development`) → Git pull + npm install + dev server restart

```javascript
app.post('/api/webhook/github', async (req, res) => {
  const ref = req.body?.ref || '';
  const branch = ref.replace('refs/heads/', '');

  if (branch === githubConfig.prodBranch) {
    // Full rebuild for production
    await cloneAndBuild(repoUrl, branch, PRODUCTION_DIR, token);
  }

  if (branch === githubConfig.devBranch) {
    // Pull latest + restart dev server
    await pullDevBranch();
    await restartDevServer();
  }
});
```

### Build System (`cloneAndBuild`)

The build system:

1. **Clones** the repository (or creates branch if missing)
2. **Installs** dependencies (`npm install --ignore-scripts` + esbuild re-install)
3. **Builds** the site (`npm run build`)
4. **Moves** build output (detects `dist/`, `build/`, `out/`, etc.) to target directory

**Gotcha:** Railway's bundled esbuild can conflict with the site's esbuild version. The build system runs `--ignore-scripts` first, then manually re-runs esbuild's `install.js` to fetch the correct platform-specific binary.

## Auth System

### Three-Layer Auth Model

1. **Setup wizard** — Basic auth with `SETUP_PASSWORD` env var
2. **Gateway admin** — Token-based auth with `OPENCLAW_GATEWAY_TOKEN`
3. **Dashboard** — Telegram Login Widget (user-specific auth)

### Setup Password (`SETUP_PASSWORD`)

The `/setup` wizard is protected with HTTP Basic Auth:

```javascript
function requireSetupAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="Openclaw Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const password = decoded.split(":")[1];
  if (password !== SETUP_PASSWORD) {
    return res.status(401).send("Invalid password");
  }
  next();
}
```

### Gateway Token (`OPENCLAW_GATEWAY_TOKEN`)

The gateway token is **stable across restarts** using this resolution order:

1. **Railway env var** (`OPENCLAW_GATEWAY_TOKEN`) — highest priority
2. **Persisted file** (`/data/.openclaw/gateway.token`) — created on first boot if env var missing
3. **Generated token** — random 64-char hex if neither exists

```javascript
function resolveGatewayToken() {
  const envTok = process.env.OPENCLAW_GATEWAY_TOKEN?.trim();
  if (envTok) return envTok;

  const tokenPath = path.join(STATE_DIR, "gateway.token");
  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) return existing;
  } catch {}

  const generated = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(tokenPath, generated, { mode: 0o600 });
  return generated;
}
```

### Anthropic Setup Token (`ANTHROPIC_SETUP_TOKEN`)

If `ANTHROPIC_SETUP_TOKEN` is set in Railway env vars, the wrapper **auto-syncs** it to `auth-profiles.json` on every gateway start:

```javascript
if (anthropicToken) {
  const authStorePath = path.join(agentDir, 'auth-profiles.json');
  let store = { version: 1, profiles: {}, order: [], lastGood: {} };
  if (fs.existsSync(authStorePath)) {
    store = JSON.parse(fs.readFileSync(authStorePath, 'utf8'));
  }
  store.profiles['anthropic:default'] = {
    credential: { type: 'token', provider: 'anthropic', token: anthropicToken },
  };
  fs.writeFileSync(authStorePath, JSON.stringify(store, null, 2));
}
```

This ensures **Claude Max/Pro subscriptions** persist through rebuilds without manual re-authentication.

### Dashboard Auth (Telegram Login Widget)

Gerald Dashboard uses Telegram's Login Widget for user authentication:

- Users click "Login with Telegram" button
- Widget verifies Telegram account via HMAC signature
- Dashboard issues JWT session token
- Allowed user IDs controlled via `ALLOWED_TELEGRAM_IDS` env var

**No gateway token injection** — Dashboard manages its own auth separately from the gateway.

## Environment Variables

### Core Config

| Variable | Purpose | Default |
|----------|---------|---------|
| `PORT` | Wrapper listen port | `8080` (Railway sets this) |
| `OPENCLAW_STATE_DIR` | Config/state directory | `~/.openclaw` |
| `OPENCLAW_WORKSPACE_DIR` | Agent workspace | `~/.openclaw/workspace` |
| `OPENCLAW_ENTRY` | OpenClaw CLI entry point | `/openclaw/dist/entry.js` |
| `OPENCLAW_NODE` | Node.js binary path | `node` |
| `INTERNAL_GATEWAY_PORT` | Gateway listen port | `18789` |
| `INTERNAL_GATEWAY_HOST` | Gateway bind address | `127.0.0.1` |

### Auth & Secrets

| Variable | Purpose | Required |
|----------|---------|----------|
| `SETUP_PASSWORD` | Setup wizard password | ✅ Yes |
| `OPENCLAW_GATEWAY_TOKEN` | Gateway admin token | Optional (auto-generated) |
| `ANTHROPIC_SETUP_TOKEN` | Claude Max/Pro setup-token | Optional (enables Claude) |
| `MOONSHOT_API_KEY` | Kimi K2.5 API key | Optional (enables Moonshot) |
| `INTERNAL_API_KEY` | Dashboard internal API key | Optional (default set) |

### AI Provider Config

| Variable | Purpose | Example |
|----------|---------|---------|
| `DEFAULT_MODEL` | Default AI model | `anthropic/claude-sonnet-4-5` |
| `MOONSHOT_API_KEY` | Moonshot AI (Kimi K2.5) | API key |
| `OPENAI_API_KEY` | OpenAI | API key |

### Client Website Config

| Variable | Purpose | Example |
|----------|---------|---------|
| `CLIENT_DOMAIN` | Client's domain name | `example.com` |
| `GITHUB_TOKEN` | GitHub personal access token | `ghp_...` |

### Services Integration

| Variable | Purpose |
|----------|---------|
| `SENDGRID_API_KEY` | SendGrid email API |
| `SENDGRID_SENDER_EMAIL` | Default sender email |
| `CLOUDFLARE_API_KEY` | Cloudflare Global API Key |
| `CLOUDFLARE_EMAIL` | Cloudflare account email |
| `DEFAULT_ALLOWED_EMAILS` | CSV of allowed emails for contact form |

### Dashboard Config

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | Dashboard JWT signing key (auto-generated) |
| `ALLOWED_TELEGRAM_IDS` | Comma-separated Telegram user IDs |
| `TELEGRAM_BOT_ID` | Telegram bot ID (read from config) |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token (read from config) |

## Gerald Dashboard

### Setup Flow

1. **Clone** — `git clone https://github.com/illumin8ca/gerald-dashboard`
2. **Install** — `npm install --production=false`
3. **Build** — `npm run build`
4. **Start** — `node server/index.js` with env vars

### Lifecycle Management

The Dashboard is managed as a **child process** by the wrapper:

```javascript
dashboardProcess = childProcess.spawn('node', ['server/index.js'], {
  cwd: DASHBOARD_DIR,
  env: {
    PORT: String(DASHBOARD_PORT),
    OPENCLAW_GATEWAY_URL: GATEWAY_TARGET,
    OPENCLAW_GATEWAY_TOKEN: OPENCLAW_GATEWAY_TOKEN,
    INTERNAL_API_KEY: INTERNAL_API_KEY,
    JWT_SECRET: dashboardJwtSecret,
    ALLOWED_TELEGRAM_IDS: process.env.ALLOWED_TELEGRAM_IDS || '511172388',
    TELEGRAM_BOT_TOKEN: telegramBotToken,
    // ... more env vars
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
```

### Auto-Update on Restart

Every time the Dashboard starts, it **pulls the latest code** from GitHub:

```javascript
async function startDashboard() {
  // Pull latest changes
  await runCmd('git', ['pull', '--ff-only', 'origin', 'main'], { cwd: DASHBOARD_DIR });
  
  // Reinstall deps + rebuild
  await runCmd('npm', ['install', '--production=false'], { cwd: DASHBOARD_DIR });
  await runCmd('npm', ['run', 'build'], { cwd: DASHBOARD_DIR });
  
  // Start the server
  dashboardProcess = childProcess.spawn('node', ['server/index.js'], { ... });
}
```

### Routing

- **`gerald.{domain}/*`** → Dashboard (except `/openclaw/*`)
- **`gerald.{domain}/openclaw/*`** → Gateway (API calls)
- **WebSocket** → Dashboard (no token injection)

## Dev Server

### Lifecycle

1. **Clone** — `cloneAndBuild(repoUrl, devBranch, DEV_DIR, token)`
2. **Install** — `npm install` (if `node_modules` missing)
3. **Start** — `npx astro dev --host 0.0.0.0 --port 4321`

### Pull Updates (`pullDevBranch`)

When webhook triggers a dev branch push:

```javascript
async function pullDevBranch() {
  if (fs.existsSync(path.join(DEV_DIR, '.git'))) {
    // Pull latest
    await runCmd('git', ['pull', '--ff-only', 'origin', devBranch], { cwd: DEV_DIR });
    await runCmd('npm', ['install'], { cwd: DEV_DIR });
  } else {
    // Fresh clone
    await runCmd('git', ['clone', '--branch', devBranch, authUrl, DEV_DIR]);
    await runCmd('npm', ['install'], { cwd: DEV_DIR });
  }
}
```

### HMR (Hot Module Replacement)

Astro dev server enables HMR via WebSocket. The wrapper proxies WebSocket connections to the dev server:

```javascript
// Dev subdomain WebSocket → dev server
if (wsHost === `dev.${clientDomain}` && devServerProcess) {
  proxy.ws(req, socket, head, { target: DEV_SERVER_TARGET });
}
```

This allows developers to edit code and see changes **instantly** without manual page refresh.

## Config Sync on Gateway Start

Every time the gateway starts, the wrapper **syncs critical config values**:

```javascript
await runCmd(OPENCLAW_NODE, clawArgs([
  "config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN
]));

await runCmd(OPENCLAW_NODE, clawArgs([
  "config", "set", "gateway.http.endpoints.chatCompletions.enabled", "true"
]));

const envModel = process.env.DEFAULT_MODEL?.trim();
if (envModel) {
  await runCmd(OPENCLAW_NODE, clawArgs([
    "config", "set", "agents.defaults.model.primary", envModel
  ]));
}
```

This ensures:
- **Token** stays in sync (wrapper's token = config token)
- **ChatCompletions endpoint** is enabled (required by Dashboard)
- **Default model** reflects Railway env vars (no manual config edits needed)

## Setup/Onboard Flow

### 1. User Accesses `/setup`

Protected by `SETUP_PASSWORD` (HTTP Basic Auth).

### 2. Frontend Loads (`/setup/api/status`)

```json
{
  "configured": false,
  "authGroups": [...],
  "defaultModel": "moonshot/kimi-k2.5",
  "defaultClientDomain": "example.com",
  "cloudflareConfigured": true
}
```

### 3. User Submits Setup Form

POST to `/setup/api/run` with:

```json
{
  "flow": "quickstart",
  "authChoice": "moonshot-api-key",
  "authSecret": "sk-...",
  "telegramToken": "...",
  "clientDomain": "example.com",
  "githubRepo": "owner/repo",
  "githubToken": "ghp_..."
}
```

### 4. Wrapper Runs Onboard Command

```javascript
const onboardArgs = buildOnboardArgs(payload);
await runCmd(OPENCLAW_NODE, clawArgs(onboardArgs));
```

Example command:
```bash
node /openclaw/dist/entry.js onboard \
  --non-interactive \
  --accept-risk \
  --json \
  --workspace /data/workspace \
  --gateway-bind loopback \
  --gateway-port 18789 \
  --gateway-auth token \
  --gateway-token <OPENCLAW_GATEWAY_TOKEN> \
  --flow quickstart \
  --auth-choice moonshot-api-key \
  --moonshot-api-key sk-...
```

### 5. Post-Onboard Config

After successful onboard, the wrapper:

1. **Syncs gateway token** to config
2. **Enables chatCompletions** endpoint
3. **Writes channel configs** (Telegram/Discord/Slack)
4. **Creates Illumin8 config** (`illumin8.json`)
5. **Sets up Cloudflare DNS** (CNAME records for root, dev, gerald subdomains)
6. **Creates Turnstile widget** (auto-saves keys)
7. **Configures SendGrid** domain auth + DNS records
8. **Clones and builds** production and dev sites
9. **Registers GitHub webhook** (auto-rebuild on push)
10. **Clones and builds** Gerald Dashboard
11. **Restarts gateway** to apply config changes

### 6. Auto-Start Services

On successful setup:
- Gateway starts on port 18789
- Dashboard starts on port 3003
- Dev server starts on port 4321

## Key Gotchas & Lessons Learned

### 1. Express + http-proxy Body Re-injection

**Problem:** `express.json()` consumes the request body stream, causing POST/PUT/PATCH to hang when proxied.

**Solution:** Re-inject the parsed body in the `proxyReq` event:

```javascript
if (req.body && Object.keys(req.body).length > 0) {
  const bodyData = JSON.stringify(req.body);
  proxyReq.setHeader('Content-Type', 'application/json');
  proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
  proxyReq.write(bodyData);
}
```

### 2. Token Injection Only for Gateway

**Problem:** Dashboard has its own auth (Telegram Login Widget + JWT). Injecting the gateway token breaks Dashboard auth.

**Solution:** Use `req._proxyTarget` flag to skip token injection for Dashboard requests:

```javascript
if (req._proxyTarget === 'dashboard') {
  // Don't inject gateway token
} else {
  proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
}
```

### 3. MIME Type Handling for Static Sites

**Problem:** `.html` files served without extension (e.g., `/about` → `/about.html`) don't get correct Content-Type.

**Solution:** Use `res.sendFile()` which auto-sets MIME types based on file extension:

```javascript
const htmlPath = filePath + '.html';
if (fs.existsSync(htmlPath)) {
  return res.sendFile(htmlPath); // Sets Content-Type: text/html automatically
}
```

### 4. SPA Route Allowlist

**Problem:** Single-page apps (React/Vue) need to serve `index.html` for all unknown routes. Static sites (Astro MPA) should 404.

**Solution:** Explicit routing order:

1. Exact file match
2. Directory with `index.html`
3. Add `.html` extension
4. Serve `404.html` if exists
5. Show "Coming Soon" placeholder

### 5. esbuild Version Conflicts

**Problem:** Railway's bundled esbuild conflicts with Astro's esbuild version during `npm install`.

**Solution:** Install with `--ignore-scripts`, then manually re-run esbuild's `install.js`:

```javascript
await runCmd('npm', ['install', '--ignore-scripts'], { cwd: targetDir });

// Re-run esbuild install
const esbuildDirs = execSync(`find ${targetDir}/node_modules -name "install.js" -path "*/esbuild/*"`);
for (const installScript of esbuildDirs) {
  await runCmd('node', ['install.js'], { cwd: path.dirname(installScript) });
}
```

### 6. WebSocket Token Passing

**Problem:** WebSocket upgrades don't go through Express middleware, so token isn't injected.

**Solution:** Append token to URL query params and pass via headers option:

```javascript
const url = new URL(req.url, GATEWAY_TARGET);
if (!url.searchParams.has('token')) {
  url.searchParams.set('token', OPENCLAW_GATEWAY_TOKEN);
}
req.url = url.pathname + url.search;

proxy.ws(req, socket, head, {
  target: GATEWAY_TARGET,
  headers: { Authorization: `Bearer ${OPENCLAW_GATEWAY_TOKEN}` },
});
```

### 7. Dev Server Auto-Restart

**Problem:** Git pull updates dev files, but changes aren't visible until server restarts.

**Solution:** Restart dev server after every dev branch webhook:

```javascript
if (branch === githubConfig.devBranch) {
  await pullDevBranch();
  if (devServerProcess) {
    await restartDevServer();
  } else {
    await startDevServer();
  }
}
```

### 8. Dashboard Auth Separation

**Problem:** Dashboard and gateway share the same domain (`gerald.{domain}`), but have different auth systems.

**Solution:** Route `/openclaw/*` to gateway (with token), everything else to Dashboard (no token):

```javascript
if (host === `gerald.${clientDomain}`) {
  if (req.path.startsWith('/openclaw')) {
    return proxy.web(req, res, { target: GATEWAY_TARGET });
  }
  req._proxyTarget = 'dashboard';
  return proxy.web(req, res, { target: DASHBOARD_TARGET });
}
```

### 9. Cloudflare DNS Auto-Setup

**Problem:** Manual DNS setup is error-prone and slows onboarding.

**Solution:** Auto-create CNAME records via Cloudflare API during setup:

```javascript
const records = [
  { name: domain, type: 'CNAME', content: railwayDomain },
  { name: `dev.${domain}`, type: 'CNAME', content: railwayDomain },
  { name: `gerald.${domain}`, type: 'CNAME', content: railwayDomain },
];
```

**Critical:** Use `*.up.railway.app` domain as CNAME target, NOT custom domains (would create circular CNAME).

### 10. SendGrid Domain Auth

**Problem:** Emails from custom domain fail without domain authentication.

**Solution:** Auto-create SendGrid domain auth + Cloudflare DNS records during setup. Retry validation up to 3 times to allow DNS propagation.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Cloudflare CDN                          │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Railway Container                          │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │  Express Wrapper (port 8080)                           │    │
│  │  - Host-based routing                                  │    │
│  │  - HTTP/WebSocket proxy                                │    │
│  │  - Lifecycle management                                │    │
│  │  - Token injection (gateway only)                      │    │
│  └──────┬─────────────────────────────────────────────────┘    │
│         │                                                       │
│         ├──────► OpenClaw Gateway (127.0.0.1:18789)            │
│         │        - AI agent runtime                            │
│         │        - WebSocket chat                              │
│         │        - Token auth                                  │
│         │                                                       │
│         ├──────► Gerald Dashboard (127.0.0.1:3003)             │
│         │        - Web UI for agent                            │
│         │        - Telegram Login Widget auth                  │
│         │        - /openclaw/* routes to gateway               │
│         │                                                       │
│         ├──────► Dev Server (127.0.0.1:4321)                   │
│         │        - Live Astro dev with HMR                     │
│         │        - WebSocket for hot reload                    │
│         │                                                       │
│         └──────► Static Files (/data/workspace/site/)          │
│                  - production/ (main branch)                   │
│                  - dev/ (development branch fallback)          │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │  Railway Volume (/data)                                │    │
│  │  - .openclaw/ (config + auth)                          │    │
│  │  - workspace/ (agent workspace)                        │    │
│  │  - dashboard/ (Gerald Dashboard clone)                 │    │
│  │  - claude-code/ (CLI binary)                           │    │
│  └────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Request Flow Examples

### 1. Production Site Request

```
User → https://example.com/about
  ↓
Cloudflare (proxied)
  ↓
Railway → Wrapper (port 8080)
  ↓
Host check: example.com
  ↓
serveStaticSite(/data/workspace/site/production/)
  ↓
/data/workspace/site/production/about/index.html
```

### 2. Dev Site Request (HMR)

```
User → https://dev.example.com/
  ↓
Cloudflare (proxied)
  ↓
Railway → Wrapper (port 8080)
  ↓
Host check: dev.example.com
  ↓
Set X-Robots-Tag: noindex, nofollow
  ↓
Proxy to dev server (127.0.0.1:4321)
  ↓
Astro dev server (HMR enabled)
```

### 3. Gerald Dashboard Request

```
User → https://gerald.example.com/dashboard
  ↓
Cloudflare (proxied)
  ↓
Railway → Wrapper (port 8080)
  ↓
Host check: gerald.example.com
Path: /dashboard (not /openclaw/*)
  ↓
req._proxyTarget = 'dashboard'
  ↓
Proxy to Dashboard (127.0.0.1:3003) — NO token injection
  ↓
Dashboard handles Telegram auth + JWT
```

### 4. Gateway API Request (from Dashboard)

```
Dashboard → fetch('https://gerald.example.com/openclaw/chat')
  ↓
Wrapper receives request
  ↓
Host check: gerald.example.com
Path: /openclaw/chat
  ↓
Proxy to Gateway (127.0.0.1:18789) — WITH token injection
  ↓
proxyReq event: set Authorization: Bearer <token>
  ↓
Gateway processes request
```

### 5. GitHub Webhook (Auto-Rebuild)

```
GitHub → POST https://example.com/api/webhook/github
  ↓
Cloudflare (proxied)
  ↓
Railway → Wrapper (port 8080)
  ↓
Exempted route (bypass host check)
  ↓
Parse ref: refs/heads/main
  ↓
cloneAndBuild(repo, 'main', PRODUCTION_DIR)
  ↓
git clone → npm install → npm run build
  ↓
Production site updated
```

## Security Model

### 1. Setup Wizard (`/setup`)

- **HTTP Basic Auth** with `SETUP_PASSWORD`
- **One-time use** (disabled after onboarding)
- **Reset endpoint** (`/setup/api/reset`) deletes config to re-enable setup

### 2. Gateway

- **Token-based auth** (`Authorization: Bearer <token>`)
- **Loopback bind** (`127.0.0.1`) — only accessible via wrapper proxy
- **Token injection** — wrapper adds token to all gateway requests

### 3. Dashboard

- **Telegram Login Widget** — OAuth-like flow via Telegram
- **HMAC verification** — validates Telegram auth data signature
- **JWT sessions** — issues tokens after successful Telegram login
- **Allowlist** — `ALLOWED_TELEGRAM_IDS` restricts who can log in
- **No gateway token** — Dashboard auth is separate from gateway auth

### 4. Static Sites

- **Production** — Public (no auth)
- **Dev** — Public but unindexable (`X-Robots-Tag: noindex, nofollow`)
- **Coming Soon placeholder** — Shown if site not built yet

### 5. API Endpoints

- `/api/rebuild` — Protected by `requireSetupAuth` (SETUP_PASSWORD)
- `/api/webhook/github` — Public (validated by GitHub signature — TODO)
- `/setup/api/*` — All protected by `requireSetupAuth`

---

## Performance Considerations

### 1. Child Process Management

All services run as **child processes** managed by the wrapper. The wrapper monitors `exit` events and can restart services as needed.

### 2. Graceful Shutdown

On `SIGTERM`, the wrapper kills all child processes:

```javascript
process.on("SIGTERM", () => {
  if (gatewayProc) gatewayProc.kill("SIGTERM");
  if (dashboardProcess) dashboardProcess.kill("SIGTERM");
  if (devServerProcess) devServerProcess.kill("SIGTERM");
  process.exit(0);
});
```

### 3. Startup Order

1. **Wrapper starts** → listens on port 8080
2. **Gateway auto-starts** → syncs config, waits for ready (`waitForGatewayReady`)
3. **Dashboard auto-starts** → pulls latest, builds, starts server
4. **Dev server auto-starts** → only if dev site exists

### 4. Proxy Error Handling

The proxy shows a **"Gerald is starting up..."** page if the gateway isn't ready yet:

```javascript
proxy.on("error", (err, req, res) => {
  if (res && !res.headersSent) {
    res.writeHead(503, { 'Content-Type': 'text/html' });
    res.end('<html>...<h2>Gerald is starting up...</h2>...</html>');
  }
});
```

---

## File Structure

```
/data/                          # Railway persistent volume
  .openclaw/                    # OpenClaw state directory
    openclaw.json               # Main config file
    gateway.token               # Persisted gateway token
    auth-profiles.json          # AI provider credentials
    illumin8.json               # Client website config
    github.json                 # GitHub integration config
    sendgrid.json               # SendGrid config
    services.json               # Turnstile, Twilio, etc.
    auth.json                   # Allowed emails for contact form
    agents/                     # Agent-specific state
      main/
        agent/
          auth-profiles.json    # Auth profiles (synced from env)
  workspace/                    # Agent workspace
    site/
      production/               # Production website build
      dev/                      # Dev website (git clone)
    CLIENT-SKILLS.md            # Custom skills for client
  dashboard/                    # Gerald Dashboard clone
    server/
      index.js                  # Dashboard entry point
    dist/                       # Built frontend
  claude-code/                  # Claude Code CLI binary
    versions/
      <version>/
        bin/
          claude
```

---

## Scaling & Limitations

### Current Limitations

1. **Single container** — All services run in one Railway container
2. **No horizontal scaling** — Stateful services (gateway) can't easily scale
3. **SQLite storage** — Gateway uses SQLite (not multi-instance safe)
4. **Port conflicts** — All services must use unique ports

### Future Scaling Options

1. **Multi-container** — Separate Railway services for gateway, dashboard, dev server
2. **Shared volume** — Use Railway shared volumes for config/workspace
3. **Redis state** — Replace SQLite with Redis for multi-instance gateway
4. **Load balancer** — Use Railway's built-in load balancing for horizontal scaling

---

## Debugging

### Enable Debug Logging

```bash
OPENCLAW_TEMPLATE_DEBUG=true
```

This enables verbose logging in the wrapper:

```javascript
const DEBUG = process.env.OPENCLAW_TEMPLATE_DEBUG?.toLowerCase() === "true";
function debug(...args) {
  if (DEBUG) console.log(...args);
}
```

### Check Service Health

```bash
# Gateway
curl http://localhost:18789/health

# Dashboard
curl http://localhost:3003/api/health

# Dev server
curl http://localhost:4321/
```

### View Logs

```bash
# Wrapper
railway logs

# Gateway
railway logs | grep '\[gateway\]'

# Dashboard
railway logs | grep '\[dashboard\]'

# Dev server
railway logs | grep '\[dev-server\]'
```

### Token Verification

The wrapper logs extensive token diagnostics on startup and onboard:

```
[token] ========== SERVER STARTUP TOKEN RESOLUTION ==========
[token] ENV OPENCLAW_GATEWAY_TOKEN exists: true
[token] ENV value length: 64
[token] After trim length: 64
[token] ✓ Using token from OPENCLAW_GATEWAY_TOKEN env variable
[token] Final resolved token: 1a2b3c4d5e6f7g8h... (len: 64)
[token] ========== TOKEN RESOLUTION COMPLETE ==========
```

---

## Summary

The OpenClaw Railway Template is a **batteries-included deployment** that wraps the OpenClaw gateway with:

- **Production-ready routing** (host-based, multi-service)
- **Auto-managed services** (gateway, dashboard, dev server)
- **GitHub integration** (webhook auto-rebuild, branch tracking)
- **Auth system** (setup wizard, gateway token, Telegram login)
- **Cloudflare integration** (DNS, Turnstile, email auth)
- **SendGrid integration** (domain auth, verified sender)
- **Dev workflow** (live HMR, git-based deploys)

All running in a **single Railway container** with **persistent storage** on Railway's volume.
