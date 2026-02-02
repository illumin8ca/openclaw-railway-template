# Developer Workflow Guide

## Quick Start

Your Gerald deployment uses a **dual-branch workflow**:

- **`main` (or your configured production branch)** → `https://yourdomain.com` (production)
- **`development` (or your configured dev branch)** → `https://dev.yourdomain.com` (live dev server with HMR)

**Push to dev → see changes instantly. Push to main → production rebuild.**

---

## Daily Development Workflow

### 1. Clone Your Site Repository

```bash
git clone https://github.com/yourorg/yoursite
cd yoursite
git checkout development
```

### 2. Make Changes Locally

```bash
# Install deps
npm install

# Start local dev server
npm run dev

# Edit files
# ... make your changes ...
```

### 3. Test Locally

```bash
# Build to verify no errors
npm run build

# Preview the build
npm run preview
```

### 4. Push to Dev Branch

```bash
git add .
git commit -m "Update hero section"
git push origin development
```

**What happens next:**

1. GitHub sends webhook to `https://yourdomain.com/api/webhook/github`
2. Wrapper detects push to dev branch
3. Runs `git pull` in `/data/workspace/site/dev/`
4. Runs `npm install` (if `package.json` changed)
5. **Restarts dev server** (Astro dev with HMR)
6. Changes appear at `https://dev.yourdomain.com` **within seconds**

**No full rebuild** — the dev server uses Astro's HMR (Hot Module Replacement) for instant updates.

### 5. Review on Dev Site

Open `https://dev.yourdomain.com` in your browser. The dev server:

- ✅ Supports HMR (edit → save → instant refresh)
- ✅ Shows error overlays for build issues
- ✅ Includes source maps for debugging
- ✅ **Is unindexable** (`X-Robots-Tag: noindex, nofollow`)

### 6. Promote to Production

Once you're happy with the changes on dev:

```bash
git checkout main
git merge development
git push origin main
```

**What happens next:**

1. GitHub sends webhook to `https://yourdomain.com/api/webhook/github`
2. Wrapper detects push to main branch
3. Runs **full rebuild**:
   - `git clone --depth 1 --branch main <repo>`
   - `npm install`
   - `npm run build`
   - Moves build output to `/data/workspace/site/production/`
4. Production site updated at `https://yourdomain.com`

**This takes 1-3 minutes** (full clone + build).

---

## Branch Workflow

### Default Branches

| Branch | Domain | Build Type | Speed |
|--------|--------|------------|-------|
| `development` | `dev.yourdomain.com` | Git pull + dev server restart | ~10 seconds |
| `main` | `yourdomain.com` | Full clone + build + deploy | ~2 minutes |

### Changing Branch Names

If you want to use different branch names (e.g., `staging` instead of `development`):

1. Go to `https://yourdomain.com/setup` (enter your `SETUP_PASSWORD`)
2. Click "Reset Setup"
3. Re-run setup wizard with new branch names

Or manually edit `/data/.openclaw/github.json`:

```json
{
  "repo": "yourorg/yoursite",
  "prodBranch": "main",
  "devBranch": "staging",
  "token": "ghp_..."
}
```

Then restart the Railway deployment.

---

## GitHub Webhook

### How It Works

The webhook is **auto-registered** during setup:

```json
{
  "name": "web",
  "active": true,
  "events": ["push"],
  "config": {
    "url": "https://yourdomain.com/api/webhook/github",
    "content_type": "json"
  }
}
```

### Verify Webhook

1. Go to `https://github.com/yourorg/yoursite/settings/hooks`
2. You should see a webhook pointing to `https://yourdomain.com/api/webhook/github`
3. Click it → "Recent Deliveries" to see webhook logs

### Re-register Webhook

If the webhook was deleted or isn't working:

```bash
curl -X POST https://yourdomain.com/api/rebuild \
  -u "admin:YOUR_SETUP_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"target": "both"}'
```

Or re-run setup wizard to auto-register again.

---

## Manual Rebuilds

### Rebuild Production

```bash
curl -X POST https://yourdomain.com/api/rebuild \
  -u "admin:YOUR_SETUP_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"target": "production"}'
```

### Rebuild Dev

```bash
curl -X POST https://yourdomain.com/api/rebuild \
  -u "admin:YOUR_SETUP_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"target": "dev"}'
```

### Rebuild Both

```bash
curl -X POST https://yourdomain.com/api/rebuild \
  -u "admin:YOUR_SETUP_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"target": "both"}'
```

Replace `YOUR_SETUP_PASSWORD` with the password from your Railway env vars.

---

## Dev Server Deep Dive

### What Is It?

The dev server is a **live Astro dev server** (`npx astro dev`) running inside the Railway container. It's **not a static build** — it compiles pages on-demand and supports HMR.

### How It Starts

1. Wrapper checks if `/data/workspace/site/dev/package.json` exists
2. If yes, runs:
   ```bash
   cd /data/workspace/site/dev
   npm install  # if node_modules missing
   npx astro dev --host 0.0.0.0 --port 4321
   ```
3. Dev server starts on `127.0.0.1:4321`
4. Wrapper proxies `https://dev.yourdomain.com` to dev server

### HMR (Hot Module Replacement)

The dev server uses WebSockets to push updates to your browser. When you save a file:

1. Dev server detects file change
2. Rebuilds affected module
3. Sends update via WebSocket
4. Browser applies update **without full page reload**

**The wrapper proxies WebSocket connections** from `wss://dev.yourdomain.com` to the dev server:

```javascript
// WebSocket upgrade handler
if (wsHost === `dev.${clientDomain}` && devServerProcess) {
  proxy.ws(req, socket, head, { target: DEV_SERVER_TARGET });
}
```

### Viewing Dev Server Logs

```bash
# Railway CLI
railway logs | grep '\[dev-server\]'
```

### Restarting Dev Server

The dev server auto-restarts on every dev branch push. To manually restart:

```bash
# Restart Railway deployment
railway restart
```

Or trigger a rebuild (which restarts the dev server):

```bash
curl -X POST https://yourdomain.com/api/rebuild \
  -u "admin:YOUR_SETUP_PASSWORD" \
  -d '{"target": "dev"}'
```

---

## Switching AI Providers

Gerald uses the AI provider configured in Railway env vars.

### Current Provider

Check your Railway dashboard → Variables:

- `DEFAULT_MODEL` — Current model (e.g., `anthropic/claude-sonnet-4-5`)
- `ANTHROPIC_SETUP_TOKEN` — Claude Max/Pro setup-token
- `MOONSHOT_API_KEY` — Kimi K2.5 API key

### Change Provider

1. **Add API key** to Railway env vars:
   ```
   ANTHROPIC_SETUP_TOKEN=setup-token-xxxxx
   # or
   MOONSHOT_API_KEY=sk-xxxxx
   # or
   OPENAI_API_KEY=sk-xxxxx
   ```

2. **Set default model**:
   ```
   DEFAULT_MODEL=anthropic/claude-sonnet-4-5
   # or
   DEFAULT_MODEL=moonshot/kimi-k2.5
   # or
   DEFAULT_MODEL=openai/gpt-4
   ```

3. **Restart deployment** (Railway auto-restarts on env var change)

The wrapper **syncs env vars to OpenClaw config** on every startup, so no manual config edits needed.

### Verify Model

```bash
railway logs | grep '\[gateway\]'
# Look for: Model synced: anthropic/claude-sonnet-4-5
```

Or check `https://gerald.yourdomain.com` → Settings → Model.

---

## Re-running Setup

If you need to reconfigure the deployment (change domain, add services, etc.):

### 1. Reset Config

```bash
curl -X POST https://yourdomain.com/setup/api/reset \
  -u "admin:YOUR_SETUP_PASSWORD"
```

This **deletes the config file** but keeps:
- ✅ Credentials (API keys, auth profiles)
- ✅ Workspace (agent memory, files)
- ✅ Website builds

### 2. Access Setup Wizard

Go to `https://yourdomain.com/setup` (or `https://your-railway-app.up.railway.app/setup`)

### 3. Fill Out Form

The wizard will **pre-fill** values from env vars:

- Client domain
- GitHub repo
- AI provider (if `MOONSHOT_API_KEY` or `ANTHROPIC_SETUP_TOKEN` set)
- SendGrid config (if `SENDGRID_API_KEY` set)

### 4. Submit

The wizard will:
- Re-run onboard command
- Sync config
- Rebuild sites
- Restart services

---

## Troubleshooting

### Issue: Dev site shows "Coming Soon" placeholder

**Cause:** Dev branch hasn't been built yet, or dev server failed to start.

**Fix:**

1. Check if dev branch exists:
   ```bash
   railway run bash
   ls -la /data/workspace/site/dev/
   ```

2. If empty, trigger rebuild:
   ```bash
   curl -X POST https://yourdomain.com/api/rebuild \
     -u "admin:YOUR_SETUP_PASSWORD" \
     -d '{"target": "dev"}'
   ```

3. Check dev server logs:
   ```bash
   railway logs | grep '\[dev-server\]'
   ```

### Issue: Production site not updating after push

**Cause:** Webhook not registered, or wrong branch.

**Fix:**

1. Verify webhook exists:
   ```bash
   # Go to GitHub → Settings → Webhooks
   # Should see: https://yourdomain.com/api/webhook/github
   ```

2. Check recent deliveries for errors

3. Verify you pushed to the **production branch** (default: `main`)

4. Manually trigger rebuild:
   ```bash
   curl -X POST https://yourdomain.com/api/rebuild \
     -u "admin:YOUR_SETUP_PASSWORD" \
     -d '{"target": "production"}'
   ```

### Issue: Build fails with "esbuild not found"

**Cause:** esbuild version conflict between Railway and your site.

**Fix:** The wrapper handles this automatically (runs `--ignore-scripts` + esbuild re-install). If it still fails:

1. Check build logs:
   ```bash
   railway logs | grep '\[build\]'
   ```

2. Verify your `package.json` has esbuild as a dependency (not just devDependency)

3. Try clearing node_modules:
   ```bash
   railway run bash
   rm -rf /data/workspace/site/production/node_modules
   curl -X POST https://yourdomain.com/api/rebuild -u "admin:YOUR_SETUP_PASSWORD" -d '{"target":"production"}'
   ```

### Issue: HMR not working on dev site

**Cause:** WebSocket connection failing.

**Fix:**

1. Check browser console for WebSocket errors

2. Verify dev server is running:
   ```bash
   railway run bash
   curl http://localhost:4321/
   ```

3. Check WebSocket proxy logs:
   ```bash
   railway logs | grep '\[ws-upgrade\]'
   ```

4. Restart dev server:
   ```bash
   curl -X POST https://yourdomain.com/api/rebuild -u "admin:YOUR_SETUP_PASSWORD" -d '{"target":"dev"}'
   ```

### Issue: "Gateway not ready" error

**Cause:** Gateway failed to start, or taking too long.

**Fix:**

1. Check gateway logs:
   ```bash
   railway logs | grep '\[gateway\]'
   ```

2. Verify token sync:
   ```bash
   railway logs | grep '\[token\]'
   # Look for: Token verification PASSED
   ```

3. Restart Railway deployment:
   ```bash
   railway restart
   ```

### Issue: Dashboard shows "Login Failed"

**Cause:** Telegram Login Widget not configured, or user ID not in allowlist.

**Fix:**

1. Verify `ALLOWED_TELEGRAM_IDS` env var is set:
   ```bash
   railway variables | grep ALLOWED_TELEGRAM_IDS
   ```

2. Add your Telegram user ID:
   ```bash
   railway variables set ALLOWED_TELEGRAM_IDS="511172388,123456789"
   ```

3. Restart deployment:
   ```bash
   railway restart
   ```

### Issue: SendGrid emails not sending

**Cause:** Domain not verified, or DNS records missing.

**Fix:**

1. Check SendGrid config:
   ```bash
   railway run bash
   cat /data/.openclaw/sendgrid.json
   ```

2. Verify domain authentication:
   ```bash
   curl -X POST https://yourdomain.com/api/verify-sendgrid-domain \
     -u "admin:YOUR_SETUP_PASSWORD"
   ```

3. Check Cloudflare DNS records for CNAME records like:
   - `em1234.yourdomain.com` → SendGrid
   - `s1._domainkey.yourdomain.com` → SendGrid
   - `s2._domainkey.yourdomain.com` → SendGrid

---

## Advanced Workflows

### Using Feature Branches

Want to test a feature before merging to dev?

1. **Create feature branch:**
   ```bash
   git checkout -b feature/new-design
   # ... make changes ...
   git push origin feature/new-design
   ```

2. **Manually deploy to dev:**
   ```bash
   # SSH into Railway
   railway run bash
   
   # Pull feature branch
   cd /data/workspace/site/dev
   git fetch origin feature/new-design
   git checkout feature/new-design
   npm install
   
   # Restart dev server
   pkill -f "astro dev"
   npx astro dev --host 0.0.0.0 --port 4321 &
   ```

3. **Review at** `https://dev.yourdomain.com`

4. **Merge to dev when ready:**
   ```bash
   git checkout development
   git merge feature/new-design
   git push origin development
   ```

### Hot-Swapping Branches

Switch dev server branch without rebuilding:

```bash
railway run bash
cd /data/workspace/site/dev
git fetch origin
git checkout <branch-name>
npm install
# Dev server auto-restarts on next webhook or manual rebuild
```

### Rollback Production

If production deploy breaks, rollback to previous commit:

```bash
# In your local repo
git revert HEAD
git push origin main
# Webhook triggers rebuild with previous version
```

Or manually rollback on Railway:

```bash
railway run bash
cd /data/workspace/site/production
git log --oneline -10
git reset --hard <commit-hash>
# Trigger rebuild to re-deploy
```

---

## Environment Variables Reference

### Required

| Variable | Example | Purpose |
|----------|---------|---------|
| `SETUP_PASSWORD` | `supersecret123` | Setup wizard password |
| `CLIENT_DOMAIN` | `example.com` | Your domain name |
| `GITHUB_TOKEN` | `ghp_xxxxx` | GitHub personal access token |

### AI Provider (pick one)

| Variable | Example |
|----------|---------|
| `ANTHROPIC_SETUP_TOKEN` | `setup-token-xxxxx` |
| `MOONSHOT_API_KEY` | `sk-xxxxx` |
| `OPENAI_API_KEY` | `sk-xxxxx` |

### Model Selection

| Variable | Example |
|----------|---------|
| `DEFAULT_MODEL` | `anthropic/claude-sonnet-4-5` |

### Services (Optional)

| Variable | Purpose |
|----------|---------|
| `SENDGRID_API_KEY` | Email sending |
| `SENDGRID_SENDER_EMAIL` | Default sender |
| `CLOUDFLARE_API_KEY` | Auto DNS setup |
| `CLOUDFLARE_EMAIL` | Cloudflare account |
| `DEFAULT_ALLOWED_EMAILS` | Contact form allowlist |

### Dashboard (Optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `ALLOWED_TELEGRAM_IDS` | `511172388` | Who can log in to Dashboard |
| `INTERNAL_API_KEY` | (auto-generated) | Dashboard → Gateway auth |
| `JWT_SECRET` | (auto-generated) | Dashboard session signing |

---

## Best Practices

### 1. Always Test on Dev First

```bash
# BAD: Push untested changes to main
git push origin main

# GOOD: Test on dev first
git push origin development
# → Review at https://dev.yourdomain.com
# → Merge to main when ready
```

### 2. Use Semantic Commit Messages

```bash
git commit -m "feat: Add hero section animation"
git commit -m "fix: Correct mobile menu alignment"
git commit -m "chore: Update dependencies"
```

This makes it easy to understand what changed in production.

### 3. Keep Dev and Main in Sync

```bash
# Regularly merge main back to dev to avoid drift
git checkout development
git merge main
git push origin development
```

### 4. Use Pull Requests

Instead of direct pushes:

1. Create feature branch
2. Push to GitHub
3. Open pull request to `development`
4. Review and merge
5. Auto-deploys to dev site

### 5. Monitor Build Logs

```bash
# Watch logs during deploy
railway logs --tail

# Check for errors
railway logs | grep -i error
```

### 6. Pin Dependencies

Use exact versions in `package.json`:

```json
{
  "dependencies": {
    "astro": "4.0.0",  // NOT "^4.0.0"
    "react": "18.2.0"
  }
}
```

This prevents surprise breakages from automatic updates.

---

## Local Development

### Running Wrapper Locally

You can run the wrapper on your local machine for testing:

```bash
# Clone template
git clone https://github.com/illumin8ca/openclaw-railway-template
cd openclaw-railway-template

# Install deps
npm install

# Set env vars
export SETUP_PASSWORD=test123
export CLIENT_DOMAIN=localhost
export OPENCLAW_STATE_DIR=/tmp/openclaw-test

# Start wrapper
npm start
```

Open `http://localhost:8080/setup`

### Testing Webhook Locally

Use ngrok to expose localhost:

```bash
ngrok http 8080
# Copy ngrok URL (e.g., https://abc123.ngrok.io)
```

Register webhook:

```bash
curl -X POST https://api.github.com/repos/yourorg/yoursite/hooks \
  -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -d '{
    "name": "web",
    "config": {
      "url": "https://abc123.ngrok.io/api/webhook/github",
      "content_type": "json"
    },
    "events": ["push"]
  }'
```

Push to GitHub → webhook fires → localhost receives request.

---

## Migration Guide

### Moving Existing Site to Gerald

If you already have a static site and want to deploy it with Gerald:

1. **Push your site to GitHub** (if not already there)

2. **Ensure it has a build script:**
   ```json
   {
     "scripts": {
       "build": "astro build",  // or your build command
       "dev": "astro dev"
     }
   }
   ```

3. **Set up Gerald:**
   - Deploy OpenClaw Railway Template to Railway
   - Run setup wizard
   - Enter your GitHub repo URL
   - Choose production branch (e.g., `main`)
   - Choose dev branch (e.g., `development`)

4. **Point your domain to Railway:**
   - Add CNAME record: `yourdomain.com` → `your-app.up.railway.app`
   - Add CNAME record: `dev.yourdomain.com` → `your-app.up.railway.app`
   - Add CNAME record: `gerald.yourdomain.com` → `your-app.up.railway.app`

5. **Done!** Gerald will:
   - Clone and build your site
   - Set up webhook
   - Auto-deploy on push

### Moving from Vercel/Netlify

Gerald supports most static site generators:

- ✅ Astro
- ✅ Next.js (static export)
- ✅ Gatsby
- ✅ Hugo
- ✅ Jekyll
- ✅ SvelteKit (adapter-static)
- ✅ Nuxt (static)

**Requirements:**
- Must have `npm run build` script
- Must output static files to `dist/`, `build/`, `out/`, or `_site/`

If your site has **serverless functions**, you'll need to adapt them to Gerald's architecture (or run them separately).

---

## Summary

**Quick Reference:**

| Action | Command |
|--------|---------|
| **Push to dev** | `git push origin development` |
| **Push to production** | `git push origin main` |
| **Manual rebuild** | `curl -X POST https://yourdomain.com/api/rebuild -u admin:PASS` |
| **View logs** | `railway logs` |
| **Restart all** | `railway restart` |
| **Re-run setup** | `curl -X POST https://yourdomain.com/setup/api/reset -u admin:PASS` |
| **Access dashboard** | `https://gerald.yourdomain.com` |

**URLs:**

- **Production:** `https://yourdomain.com`
- **Dev:** `https://dev.yourdomain.com`
- **Dashboard:** `https://gerald.yourdomain.com`
- **Setup:** `https://yourdomain.com/setup`

**Support:**

- [OpenClaw Docs](https://github.com/openc2e/openclaw)
- [Railway Docs](https://docs.railway.app)
- [Astro Docs](https://docs.astro.build)
