# Quick Deploy Checklist (For New Clients)

With Railway Shared Variables configured, deploying Gerald for a new client is **super fast**.

## ✅ One-Time Setup (Already Done)

Railway Shared Variables configured:
- `GITHUB_TOKEN` ✅
- `DEFAULT_MODEL` ✅
- `MOONSHOT_API_KEY` ✅
- `SENDGRID_API_KEY` ✅
- `CLOUDFLARE_API_KEY` ✅
- `CLOUDFLARE_EMAIL` ✅
- `SETUP_PASSWORD` ✅

## 🚀 Deploy New Client (2 Minutes)

### 1. Deploy from Template
Click "Deploy to Railway" → Service deploys automatically

### 2. Add ONE Variable
In Railway service settings, add:
```bash
CLIENT_DOMAIN=clientdomain.com
```

(Optional: `SENDGRID_SENDER_EMAIL=noreply@clientdomain.com` - auto-defaults if not set)

### 3. Add Volume (One Click)
- Settings → Volumes
- Mount Path: `/data`
- Size: 1 GB
- Save → Auto-restarts

### 4. Visit Setup Wizard
```
https://<service-url>.railway.app/setup
```

Password: `wuw1fvz5QHA0rpd-wvu` (from shared SETUP_PASSWORD)

### 5. Run Setup (30 Seconds)
- Click "Run Setup"
- Wait for completion
- Done!

## 🎯 What You Get

After setup completes:
- ✅ `https://clientdomain.com` - Production site
- ✅ `https://dev.clientdomain.com` - Dev site (hot reload)
- ✅ `https://gerald.clientdomain.com` - Gerald dashboard
- ✅ DNS automatically configured (Cloudflare)
- ✅ Email sending ready (SendGrid)
- ✅ GitHub webhooks auto-rebuild on push
- ✅ Configuration persists forever (volume)

## 📋 Client Repo Requirements

The client's website repo needs:
1. GitHub repository (public or private with GITHUB_TOKEN access)
2. `main` branch for production
3. `development` branch for dev server
4. Astro-based site (or compatible)
5. Build-time dependencies in `dependencies`, not `devDependencies`

## ⚙️ Post-Deploy Customization (Optional)

After setup, you can customize via `/setup` page:
- Add more AI providers (Anthropic, OpenAI, etc.)
- Add custom skills
- Adjust model settings

**⛔ DO NOT configure Telegram** - Telegram is reserved for Andy's personal Gerald only.
Railway "Geraldinos" communicate via webchat and Discord only.

## 🔧 Troubleshooting

### "Email service not configured"
→ Check `SENDGRID_API_KEY` is in shared variables

### "DNS update failed"
→ Check `CLOUDFLARE_API_KEY` and `CLOUDFLARE_EMAIL`

### "Config lost after redeploy"
→ Volume not added - add in Settings → Volumes → `/data`

### "Build failed - missing dependency"
→ Move build-time deps from `devDependencies` to `dependencies` in package.json

---

**Total time: ~2 minutes** (most of it waiting for Railway to deploy)
