# Railway Template Configuration

## ⚠️ IMPORTANT: Volume Must Be Added in Template Composer

When publishing this as a Railway Template, you MUST configure the volume in the **Railway Template Composer UI**, NOT in code files.

## How to Add Volume to Railway Template

### Step 1: Go to Railway Template Composer
https://railway.app/new/template

### Step 2: Create Template from GitHub
- Repository: `illumin8ca/gerald-railway-template`
- Branch: `main`

### Step 3: Add Volume (CRITICAL)
Click **"Add Volume"** in the template config:

```
Mount Path: /data
Size: 1 GB
Description: Persistent storage for Gerald configuration and workspace
```

### Step 4: Configure Environment Variables

**✅ ALREADY SET AS RAILWAY SHARED VARIABLES:**
All required variables are now shared across all deployments:
- `GITHUB_TOKEN` - For dashboard updates + webhooks
- `DEFAULT_MODEL` - AI model (moonshot/kimi-k2.5)
- `MOONSHOT_API_KEY` - API key for fallback model
- `SENDGRID_API_KEY` - Email service for magic links
- `CLOUDFLARE_API_KEY` - DNS automation
- `CLOUDFLARE_EMAIL` - Cloudflare account email
- `SETUP_PASSWORD` - Standard setup password

**⛔ NOT INCLUDED (BY DESIGN):**
- `TELEGRAM_BOT_TOKEN` - **DO NOT ADD** - Telegram is reserved for Andy's personal Gerald only
- `TELEGRAM_BOT_ID` - **DO NOT ADD** - Railway "Geraldinos" use webchat/Discord only

**User Must Provide (Per-Deployment):**
- `CLIENT_DOMAIN` - Their domain (e.g., solarwyse.ca)

**Optional (Auto-Defaults):**
- `SENDGRID_SENDER_EMAIL` - Defaults to `noreply@CLIENT_DOMAIN`
- `PORT` - Defaults to 8080

### Step 5: Set Health Check
- Path: `/setup/healthz`
- Timeout: 300 seconds

### Step 6: Publish Template
Click "Publish Template"

## Result

When users click "Deploy to Railway":
1. ✅ Volume is automatically created and mounted to `/data`
2. ✅ Environment variables are pre-filled (except SETUP_PASSWORD)
3. ✅ Service starts with health checks
4. ✅ User visits /setup to complete configuration
5. ✅ Configuration persists forever

## The Issue

The volume configuration lives in **Railway's template metadata**, not in the repository files.

You can't define volumes in:
- railway.toml ❌
- railway.json ❌  
- Dockerfile ❌

You MUST configure it in the Template Composer UI when creating the template.

## If Template Not Published Yet

Users must manually add the volume:
1. Deploy the repository directly
2. Go to Settings → Volumes
3. Add volume mounted to `/data`
4. Service restarts automatically

## Updating an Existing Template

1. Go to Railway dashboard
2. Find your published template
3. Click "Edit Template"
4. Add/update the Volume configuration
5. Save changes
6. Users deploying from now on will get the volume automatically
