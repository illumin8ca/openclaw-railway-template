# CLI Authentication - Claude Code & Codex

This Railway template supports subscription-based authentication using Claude Code and Codex CLIs. These authenticate via OAuth with your Claude Pro/Max or ChatGPT Plus/Pro subscriptions.

## Overview

Both CLIs are installed globally in the Docker image and configured to store auth data in `/data`:
- **Codex**: `/data/.codex/auth.json`
- **Claude Code**: `/data/.claude.json`

The `/data` directory is a persistent volume in Railway, so auth credentials survive container restarts.

## Codex (OpenAI) - Device Code Flow

### Requirements
- ChatGPT Plus, Pro, Team, Edu, or Enterprise subscription
- Device code authentication enabled in ChatGPT security settings

### How It Works
1. User clicks "Connect Codex" in the setup wizard
2. Backend runs `codex login --device-auth`
3. Codex CLI generates a device code and verification URL
4. User visits the URL (e.g., `https://chatgpt.com/device`) and enters the code
5. Frontend polls `/setup/api/codex/status` until auth is complete
6. Auth token is saved to `/data/.codex/auth.json`

### Enabling Device Code Auth
Users must enable this feature in their ChatGPT account:
1. Go to ChatGPT Settings → Security
2. Enable "Device Code Authentication"
3. Then they can use the setup wizard flow

### API Endpoints
- `POST /setup/api/codex/start-auth` - Initiates device code flow
- `GET /setup/api/codex/status` - Check if authenticated
- `POST /setup/api/codex/disconnect` - Remove auth credentials

## Claude Code (Anthropic) - Manual Auth

### Requirements
- Claude Pro or Max subscription
- SSH access to Railway instance

### How It Works
Claude Code does not support headless device code authentication. Instead:

1. User clicks "Show Authentication Instructions" in the setup wizard
2. Instructions guide them to SSH into Railway
3. They run `claude` command which opens browser OAuth flow
4. After completing auth, they click "Check Status" to verify

### Manual Authentication Steps
```bash
# SSH into Railway instance
railway shell

# Set HOME to persistent volume
export HOME=/data

# Run Claude CLI (opens browser for OAuth)
claude

# Follow the browser prompts to authenticate with your Claude account
# After success, exit the CLI and return to the setup wizard
```

### API Endpoints
- `GET /setup/api/claude/status` - Check if authenticated
- `POST /setup/api/claude/disconnect` - Remove auth credentials

## OpenClaw Integration

After authentication, OpenClaw should automatically detect the CLI credentials:

### For Codex:
OpenClaw reads `~/.codex/auth.json` when `HOME=/data`

### For Claude Code:
OpenClaw reads `~/.claude.json` when `HOME=/data`

If OpenClaw doesn't automatically detect these, you may need to configure it via:
1. Environment variables pointing to the auth files
2. Symlinks from standard locations to `/data/.claude.json` and `/data/.codex/auth.json`
3. OpenClaw provider configuration

## Dockerfile Changes

```dockerfile
# Install Claude Code CLI and Codex CLI
RUN npm install -g @anthropic-ai/claude-code@latest @openai/codex@latest

# Create config directories for CLI auth files
RUN mkdir -p /data/.claude /data/.codex
ENV HOME=/data
```

## Alternative Approaches

If the device code flow doesn't work or if users can't SSH:

### Option 1: Pre-authenticate Locally
1. Authenticate on your local machine
2. Copy the auth files to Railway:
   ```bash
   # For Codex
   railway volume cp ~/.codex/auth.json /data/.codex/auth.json
   
   # For Claude
   railway volume cp ~/.claude.json /data/.claude.json
   ```

### Option 2: Web Terminal Widget
Future enhancement: Add a web-based terminal to the setup wizard so users can run `claude` or `codex login` directly from the browser.

### Option 3: API Key Fallback
Both CLIs support API key authentication as a fallback:
- Codex: Sign in with OpenAI API key instead of ChatGPT subscription
- Claude: Use Anthropic API key instead of Claude subscription

## Security Notes

1. **Auth files contain access tokens** - treat them like passwords
2. `/data` is the persistent volume - stored securely by Railway
3. The `HOME=/data` environment variable makes CLIs use this path
4. Auth endpoints are protected by `requireSetupAuth` middleware

## Testing

After implementing:

1. **Test Codex flow:**
   ```bash
   curl -X POST http://localhost:8080/setup/api/codex/start-auth
   # Should return { verification_uri, user_code }
   
   curl http://localhost:8080/setup/api/codex/status
   # Should return { authenticated: true/false }
   ```

2. **Test Claude flow:**
   ```bash
   # SSH into container
   railway shell
   
   # Run authentication
   HOME=/data claude
   
   # Check status via API
   curl http://localhost:8080/setup/api/claude/status
   ```

## Troubleshooting

### Codex authentication hangs
- Ensure device code auth is enabled in ChatGPT settings
- Check container logs for Codex CLI output
- Verify `CODEX_HOME` environment variable is set to `/data/.codex`

### Claude authentication fails
- Verify Claude CLI is installed: `which claude`
- Check that `HOME=/data` is set
- Ensure user is in a supported country for Claude
- Try manual authentication via SSH first

### OpenClaw doesn't detect credentials
- Check file permissions on auth files (should be 600)
- Verify OpenClaw's provider configuration
- Check OpenClaw logs for auth detection attempts
- May need to configure explicit paths in OpenClaw config
