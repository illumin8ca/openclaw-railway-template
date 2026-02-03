# Build openclaw from source to avoid npm packaging gaps (some dist files are not shipped).
FROM node:22-bookworm AS openclaw-build

# Dependencies needed for openclaw build
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    python3 \
    make \
    g++ \
  && rm -rf /var/lib/apt/lists/*

# Install Bun (openclaw build uses it)
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"

RUN corepack enable

WORKDIR /openclaw

# Pin to a known ref (tag/branch). If it doesn't exist, fall back to main.
ARG OPENCLAW_GIT_REF=main
RUN git clone --depth 1 --branch "${OPENCLAW_GIT_REF}" https://github.com/openclaw/openclaw.git .

# Patch: relax version requirements for packages that may reference unpublished versions.
# Apply to all extension package.json files to handle workspace protocol (workspace:*).
RUN set -eux; \
  find ./extensions -name 'package.json' -type f | while read -r f; do \
    sed -i -E 's/"openclaw"[[:space:]]*:[[:space:]]*">=[^"]+"/"openclaw": "*"/g' "$f"; \
    sed -i -E 's/"openclaw"[[:space:]]*:[[:space:]]*"workspace:[^"]+"/"openclaw": "*"/g' "$f"; \
  done

RUN pnpm install --no-frozen-lockfile
RUN pnpm build
ENV OPENCLAW_PREFER_PNPM=1
RUN pnpm ui:install && pnpm ui:build


# Runtime image
FROM node:22-bookworm
ENV NODE_ENV=production

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    gcc \
    g++ \
    make \
    procps \
    file \
    git \
    python3 \
    pkg-config \
    sudo \
    ffmpeg \
    rclone \
    imagemagick \
  && rm -rf /var/lib/apt/lists/* \
  && curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o /usr/local/bin/yt-dlp \
  && chmod +x /usr/local/bin/yt-dlp

# Install Tailscale
RUN curl -fsSL https://tailscale.com/install.sh | sh

# Install Homebrew (must run as non-root user)
# Create a user for Homebrew installation, install it, then make it accessible to all users
RUN useradd -m -s /bin/bash linuxbrew \
  && echo 'linuxbrew ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER linuxbrew
RUN NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

USER root
RUN chown -R root:root /home/linuxbrew/.linuxbrew
ENV PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"

# Install Claude Code CLI and Codex CLI
RUN npm install -g @anthropic-ai/claude-code@latest @openai/codex@latest

# Create config directories for CLI auth files
RUN mkdir -p /data/.claude /data/.codex
ENV HOME=/data

WORKDIR /app

# Wrapper deps
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile && pnpm store prune

# Copy built openclaw
COPY --from=openclaw-build /openclaw /openclaw

# Remove esbuild binaries from openclaw's dependencies to prevent version conflicts
# with client project builds (openclaw bundles esbuild 0.25.x which breaks projects needing 0.27.x)
RUN find /openclaw -name 'esbuild' -path '*/bin/esbuild' -type f -delete 2>/dev/null; \
    find /openclaw -name 'esbuild' -path '*/.bin/esbuild' -type l -delete 2>/dev/null; \
    true

# Provide a openclaw executable
RUN printf '%s\n' '#!/usr/bin/env bash' 'exec node /openclaw/dist/entry.js "$@"' > /usr/local/bin/openclaw \
  && chmod +x /usr/local/bin/openclaw

COPY src ./src

# Persist rclone config and chroma cache on /data volume
ENV RCLONE_CONFIG=/data/.config/rclone/rclone.conf
ENV XDG_CACHE_HOME=/data/.cache

ENV PORT=8080
EXPOSE 8080
CMD ["node", "src/server.js"]
