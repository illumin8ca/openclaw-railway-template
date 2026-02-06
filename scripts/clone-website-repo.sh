#!/bin/bash
# Clone and setup website repository for Railway deployment

set -e

REPO_URL=$1
GITHUB_TOKEN=$2
WORKSPACE_DIR=${3:-/data/workspace/site}

if [ -z "$REPO_URL" ] || [ -z "$GITHUB_TOKEN" ]; then
  echo "Usage: $0 <repo-url> <github-token> [workspace-dir]"
  echo "Example: $0 https://github.com/illumin8ca/cassandkathryn-com ghp_xxx /data/workspace/site"
  exit 1
fi

# Create workspace directory
mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"

echo "=== Cloning repository ==="
echo "Repo: $REPO_URL"
echo "Workspace: $WORKSPACE_DIR"

# Clone production (main branch)
if [ ! -d "$WORKSPACE_DIR/production" ]; then
  echo "Cloning main branch to production/"
  git clone --branch main "https://${GITHUB_TOKEN}@${REPO_URL#https://}" production
  echo "✓ Production clone complete"
else
  echo "✓ Production directory exists, pulling latest"
  cd production
  git pull origin main
  cd ..
fi

# Clone development branch
if [ ! -d "$WORKSPACE_DIR/dev" ]; then
  echo "Cloning development branch to dev/"
  git clone --branch development "https://${GITHUB_TOKEN}@${REPO_URL#https://}" dev
  echo "✓ Development clone complete"
else
  echo "✓ Development directory exists, pulling latest"
  cd dev
  git pull origin development
  cd ..
fi

# Set git config for both
echo "=== Configuring git ==="
cd production
git config user.email "gerald@railway.app"
git config user.name "Gerald Railway"
cd ..

cd dev
git config user.email "gerald@railway.app"
git config user.name "Gerald Railway"
cd ..

echo ""
echo "=== Setup complete ==="
echo "Production: $WORKSPACE_DIR/production (main branch)"
echo "Development: $WORKSPACE_DIR/dev (development branch)"
echo ""
echo "Next steps:"
echo "1. Build production: cd production && npm install && npm run build"
echo "2. Build dev: cd dev && npm install && npm run build"
