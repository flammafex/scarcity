# 🔧 Troubleshooting Guide

This guide covers common issues you might encounter when setting up and running Scarcity for the first time.

---

## Table of Contents

- [Installation Issues](#installation-issues)
- [Build Issues](#build-issues)
- [Docker Issues](#docker-issues)
- [Runtime Issues](#runtime-issues)
- [Network and Port Issues](#network-and-port-issues)
- [Test Failures](#test-failures)
- [External Service Issues](#external-service-issues)
- [Platform-Specific Issues](#platform-specific-issues)

---

## Installation Issues

### ❌ `npm install` fails with "Cannot find module 'node-gyp'"

**Problem:** Native module compilation requires `node-gyp` and build tools.

**Solution:**
```bash
# Linux (Ubuntu/Debian)
sudo apt-get install build-essential python3

# macOS
xcode-select --install

# Windows (run as Administrator)
npm install --global windows-build-tools
```

Then retry:
```bash
npm install
```

---

### ❌ `better-sqlite3` installation fails

**Problem:** The SQLite3 native module can't compile.

**Solutions:**

**Option 1: Use prebuilt binaries**
```bash
npm install better-sqlite3 --build-from-source=false
```

**Option 2: Install build dependencies**
```bash
# Linux
sudo apt-get install build-essential python3

# macOS
xcode-select --install
brew install python3

# Windows
npm install --global windows-build-tools
```

**Option 3: Use Docker instead**
```bash
# Skip local installation and use Docker
docker compose up --build
```

---

### ❌ "Node version not supported" error

**Problem:** You're running Node.js < 20.

**Solution:**
```bash
# Check your Node version
node --version

# If < v20.0.0, install Node 20 LTS
# Using nvm (recommended):
nvm install 20
nvm use 20

# Or download from https://nodejs.org/
```

---

### ❌ "Permission denied" errors during `npm install -g`

**Problem:** Global npm installation requires root/admin permissions.

**Solutions:**

**Option 1: Use npx (no global install needed)**
```bash
npx scar wallet list
```

**Option 2: Fix npm permissions (Linux/macOS)**
```bash
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Now install without sudo
npm install -g .
```

**Option 3: Use sudo (not recommended)**
```bash
sudo npm install -g .
```

---

## Build Issues

### ❌ `npm run build` fails with "Cannot find module 'typescript'"

**Problem:** TypeScript isn't installed.

**Solution:**
```bash
npm install
npm run build
```

If that doesn't work:
```bash
npm install --save-dev typescript
npm run build
```

---

### ❌ Build succeeds but `dist/` folder is empty

**Problem:** TypeScript compilation failed silently.

**Solution:**
```bash
# Clean and rebuild
npm run clean
npm run build

# Check for compilation errors
npx tsc --noEmit
```

---

### ❌ "Cannot copy static files" error during build

**Problem:** `copy-static` script failing on Windows or due to missing directories.

**Solution:**
```bash
# Manually create directories
mkdir -p dist/src/web dist/src/explorer

# Copy static files manually
cp -r src/web/public dist/src/web/ 2>/dev/null || true
cp -r src/explorer/public dist/src/explorer/ 2>/dev/null || true

# Or on Windows (PowerShell)
New-Item -Path "dist/src/web" -ItemType Directory -Force
New-Item -Path "dist/src/explorer" -ItemType Directory -Force
Copy-Item -Path "src/web/public" -Destination "dist/src/web/" -Recurse -Force
Copy-Item -Path "src/explorer/public" -Destination "dist/src/explorer/" -Recurse -Force
```

---

## Docker Issues

### ❌ "Cannot connect to Docker daemon"

**Problem:** Docker isn't running or you don't have permissions.

**Solutions:**

**Linux:**
```bash
# Start Docker service
sudo systemctl start docker

# Add your user to docker group (logout required)
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker ps
```

**macOS/Windows:**
- Start Docker Desktop application
- Wait for "Docker is running" status

---

### ❌ "Port already in use" error with Docker Compose

**Problem:** Docker services need specific ports that are already occupied.

**Ports used by Scarcity Docker services:**
- `3000`: HyperToken Relay (WebSocket)
- `8080`: Witness Gateway (HTTP)
- `8081`: Freebird Issuer
- `8082`: Freebird Verifier

**Note:** Port 3001 is used by Nullscape Explorer when run locally, not by Docker services.

**Solution:**

**Option 1: Stop conflicting services**
```bash
# Find what's using the port
# Linux/macOS:
lsof -i :3000
lsof -i :8080

# Windows:
netstat -ano | findstr :3000

# Kill the process or stop the conflicting service
```

**Option 2: Change ports in docker-compose.yaml**
```yaml
# Edit docker-compose.yaml
services:
  hypertoken-relay:
    ports:
      - "3333:8080"  # Use host port 3333 instead of 3000
```

**Option 3: Use random ports**
```bash
# Let Docker assign random ports
docker compose up --build --remove-orphans
docker compose ps  # See assigned ports
```

---

### ❌ Docker build fails with "no space left on device"

**Problem:** Docker has filled up its storage quota.

**Solution:**
```bash
# Clean up Docker resources
docker system prune -a --volumes

# Check space
docker system df
```

---

### ❌ "Failed to pull image" errors

**Problem:** Can't download Freebird/Witness/HyperToken images.

**Solutions:**

**Check your internet connection:**
```bash
ping github.com
```

**Retry with explicit pull:**
```bash
docker compose pull
docker compose up --build
```

**Build locally if pull fails:**
```bash
# Clone dependencies manually and build
git clone https://github.com/flammafex/freebird
git clone https://github.com/flammafex/witness
git clone https://github.com/flammafex/hypertoken

# Update docker-compose.yaml to use local builds
```

---

### ❌ HyperToken Relay build fails with "Cannot find module 'prompts'" or similar TypeScript errors

**Problem:** The HyperToken repository's monorepo workspace dependencies aren't fully installed during Docker build.

**Error message:**
```
error TS2307: Cannot find module 'prompts' or its corresponding type declarations.
error TS2307: Cannot find module 'chalk' or its corresponding type declarations.
```

**This is a known issue with the upstream HyperToken repository.**

**Solution: Fix the docker-compose.yaml inline Dockerfile**

Edit `docker-compose.yaml` and replace the `hypertoken-relay` service configuration:

```yaml
hypertoken-relay:
  build:
    context: https://github.com/flammafex/hypertoken.git
    dockerfile_inline: |
      FROM node:20-alpine
      WORKDIR /app
      COPY package*.json ./
      # Install root dependencies first
      RUN npm install
      # Copy all workspace package.json files
      COPY packages/*/package*.json ./packages/
      # Install workspace dependencies
      RUN npm install --workspaces
      # Now copy the rest of the code
      COPY . .
      # Build only the relay (skip quickstart to avoid missing deps)
      RUN npx tsc -p packages/relay/tsconfig.json || npm run build --workspace=hypertoken-relay
      EXPOSE 8080
      CMD ["node", "start-relay.js", "8080"]
  ports:
    - "3000:8080"
```

**Alternative: Use a simpler single-workspace build**

Replace with this minimal configuration that skips the problematic quickstart package:

```yaml
hypertoken-relay:
  build:
    context: https://github.com/flammafex/hypertoken.git
    dockerfile_inline: |
      FROM node:20-alpine
      WORKDIR /app
      COPY package*.json ./
      RUN npm install --ignore-scripts
      COPY . .
      # Build only what's needed for the relay
      RUN cd packages/relay && npm install && npx tsc || true
      EXPOSE 8080
      CMD ["node", "start-relay.js", "8080"]
  ports:
    - "3000:8080"
```

**Quick workaround: Skip HyperToken and run in simulation mode**

If you just want to test Scarcity without HyperToken relay:

```bash
# Start only Freebird and Witness
docker compose up -d freebird-issuer freebird-verifier witness-gateway

# Run tests (will use simulation mode for HyperToken)
npm test
```

Scarcity is designed to work with graceful degradation - the tests will pass even without HyperToken relay.

---

### ❌ Witness build fails with "feature `edition2024` is required" Cargo error

**Problem:** The Witness repository uses Rust dependencies that require edition 2024 features not available in the Rust toolchain shipped with the Docker image.

**Error message:**
```
error: failed to parse manifest at `.../base64ct-1.8.0/Cargo.toml`
Caused by:
  feature `edition2024` is required
  The package requires the Cargo feature called `edition2024`, but that feature is not
  stabilized in this version of Cargo (1.83.0).
```

**This is an upstream issue with the Witness repository's dependencies.**

**Solution 1: Skip Witness and use simulation mode (quickest)**

```bash
# Start only Freebird (skip Witness and HyperToken)
docker compose up -d freebird-issuer freebird-verifier

# Run tests in simulation mode
npm run build
npm test
```

Scarcity's tests work in simulation mode without Witness or HyperToken.

**Solution 2: Report to upstream Witness repository**

This needs to be fixed in the Witness repository by either:
- Pinning `base64ct` to an older version that doesn't require edition 2024
- Updating the Witness Docker image to use Rust nightly/beta

File an issue at: https://github.com/flammafex/witness/issues

**Solution 3: Run only local Scarcity tests (no Docker)**

```bash
# Build and test Scarcity locally
npm install
npm run build
npm test

# All tests pass in simulation mode without external services
```

---

## Runtime Issues

### ❌ "ENOENT: no such file or directory, open '~/.scarcity/config.json'"

**Problem:** Configuration directory doesn't exist.

**Solution:**
```bash
# Create config directory
mkdir -p ~/.scarcity

# Initialize with empty config
echo '{}' > ~/.scarcity/config.json
echo '{"wallets":[]}' > ~/.scarcity/wallets.json
echo '{"tokens":[]}' > ~/.scarcity/tokens.json

# Or let the CLI create it automatically
./dist/src/cli/index.js wallet list
```

---

### ❌ "Permission denied" when writing to `~/.scarcity/`

**Problem:** Directory has wrong permissions.

**Solution:**
```bash
# Fix permissions
chmod 755 ~/.scarcity
chmod 644 ~/.scarcity/*.json

# On Windows (PowerShell):
icacls "$env:USERPROFILE\.scarcity" /grant "$env:USERNAME:(OI)(CI)F" /T
```

---

### ❌ Web Wallet doesn't open / shows blank page

**Problem:** Build didn't copy static assets or wrong port.

**Solutions:**

**Check if server is running:**
```bash
curl http://localhost:3000
```

**Rebuild with static files:**
```bash
npm run build
npm run web
```

**Check the console output:**
- Should show: `Web Wallet listening on http://localhost:3000`
- If different port, use that URL

**Check browser console:**
- Open DevTools (F12)
- Look for JavaScript errors
- Ensure static files are loading (Network tab)

---

### ❌ "Failed to connect to Tor" errors

**Problem:** Tor proxy not running or not configured.

**Solutions:**

**Verify Tor is optional:**
```bash
# Tor is ONLY needed if you explicitly enable it in config
# Scarcity works fine without Tor
```

**To enable Tor (optional):**
```bash
# Linux/macOS:
# Install Tor
sudo apt-get install tor  # Ubuntu/Debian
brew install tor          # macOS

# Start Tor
tor

# Windows:
# Download Tor Browser Bundle from torproject.org
# Or use Tor Expert Bundle
```

**Configure Scarcity to use Tor:**
```json
// ~/.scarcity/config.json
{
  "torProxy": "socks5://127.0.0.1:9050"
}
```

---

## Network and Port Issues

### ❌ "EADDRINUSE: address already in use" errors

**Problem:** Another process is using required ports (3000, 3001, 8080, etc.).

**Solution:**

**Find and stop the conflicting process:**
```bash
# Linux/macOS:
sudo lsof -i :3000
sudo kill -9 <PID>

# Windows (PowerShell as Admin):
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

**Or use different ports:**
```bash
# For Web Wallet:
PORT=3333 npm run web

# For Explorer:
PORT=3334 npm run explorer
```

---

### ❌ Can't connect to Freebird/Witness/HyperToken services

**Problem:** External services aren't running or misconfigured.

**Solutions:**

**Check if services are running (Docker):**
```bash
docker compose ps

# Should show:
# - freebird-issuer (port 8081)
# - freebird-verifier (port 8082)
# - witness-gateway (port 8080)
# - hypertoken-relay (ws://localhost:8080)
```

**Start services if not running:**
```bash
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay
```

**Check service health:**
```bash
# Freebird Issuer
curl http://localhost:8081/health

# Freebird Verifier
curl http://localhost:8082/health

# Witness Gateway
curl http://localhost:8080/api/status
```

**Run in simulation mode (no external services needed):**
```bash
# Tests work WITHOUT external services
npm test

# CLI also has graceful degradation
./dist/src/cli/index.js wallet list
```

---

## Test Failures

### ❌ Tests fail with "Connection refused" errors

**Problem:** External services not running (expected in simulation mode).

**Solution:**
```bash
# Tests should PASS even without external services (simulation mode)
npm test

# If you want full integration tests, start services first:
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay

# Wait 10 seconds for services to be ready
sleep 10

# Run tests again
npm test
```

---

### ❌ Tests timeout or hang

**Problem:** Network requests taking too long or external services unresponsive.

**Solutions:**

**Check external services:**
```bash
docker compose ps
docker compose logs freebird-issuer
docker compose logs witness-gateway
```

**Restart services:**
```bash
docker compose down
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay
sleep 10
npm test
```

**Run individual test suites:**
```bash
npm run test:basic         # Basic transfer test
npm run test:double-spend  # Double-spend prevention test
npm run test:degradation   # Graceful degradation test
```

---

### ❌ "All tests passed" but with warnings

**Problem:** Some features degraded to simulation mode (expected).

**Solution:**
- **This is normal!** Scarcity is designed to work WITHOUT external services
- Warnings like "Simulating Freebird" or "Simulating Witness" are expected
- To enable full functionality, start external services:
  ```bash
  docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay
  ```

---

## External Service Issues

### ❌ Freebird returns "Rate limit exceeded"

**Problem:** Too many requests to Freebird issuer.

**Solutions:**

**Wait and retry:**
```bash
# Freebird has rate limiting (by design)
sleep 60
# Retry your operation
```

**Use simulation mode:**
```bash
# Scarcity falls back to simulation automatically
# No action needed
```

**Deploy your own Freebird:**
```bash
# See https://github.com/flammafex/freebird
git clone https://github.com/flammafex/freebird
cd freebird
docker compose up -d
```

---

### ❌ Witness federation returns "Threshold not met"

**Problem:** Not enough Witness nodes responded.

**Solutions:**

**Check Witness gateway:**
```bash
curl http://localhost:8080/api/status
docker compose logs witness-gateway
```

**Restart Witness services:**
```bash
docker compose restart witness-gateway witness-1 witness-2 witness-3
sleep 10
```

**Lower threshold (for testing only):**
```typescript
// In your code, adjust Witness config:
const witness = new WitnessAdapter({
  gatewayUrl: 'http://localhost:8080',
  threshold: 1  // Lower threshold for testing
});
```

---

### ❌ HyperToken relay connection fails

**Problem:** WebSocket connection to relay failed.

**Solutions:**

**Check if relay is running:**
```bash
docker compose ps hypertoken-relay
docker compose logs hypertoken-relay
```

**Test WebSocket connection:**
```bash
# Using websocat (install: cargo install websocat)
websocat ws://localhost:8080

# Or using wscat (install: npm install -g wscat)
wscat -c ws://localhost:8080
```

**Use simulation mode:**
```bash
# Scarcity works WITHOUT HyperToken relay
# Gossip features will be simulated
npm test
```

---

## Platform-Specific Issues

### 🐧 Linux Issues

**Issue: "Cannot find sqlite3.node" on Alpine Linux**

**Solution:**
```bash
# Install build dependencies
apk add python3 make g++ sqlite-dev

# Rebuild better-sqlite3
npm rebuild better-sqlite3
```

---

### 🍎 macOS Issues

**Issue: "xcrun: error: invalid active developer path"**

**Solution:**
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Accept license
sudo xcodebuild -license accept

# Retry
npm install
```

**Issue: "Operation not permitted" on macOS Catalina+**

**Solution:**
```bash
# Grant Terminal full disk access:
# System Preferences → Security & Privacy → Privacy → Full Disk Access
# Add Terminal.app or your terminal emulator
```

---

### 🪟 Windows Issues

**Issue: "Cannot find module 'win32'" or similar**

**Solution:**
```bash
# Use WSL2 (recommended):
wsl --install
wsl

# Inside WSL2:
git clone https://github.com/flammafex/scarcity.git
cd scarcity
npm install
npm run build
npm test
```

**Issue: Path too long errors**

**Solution:**
```powershell
# Enable long paths (run as Administrator):
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Or use shorter path:
cd C:\s
git clone https://github.com/flammafex/scarcity.git
cd scarcity
```

**Issue: Line ending issues (CRLF vs LF)**

**Solution:**
```bash
# Configure Git to use LF:
git config --global core.autocrlf false
git config --global core.eol lf

# Re-clone repository:
cd ..
rm -rf scarcity
git clone https://github.com/flammafex/scarcity.git
cd scarcity
```

---

## Still Having Issues?

If none of these solutions work:

1. **Check existing issues:** https://github.com/flammafex/scarcity/issues
2. **Open a new issue:** Include:
   - Operating system and version
   - Node.js version (`node --version`)
   - npm version (`npm --version`)
   - Docker version (`docker --version`)
   - Full error message
   - Steps to reproduce
3. **Join the community:** See README for community links

---

## Quick Diagnostics Script

Run this script to gather system information for debugging:

```bash
#!/bin/bash
echo "=== Scarcity Diagnostics ==="
echo ""
echo "Operating System:"
uname -a
echo ""
echo "Node.js Version:"
node --version || echo "Node.js not found"
echo ""
echo "npm Version:"
npm --version || echo "npm not found"
echo ""
echo "Docker Version:"
docker --version || echo "Docker not found"
echo ""
echo "Docker Compose Version:"
docker compose version || echo "Docker Compose not found"
echo ""
echo "Python Version:"
python3 --version || echo "Python not found"
echo ""
echo "Git Version:"
git --version || echo "Git not found"
echo ""
echo "Build Tools:"
which gcc g++ make || echo "Build tools not found"
echo ""
echo "Port Status:"
lsof -i :3000 -i :3001 -i :8080 -i :8081 -i :8082 || netstat -an | grep -E ':(3000|3001|8080|8081|8082)'
echo ""
echo "Scarcity Config:"
ls -la ~/.scarcity/ 2>/dev/null || echo "~/.scarcity/ not found"
echo ""
echo "Docker Containers:"
docker compose ps 2>/dev/null || echo "Docker Compose not running"
```

Save as `diagnostics.sh`, run with `bash diagnostics.sh`, and include output when reporting issues.
