# Troubleshooting

## Installation

### `npm install` fails with node-gyp errors

Install build tools:

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install build-essential python3

# macOS
xcode-select --install

# Windows
npm install --global windows-build-tools
```

### `better-sqlite3` won't compile

```bash
# Try prebuilt binaries
npm install better-sqlite3 --build-from-source=false

# Or use Docker instead
docker compose up --build
```

### Node version errors

Scarcity requires Node.js 20+:

```bash
node --version  # Must be >= 20.0.0

# Use nvm to install
nvm install 20
nvm use 20
```

## Build Issues

### TypeScript errors

```bash
npm install
npm run build
```

### Empty `dist/` folder

```bash
rm -rf dist/
npm run build
npx tsc --noEmit  # Check for errors
```

## Docker Issues

### "Cannot connect to Docker daemon"

```bash
# Linux
sudo systemctl start docker
sudo usermod -aG docker $USER

# macOS/Windows
# Start Docker Desktop application
```

### "Port already in use"

Find and stop the conflicting process:

```bash
# Linux/macOS
lsof -i :3000
kill -9 <PID>

# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

### Docker build fails

```bash
# Clean up and retry
docker system prune -a --volumes
docker compose up --build
```

## Test Failures

### "Connection refused" errors

**Tests require Docker services.** Start them first:

```bash
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay
sleep 10
npm test
```

### Tests timeout

```bash
# Check service health
docker compose ps
docker compose logs freebird-issuer
docker compose logs witness-gateway

# Restart if needed
docker compose down
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay
```

## Service Issues

### Freebird returns errors

```bash
# Check if running
curl http://localhost:8081/health
curl http://localhost:8082/health

# Check logs
docker compose logs freebird-issuer
docker compose logs freebird-verifier
```

### Witness returns errors

```bash
# Check if running
curl http://localhost:8080/api/status

# Check logs
docker compose logs witness-gateway
```

### HyperToken relay won't connect

```bash
# Check if running
docker compose logs hypertoken-relay

# Test WebSocket (requires wscat: npm install -g wscat)
wscat -c ws://localhost:3000
```

## Platform-Specific

### Linux: sqlite3.node not found (Alpine)

```bash
apk add python3 make g++ sqlite-dev
npm rebuild better-sqlite3
```

### macOS: Xcode errors

```bash
xcode-select --install
sudo xcodebuild -license accept
```

### Windows: Path issues

Use WSL2:

```bash
wsl --install
wsl
git clone https://github.com/flammafex/scarcity.git
cd scarcity
npm install && npm run build && npm test
```

## Still Stuck?

1. Check existing issues: https://github.com/flammafex/scarcity/issues
2. Open a new issue with:
   - OS and version
   - Node.js version (`node --version`)
   - Docker version (`docker --version`)
   - Full error message
   - Steps to reproduce
