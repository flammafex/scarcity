# Quickstart

## Prerequisites

- Docker & Docker Compose
- Node.js 20+ (for local development)

## Run Everything

Start all services and run tests:

```bash
docker compose up --build --abort-on-container-exit
```

This will:
1. Build Scarcity
2. Start Freebird (issuer + verifier)
3. Start Witness (gateway + nodes)
4. Start HyperToken (relay)
5. Run the integration test suite

## Interactive Development

Start services in background:

```bash
docker compose up -d freebird-issuer freebird-verifier witness-gateway hypertoken-relay
```

Run tests:

```bash
docker compose run --rm scarcity-tests npm test
```

Run CLI:

```bash
docker compose run --rm scarcity-tests ./dist/src/cli/index.js wallet list
```

## Local Development (without Docker)

```bash
npm install
npm run build
```

**Note:** Tests require Docker services. Without them, tests will fail.

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Freebird Issuer | 8081 | Anonymous token issuance |
| Freebird Verifier | 8082 | Token verification |
| Witness Gateway | 8080 | Timestamp API |
| HyperToken Relay | 3000 | P2P WebSocket relay |

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
