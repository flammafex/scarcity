# Scarcity Web Wallet

A browser-based wallet for the Scarcity privacy-preserving P2P value transfer protocol.

## Quick Start

```bash
npm run web
# Open http://localhost:3000
```

## Features

### Core Operations
- Create, import, and manage multiple wallets
- Mint, transfer, receive, split, and merge tokens
- Real-time balance updates

### Security
- **PIN Protection**: Secret key export requires PIN verification
- **Secure Storage**: Keys stored in browser localStorage with PIN-derived encryption

### User Experience
- **Token Expiration Visibility**: See remaining validity time for each token
- **Expiry Warnings**: Banner alerts when tokens are approaching expiration
- **Transaction Progress**: Step-by-step feedback during transfers (blinding, timestamping, gossip, confirmation)
- **Privacy Explainer**: In-app modal explaining Scarcity's privacy guarantees

### PWA Support
- **Installable**: Add to home screen on mobile/desktop
- **Offline Capable**: Service worker caches static assets
- **Update Notifications**: Banner when new version is available

## Architecture

### Backend (Express API)

The server (`server.ts`) provides a REST API:

- **Infrastructure**: Initializes Witness, Freebird, HyperToken, and Gossip networks
- **Wallet API**: CRUD operations for wallets
- **Token API**: All token operations (mint, transfer, split, merge)

### Frontend (Vanilla JS)

The frontend (`public/`) is a single-page application:

- No framework dependencies (pure HTML/CSS/JavaScript)
- Tab-based navigation
- Real-time feedback with loading states

## API Endpoints

### Health & Initialization
- `GET /api/health` - Server status
- `POST /api/init` - Initialize network infrastructure

### Wallets
- `GET /api/wallets` - List all wallets
- `POST /api/wallets` - Create new wallet
- `POST /api/wallets/import` - Import from secret key
- `GET /api/wallets/:name` - Get wallet details
- `DELETE /api/wallets/:name` - Delete wallet
- `POST /api/wallets/:name/default` - Set as default
- `GET /api/wallets/:name/export` - Export secret key
- `GET /api/wallets/:name/balance` - Get balance

### Tokens
- `GET /api/tokens` - List tokens (with filters)
- `POST /api/tokens/mint` - Mint new token
- `POST /api/tokens/transfer` - Transfer to recipient
- `POST /api/tokens/receive` - Receive from transfer package
- `POST /api/tokens/split` - Split into multiple tokens
- `POST /api/tokens/merge` - Merge multiple tokens

## Configuration

Uses the same config as CLI:
- `~/.scarcity/config.json`
- `~/.scarcity/wallets.json`
- `~/.scarcity/tokens.json`

### Custom Port

```bash
PORT=8080 npm run web
```

## Token Expiration

Tokens have a validity window of approximately 576 days from creation. The wallet displays:

- **Remaining time** for each token
- **Warning banner** when any token is within 30 days of expiry
- **Visual indicators** (yellow for expiring soon, red for expired)

Expired tokens cannot be transferred. Transfer tokens before expiry to refresh them.

## PIN Protection

Secret key export is protected by a 4-digit PIN:

1. First export attempt prompts to set a PIN
2. Subsequent exports require PIN verification
3. PIN is hashed with SHA-256 before storage
4. Three incorrect attempts locks the wallet (refresh to retry)

## Privacy Explainer

Click the info button next to "Your Tokens" to see how Scarcity protects privacy:

- **Anonymous Issuance**: Freebird VOPRF blinds requests
- **Unlinkable Transfers**: Nullifiers can't be correlated
- **No Addresses**: Bearer tokens, possession = ownership
- **E2E Encryption**: All peer communication encrypted
- **Network Privacy**: Optional Tor support

## PWA Installation

### Desktop (Chrome/Edge)
Click the install icon in the address bar, or Menu → "Install Scarcity Wallet"

### Mobile
- **iOS Safari**: Share → "Add to Home Screen"
- **Android Chrome**: Menu → "Add to Home Screen"

## Security Notes

- **Local Only**: Server runs locally, data in home directory
- **No Authentication**: Development tool - don't expose to internet
- **Secret Keys**: Handle exports carefully
- **HTTPS**: Add TLS for production use

## File Structure

```
src/web/
├── server.ts           # Express API server
├── public/
│   ├── index.html      # Main HTML
│   ├── styles.css      # UI styles
│   ├── app.js          # Frontend logic
│   ├── manifest.json   # PWA manifest
│   └── sw.js           # Service worker
└── README.md
```

## Troubleshooting

### Server won't start
- Check if port 3000 is available
- Run `npm run build` first

### Network initialization fails
- Verify external services are running (Docker)
- Check `~/.scarcity/config.json` endpoints

### Tokens not appearing
- Ensure network is initialized
- Check `~/.scarcity/tokens.json`
- Refresh the page

### PWA not updating
- Hard refresh (Ctrl+Shift+R)
- Clear site data in browser settings
- Check for update banner
