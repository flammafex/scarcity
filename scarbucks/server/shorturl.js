/**
 * Scarbucks Short URL Server
 * Minimal server for storing and retrieving transfer packages
 */

import express from 'express';
import { randomBytes } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory store with TTL
// In production, use Redis or similar
const transferStore = new Map();

// Cleanup expired entries every minute
setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of transferStore.entries()) {
    if (entry.expiresAt <= now) {
      transferStore.delete(code);
    }
  }
}, 60000);

// Middleware
app.use(express.json());
app.use(express.static(join(__dirname, '..')));

// Generate short code
function generateCode(length = 8) {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = randomBytes(length);
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars[bytes[i] % chars.length];
  }
  return code;
}

// Store transfer package
app.post('/api/transfer', (req, res) => {
  try {
    const { package: pkg, expiresAt } = req.body;

    if (!pkg || !expiresAt) {
      return res.status(400).json({ error: 'Missing package or expiresAt' });
    }

    // Don't store already expired packages
    if (expiresAt <= Date.now()) {
      return res.status(400).json({ error: 'Package already expired' });
    }

    // Generate unique code
    let code;
    do {
      code = generateCode(8);
    } while (transferStore.has(code));

    // Store with TTL
    transferStore.set(code, {
      package: pkg,
      expiresAt: expiresAt,
      createdAt: Date.now()
    });

    console.log(`[${new Date().toISOString()}] Created transfer: ${code} (expires in ${Math.round((expiresAt - Date.now()) / 1000)}s)`);

    res.json({ code, url: `/t/${code}` });
  } catch (error) {
    console.error('Error storing transfer:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Retrieve transfer package
app.get('/api/transfer/:code', (req, res) => {
  const { code } = req.params;

  const entry = transferStore.get(code);

  if (!entry) {
    return res.status(404).json({ error: 'Not found' });
  }

  // Check if expired
  if (entry.expiresAt <= Date.now()) {
    transferStore.delete(code);
    return res.status(410).json({ error: 'Gone', expired: true });
  }

  // Return the package (but don't delete - allow multiple claims for demo)
  // In production, you'd want to invalidate after first claim
  console.log(`[${new Date().toISOString()}] Retrieved transfer: ${code} (${Math.round((entry.expiresAt - Date.now()) / 1000)}s remaining)`);

  res.json({ package: entry.package });
});

// Serve short URLs - redirect to main page with claim param
app.get('/t/:code', (req, res) => {
  const { code } = req.params;

  // Check if valid
  const entry = transferStore.get(code);

  if (!entry) {
    // Serve the expired page
    return res.sendFile(join(__dirname, '..', 'index.html'));
  }

  if (entry.expiresAt <= Date.now()) {
    transferStore.delete(code);
    return res.sendFile(join(__dirname, '..', 'index.html'));
  }

  // Redirect to main page with claim param
  res.redirect(`/?claim=${code}`);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    activeTransfers: transferStore.size,
    uptime: process.uptime()
  });
});

// Stats (for debugging)
app.get('/api/stats', (req, res) => {
  const now = Date.now();
  const active = [...transferStore.entries()]
    .filter(([_, e]) => e.expiresAt > now)
    .map(([code, e]) => ({
      code,
      remainingMs: e.expiresAt - now
    }));

  res.json({
    total: transferStore.size,
    active: active.length,
    transfers: active
  });
});

// Fallback - serve index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, '..', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗ ██████╗ █████╗ ██████╗ ██████╗ ██╗   ██╗ ██████╗██╗  ██╗███████╗  ║
║   ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝██║ ██╔╝██╔════╝  ║
║   ███████╗██║     ███████║██████╔╝██████╔╝██║   ██║██║     █████╔╝ ███████╗  ║
║   ╚════██║██║     ██╔══██║██╔══██╗██╔══██╗██║   ██║██║     ██╔═██╗ ╚════██║  ║
║   ███████║╚██████╗██║  ██║██║  ██║██████╔╝╚██████╔╝╚██████╗██║  ██╗███████║  ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝  ║
║                                                                              ║
║                         CASH THAT BLEEDS                                     ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${PORT}                                    ║
║  90-second demo tokens | Zero-fee | Serverless                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
  `);
});

export default app;
