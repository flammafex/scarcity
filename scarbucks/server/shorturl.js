/**
 * Scarcity Landing Page Server
 * Serves the educational landing page for Scarcity
 */

import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from parent directory
app.use(express.static(join(__dirname, '..')));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// Fallback - serve index.html
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, '..', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗ ██████╗ █████╗ ██████╗  ██████╗██╗████████╗██╗   ██╗              ║
║   ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║╚══██╔══╝╚██╗ ██╔╝              ║
║   ███████╗██║     ███████║██████╔╝██║     ██║   ██║    ╚████╔╝               ║
║   ╚════██║██║     ██╔══██║██╔══██╗██║     ██║   ██║     ╚██╔╝                ║
║   ███████║╚██████╗██║  ██║██║  ██║╚██████╗██║   ██║      ██║                 ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝   ╚═╝      ╚═╝                 ║
║                                                                              ║
║                         CASH THAT BLEEDS                                     ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${PORT}                                    ║
║  Zero-cost · Serverless · Privacy-preserving                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
  `);
});

export default app;
