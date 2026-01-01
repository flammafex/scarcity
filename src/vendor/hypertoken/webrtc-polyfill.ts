/*
 * network/webrtc-polyfill.ts
 * WebRTC polyfill for Node.js environments
 *
 * This module provides WebRTC APIs in Node.js by importing the @roamhq/wrtc package
 * when running in a Node.js environment (where native WebRTC APIs are not available).
 */

// Detect if we're in a Node.js environment (no window object)
const isNode = typeof window === 'undefined';

let RTCPeerConnection: typeof globalThis.RTCPeerConnection;
let RTCSessionDescription: typeof globalThis.RTCSessionDescription;
let RTCIceCandidate: typeof globalThis.RTCIceCandidate;

if (isNode) {
  // We're in Node.js - use the wrtc polyfill
  try {
    // Dynamic import for ES modules - convert to synchronous using createRequire
    const { createRequire } = await import('node:module');
    const require = createRequire(import.meta.url);
    const wrtc = require('@roamhq/wrtc');

    RTCPeerConnection = wrtc.RTCPeerConnection;
    RTCSessionDescription = wrtc.RTCSessionDescription;
    RTCIceCandidate = wrtc.RTCIceCandidate;
    console.log('[WebRTC Polyfill] Using @roamhq/wrtc for Node.js environment');
  } catch (err) {
    console.error('[WebRTC Polyfill] Failed to load @roamhq/wrtc. WebRTC will not be available.');
    console.error('Install it with: npm install @roamhq/wrtc');
    console.error('Error:', err);
    throw new Error('WebRTC polyfill not available. Please install @roamhq/wrtc');
  }
} else {
  // We're in a browser - use native APIs
  RTCPeerConnection = globalThis.RTCPeerConnection;
  RTCSessionDescription = globalThis.RTCSessionDescription;
  RTCIceCandidate = globalThis.RTCIceCandidate;
}

export {
  RTCPeerConnection,
  RTCSessionDescription,
  RTCIceCandidate
};
