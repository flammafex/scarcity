/*
 * network/MessageCodec.ts
 *
 * Unified message encoding/decoding with:
 * - Binary protocol (MessagePack) for efficiency
 * - Optional compression for large payloads
 * - Backward-compatible JSON fallback
 *
 * Wire format (when binary):
 *   [flags: 1 byte][payload: N bytes]
 *
 * Flags byte:
 *   bit 0: compressed (1 = yes)
 *   bit 1: encrypted (reserved for E2E)
 *   bits 2-7: reserved
 */

import { encode as msgpackEncode, decode as msgpackDecode } from "@msgpack/msgpack";
import * as pako from "pako";

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export type CodecFormat = "json" | "msgpack";

export interface CompressionConfig {
  /** Enable compression (default: true) */
  enabled: boolean;
  /** Only compress if payload exceeds this size in bytes (default: 1024) */
  threshold: number;
  /** Compression level 1-9 (default: 6) */
  level: number;
}

export interface CodecConfig {
  /** Serialization format (default: 'msgpack') */
  format: CodecFormat;
  /** Compression settings */
  compression: CompressionConfig;
}

export const DEFAULT_COMPRESSION: CompressionConfig = {
  enabled: true,
  threshold: 1024,
  level: 6,
};

export const DEFAULT_CODEC_CONFIG: CodecConfig = {
  format: "msgpack",
  compression: DEFAULT_COMPRESSION,
};

// Flags byte bit positions
const FLAG_COMPRESSED = 0x01;
const FLAG_ENCRYPTED = 0x02; // Reserved for E2E encryption

// ─────────────────────────────────────────────────────────────
// MessageCodec Class
// ─────────────────────────────────────────────────────────────

export class MessageCodec {
  private config: CodecConfig;

  constructor(config: Partial<CodecConfig> = {}) {
    this.config = {
      format: config.format ?? DEFAULT_CODEC_CONFIG.format,
      compression: {
        ...DEFAULT_COMPRESSION,
        ...config.compression,
      },
    };
  }

  /**
   * Get current codec configuration
   */
  getConfig(): CodecConfig {
    return { ...this.config };
  }

  /**
   * Update codec configuration
   */
  setConfig(config: Partial<CodecConfig>): void {
    if (config.format !== undefined) {
      this.config.format = config.format;
    }
    if (config.compression !== undefined) {
      this.config.compression = {
        ...this.config.compression,
        ...config.compression,
      };
    }
  }

  /**
   * Encode a message for transmission
   *
   * @param message - Any JSON-serializable object
   * @returns Encoded data (Uint8Array for msgpack, string for JSON)
   */
  encode(message: unknown): Uint8Array | string {
    if (this.config.format === "json") {
      return this.encodeJSON(message);
    }
    return this.encodeBinary(message);
  }

  /**
   * Decode received data back to a message object
   *
   * @param data - Encoded data (Uint8Array, ArrayBuffer, or string)
   * @returns Decoded message object
   */
  decode(data: Uint8Array | ArrayBuffer | string): unknown {
    // Handle string input (JSON or base64-encoded binary)
    if (typeof data === "string") {
      return this.decodeJSON(data);
    }

    // Convert ArrayBuffer to Uint8Array if needed
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;

    // Try to detect format from content
    // JSON starts with '{' (0x7b) or '[' (0x5b)
    if (bytes.length > 0 && (bytes[0] === 0x7b || bytes[0] === 0x5b)) {
      const str = new TextDecoder().decode(bytes);
      return this.decodeJSON(str);
    }

    return this.decodeBinary(bytes);
  }

  /**
   * Check if data appears to be binary encoded
   */
  isBinaryEncoded(data: Uint8Array | ArrayBuffer | string): boolean {
    if (typeof data === "string") {
      return false;
    }
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    // JSON starts with '{' or '['
    return bytes.length > 0 && bytes[0] !== 0x7b && bytes[0] !== 0x5b;
  }

  // ─────────────────────────────────────────────────────────────
  // JSON Encoding (fallback/compatibility)
  // ─────────────────────────────────────────────────────────────

  private encodeJSON(message: unknown): string {
    return JSON.stringify(message);
  }

  private decodeJSON(data: string): unknown {
    return JSON.parse(data);
  }

  // ─────────────────────────────────────────────────────────────
  // Binary Encoding (MessagePack + Compression)
  // ─────────────────────────────────────────────────────────────

  private encodeBinary(message: unknown): Uint8Array {
    // First encode with MessagePack
    let payload = msgpackEncode(message);
    let flags = 0;

    // Apply compression if enabled and payload exceeds threshold
    if (
      this.config.compression.enabled &&
      payload.length > this.config.compression.threshold
    ) {
      const compressed = pako.deflate(payload, {
        level: this.config.compression.level as 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9,
      });

      // Only use compression if it actually reduces size
      if (compressed.length < payload.length) {
        payload = compressed;
        flags |= FLAG_COMPRESSED;
      }
    }

    // Prepend flags byte
    const result = new Uint8Array(1 + payload.length);
    result[0] = flags;
    result.set(payload, 1);

    return result;
  }

  private decodeBinary(data: Uint8Array): unknown {
    if (data.length < 1) {
      throw new Error("MessageCodec: Empty binary data");
    }

    const flags = data[0];
    let payload = data.slice(1);

    // Decompress if needed
    if (flags & FLAG_COMPRESSED) {
      payload = pako.inflate(payload);
    }

    // Decrypt if needed (reserved for future E2E)
    if (flags & FLAG_ENCRYPTED) {
      throw new Error("MessageCodec: Encryption not yet implemented");
    }

    // Decode MessagePack
    return msgpackDecode(payload);
  }

  // ─────────────────────────────────────────────────────────────
  // Static Utilities
  // ─────────────────────────────────────────────────────────────

  /**
   * Create a codec with JSON format (for compatibility)
   */
  static json(): MessageCodec {
    return new MessageCodec({ format: "json" });
  }

  /**
   * Create a codec with MessagePack format (default)
   */
  static msgpack(compression?: Partial<CompressionConfig>): MessageCodec {
    return new MessageCodec({
      format: "msgpack",
      compression: compression ? { ...DEFAULT_COMPRESSION, ...compression } : undefined,
    });
  }

  /**
   * Create a codec with compression disabled
   */
  static uncompressed(format: CodecFormat = "msgpack"): MessageCodec {
    return new MessageCodec({
      format,
      compression: { enabled: false, threshold: 0, level: 6 },
    });
  }
}

// ─────────────────────────────────────────────────────────────
// Shared Instance
// ─────────────────────────────────────────────────────────────

/**
 * Default shared codec instance
 * Uses MessagePack with compression enabled
 */
export const defaultCodec = new MessageCodec();

/**
 * JSON-only codec for backward compatibility
 */
export const jsonCodec = MessageCodec.json();

export default MessageCodec;
