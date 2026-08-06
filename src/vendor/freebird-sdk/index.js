// src/client/discovery.ts
import { sha256 as sha2564 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";

// src/crypto/voprf.ts
import { p256 as p2562 } from "@noble/curves/p256";
import { sha256 as sha2562 } from "@noble/hashes/sha256";
import { sha384 } from "@noble/hashes/sha512";
import { concatBytes as concatBytes2, bytesToHex as bytesToHex2, hexToBytes } from "@noble/hashes/utils";

// src/crypto/p256.ts
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
var P = p256.CURVE.Fp.ORDER;
var N = p256.CURVE.n;
var A = p256.CURVE.a;
var B = p256.CURVE.b;
var Z = BigInt(-10);
var VOPRF_DST = "P256_XMD:SHA-256_SSWU_RO_";
function hashToCurve(input, context) {
  const dst = new Uint8Array(VOPRF_DST.length + context.length);
  dst.set(new TextEncoder().encode(VOPRF_DST), 0);
  dst.set(context, VOPRF_DST.length);
  const [u0, u1] = hashToField(input, dst, 2);
  const Q0 = mapToCurveSSWU(u0);
  const Q1 = mapToCurveSSWU(u1);
  return Q0.add(Q1);
}
function randomScalar() {
  const randomBytes2 = p256.utils.randomPrivateKey();
  const num = os2ip(randomBytes2);
  return num % N;
}
function encodePoint(point) {
  return point.toRawBytes(true);
}
function decodePoint(bytes) {
  try {
    return p256.ProjectivePoint.fromHex(bytesToHex(bytes));
  } catch (e) {
    throw new Error("Invalid P-256 point encoding");
  }
}
function multiply(point, scalar) {
  return point.multiply(scalar);
}
function invertScalar(scalar) {
  return pow(scalar, N - 2n, N);
}
function invertField(num) {
  return pow(num, P - 2n, P);
}
function pow(base, exp, m) {
  let res = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp % 2n === 1n)
      res = mod(res * base, m);
    base = mod(base * base, m);
    exp /= 2n;
  }
  return res;
}
function mod(a, b) {
  const result = a % b;
  return result >= 0n ? result : result + b;
}
function os2ip(bytes) {
  return BigInt("0x" + bytesToHex(bytes));
}
function hashToField(msg, dst, count) {
  const L = 48;
  const lenInBytes = count * L;
  const pseudoRandomBytes = expandMessageXMD(msg, dst, lenInBytes);
  const u = new Array(count);
  for (let i = 0; i < count; i++) {
    const elmBytes = pseudoRandomBytes.slice(i * L, (i + 1) * L);
    u[i] = mod(os2ip(elmBytes), P);
  }
  return u;
}
function expandMessageXMD(msg, dst, lenInBytes) {
  const b_in_bytes = 32;
  const r_in_bytes = 64;
  if (dst.length > 255)
    throw new Error("DST too long");
  const dstPrime = concatBytes(dst, new Uint8Array([dst.length]));
  const Z_pad = new Uint8Array(r_in_bytes);
  const l_i_b_str = new Uint8Array(2);
  l_i_b_str[0] = lenInBytes >> 8 & 255;
  l_i_b_str[1] = lenInBytes & 255;
  const msgPrime = concatBytes(Z_pad, msg, l_i_b_str, new Uint8Array([0]), dstPrime);
  let b_0 = sha256(msgPrime);
  let b_1 = sha256(concatBytes(b_0, new Uint8Array([1]), dstPrime));
  const res = new Uint8Array(lenInBytes);
  let offset = 0;
  res.set(b_1.slice(0, Math.min(lenInBytes, b_in_bytes)), 0);
  offset += b_in_bytes;
  let b_i = b_1;
  let i = 2;
  while (offset < lenInBytes) {
    const xorBytes = new Uint8Array(b_0.length);
    for (let j = 0; j < b_0.length; j++)
      xorBytes[j] = b_0[j] ^ b_i[j];
    b_i = sha256(concatBytes(xorBytes, new Uint8Array([i]), dstPrime));
    const len = Math.min(lenInBytes - offset, b_in_bytes);
    res.set(b_i.slice(0, len), offset);
    offset += len;
    i++;
  }
  return res;
}
function mapToCurveSSWU(u) {
  const Z_u2 = mod(Z * mod(u * u, P), P);
  const Z_u2_sq = mod(Z_u2 * Z_u2, P);
  let tv1 = mod(Z_u2_sq + Z_u2, P);
  tv1 = invertField(tv1);
  let x1 = mod(mod(-B, P) * invertField(A) * (BigInt(1) + tv1), P);
  if (x1 < BigInt(0))
    x1 += P;
  const gx1 = mod(mod(x1 * x1, P) * x1 + A * x1 + B, P);
  let y1 = sqrt(gx1);
  if (y1 !== null) {
    if (y1 % BigInt(2) !== u % BigInt(2))
      y1 = mod(-y1, P);
    return new p256.ProjectivePoint(x1, y1, BigInt(1));
  }
  const x2 = mod(Z_u2 * x1, P);
  const gx2 = mod(mod(x2 * x2, P) * x2 + A * x2 + B, P);
  let y2 = sqrt(gx2);
  if (y2 === null)
    throw new Error("SSWU failed to find point");
  if (y2 % BigInt(2) !== u % BigInt(2))
    y2 = mod(-y2, P);
  return new p256.ProjectivePoint(x2, y2, BigInt(1));
}
function sqrt(x) {
  const root = pow(x, (P + 1n) / 4n, P);
  if (mod(root * root, P) !== x)
    return null;
  return root;
}

// src/crypto/voprf.ts
var DLEQ_DST_PREFIX = new TextEncoder().encode("DLEQ-P256-v1");
var COMPRESSED_POINT_LEN = 33;
var TOKEN_VERSION_V1 = 1;
var TOKEN_VERSION_LEN = 1;
var PROOF_LEN = 64;
var RAW_TOKEN_LEN_V1 = TOKEN_VERSION_LEN + COMPRESSED_POINT_LEN * 2 + PROOF_LEN;
var REDEMPTION_TOKEN_VERSION_V4 = 4;
var REDEMPTION_TOKEN_VERSION_V5 = 5;
var PRIVATE_TOKEN_LEN = 32;
var PUBLIC_BEARER_NONCE_LEN = 32;
var PUBLIC_BEARER_TOKEN_KEY_ID_LEN = 32;
var PUBLIC_BEARER_MAX_SIGNATURE_LEN = 512;
function blind(input, context) {
  const P2 = hashToCurve(input, context);
  const r = randomScalar();
  const A2 = multiply(P2, r);
  return {
    blinded: encodePoint(A2),
    state: { r, p: P2 }
    // We keep P to avoid re-hashing later
  };
}
function finalize(state, tokenB64, issuerPubkeyB64, context) {
  const tokenBytes = base64UrlToBytes(tokenB64);
  const pubkeyBytes = base64UrlToBytes(issuerPubkeyB64);
  if (tokenBytes.length !== RAW_TOKEN_LEN_V1) {
    throw new Error(
      `Invalid token length: expected ${RAW_TOKEN_LEN_V1}; got ${tokenBytes.length}`
    );
  }
  const offset = TOKEN_VERSION_LEN;
  if (tokenBytes[0] !== TOKEN_VERSION_V1) {
    throw new Error(`Unsupported token version: ${tokenBytes[0]}`);
  }
  const A_bytes = tokenBytes.slice(offset, offset + COMPRESSED_POINT_LEN);
  const B_bytes = tokenBytes.slice(
    offset + COMPRESSED_POINT_LEN,
    offset + COMPRESSED_POINT_LEN * 2
  );
  const proofBytes = tokenBytes.slice(offset + COMPRESSED_POINT_LEN * 2);
  const A2 = decodePoint(A_bytes);
  const B2 = decodePoint(B_bytes);
  const Q = decodePoint(pubkeyBytes);
  const G = p2562.ProjectivePoint.BASE;
  const isValid = verifyDleq(G, Q, A2, B2, proofBytes, context);
  if (!isValid) {
    throw new Error("VOPRF verification failed: Invalid DLEQ proof from issuer");
  }
  const rInv = invertScalar(state.r);
  const W = multiply(B2, rInv);
  const wBytes = encodePoint(W);
  const finalizeInput = concatBytes2(
    new TextEncoder().encode("VOPRF-P256-SHA256:Finalize"),
    context,
    wBytes
  );
  const output = sha2562(finalizeInput);
  return output;
}
function buildScopeDigest(verifierId, audience) {
  const verifierIdBytes = new TextEncoder().encode(verifierId);
  const audienceBytes = new TextEncoder().encode(audience);
  if (verifierIdBytes.length === 0 || verifierIdBytes.length > 255) {
    throw new Error("verifier_id must be 1-255 bytes");
  }
  if (audienceBytes.length === 0 || audienceBytes.length > 255) {
    throw new Error("audience must be 1-255 bytes");
  }
  return sha2562(concatBytes2(
    new TextEncoder().encode("freebird:scope:v4"),
    new Uint8Array([verifierIdBytes.length]),
    verifierIdBytes,
    new Uint8Array([audienceBytes.length]),
    audienceBytes
  ));
}
function buildPrivateTokenInput(issuerId, kid, nonce, scopeDigest) {
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  const kidBytes = new TextEncoder().encode(kid);
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) {
    throw new Error("issuer_id must be 1-255 bytes");
  }
  if (kidBytes.length === 0 || kidBytes.length > 255) {
    throw new Error("kid must be 1-255 bytes");
  }
  if (nonce.length !== PRIVATE_TOKEN_LEN)
    throw new Error("nonce must be 32 bytes");
  if (scopeDigest.length !== PRIVATE_TOKEN_LEN)
    throw new Error("scope_digest must be 32 bytes");
  return concatBytes2(
    new TextEncoder().encode("freebird:private-token-input:v4"),
    new Uint8Array([issuerIdBytes.length]),
    issuerIdBytes,
    new Uint8Array([kidBytes.length]),
    kidBytes,
    nonce,
    scopeDigest
  );
}
function buildRedemptionToken(nonce, scopeDigest, kid, issuerId, authenticator) {
  const kidBytes = new TextEncoder().encode(kid);
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  if (kidBytes.length === 0 || kidBytes.length > 255)
    throw new Error("kid must be 1-255 bytes");
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255)
    throw new Error("issuer_id must be 1-255 bytes");
  if (nonce.length !== PRIVATE_TOKEN_LEN)
    throw new Error("nonce must be 32 bytes");
  if (scopeDigest.length !== PRIVATE_TOKEN_LEN)
    throw new Error("scope_digest must be 32 bytes");
  if (authenticator.length !== PRIVATE_TOKEN_LEN)
    throw new Error("authenticator must be 32 bytes");
  const buf = new Uint8Array(1 + 32 + 32 + 1 + kidBytes.length + 1 + issuerIdBytes.length + 32);
  let pos = 0;
  buf[pos++] = REDEMPTION_TOKEN_VERSION_V4;
  buf.set(nonce, pos);
  pos += 32;
  buf.set(scopeDigest, pos);
  pos += 32;
  buf[pos++] = kidBytes.length;
  buf.set(kidBytes, pos);
  pos += kidBytes.length;
  buf[pos++] = issuerIdBytes.length;
  buf.set(issuerIdBytes, pos);
  pos += issuerIdBytes.length;
  buf.set(authenticator, pos);
  return buf;
}
function parseRedemptionToken(bytes) {
  if (bytes.length < 101 || bytes.length > 512)
    throw new Error("invalid token length");
  if (bytes[0] !== REDEMPTION_TOKEN_VERSION_V4)
    throw new Error("unsupported token version");
  let pos = 1;
  const nonce = bytes.slice(pos, pos + 32);
  pos += 32;
  const scopeDigest = bytes.slice(pos, pos + 32);
  pos += 32;
  const kidLen = bytes[pos++];
  if (kidLen === 0 || pos + kidLen > bytes.length)
    throw new Error("invalid kid_len");
  const kid = new TextDecoder().decode(bytes.slice(pos, pos + kidLen));
  pos += kidLen;
  const issuerIdLen = bytes[pos++];
  if (issuerIdLen === 0 || pos + issuerIdLen > bytes.length)
    throw new Error("invalid issuer_id_len");
  const issuerId = new TextDecoder().decode(bytes.slice(pos, pos + issuerIdLen));
  pos += issuerIdLen;
  if (bytes.length - pos !== 32)
    throw new Error("invalid authenticator length");
  const authenticator = bytes.slice(pos, pos + 32);
  return { nonce, scopeDigest, kid, issuerId, authenticator };
}
function tokenKeyIdFromSpki(pubkeySpki) {
  return sha2562(pubkeySpki);
}
function tokenKeyIdToHex(tokenKeyId) {
  if (tokenKeyId.length !== PUBLIC_BEARER_TOKEN_KEY_ID_LEN) {
    throw new Error("token_key_id must be 32 bytes");
  }
  return bytesToHex2(tokenKeyId);
}
function tokenKeyIdFromHex(tokenKeyIdHex) {
  if (!/^[0-9a-f]{64}$/.test(tokenKeyIdHex)) {
    throw new Error("token_key_id must be 64 lowercase hex characters");
  }
  return hexToBytes(tokenKeyIdHex);
}
function buildPublicBearerMessage(nonce, tokenKeyId, issuerId) {
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  if (nonce.length !== PUBLIC_BEARER_NONCE_LEN)
    throw new Error("nonce must be 32 bytes");
  if (tokenKeyId.length !== PUBLIC_BEARER_TOKEN_KEY_ID_LEN) {
    throw new Error("token_key_id must be 32 bytes");
  }
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) {
    throw new Error("issuer_id must be 1-255 bytes");
  }
  return sha384(concatBytes2(
    new TextEncoder().encode("freebird:public-bearer-pass:v5"),
    new Uint8Array([0]),
    new Uint8Array([REDEMPTION_TOKEN_VERSION_V5]),
    nonce,
    tokenKeyId,
    new Uint8Array([issuerIdBytes.length]),
    issuerIdBytes
  ));
}
function buildPublicBearerPass(nonce, tokenKeyId, issuerId, signature) {
  const issuerIdBytes = new TextEncoder().encode(issuerId);
  if (nonce.length !== PUBLIC_BEARER_NONCE_LEN)
    throw new Error("nonce must be 32 bytes");
  if (tokenKeyId.length !== PUBLIC_BEARER_TOKEN_KEY_ID_LEN) {
    throw new Error("token_key_id must be 32 bytes");
  }
  if (issuerIdBytes.length === 0 || issuerIdBytes.length > 255) {
    throw new Error("issuer_id must be 1-255 bytes");
  }
  if (signature.length === 0 || signature.length > PUBLIC_BEARER_MAX_SIGNATURE_LEN) {
    throw new Error("invalid signature length");
  }
  const buf = new Uint8Array(1 + 32 + 32 + 1 + issuerIdBytes.length + 2 + signature.length);
  let pos = 0;
  buf[pos++] = REDEMPTION_TOKEN_VERSION_V5;
  buf.set(nonce, pos);
  pos += 32;
  buf.set(tokenKeyId, pos);
  pos += 32;
  buf[pos++] = issuerIdBytes.length;
  buf.set(issuerIdBytes, pos);
  pos += issuerIdBytes.length;
  buf[pos++] = signature.length >> 8 & 255;
  buf[pos++] = signature.length & 255;
  buf.set(signature, pos);
  return buf;
}
function parsePublicBearerPass(bytes) {
  if (bytes.length < 69 || bytes.length > 835)
    throw new Error("invalid token length");
  if (bytes[0] !== REDEMPTION_TOKEN_VERSION_V5)
    throw new Error("unsupported token version");
  let pos = 1;
  const nonce = bytes.slice(pos, pos + 32);
  pos += 32;
  const tokenKeyId = bytes.slice(pos, pos + 32);
  pos += 32;
  const issuerIdLen = bytes[pos++];
  if (issuerIdLen === 0 || pos + issuerIdLen > bytes.length) {
    throw new Error("invalid issuer_id_len");
  }
  const issuerId = new TextDecoder().decode(bytes.slice(pos, pos + issuerIdLen));
  pos += issuerIdLen;
  if (pos + 2 > bytes.length)
    throw new Error("invalid signature length");
  const sigLen = bytes[pos++] << 8 | bytes[pos++];
  if (sigLen === 0 || sigLen > PUBLIC_BEARER_MAX_SIGNATURE_LEN || pos + sigLen !== bytes.length) {
    throw new Error("invalid signature length");
  }
  const signature = bytes.slice(pos, pos + sigLen);
  return { nonce, tokenKeyId, issuerId, signature };
}
function verifyDleq(G, Y, A2, B2, proofBytes, context) {
  const cBytes = proofBytes.slice(0, 32);
  const sBytes = proofBytes.slice(32, 64);
  const c = bytesToNumber(cBytes);
  const s = bytesToNumber(sBytes);
  const sG = multiply(G, s);
  const cY = multiply(Y, c);
  const t1 = sG.subtract(cY);
  const sA = multiply(A2, s);
  const cB = multiply(B2, c);
  const t2 = sA.subtract(cB);
  const dst = concatBytes2(DLEQ_DST_PREFIX, context);
  const dstLenBytes = numberToBytesBE(dst.length, 4);
  const transcript = concatBytes2(
    dstLenBytes,
    dst,
    encodePoint(G),
    encodePoint(Y),
    encodePoint(A2),
    encodePoint(B2),
    encodePoint(t1),
    encodePoint(t2)
  );
  const computedC = hashToScalar(transcript);
  return c === computedC;
}
function base64UrlToBytes(base64) {
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, "=");
  const binString = atob(padded);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}
function bytesToNumber(bytes) {
  return BigInt("0x" + bytesToHex2(bytes));
}
function numberToBytesBE(num, len) {
  const hex2 = num.toString(16).padStart(len * 2, "0");
  return hexToBytes(hex2);
}
function hashToScalar(bytes) {
  const hash = sha2562(bytes);
  const num = bytesToNumber(hash);
  return num % p2562.CURVE.n;
}

// src/errors.ts
var FreebirdError = class extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.name = "FreebirdError";
    this.code = code;
  }
};
var DiscoveryError = class extends FreebirdError {
  constructor(message = "Failed to load issuer or verifier discovery metadata") {
    super("discovery", message);
    this.name = "DiscoveryError";
  }
};
var VerificationError = class extends FreebirdError {
  constructor(message = "Token verification failed", code = "verification") {
    super(code, message);
    this.name = "VerificationError";
  }
};
var VerifierNotConfiguredError = class extends FreebirdError {
  constructor(message = "Verifier is not configured") {
    super("verifier_not_configured", message);
    this.name = "VerifierNotConfiguredError";
  }
};
var ExchangeError = class extends FreebirdError {
  outcome;
  constructor(message = "Exchange operation failed", outcome) {
    super("exchange", message);
    this.name = "ExchangeError";
    this.outcome = outcome;
  }
};
var GraphIssuanceError = class extends FreebirdError {
  outcome;
  constructor(message = "Graph issuance failed", outcome) {
    super("graph_issuance", message);
    this.name = "GraphIssuanceError";
    this.outcome = outcome;
  }
};
var RateLimitedError = class extends FreebirdError {
  retryAfter;
  constructor(retryAfter, message = "Rate limited") {
    super("rate_limited", message);
    this.name = "RateLimitedError";
    this.retryAfter = retryAfter;
  }
};
var VerifierUnavailableError = class extends FreebirdError {
  constructor(message = "Verifier is unavailable") {
    super("verifier_unavailable", message);
    this.name = "VerifierUnavailableError";
  }
};
var InvalidTokenError = class extends VerificationError {
  constructor(message = "Token is invalid") {
    super(message, "invalid_token");
    this.name = "InvalidTokenError";
  }
};
var ReplayedTokenError = class extends VerificationError {
  constructor(message = "Token has already been used") {
    super(message, "replayed_token");
    this.name = "ReplayedTokenError";
  }
};
var PollError = class extends FreebirdError {
  constructor(message = "Polling operation failed") {
    super("poll", message);
    this.name = "PollError";
  }
};
var PollTimeoutError = class extends PollError {
  constructor(message = "Polling timed out") {
    super(message);
    this.name = "PollTimeoutError";
  }
};
var PollAbortedError = class extends PollError {
  constructor(message = "Polling was aborted") {
    super(message);
    this.name = "PollAbortedError";
  }
};
var BatchIssuanceError = class extends FreebirdError {
  results;
  tokens;
  failed;
  constructor(results, tokens) {
    super("issuance", "One or more tokens in the batch failed to issue");
    this.name = "BatchIssuanceError";
    this.results = results;
    this.tokens = tokens;
    this.failed = results.filter((result) => result.status === "error").length;
  }
};

// src/client/wire.ts
import { sha256 as sha2563 } from "@noble/hashes/sha256";
function ascii(value) {
  return new TextEncoder().encode(value);
}
function concatBytes3(...values) {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}
function base64UrlToBytes2(b64) {
  const normalized = b64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++)
    bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function bytesEqual(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function domainHex(domain, value) {
  return hex(sha2563(concatBytes3(ascii(domain), value)));
}
function isLowerHexId(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
function isSafeUnsigned(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function isSafePositive(value) {
  return isSafeUnsigned(value) && value > 0;
}
function isBoundedAscii(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[\x00-\x7F]+$/.test(value);
}
function isCanonicalBase64Url(value, exactBytes, maxBytes, minBytes = 0) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value))
    return false;
  if (maxBytes !== void 0 && value.length > Math.ceil(maxBytes / 3) * 4)
    return false;
  try {
    const decoded = base64UrlToBytes2(value);
    return bytesToBase64Url(decoded) === value && (exactBytes === void 0 || decoded.length === exactBytes) && (maxBytes === void 0 || decoded.length <= maxBytes) && decoded.length >= minBytes;
  } catch {
    return false;
  }
}
function decodeCanonical(value, exactBytes, maxBytes, minBytes = 0) {
  if (!isCanonicalBase64Url(value, exactBytes, maxBytes, minBytes)) {
    throw new Error("Invalid canonical base64url");
  }
  return base64UrlToBytes2(value);
}
function hasExactKeys(value, keys) {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const actualKeys = Object.keys(value);
  return actualKeys.length === keys.length && keys.every((key) => actualKeys.includes(key));
}
function put(output, value) {
  pushU32(output, value.length);
  output.push(...value);
}
function pushU32(output, value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 4294967295) {
    throw new Error("Integer is outside the V2 exchange wire range");
  }
  output.push(value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255);
}
function pushU64(output, value) {
  if (!isSafeUnsigned(value))
    throw new Error("Invalid V2 exchange integer");
  let integer = BigInt(value);
  const bytes = new Array(8);
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(integer & 0xffn);
    integer >>= 8n;
  }
  output.push(...bytes);
}
function pushI64(output, value) {
  if (!Number.isSafeInteger(value))
    throw new Error("Invalid V2 exchange integer");
  let integer = BigInt.asUintN(64, BigInt(value));
  const bytes = new Array(8);
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(integer & 0xffn);
    integer >>= 8n;
  }
  output.push(...bytes);
}

// src/client/discovery.ts
async function init(state) {
  if (state.metadata && state.verifierMetadata)
    return;
  if (!state.metadata) {
    const url = `${state.config.issuerUrl}/.well-known/issuer`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new DiscoveryError("Failed to fetch issuer metadata");
    }
    state.metadata = await res.json();
  }
  if (!state.verifierMetadata) {
    if (state.config.verifierUrl) {
      const url = `${state.config.verifierUrl}/.well-known/verifier`;
      const res = await fetch(url);
      if (!res.ok) {
        throw new DiscoveryError("Failed to fetch verifier metadata");
      }
      state.verifierMetadata = await res.json();
    } else if (state.config.verifierId && state.config.audience) {
      state.verifierMetadata = {
        verifier_id: state.config.verifierId,
        audience: state.config.audience,
        scope_digest_b64: bytesToBase64Url(
          buildScopeDigest(state.config.verifierId, state.config.audience)
        )
      };
    } else {
      throw new VerifierNotConfiguredError("Verifier scope required: configure verifierUrl or verifierId+audience");
    }
  }
}
async function getKeyDiscoveryMetadata(state) {
  if (state.keyDiscoveryMetadata && isKeyDiscoveryFresh(state)) {
    return state.keyDiscoveryMetadata;
  }
  return fetchKeyDiscoveryMetadata(state);
}
async function refreshKeyDiscoveryMetadata(state) {
  return fetchKeyDiscoveryMetadata(state);
}
function isKeyDiscoveryFresh(state) {
  if (!state.keyDiscoveryMetadata || state.keyDiscoveryMetadataFetchedAt === null)
    return false;
  const ttlMs = state.config.keyCacheTtlMs ?? state.keyDiscoveryMetadata.epoch_duration_sec * 1e3;
  return Date.now() - state.keyDiscoveryMetadataFetchedAt < ttlMs;
}
async function fetchKeyDiscoveryMetadata(state) {
  const url = `${state.config.issuerUrl}/.well-known/keys`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new DiscoveryError("Failed to fetch issuer key metadata");
  }
  const metadata = await res.json();
  if (metadata.exchange !== void 0) {
    await validateExchangeDiscovery(metadata.issuer_id, metadata.exchange);
  }
  if (metadata.graph_issuance !== void 0) {
    if (!metadata.exchange)
      throw new DiscoveryError("Invalid graph issuance discovery metadata");
    validateGraphIssuanceDiscovery(metadata.graph_issuance, metadata.exchange);
  }
  state.keyDiscoveryMetadata = metadata;
  state.keyDiscoveryMetadataFetchedAt = Date.now();
  return state.keyDiscoveryMetadata;
}
async function selectExchangeTransition(getMetadata, graphId, transitionId) {
  const metadata = await getMetadata();
  if (!metadata.exchange)
    throw new DiscoveryError("Issuer does not publish V2 exchange discovery");
  const graph = [metadata.exchange.active_graph, ...metadata.exchange.retained_graphs].find((candidate) => candidate.graph_id === graphId);
  const transition = graph?.transitions.find((candidate) => candidate.transition_id === transitionId);
  if (!graph || !transition)
    throw new DiscoveryError("Unknown exchange graph or transition");
  return { graph, transition };
}
function validateGraphIssuanceDiscovery(issuance, exchange2) {
  const invalid = () => {
    throw new DiscoveryError("Invalid graph issuance discovery metadata");
  };
  if (!hasExactKeys(issuance, ["version", "policies", "replay_authority"]) || issuance.version !== 2 || !Array.isArray(issuance.policies) || issuance.policies.length > 64 || !hasExactKeys(issuance.replay_authority, ["authority_id", "v4_scope_digest_tombstones"]) || !isCanonicalBase64Url(issuance.replay_authority.authority_id, 32) || !Array.isArray(issuance.replay_authority.v4_scope_digest_tombstones) || issuance.replay_authority.v4_scope_digest_tombstones.length > 64)
    invalid();
  const tombstones = /* @__PURE__ */ new Set();
  for (const tombstone of issuance.replay_authority.v4_scope_digest_tombstones) {
    if (!isCanonicalBase64Url(tombstone, 32) || tombstones.has(tombstone))
      invalid();
    tombstones.add(tombstone);
  }
  const ids = /* @__PURE__ */ new Set();
  const budgets = /* @__PURE__ */ new Set();
  for (const policy of issuance.policies) {
    if (typeof policy !== "object" || policy === null || Array.isArray(policy))
      invalid();
    const policyKeys = Object.prototype.hasOwnProperty.call(policy, "authorization_scope_digest_b64") ? [
      "issuance_policy_id",
      "graph_id",
      "keyset_id",
      "descriptor_id",
      "budget_id",
      "budget_limit",
      "quantity",
      "admission_state",
      "authorization_scheme",
      "authorization_scope_digest_b64"
    ] : [
      "issuance_policy_id",
      "graph_id",
      "keyset_id",
      "descriptor_id",
      "budget_id",
      "budget_limit",
      "quantity",
      "admission_state",
      "authorization_scheme"
    ];
    if (!hasExactKeys(policy, policyKeys) || !isBoundedAscii(policy.issuance_policy_id) || !isLowerHexId(policy.graph_id) || !isLowerHexId(policy.keyset_id) || !isLowerHexId(policy.descriptor_id) || !isBoundedAscii(policy.budget_id) || !isSafePositive(policy.budget_limit) || !isSafePositive(policy.quantity) || policy.quantity !== 1 || policy.quantity > policy.budget_limit || !["accepting_new", "recovery_only", "disabled"].includes(policy.admission_state) || !isBoundedAscii(policy.authorization_scheme) || !["hmac_sha256", "v4_local", "development_mock"].includes(policy.authorization_scheme) || ids.has(policy.issuance_policy_id) || budgets.has(policy.budget_id))
      invalid();
    const active = exchange2.active_graph.graph_id === policy.graph_id;
    const graph = [exchange2.active_graph, ...exchange2.retained_graphs].find((candidate) => candidate.graph_id === policy.graph_id);
    const keyset = graph?.keysets.find((candidate) => candidate.keyset_id === policy.keyset_id);
    if (!keyset?.descriptor_ids.includes(policy.descriptor_id) || policy.admission_state === "accepting_new" && !active)
      invalid();
    if (policy.authorization_scheme === "v4_local") {
      if (typeof policy.authorization_scope_digest_b64 !== "string" || !isCanonicalBase64Url(policy.authorization_scope_digest_b64, 32) || !tombstones.has(policy.authorization_scope_digest_b64))
        invalid();
    } else if (policy.authorization_scope_digest_b64 !== void 0)
      invalid();
    ids.add(policy.issuance_policy_id);
    budgets.add(policy.budget_id);
  }
}
async function validateExchangeDiscovery(issuerId, discovery) {
  const invalid = () => {
    throw new DiscoveryError("Invalid V2 exchange discovery metadata");
  };
  if (!hasExactKeys(discovery, [
    "active_graph",
    "retained_graphs",
    "active_receipt_key",
    "retained_receipt_keys"
  ]) || !Array.isArray(discovery.retained_graphs) || !Array.isArray(discovery.retained_receipt_keys) || discovery.retained_graphs.length >= 64 || discovery.retained_receipt_keys.length >= 64)
    invalid();
  const graphs = [discovery.active_graph, ...discovery.retained_graphs];
  const graphIds = /* @__PURE__ */ new Set();
  const descriptorContracts = /* @__PURE__ */ new Map();
  const budgetContracts = /* @__PURE__ */ new Map();
  for (let graphIndex = 0; graphIndex < graphs.length; graphIndex++) {
    const graph = graphs[graphIndex];
    const retained = graphIndex > 0;
    if (!hasExactKeys(graph, ["profile_id", "graph_id", "descriptors", "keysets", "transitions"]) || graph.profile_id !== "freebird/public-bearer-exchange/v2" || !Array.isArray(graph.descriptors) || !Array.isArray(graph.keysets) || !Array.isArray(graph.transitions) || graph.descriptors.length === 0 || graph.descriptors.length > 64 || graph.keysets.length === 0 || graph.keysets.length > 64 || graph.transitions.length === 0 || graph.transitions.length > 64 || !isLowerHexId(graph.graph_id) || graphIds.has(graph.graph_id))
      invalid();
    graphIds.add(graph.graph_id);
    const descriptors = /* @__PURE__ */ new Map();
    const graphTokenKeys = /* @__PURE__ */ new Set();
    for (const descriptor of graph.descriptors) {
      const descriptorKeys = Object.prototype.hasOwnProperty.call(descriptor, "audience") ? [
        "descriptor_id",
        "profile_id",
        "issuer_id",
        "token_key_id",
        "audience",
        "pubkey_spki_b64",
        "suite",
        "valid_from",
        "valid_until"
      ] : [
        "descriptor_id",
        "profile_id",
        "issuer_id",
        "token_key_id",
        "pubkey_spki_b64",
        "suite",
        "valid_from",
        "valid_until"
      ];
      if (!hasExactKeys(descriptor, descriptorKeys) || !isLowerHexId(descriptor.descriptor_id) || descriptor.profile_id !== graph.profile_id || descriptor.issuer_id !== issuerId || !isLowerHexId(descriptor.token_key_id) || descriptor.suite !== "RSABSSA-SHA384-PSS-Deterministic" || !isSafePositive(descriptor.valid_from) || !isSafePositive(descriptor.valid_until) || descriptor.valid_from >= descriptor.valid_until || descriptor.audience !== void 0 && !isBoundedAscii(descriptor.audience) || descriptors.has(descriptor.descriptor_id) || graphTokenKeys.has(descriptor.token_key_id))
        invalid();
      const spki = decodeCanonical(descriptor.pubkey_spki_b64, void 0, 4096, 1);
      if (hex(sha2564(spki)) !== descriptor.token_key_id)
        invalid();
      const pssOid = [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 10];
      if (spki.length > 800 || spki.length <= 72 || !pssOid.every((byte, index) => spki[index + 6] === byte) || spki[17] !== 48)
        invalid();
      try {
        const rawOffset = spki[5] + 10;
        if (spki.length <= rawOffset)
          invalid();
        const raw = spki.slice(rawOffset);
        const standardHeader = new Uint8Array([
          48,
          130,
          0,
          0,
          48,
          13,
          6,
          9,
          42,
          134,
          72,
          134,
          247,
          13,
          1,
          1,
          1,
          5,
          0,
          3,
          130,
          0,
          0
        ]);
        standardHeader[2] = raw.length + 19 >>> 8;
        standardHeader[3] = raw.length + 19 & 255;
        standardHeader[21] = raw.length >>> 8;
        standardHeader[22] = raw.length & 255;
        const standardSpki = new Uint8Array(standardHeader.length + raw.length);
        standardSpki.set(standardHeader);
        standardSpki.set(raw, standardHeader.length);
        const publicKey = await crypto.subtle.importKey(
          "spki",
          new Uint8Array(standardSpki).buffer,
          { name: "RSA-PSS", hash: "SHA-384" },
          false,
          ["verify"]
        );
        const algorithm = publicKey.algorithm;
        const exponent = Array.from(algorithm.publicExponent).reduce((value, byte) => value * 256 + byte, 0);
        if (algorithm.modulusLength < 2048 || algorithm.modulusLength > 4096 || exponent !== 3 && exponent !== 65537)
          invalid();
      } catch {
        invalid();
      }
      if (domainHex("freebird exchange descriptor v2\0", descriptorBytes(descriptor)) !== descriptor.descriptor_id)
        invalid();
      const contract = bytesToBase64Url(descriptorBytes(descriptor));
      const previous = descriptorContracts.get(descriptor.token_key_id);
      if (previous !== void 0 && previous !== contract)
        invalid();
      descriptorContracts.set(descriptor.token_key_id, contract);
      descriptors.set(descriptor.descriptor_id, descriptor);
      graphTokenKeys.add(descriptor.token_key_id);
    }
    const keysets = /* @__PURE__ */ new Map();
    const memberships = /* @__PURE__ */ new Set();
    for (const keyset of graph.keysets) {
      if (!hasExactKeys(keyset, ["keyset_id", "descriptor_ids"]) || !isLowerHexId(keyset.keyset_id) || !Array.isArray(keyset.descriptor_ids) || keyset.descriptor_ids.length === 0 || keyset.descriptor_ids.length > 64 || keysets.has(keyset.keyset_id))
        invalid();
      const members = /* @__PURE__ */ new Set();
      for (const descriptorId of keyset.descriptor_ids) {
        if (typeof descriptorId !== "string" || !descriptors.has(descriptorId) || members.has(descriptorId) || memberships.has(descriptorId))
          invalid();
        members.add(descriptorId);
        memberships.add(descriptorId);
      }
      const keysetBytes = [];
      for (const descriptorId of keyset.descriptor_ids)
        put(keysetBytes, ascii(descriptorId));
      if (domainHex("freebird exchange keyset v2\0", new Uint8Array(keysetBytes)) !== keyset.keyset_id)
        invalid();
      keysets.set(keyset.keyset_id, members);
    }
    if (memberships.size !== descriptors.size)
      invalid();
    const transitionIds = /* @__PURE__ */ new Set();
    const graphBudgetIds = /* @__PURE__ */ new Set();
    for (const transition of graph.transitions) {
      if (!hasExactKeys(transition, [
        "transition_id",
        "source_keyset_id",
        "target_keyset_id",
        "source_slots",
        "output_slots",
        "budget_id",
        "budget_limit",
        "admission_state"
      ]) || !isLowerHexId(transition.transition_id) || !isLowerHexId(transition.source_keyset_id) || !isLowerHexId(transition.target_keyset_id) || transition.source_keyset_id === transition.target_keyset_id || !keysets.has(transition.source_keyset_id) || !keysets.has(transition.target_keyset_id) || !isBoundedAscii(transition.budget_id) || !isSafePositive(transition.budget_limit) || !["accepting_new", "recovery_only", "disabled"].includes(transition.admission_state) || retained && transition.admission_state === "accepting_new" || transitionIds.has(transition.transition_id) || graphBudgetIds.has(transition.budget_id))
        invalid();
      validateDiscoverySlots(transition.source_slots, keysets.get(transition.source_keyset_id));
      validateDiscoverySlots(transition.output_slots, keysets.get(transition.target_keyset_id));
      const stable = transitionBytes(transition);
      if (domainHex("freebird exchange transition v2\0", stable) !== transition.transition_id)
        invalid();
      const contract = bytesToBase64Url(stable);
      const previous = budgetContracts.get(transition.budget_id);
      if (previous !== void 0 && previous !== contract)
        invalid();
      budgetContracts.set(transition.budget_id, contract);
      transitionIds.add(transition.transition_id);
      graphBudgetIds.add(transition.budget_id);
      const outputQuantity = transition.output_slots.reduce((sum, slot) => sum + slot.quantity, 0);
      if (!Number.isSafeInteger(outputQuantity) || outputQuantity > transition.budget_limit)
        invalid();
    }
    const graphBytes = [];
    put(graphBytes, ascii(graph.profile_id));
    for (const keyset of graph.keysets)
      put(graphBytes, ascii(keyset.keyset_id));
    for (const transition of graph.transitions)
      put(graphBytes, ascii(transition.transition_id));
    if (domainHex("freebird exchange graph v2\0", new Uint8Array(graphBytes)) !== graph.graph_id)
      invalid();
  }
  const receiptIds = /* @__PURE__ */ new Set();
  validateReceiptDiscoveryKey(discovery.active_receipt_key, "exchange_receipt_active", receiptIds);
  for (const key of discovery.retained_receipt_keys) {
    validateReceiptDiscoveryKey(key, "exchange_receipt_retained", receiptIds);
  }
}
function validateDiscoverySlots(value, members) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new DiscoveryError("Invalid V2 exchange discovery metadata");
  }
  const slotIds = /* @__PURE__ */ new Set();
  const descriptorIds = /* @__PURE__ */ new Set();
  for (const slot of value) {
    if (!hasExactKeys(slot, ["descriptor_id", "slot_id", "class", "quantity"]) || typeof slot.descriptor_id !== "string" || !isLowerHexId(slot.descriptor_id) || typeof slot.slot_id !== "string" || !isBoundedAscii(slot.slot_id) || typeof slot.class !== "string" || !isBoundedAscii(slot.class) || !isSafePositive(slot.quantity) || slot.quantity > 64 || !members.has(slot.descriptor_id) || slotIds.has(slot.slot_id) || descriptorIds.has(slot.descriptor_id)) {
      throw new DiscoveryError("Invalid V2 exchange discovery metadata");
    }
    slotIds.add(slot.slot_id);
    descriptorIds.add(slot.descriptor_id);
  }
}
function validateReceiptDiscoveryKey(key, purpose, ids) {
  if (!hasExactKeys(key, [
    "key_id",
    "algorithm",
    "purpose",
    "public_key_b64",
    "valid_from",
    "valid_until"
  ]) || !isLowerHexId(key.key_id) || key.algorithm !== "Ed25519" || key.purpose !== purpose || !isSafePositive(key.valid_from) || !isSafePositive(key.valid_until) || key.valid_from >= key.valid_until || ids.has(key.key_id)) {
    throw new DiscoveryError("Invalid V2 exchange discovery metadata");
  }
  const publicKey = decodeCanonical(key.public_key_b64, 32);
  if (!ed25519.utils.isValidPublicKey(publicKey, false) || hex(sha2564(publicKey)) !== key.key_id) {
    throw new DiscoveryError("Invalid V2 exchange discovery metadata");
  }
  ids.add(key.key_id);
}
function descriptorBytes(descriptor) {
  const output = [];
  for (const value of [
    descriptor.profile_id,
    descriptor.issuer_id,
    descriptor.token_key_id,
    descriptor.suite
  ])
    put(output, ascii(value));
  if (descriptor.audience === void 0) {
    output.push(0);
    put(output, new Uint8Array());
  } else {
    output.push(1);
    put(output, ascii(descriptor.audience));
  }
  put(output, decodeCanonical(descriptor.pubkey_spki_b64, void 0, 4096, 1));
  pushI64(output, descriptor.valid_from);
  pushI64(output, descriptor.valid_until);
  return new Uint8Array(output);
}
function transitionBytes(transition) {
  const output = [];
  put(output, ascii(transition.source_keyset_id));
  put(output, ascii(transition.target_keyset_id));
  for (const slots of [transition.source_slots, transition.output_slots]) {
    pushU32(output, slots.length);
    for (const slot of slots) {
      put(output, ascii(slot.descriptor_id));
      put(output, ascii(slot.slot_id));
      put(output, ascii(slot.class));
      pushU32(output, slot.quantity);
    }
  }
  put(output, ascii(transition.budget_id));
  pushU64(output, transition.budget_limit);
  return new Uint8Array(output);
}

// src/client/exchange.ts
import { sha256 as sha2565 } from "@noble/hashes/sha256";
import { ed25519 as ed255192 } from "@noble/curves/ed25519";
function validateExchangeOperationId(operationId) {
  if (!/^[A-Za-z0-9_-]{22}$/.test(operationId)) {
    throw new ExchangeError("Exchange operation ID must be canonical base64url for exactly 16 bytes");
  }
  let decoded;
  try {
    decoded = base64UrlToBytes2(operationId);
  } catch {
    throw new ExchangeError("Exchange operation ID must be canonical base64url for exactly 16 bytes");
  }
  if (decoded.length !== 16 || bytesToBase64Url(decoded) !== operationId) {
    throw new ExchangeError("Exchange operation ID must be canonical base64url for exactly 16 bytes");
  }
}
function validateStatusCapability(capability) {
  if (!isCanonicalBase64Url(capability, 32)) {
    throw new ExchangeError("Exchange status capability must be canonical base64url for exactly 32 bytes");
  }
}
function isExchangeSlot(value) {
  return hasExactKeys(value, ["descriptor_id", "keyset_id", "slot_id", "quantity"]) && typeof value.descriptor_id === "string" && isLowerHexId(value.descriptor_id) && typeof value.keyset_id === "string" && isLowerHexId(value.keyset_id) && typeof value.slot_id === "string" && value.slot_id.length > 0 && value.slot_id.length <= 128 && /^[\x00-\x7F]+$/.test(value.slot_id) && typeof value.quantity === "number" && Number.isSafeInteger(value.quantity) && value.quantity > 0 && value.quantity <= 4294967295;
}
function v2SelectorBytes(value) {
  if (value.version !== 2 || !isCanonicalBase64Url(value.public_operation_id, 16) || !isLowerHexId(value.graph_id) || !isLowerHexId(value.transition_id) || !isLowerHexId(value.source_keyset_id) || !isLowerHexId(value.target_keyset_id) || value.source_keyset_id === value.target_keyset_id) {
    throw new ExchangeError("Invalid V2 exchange selectors");
  }
  const output = [2];
  put(output, base64UrlToBytes2(value.public_operation_id));
  for (const field of [
    value.graph_id,
    value.transition_id,
    value.source_keyset_id,
    value.target_keyset_id
  ])
    put(output, ascii(field));
  return new Uint8Array(output);
}
function slotBytes(slot) {
  const output = [];
  put(output, ascii(slot.descriptor_id));
  put(output, ascii(slot.keyset_id));
  put(output, ascii(slot.slot_id));
  pushU32(output, slot.quantity);
  return output;
}
function requestBytes(request) {
  if (!hasExactKeys(request, [
    "version",
    "public_operation_id",
    "graph_id",
    "transition_id",
    "source_keyset_id",
    "target_keyset_id",
    "sources",
    "outputs"
  ]))
    throw new ExchangeError("Invalid V2 exchange request");
  const output = [...v2SelectorBytes(request)];
  if (!Array.isArray(request.sources) || !Array.isArray(request.outputs) || request.sources.length === 0 || request.sources.length > 64 || request.outputs.length === 0 || request.outputs.length > 64) {
    throw new ExchangeError("Invalid V2 exchange request");
  }
  pushU32(output, request.sources.length);
  for (const source of request.sources) {
    if (!hasExactKeys(source, ["slot", "artifact"]) || !isExchangeSlot(source.slot) || source.slot.keyset_id !== request.source_keyset_id || typeof source.artifact !== "string") {
      throw new ExchangeError("Invalid V2 exchange request");
    }
    const artifact = decodeCanonical(source.artifact, void 0, 16 * 1024, 1);
    output.push(...slotBytes(source.slot));
    put(output, artifact);
  }
  pushU32(output, request.outputs.length);
  for (const requestedOutput of request.outputs) {
    if (!hasExactKeys(requestedOutput, ["slot", "blinded_value"]) || !isExchangeSlot(requestedOutput.slot) || requestedOutput.slot.keyset_id !== request.target_keyset_id || typeof requestedOutput.blinded_value !== "string") {
      throw new ExchangeError("Invalid V2 exchange request");
    }
    const blinded = decodeCanonical(requestedOutput.blinded_value, void 0, 16 * 1024, 1);
    output.push(...slotBytes(requestedOutput.slot));
    put(output, blinded);
  }
  return new Uint8Array(output);
}
function resultBytes(result) {
  const output = [...v2SelectorBytes(result)];
  pushU32(output, result.outputs.length);
  for (const item of result.outputs) {
    output.push(...slotBytes(item.slot));
    put(output, decodeCanonical(item.blinded_value, void 0, 16 * 1024, 1));
    put(output, decodeCanonical(item.blind_signature, void 0, 512, 1));
  }
  return new Uint8Array(output);
}
function receiptPayload(receipt) {
  const output = [...v2SelectorBytes(receipt)];
  put(output, decodeCanonical(receipt.result_digest, 32));
  pushU64(output, receipt.created_at);
  pushU64(output, receipt.expires_at);
  put(output, ascii(receipt.receipt_key_id));
  return new Uint8Array(output);
}
async function exchange(state, request, statusCapability, selectTransition, digest) {
  validateStatusCapability(statusCapability);
  const selection = await validateExchangeRequestSelection(request, selectTransition);
  digest(request);
  const response = await fetch(`${state.config.issuerUrl}/v2/public/exchange`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "exchange-status-capability": statusCapability
    },
    body: JSON.stringify(request)
  });
  return parseExchangeResponse(state, response, request, selection.graph);
}
async function getExchangeStatus(state, publicOperationIdOrRequest, statusCapability, request, selectTransition, digest) {
  const submittedRequest = typeof publicOperationIdOrRequest === "string" ? request : publicOperationIdOrRequest;
  const publicOperationId = typeof publicOperationIdOrRequest === "string" ? publicOperationIdOrRequest : publicOperationIdOrRequest.public_operation_id;
  if (!submittedRequest)
    throw new ExchangeError("Original exchange request is required for status");
  validateExchangeOperationId(publicOperationId);
  validateStatusCapability(statusCapability);
  if (submittedRequest.public_operation_id !== publicOperationId) {
    throw new ExchangeError("Exchange status request does not match the submitted request");
  }
  const selection = await validateExchangeRequestSelection(submittedRequest, selectTransition);
  digest(submittedRequest);
  const url = `${state.config.issuerUrl}/v2/public/exchange/status?public_operation_id=${encodeURIComponent(publicOperationId)}`;
  const response = await fetch(url, {
    method: "GET",
    headers: { "exchange-status-capability": statusCapability }
  });
  return parseExchangeResponse(state, response, submittedRequest, selection.graph);
}
function exchangeRequestDigest(request) {
  return bytesToBase64Url(sha2565(new Uint8Array([
    ...ascii("freebird exchange request v2\0"),
    ...requestBytes(request)
  ])));
}
async function validateExchangeRequestSelection(request, selectTransition) {
  requestBytes(request);
  const selection = await selectTransition(request.graph_id, request.transition_id);
  const transition = selection.transition;
  if (transition.source_keyset_id !== request.source_keyset_id || transition.target_keyset_id !== request.target_keyset_id || request.sources.length !== transition.source_slots.length || request.outputs.length !== transition.output_slots.length) {
    throw new ExchangeError("Exchange request does not match the selected transition");
  }
  const slotsMatch = (actual, expected, keysetId) => actual.descriptor_id === expected.descriptor_id && actual.keyset_id === keysetId && actual.slot_id === expected.slot_id && actual.quantity === expected.quantity;
  if (!request.sources.every((source, index) => slotsMatch(source.slot, transition.source_slots[index], request.source_keyset_id)) || !request.outputs.every((output, index) => slotsMatch(output.slot, transition.output_slots[index], request.target_keyset_id))) {
    throw new ExchangeError("Exchange request does not match the selected transition");
  }
  return selection;
}
async function parseExchangeResponse(state, response, submittedRequest, selectedGraph) {
  const cacheControl = response.headers.get("Cache-Control");
  if (!cacheControl?.split(",").some((value) => value.trim().toLowerCase() === "no-store")) {
    throw new ExchangeError("Exchange response did not enforce Cache-Control: no-store");
  }
  const rawResponseBody = await response.text();
  let body;
  try {
    body = JSON.parse(rawResponseBody);
  } catch {
    throw new ExchangeError("Exchange endpoint returned malformed JSON");
  }
  if (response.status === 200) {
    if (!await isExchangeSuccessResponse(state, body, submittedRequest, selectedGraph)) {
      throw new ExchangeError("Exchange endpoint returned malformed success JSON");
    }
    return {
      kind: "committed",
      httpStatus: 200,
      response: body,
      rawResponseBody,
      cacheControl: "no-store"
    };
  }
  if (response.status === 202) {
    if (!hasExactKeys(body, ["error"]) || body.error !== "exchange_retryable") {
      throw new ExchangeError("Exchange endpoint returned malformed pending JSON");
    }
    const retryAfterHeader = response.headers.get("Retry-After");
    if (!retryAfterHeader || !/^(0|[1-9][0-9]*)$/.test(retryAfterHeader)) {
      throw new ExchangeError("Exchange pending response has invalid Retry-After");
    }
    return {
      kind: "pending",
      httpStatus: 202,
      response: { error: "exchange_retryable" },
      retryAfter: Number(retryAfterHeader),
      rawResponseBody,
      cacheControl: "no-store"
    };
  }
  if (!hasExactKeys(body, ["error"]) || !isExchangeErrorCode(body.error)) {
    throw new ExchangeError("Exchange endpoint returned malformed error JSON");
  }
  if (response.status === 403 && body.error === "status_unauthorized") {
    throw new ExchangeError("Exchange status capability was not authorized");
  }
  const common = { rawResponseBody, cacheControl: "no-store" };
  if (response.status === 400 && (body.error === "invalid_status_capability" || body.error === "invalid_public_operation_id" || body.error === "invalid_exchange_request" || body.error === "invalid_exchange")) {
    return { ...common, kind: "error", httpStatus: 400, response: { error: body.error } };
  }
  if (response.status === 413 && body.error === "exchange_request_too_large") {
    return { ...common, kind: "error", httpStatus: 413, response: { error: "exchange_request_too_large" } };
  }
  if (response.status === 404 && body.error === "unknown_operation") {
    return { ...common, kind: "error", httpStatus: 404, response: { error: "unknown_operation" } };
  }
  if (response.status === 409 && body.error === "operation_conflict") {
    return { ...common, kind: "error", httpStatus: 409, response: { error: "operation_conflict" } };
  }
  if (response.status === 503 && body.error === "exchange_unavailable") {
    return { ...common, kind: "error", httpStatus: 503, response: { error: "exchange_unavailable" } };
  }
  throw new ExchangeError("Exchange endpoint returned an unexpected error status");
}
async function isExchangeSuccessResponse(state, value, submittedRequest, selectedGraph) {
  if (!hasExactKeys(value, ["result", "receipt"]))
    return false;
  const { result, receipt } = value;
  if (!hasExactKeys(result, [
    "version",
    "public_operation_id",
    "graph_id",
    "transition_id",
    "source_keyset_id",
    "target_keyset_id",
    "outputs",
    "result_digest"
  ]) || result.version !== 2 || typeof result.public_operation_id !== "string" || typeof result.graph_id !== "string" || typeof result.transition_id !== "string" || typeof result.source_keyset_id !== "string" || typeof result.target_keyset_id !== "string" || typeof result.result_digest !== "string" || !Array.isArray(result.outputs) || result.outputs.length === 0 || result.outputs.length > 64 || result.outputs.length !== submittedRequest.outputs.length)
    return false;
  if (!result.outputs.every((output, index) => isExchangeResultOutput(output, submittedRequest.outputs[index], result.target_keyset_id)))
    return false;
  if (!isCanonicalBase64Url(result.public_operation_id, 16) || result.public_operation_id !== submittedRequest.public_operation_id || result.graph_id !== submittedRequest.graph_id || result.transition_id !== submittedRequest.transition_id || result.source_keyset_id !== submittedRequest.source_keyset_id || result.target_keyset_id !== submittedRequest.target_keyset_id || !isLowerHexId(result.graph_id) || !isLowerHexId(result.transition_id) || !isLowerHexId(result.source_keyset_id) || !isLowerHexId(result.target_keyset_id) || !isCanonicalBase64Url(result.result_digest, 32))
    return false;
  const calculatedResultDigest = bytesToBase64Url(
    sha2565(new Uint8Array([
      ...ascii("freebird exchange result v2\0"),
      ...resultBytes(result)
    ]))
  );
  if (calculatedResultDigest !== result.result_digest)
    return false;
  if (!hasExactKeys(receipt, [
    "version",
    "public_operation_id",
    "graph_id",
    "transition_id",
    "source_keyset_id",
    "target_keyset_id",
    "result_digest",
    "created_at",
    "expires_at",
    "receipt_key_id",
    "signature"
  ]) || receipt.version !== 2 || typeof receipt.public_operation_id !== "string" || typeof receipt.graph_id !== "string" || typeof receipt.transition_id !== "string" || typeof receipt.source_keyset_id !== "string" || typeof receipt.target_keyset_id !== "string" || typeof receipt.result_digest !== "string" || !isSafeUnsigned(receipt.created_at) || !isSafeUnsigned(receipt.expires_at) || receipt.expires_at <= receipt.created_at || typeof receipt.receipt_key_id !== "string" || typeof receipt.signature !== "string" || !isCanonicalBase64Url(receipt.public_operation_id, 16) || !isLowerHexId(receipt.graph_id) || !isLowerHexId(receipt.transition_id) || !isLowerHexId(receipt.source_keyset_id) || !isLowerHexId(receipt.target_keyset_id) || !isCanonicalBase64Url(receipt.result_digest, 32) || !isLowerHexId(receipt.receipt_key_id) || !isCanonicalBase64Url(receipt.signature, 64))
    return false;
  for (const field of [
    "public_operation_id",
    "graph_id",
    "transition_id",
    "source_keyset_id",
    "target_keyset_id",
    "result_digest"
  ])
    if (receipt[field] !== result[field])
      return false;
  const receiptKeys = state.keyDiscoveryMetadata?.exchange ? [
    state.keyDiscoveryMetadata.exchange.active_receipt_key,
    ...state.keyDiscoveryMetadata.exchange.retained_receipt_keys
  ] : [];
  const receiptKey = receiptKeys.find((key) => key.key_id === receipt.receipt_key_id);
  if (!receiptKey || receipt.created_at < receiptKey.valid_from || receipt.expires_at > receiptKey.valid_until)
    return false;
  const receiptDigest = sha2565(new Uint8Array([
    ...ascii("freebird exchange receipt v2\0"),
    ...receiptPayload(receipt)
  ]));
  try {
    return ed255192.verify(
      base64UrlToBytes2(receipt.signature),
      receiptDigest,
      base64UrlToBytes2(receiptKey.public_key_b64),
      { zip215: false }
    ) && selectedGraph.graph_id === result.graph_id;
  } catch {
    return false;
  }
}
function isExchangeResultOutput(value, submitted, targetKeysetId) {
  return hasExactKeys(value, ["slot", "blinded_value", "blind_signature"]) && isExchangeSlot(value.slot) && value.slot.descriptor_id === submitted.slot.descriptor_id && value.slot.keyset_id === submitted.slot.keyset_id && value.slot.keyset_id === targetKeysetId && value.slot.slot_id === submitted.slot.slot_id && value.slot.quantity === submitted.slot.quantity && typeof value.blinded_value === "string" && value.blinded_value === submitted.blinded_value && isCanonicalBase64Url(value.blinded_value, void 0, 16 * 1024) && typeof value.blind_signature === "string" && isCanonicalBase64Url(value.blind_signature, void 0, 512, 1);
}
function isExchangeErrorCode(value) {
  return typeof value === "string" && [
    "invalid_status_capability",
    "invalid_public_operation_id",
    "exchange_request_too_large",
    "exchange_unavailable",
    "invalid_exchange_request",
    "operation_conflict",
    "invalid_exchange",
    "unknown_operation",
    "status_unauthorized"
  ].includes(value);
}

// src/client/graph_protocol.ts
import { sha256 as sha2566 } from "@noble/hashes/sha256";
function validateGraphStatusCapability(capability) {
  if (!isCanonicalBase64Url(capability, 32)) {
    throw new Error("Graph issuance status capability must be canonical base64url for exactly 32 bytes");
  }
}
function graphIssuanceRequestBytes(request, includeAuthorization) {
  if (!hasExactKeys(request, [
    "version",
    "public_operation_id",
    "issuance_policy_id",
    "graph_id",
    "keyset_id",
    "descriptor_id",
    "blinded_message",
    "authorization"
  ]) || request.version !== 2 || !isCanonicalBase64Url(request.public_operation_id, 16) || !isBoundedAscii(request.issuance_policy_id) || !isLowerHexId(request.graph_id) || !isLowerHexId(request.keyset_id) || !isLowerHexId(request.descriptor_id) || typeof request.blinded_message !== "string" || typeof request.authorization !== "string") {
    throw new Error("Invalid graph issuance request");
  }
  const output = [2];
  put(output, decodeCanonical(request.public_operation_id, 16));
  for (const selector of [
    request.issuance_policy_id,
    request.graph_id,
    request.keyset_id,
    request.descriptor_id
  ])
    put(output, ascii(selector));
  put(output, decodeCanonical(request.blinded_message, void 0, 512, 1));
  if (includeAuthorization)
    put(output, decodeCanonical(request.authorization, void 0, 16 * 1024, 1));
  return new Uint8Array(output);
}
function graphResultBytes(value) {
  const output = [2];
  put(output, decodeCanonical(value.public_operation_id, 16));
  for (const selector of [
    value.issuance_policy_id,
    value.graph_id,
    value.keyset_id,
    value.descriptor_id,
    value.token_key_id
  ])
    put(output, ascii(selector));
  pushU32(output, value.quantity);
  put(output, decodeCanonical(value.request_digest, 32));
  put(output, decodeCanonical(value.blind_signature, void 0, 512, 1));
  return new Uint8Array(output);
}
function graphIssuanceRequestDigest(request) {
  return bytesToBase64Url(sha2566(new Uint8Array([
    ...ascii("freebird graph blind issuance request v2\0"),
    ...graphIssuanceRequestBytes(request, true)
  ])));
}
function graphIssuanceAuthorizationBindingDigest(request) {
  return bytesToBase64Url(sha2566(new Uint8Array([
    ...ascii("freebird graph blind issuance authorization binding v2\0"),
    ...graphIssuanceRequestBytes(request, false)
  ])));
}
async function parseGraphIssuanceResponse(response, request, expectedTokenKeyId, digest) {
  const cacheControl = response.headers.get("Cache-Control");
  if (!cacheControl?.split(",").some((value) => value.trim().toLowerCase() === "no-store")) {
    throw new Error("Graph issuance response did not enforce Cache-Control: no-store");
  }
  const rawResponseBody = await response.text();
  let body;
  try {
    body = JSON.parse(rawResponseBody);
  } catch {
    throw new Error("Graph issuance endpoint returned malformed JSON");
  }
  if (response.status === 200) {
    if (!isGraphIssuanceResult(body, request, expectedTokenKeyId, digest)) {
      throw new Error("Graph issuance endpoint returned malformed success JSON");
    }
    return { kind: "committed", httpStatus: 200, response: body, rawResponseBody, cacheControl: "no-store" };
  }
  if (!hasExactKeys(body, ["error"]) || !isGraphIssuanceErrorCode(body.error)) {
    throw new Error("Graph issuance endpoint returned malformed error JSON");
  }
  if (response.status === 403 && body.error === "status_unauthorized") {
    throw new Error("Graph issuance status capability was not authorized");
  }
  if (![400, 404, 409, 413, 503].includes(response.status) || response.status === 400 && ![
    "invalid_status_capability",
    "invalid_public_operation_id",
    "invalid_graph_issuance_request",
    "invalid_graph_issuance"
  ].includes(body.error) || response.status === 404 && body.error !== "unknown_operation" || response.status === 409 && body.error !== "operation_conflict" || response.status === 413 && body.error !== "graph_issuance_request_too_large" || response.status === 503 && body.error !== "graph_issuance_unavailable") {
    throw new Error("Graph issuance endpoint returned an unexpected error status");
  }
  return {
    kind: "error",
    httpStatus: response.status,
    response: { error: body.error },
    rawResponseBody,
    cacheControl: "no-store"
  };
}
function isGraphIssuanceErrorCode(value) {
  return typeof value === "string" && [
    "invalid_status_capability",
    "invalid_public_operation_id",
    "graph_issuance_request_too_large",
    "invalid_graph_issuance_request",
    "invalid_graph_issuance",
    "operation_conflict",
    "unknown_operation",
    "graph_issuance_unavailable",
    "status_unauthorized"
  ].includes(value);
}
function isGraphIssuanceResult(value, request, expectedTokenKeyId, digest) {
  if (!hasExactKeys(value, [
    "version",
    "public_operation_id",
    "issuance_policy_id",
    "graph_id",
    "keyset_id",
    "descriptor_id",
    "token_key_id",
    "quantity",
    "request_digest",
    "blind_signature",
    "result_digest"
  ]) || value.version !== 2 || typeof value.public_operation_id !== "string" || typeof value.issuance_policy_id !== "string" || typeof value.graph_id !== "string" || typeof value.keyset_id !== "string" || typeof value.descriptor_id !== "string" || typeof value.token_key_id !== "string" || typeof value.quantity !== "number" || typeof value.request_digest !== "string" || typeof value.blind_signature !== "string" || typeof value.result_digest !== "string" || value.public_operation_id !== request.public_operation_id || value.issuance_policy_id !== request.issuance_policy_id || value.graph_id !== request.graph_id || value.keyset_id !== request.keyset_id || value.descriptor_id !== request.descriptor_id || !isLowerHexId(value.graph_id) || !isLowerHexId(value.keyset_id) || !isLowerHexId(value.descriptor_id) || !isLowerHexId(value.token_key_id) || value.token_key_id !== expectedTokenKeyId || value.quantity !== 1 || !isCanonicalBase64Url(value.public_operation_id, 16) || !isCanonicalBase64Url(value.request_digest, 32) || !isCanonicalBase64Url(value.blind_signature, void 0, 512, 1) || !isCanonicalBase64Url(value.result_digest, 32))
    return false;
  if (value.request_digest !== digest(request))
    return false;
  const resultDigest = bytesToBase64Url(sha2566(new Uint8Array([
    ...ascii("freebird graph blind issuance result v2\0"),
    ...graphResultBytes(value)
  ])));
  return resultDigest === value.result_digest;
}

// src/client/graph_issuance.ts
async function selectGraphIssuancePolicy(state, policyId) {
  const metadata = await refreshKeyDiscoveryMetadata(state);
  const policy = metadata.graph_issuance?.policies.find(
    (candidate) => candidate.issuance_policy_id === policyId
  );
  if (!policy)
    throw new GraphIssuanceError("Unknown graph issuance policy");
  if (policy.admission_state !== "accepting_new" || policy.graph_id !== metadata.exchange?.active_graph.graph_id) {
    throw new GraphIssuanceError("Graph issuance policy is not accepting new issuance");
  }
  graphIssuanceTokenKeyId(metadata.exchange, policy.graph_id, policy.keyset_id, policy.descriptor_id);
  return policy;
}
async function issueGraphBlindSignature(state, request, statusCapability, selectPolicy, digest) {
  validateGraphStatusCapability(statusCapability);
  const selection = await validateGraphIssuanceRequestSelection(
    state,
    request,
    selectPolicy
  );
  digest(request);
  const response = await fetch(`${state.config.issuerUrl}/v1/public/graph/issue`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "graph-issuance-status-capability": statusCapability
    },
    body: JSON.stringify(request)
  });
  return parseGraphIssuanceResponse(response, request, selection.tokenKeyId, digest);
}
async function validateGraphIssuanceRequestSelection(state, request, selectPolicy) {
  graphIssuanceRequestBytes(request, true);
  const policy = await selectPolicy(request.issuance_policy_id);
  if (policy.admission_state !== "accepting_new" || policy.graph_id !== request.graph_id || policy.keyset_id !== request.keyset_id || policy.descriptor_id !== request.descriptor_id) {
    throw new GraphIssuanceError("Graph issuance request does not match the selected active policy");
  }
  return {
    policy,
    tokenKeyId: graphIssuanceTokenKeyId(
      state.keyDiscoveryMetadata?.exchange,
      request.graph_id,
      request.keyset_id,
      request.descriptor_id
    )
  };
}
function graphIssuanceTokenKeyId(exchange2, graphId, keysetId, descriptorId) {
  const graph = exchange2 && [exchange2.active_graph, ...exchange2.retained_graphs].find((candidate) => candidate.graph_id === graphId);
  const keyset = graph?.keysets.find((candidate) => candidate.keyset_id === keysetId);
  if (!keyset || !keyset.descriptor_ids.includes(descriptorId)) {
    throw new GraphIssuanceError("Graph issuance selection has no valid token key");
  }
  const tokenKeyId = graph?.descriptors.find(
    (candidate) => candidate.descriptor_id === descriptorId
  )?.token_key_id;
  if (!tokenKeyId)
    throw new GraphIssuanceError("Graph issuance selection has no valid token key");
  return tokenKeyId;
}

// src/client/graph_recovery.ts
async function createGraphIssuanceRecoveryContext(request, statusCapability, expectedTokenKeyId, blindingState, digest) {
  validateGraphIssuanceRequest(request);
  validateGraphStatusCapability(statusCapability);
  if (!isLowerHexId(expectedTokenKeyId))
    throw new GraphIssuanceError("Invalid graph issuance token key ID");
  if (blindingState === void 0 || blindingState === null) {
    throw new GraphIssuanceError("Graph issuance blinding state is required for recovery");
  }
  return {
    request,
    requestDigest: digest(request),
    publicOperationId: request.public_operation_id,
    issuancePolicyId: request.issuance_policy_id,
    graphId: request.graph_id,
    keysetId: request.keyset_id,
    descriptorId: request.descriptor_id,
    statusCapability,
    expectedTokenKeyId,
    blindingState
  };
}
async function retryGraphBlindSignature(state, context, digest) {
  const recovery = graphIssuanceRecovery(context, digest);
  const response = await fetch(`${state.config.issuerUrl}/v1/public/graph/issue`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "graph-issuance-status-capability": recovery.statusCapability
    },
    body: JSON.stringify(recovery.request)
  });
  return parseGraphIssuanceResponse(
    response,
    recovery.request,
    recovery.expectedTokenKeyId,
    digest
  );
}
async function getGraphIssuanceStatus(state, context, digest) {
  const recovery = graphIssuanceRecovery(context, digest);
  const url = `${state.config.issuerUrl}/v1/public/graph/issue/status?public_operation_id=${encodeURIComponent(recovery.request.public_operation_id)}`;
  const response = await fetch(url, {
    method: "GET",
    headers: { "graph-issuance-status-capability": recovery.statusCapability }
  });
  return parseGraphIssuanceResponse(
    response,
    recovery.request,
    recovery.expectedTokenKeyId,
    digest
  );
}
function validateGraphIssuanceRequest(request) {
  graphIssuanceRequestBytes(request, true);
}
var RECOVERY_CONTEXT_SERIALIZATION_VERSION = 1;
var RECOVERY_CONTEXT_TYPE = "graph_issuance_recovery_context";
function serializeGraphIssuanceRecoveryContext(context) {
  return JSON.stringify({
    version: RECOVERY_CONTEXT_SERIALIZATION_VERSION,
    type: RECOVERY_CONTEXT_TYPE,
    context
  });
}
function deserializeGraphIssuanceRecoveryContext(serialized) {
  let parsed;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new GraphIssuanceError("Invalid graph issuance recovery context serialization");
  }
  if (typeof parsed !== "object" || parsed === null || !hasExactKeys(parsed, ["version", "type", "context"]) || parsed.version !== RECOVERY_CONTEXT_SERIALIZATION_VERSION || parsed.type !== RECOVERY_CONTEXT_TYPE) {
    throw new GraphIssuanceError("Invalid graph issuance recovery context serialization");
  }
  const context = parsed.context;
  if (typeof context !== "object" || context === null || !hasExactKeys(context, [
    "request",
    "requestDigest",
    "publicOperationId",
    "issuancePolicyId",
    "graphId",
    "keysetId",
    "descriptorId",
    "statusCapability",
    "expectedTokenKeyId",
    "blindingState"
  ])) {
    throw new GraphIssuanceError("Invalid graph issuance recovery context serialization");
  }
  return context;
}
function graphIssuanceRecovery(context, digest) {
  if (typeof context !== "object" || context === null || !hasExactKeys(context, [
    "request",
    "requestDigest",
    "publicOperationId",
    "issuancePolicyId",
    "graphId",
    "keysetId",
    "descriptorId",
    "statusCapability",
    "expectedTokenKeyId",
    "blindingState"
  ])) {
    throw new GraphIssuanceError("Invalid graph issuance recovery context");
  }
  if (context.blindingState === void 0 || context.blindingState === null || !isLowerHexId(context.expectedTokenKeyId)) {
    throw new GraphIssuanceError("Invalid graph issuance recovery context");
  }
  validateGraphIssuanceRequest(context.request);
  if (!isCanonicalBase64Url(context.requestDigest, 32) || context.requestDigest !== digest(context.request) || !isCanonicalBase64Url(context.publicOperationId, 16) || context.publicOperationId !== context.request.public_operation_id || context.issuancePolicyId !== context.request.issuance_policy_id || context.graphId !== context.request.graph_id || context.keysetId !== context.request.keyset_id || context.descriptorId !== context.request.descriptor_id) {
    throw new GraphIssuanceError("Invalid graph issuance recovery context");
  }
  validateGraphStatusCapability(context.statusCapability);
  return context;
}

// src/crypto/rsa.ts
import { RSABSSA } from "@cloudflare/blindrsa-ts";
var suite = RSABSSA.SHA384.PSS.Deterministic();
async function importRsaPssPublicKey(spki) {
  const rawOffset = spki[5] + 10;
  if (spki.length <= rawOffset)
    throw new Error("Invalid RSA public key");
  const raw = spki.slice(rawOffset);
  const standardHeader = new Uint8Array([
    48,
    130,
    0,
    0,
    48,
    13,
    6,
    9,
    42,
    134,
    72,
    134,
    247,
    13,
    1,
    1,
    1,
    5,
    0,
    3,
    130,
    0,
    0
  ]);
  standardHeader[2] = raw.length + 19 >>> 8;
  standardHeader[3] = raw.length + 19 & 255;
  standardHeader[21] = raw.length >>> 8;
  standardHeader[22] = raw.length & 255;
  const standardSpki = new Uint8Array(standardHeader.length + raw.length);
  standardSpki.set(standardHeader);
  standardSpki.set(raw, standardHeader.length);
  return crypto.subtle.importKey(
    "spki",
    standardSpki.buffer,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["verify"]
  );
}
async function rsaBlind(publicKey, msg) {
  const key = await importRsaPssPublicKey(publicKey);
  const prepared = suite.prepare(msg);
  const { blindedMsg, inv } = await suite.blind(key, prepared);
  return { blinded: blindedMsg, state: { inv, prepared, publicKey } };
}
async function rsaUnblind(state, blindSignature) {
  const key = await importRsaPssPublicKey(state.publicKey);
  return suite.finalize(key, state.prepared, blindSignature, state.inv);
}
async function rsaVerify(publicKey, msg, signature) {
  const key = await importRsaPssPublicKey(publicKey);
  const prepared = suite.prepare(msg);
  return crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 48 },
    key,
    signature.buffer,
    prepared.buffer
  );
}

// src/client/sybil.ts
import { sha256 as sha2567 } from "@noble/hashes/sha256";
var MAX_POW_DIFFICULTY = 32;
var DEFAULT_YIELD_EVERY = 1e3;
function u64Le(value) {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, value >>> 0, true);
  view.setUint32(4, Math.floor(value / 4294967296), true);
  return bytes;
}
function hashPow(input, nonce, timestamp) {
  return sha2567(concatBytes3(
    new TextEncoder().encode(input),
    u64Le(nonce),
    u64Le(timestamp)
  ));
}
function verifyPow(input, nonce, timestamp, difficulty) {
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 256)
    return false;
  const hash = hashPow(input, nonce, timestamp);
  const requiredZeros = Math.floor(difficulty / 8);
  const remainingBits = difficulty % 8;
  for (let i = 0; i < requiredZeros; i++) {
    if (hash[i] !== 0)
      return false;
  }
  if (remainingBits > 0) {
    const mask = 255 << 8 - remainingBits;
    if ((hash[requiredZeros] & mask) !== 0)
      return false;
  }
  return true;
}
async function generateProofOfWork(input, difficulty, opts = {}) {
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > MAX_POW_DIFFICULTY) {
    throw new Error(`difficulty must be an integer in [1, ${MAX_POW_DIFFICULTY}]`);
  }
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1e3);
  const yieldEvery = opts.yieldEvery ?? DEFAULT_YIELD_EVERY;
  const requiredZeros = Math.floor(difficulty / 8);
  const remainingBits = difficulty % 8;
  const mask = remainingBits > 0 ? 255 << 8 - remainingBits : 0;
  let nonce = 0;
  for (; ; ) {
    const hash = hashPow(input, nonce, timestamp);
    let ok = true;
    for (let i = 0; i < requiredZeros; i++) {
      if (hash[i] !== 0) {
        ok = false;
        break;
      }
    }
    if (ok && (remainingBits === 0 || (hash[requiredZeros] & mask) === 0)) {
      return { type: "proof_of_work", nonce, input, timestamp };
    }
    nonce++;
    if (nonce % yieldEvery === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    if (nonce >= Number.MAX_SAFE_INTEGER) {
      throw new Error("exhausted nonce space");
    }
  }
}
function buildIssueBinding(issuerId, blindedElementB64) {
  return `freebird:issue:v1:${issuerId}:${blindedElementB64}`;
}
function buildPublicIssueBinding(issuerId, blindedMsgB64) {
  return `freebird:public-issue:v1:${issuerId}:${blindedMsgB64}`;
}
function buildRenewBinding(issuerId, blindedElementB64) {
  return `freebird:renew:v1:${issuerId}:${blindedElementB64}`;
}
function buildBatchBinding(routeScope, issuerId, blindedElements) {
  const hasher = sha2567.create();
  for (const element of blindedElements) {
    hasher.update(u64Le(element.length));
    hasher.update(new TextEncoder().encode(element));
  }
  const digest = hasher.digest();
  return `freebird:${routeScope}:v1:${issuerId}:${blindedElements.length}:${bytesToBase64Url(digest.slice(0, 16))}`;
}
function resolvePowDifficulty(state) {
  const sybil = state.metadata?.sybil;
  if (sybil && (sybil.mode === "pow" || sybil.mode === "proof_of_work")) {
    const settings = sybil.settings;
    if (typeof settings.difficulty === "number" && settings.difficulty > 0) {
      return settings.difficulty;
    }
  }
  if (typeof state.config.powDifficulty === "number" && state.config.powDifficulty > 0) {
    return state.config.powDifficulty;
  }
  return void 0;
}
async function resolveSybilProof(state, provided, binding) {
  if (provided !== void 0)
    return provided;
  const difficulty = resolvePowDifficulty(state);
  if (difficulty === void 0)
    return void 0;
  return generateProofOfWork(binding, difficulty);
}

// src/client/issuance.ts
var MAX_BATCH_SIZE = 1e4;
function chunk(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}
function chunkPairs(a, b, size) {
  const pairs = [];
  for (let i = 0; i < a.length; i += size) {
    pairs.push({ msgs: a.slice(i, i + size), nonces: b.slice(i, i + size) });
  }
  return pairs;
}
async function issueToken(state, sybilProof, initialize, refreshKeyDiscovery) {
  if (!state.metadata)
    await initialize();
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const scopeDigest = base64UrlToBytes2(state.verifierMetadata.scope_digest_b64);
  const expectedScopeDigest = buildScopeDigest(
    state.verifierMetadata.verifier_id,
    state.verifierMetadata.audience
  );
  if (!bytesEqual(scopeDigest, expectedScopeDigest)) {
    throw new DiscoveryError("Verifier scope metadata is inconsistent");
  }
  let refreshed = false;
  for (; ; ) {
    const input = buildPrivateTokenInput(
      state.metadata.issuer_id,
      state.metadata.voprf.kid,
      nonce,
      scopeDigest
    );
    const { blinded, state: blindState } = blind(input, state.context);
    const blinded_element_b64 = bytesToBase64Url(blinded);
    const binding = buildIssueBinding(state.metadata.issuer_id, blinded_element_b64);
    const effectiveProof = await resolveSybilProof(state, sybilProof, binding);
    const reqBody = {
      blinded_element_b64,
      sybil_proof: effectiveProof
    };
    const res = await fetch(`${state.config.issuerUrl}/v1/oprf/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reqBody)
    });
    if (!res.ok) {
      if (res.status === 400 || res.status === 401 || res.status === 403) {
        throw new FreebirdError("issuance", "Issuer rejected the request");
      }
      throw new FreebirdError("issuance", "Token issuance failed");
    }
    const resp = await res.json();
    if (resp.kid === state.metadata.voprf.kid && resp.issuer_id === state.metadata.issuer_id) {
      const output = finalize(
        blindState,
        resp.token,
        state.metadata.voprf.pubkey,
        state.context
      );
      const redemptionToken = buildRedemptionToken(
        nonce,
        scopeDigest,
        resp.kid,
        resp.issuer_id,
        output
      );
      return {
        tokenValue: bytesToBase64Url(redemptionToken),
        issuerId: resp.issuer_id,
        version: 4,
        kid: resp.kid
      };
    }
    if (refreshed) {
      throw new DiscoveryError("Issuer metadata changed during issuance");
    }
    refreshed = true;
    const refreshedMetadata = await refreshKeyDiscovery();
    state.metadata.voprf.kid = refreshedMetadata.voprf.kid;
    state.metadata.voprf.pubkey = refreshedMetadata.voprf.pubkey;
  }
}
async function issuePublicBlindSignature(state, blindedMsg, sybilProof, tokenKeyId, getDiscovery, refreshKeyDiscovery) {
  const blinded_msg_b64 = typeof blindedMsg === "string" ? blindedMsg : bytesToBase64Url(blindedMsg);
  const powDifficulty = resolvePowDifficulty(state);
  let refreshed = false;
  for (; ; ) {
    const needsDiscovery = tokenKeyId === void 0 || powDifficulty !== void 0;
    const discovery = needsDiscovery ? await getDiscovery() : void 0;
    const issuerId = discovery?.issuer_id ?? state.metadata?.issuer_id;
    const requestedKeyId = tokenKeyId ?? discovery?.public.find(
      (key) => key.token_type === "public_bearer_pass" && key.rfc9474_variant === "RSABSSA-SHA384-PSS-Deterministic" && key.spend_policy === "single_use"
    )?.token_key_id;
    if (!requestedKeyId)
      throw new DiscoveryError("No V5 public bearer key is available");
    let effectiveProof = sybilProof;
    if (effectiveProof === void 0 && powDifficulty !== void 0) {
      if (issuerId === void 0)
        throw new DiscoveryError("Issuer metadata is unavailable");
      effectiveProof = await generateProofOfWork(
        buildPublicIssueBinding(issuerId, blinded_msg_b64),
        powDifficulty
      );
    }
    const res = await fetch(`${state.config.issuerUrl}/v1/public/issue`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blinded_msg_b64, token_key_id: requestedKeyId, sybil_proof: effectiveProof })
    });
    if (!res.ok) {
      throw new FreebirdError("issuance", "Public bearer issuance failed");
    }
    const resp = await res.json();
    if (resp.token_key_id === requestedKeyId) {
      return resp;
    }
    if (refreshed) {
      throw new DiscoveryError("Issuer metadata changed during public issuance");
    }
    refreshed = true;
    await refreshKeyDiscovery();
  }
}
async function issueTokens(state, msgs, opts, initialize, refreshKeyDiscovery) {
  if (!state.metadata)
    await initialize();
  const scopeDigest = base64UrlToBytes2(state.verifierMetadata.scope_digest_b64);
  const expectedScopeDigest = buildScopeDigest(
    state.verifierMetadata.verifier_id,
    state.verifierMetadata.audience
  );
  if (!bytesEqual(scopeDigest, expectedScopeDigest)) {
    throw new DiscoveryError("Verifier scope metadata is inconsistent");
  }
  let refreshed = false;
  for (; ; ) {
    const tokens = [];
    const results = [];
    let kidMismatch = false;
    for (const chunkMsgs of chunk(msgs, MAX_BATCH_SIZE)) {
      const blinded = chunkMsgs.map(() => {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const input = buildPrivateTokenInput(
          state.metadata.issuer_id,
          state.metadata.voprf.kid,
          nonce,
          scopeDigest
        );
        const { blinded: blinded2, state: blindState } = blind(input, state.context);
        return { blinded: bytesToBase64Url(blinded2), blindState, nonce };
      });
      const blindedElements = blinded.map((b) => b.blinded);
      const binding = buildBatchBinding("issue-batch", state.metadata.issuer_id, blindedElements);
      const effectiveProof = await resolveSybilProof(state, opts.sybilProof, binding);
      const reqBody = {
        blinded_elements: blindedElements,
        sybil_proof: effectiveProof
      };
      if (opts.ctxB64 !== void 0)
        reqBody.ctx_b64 = opts.ctxB64;
      const res = await fetch(`${state.config.issuerUrl}/v1/oprf/issue/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody)
      });
      if (!res.ok) {
        if (res.status === 400 || res.status === 401 || res.status === 403) {
          throw new FreebirdError("issuance", "Issuer rejected the batch request");
        }
        throw new FreebirdError("issuance", "Batch token issuance failed");
      }
      const resp = await res.json();
      if (resp.results.length !== blinded.length) {
        throw new FreebirdError("issuance", "Batch issuance response is malformed");
      }
      for (let i = 0; i < resp.results.length; i++) {
        const result = resp.results[i];
        if (result.status === "success") {
          if (result.kid !== state.metadata.voprf.kid || result.issuer_id !== state.metadata.issuer_id) {
            kidMismatch = true;
            break;
          }
          const output = finalize(
            blinded[i].blindState,
            result.token,
            state.metadata.voprf.pubkey,
            state.context
          );
          const redemptionToken = buildRedemptionToken(
            blinded[i].nonce,
            scopeDigest,
            result.kid,
            result.issuer_id,
            output
          );
          tokens.push({
            tokenValue: bytesToBase64Url(redemptionToken),
            issuerId: result.issuer_id,
            version: 4,
            kid: result.kid
          });
        }
        results.push(result);
      }
      if (kidMismatch)
        break;
    }
    if (!kidMismatch) {
      const failed = results.filter((r) => r.status === "error").length;
      if (failed > 0)
        throw new BatchIssuanceError(results, tokens);
      return tokens;
    }
    if (refreshed) {
      throw new DiscoveryError("Issuer metadata changed during batch issuance");
    }
    refreshed = true;
    const refreshedMetadata = await refreshKeyDiscovery();
    state.metadata.voprf.kid = refreshedMetadata.voprf.kid;
    state.metadata.voprf.pubkey = refreshedMetadata.voprf.pubkey;
  }
}
async function issuePublicTokens(state, msgs, opts, getDiscovery, refreshKeyDiscovery) {
  if (opts.nonces.length !== msgs.length) {
    throw new FreebirdError("issuance", "Nonces must be provided for each message");
  }
  let refreshed = false;
  for (; ; ) {
    const metadata = await getDiscovery();
    const requestedKeyId = opts.tokenKeyId ?? metadata.public.find(
      (key2) => key2.token_type === "public_bearer_pass" && key2.rfc9474_variant === "RSABSSA-SHA384-PSS-Deterministic" && key2.spend_policy === "single_use"
    )?.token_key_id;
    if (!requestedKeyId)
      throw new DiscoveryError("No V5 public bearer key is available");
    const key = metadata.public.find((candidate) => candidate.token_key_id === requestedKeyId);
    if (!key)
      throw new DiscoveryError("No V5 public bearer key is available");
    const passes = [];
    let mismatch = false;
    for (const { msgs: chunkMsgs, nonces: chunkNonces } of chunkPairs(
      msgs,
      opts.nonces,
      MAX_BATCH_SIZE
    )) {
      const blinded = [];
      for (let i = 0; i < chunkMsgs.length; i++) {
        const { blinded: b, state: blindState } = await rsaBlind(
          base64UrlToBytes2(key.pubkey_spki_b64),
          chunkMsgs[i]
        );
        blinded.push({ blinded: bytesToBase64Url(b), blindState });
      }
      const blindedMsgs = blinded.map((b) => b.blinded);
      const binding = buildBatchBinding("public-issue-batch", metadata.issuer_id, blindedMsgs);
      const effectiveProof = await resolveSybilProof(state, opts.sybilProof, binding);
      const reqBody = {
        blinded_msgs: blindedMsgs,
        token_key_id: requestedKeyId,
        sybil_proof: effectiveProof
      };
      const res = await fetch(`${state.config.issuerUrl}/v1/public/issue/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody)
      });
      if (!res.ok) {
        throw new FreebirdError("issuance", "Public bearer batch issuance failed");
      }
      const resp = await res.json();
      if (resp.token_key_id !== requestedKeyId) {
        mismatch = true;
        break;
      }
      if (resp.blind_signatures.length !== blinded.length) {
        throw new FreebirdError("issuance", "Public bearer batch response is malformed");
      }
      for (let i = 0; i < blinded.length; i++) {
        const signature = await rsaUnblind(
          blinded[i].blindState,
          base64UrlToBytes2(resp.blind_signatures[i])
        );
        passes.push(buildPublicBearerPass(
          chunkNonces[i],
          tokenKeyIdFromHex(requestedKeyId),
          opts.issuerId,
          signature
        ));
      }
    }
    if (!mismatch)
      return passes;
    if (refreshed) {
      throw new DiscoveryError("Issuer metadata changed during public batch issuance");
    }
    refreshed = true;
    await refreshKeyDiscovery();
  }
}

// src/client/poll.ts
var DEFAULT_INTERVAL_MS = 1e3;
var DEFAULT_TIMEOUT_MS = 6e4;
async function pollUntilTerminal(fetchStatus, options, shouldRetry, retryAfterOf) {
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const signal = options.signal;
  const deadline = Date.now() + timeoutMs;
  if (signal?.aborted)
    throw new PollAbortedError();
  for (; ; ) {
    const outcome = await fetchStatus();
    if (!shouldRetry(outcome))
      return outcome;
    const retryAfter = retryAfterOf(outcome);
    const floorMs = retryAfter !== void 0 ? retryAfter * 1e3 : 0;
    const delay = Math.max(intervalMs, floorMs);
    if (Date.now() + delay > deadline)
      throw new PollTimeoutError();
    await sleep(delay, signal);
  }
}
function pollExchangeStatus(fetchStatus, options = {}) {
  return pollUntilTerminal(
    fetchStatus,
    options,
    (outcome) => outcome.kind === "pending",
    (outcome) => outcome.kind === "pending" ? outcome.retryAfter : void 0
  );
}
function pollGraphIssuanceStatus(fetchStatus, options = {}) {
  return pollUntilTerminal(
    fetchStatus,
    options,
    (outcome) => outcome.kind === "error" && outcome.httpStatus === 503,
    () => void 0
  );
}
function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new PollAbortedError());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new PollAbortedError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

// src/client/protocol.ts
function generateOperationId() {
  return bytesToBase64Url(randomBytes(16));
}
function generateStatusCapability() {
  return bytesToBase64Url(randomBytes(32));
}
async function exchangePasses(sources, transition, opts = {}, selectTransition) {
  const selection = await selectTransition(transition.graphId, transition.transitionId);
  const { graph, transition: rule } = selection;
  if (sources.length !== rule.source_slots.length) {
    throw new ExchangeError("Exchange sources do not match the selected transition");
  }
  const messages = opts.messages ?? [];
  if (messages.length !== rule.output_slots.length) {
    throw new ExchangeError("Exchange output messages do not match the selected transition");
  }
  const sourceKeysetId = rule.source_keyset_id;
  const targetKeysetId = rule.target_keyset_id;
  const assembledSources = sources.map((source, index) => {
    const expected = rule.source_slots[index];
    if (source.slot.descriptor_id !== expected.descriptor_id || source.slot.keyset_id !== sourceKeysetId || source.slot.slot_id !== expected.slot_id || source.slot.quantity !== expected.quantity || !isCanonicalBase64Url(source.artifact, void 0, 16 * 1024, 1)) {
      throw new ExchangeError("Exchange sources do not match the selected transition");
    }
    return source;
  });
  const outputs = await Promise.all(rule.output_slots.map(async (slot, index) => {
    const descriptor = graph.descriptors.find(
      (candidate) => candidate.descriptor_id === slot.descriptor_id
    );
    if (!descriptor) {
      throw new ExchangeError("Exchange output descriptor is not in the selected graph");
    }
    const message = messages[index] ?? buildPublicBearerMessage(
      randomBytes(32),
      tokenKeyIdFromHex(descriptor.token_key_id),
      descriptor.issuer_id
    );
    const { blinded } = await rsaBlind(
      base64UrlToBytes2(descriptor.pubkey_spki_b64),
      message
    );
    return {
      slot: {
        descriptor_id: slot.descriptor_id,
        keyset_id: targetKeysetId,
        slot_id: slot.slot_id,
        quantity: slot.quantity
      },
      blinded_value: bytesToBase64Url(blinded)
    };
  }));
  return {
    version: 2,
    public_operation_id: opts.publicOperationId ?? generateOperationId(),
    graph_id: graph.graph_id,
    transition_id: rule.transition_id,
    source_keyset_id: sourceKeysetId,
    target_keyset_id: targetKeysetId,
    sources: assembledSources,
    outputs
  };
}
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

// src/client/state.ts
function createClientState(config) {
  return {
    config,
    metadata: null,
    keyDiscoveryMetadata: null,
    keyDiscoveryMetadataFetchedAt: null,
    verifierMetadata: null,
    context: new TextEncoder().encode("freebird:v4")
  };
}

// src/client/verification.ts
function requireVerifierUrl(state) {
  if (!state.config.verifierUrl)
    throw new VerifierNotConfiguredError();
  return state.config.verifierUrl;
}
function parseRetryAfter(res) {
  const header = res.headers.get("Retry-After");
  if (!header)
    return 0;
  const seconds = Number.parseInt(header, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : 0;
}
function throwForStatus(res) {
  switch (res.status) {
    case 400:
      throw new InvalidTokenError();
    case 401:
      throw new ReplayedTokenError();
    case 429:
      throw new RateLimitedError(parseRetryAfter(res));
    case 503:
      throw new VerifierUnavailableError();
    default:
      throw new VerificationError();
  }
}
async function verifyToken(state, token) {
  const verifierUrl = requireVerifierUrl(state);
  const res = await fetch(`${verifierUrl}/v1/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token_b64: token.tokenValue })
  });
  if (!res.ok)
    return throwForStatus(res);
  return await res.json();
}
async function checkToken(state, token) {
  const verifierUrl = requireVerifierUrl(state);
  const res = await fetch(`${verifierUrl}/v1/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token_b64: token.tokenValue })
  });
  if (!res.ok)
    return throwForStatus(res);
  return await res.json();
}
async function verifyBatch(state, tokens) {
  const verifierUrl = requireVerifierUrl(state);
  const body = {
    tokens: tokens.map((token) => ({ token_b64: token.tokenValue }))
  };
  const res = await fetch(`${verifierUrl}/v1/verify/batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok)
    return throwForStatus(res);
  return await res.json();
}
async function verifyTokenValid(state, token) {
  try {
    const resp = await verifyToken(state, token);
    return resp.ok === true;
  } catch (err) {
    if (err instanceof InvalidTokenError || err instanceof ReplayedTokenError) {
      return false;
    }
    throw err;
  }
}

// src/client.ts
var FreebirdClient = class {
  state;
  constructor(config) {
    this.state = createClientState(config);
  }
  /**
   * The optional {@link TokenStore} configured for this client, or `undefined`
   * if none was provided.
   */
  get tokenStore() {
    return this.state.config.tokenStore;
  }
  /** Initializes the client by fetching the issuer's public key. */
  async init() {
    return init(this.state);
  }
  /** Issues a new anonymous V4 token. */
  async issueToken(sybilProof) {
    return issueToken(
      this.state,
      sybilProof,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadata()
    );
  }
  /**
   * Issues a batch of anonymous V4 tokens.
   *
   * `msgs` determines how many tokens to issue (one per element; the element
   * content is not part of the V4 input). Inputs larger than 10_000 are
   * chunked into multiple requests. If any token fails, a
   * {@link BatchIssuanceError} is thrown carrying the per-token outcomes and
   * the successfully finalized tokens.
   */
  async issueTokens(msgs, opts = {}) {
    return issueTokens(
      this.state,
      msgs,
      opts,
      () => this.init(),
      () => this.refreshKeyDiscoveryMetadata()
    );
  }
  async getKeyDiscoveryMetadata() {
    return getKeyDiscoveryMetadata(this.state);
  }
  /**
   * Forces a fresh fetch of the issuer's `/.well-known/keys` discovery
   * metadata, bypassing the TTL-based cache. Useful for long-lived clients
   * that want to observe key rotation proactively.
   */
  async refreshKeyDiscoveryMetadata() {
    return refreshKeyDiscoveryMetadata(this.state);
  }
  /** Requests a V5 public bearer pass blind signature. */
  async issuePublicBlindSignature(blindedMsg, sybilProof, tokenKeyId) {
    return issuePublicBlindSignature(
      this.state,
      blindedMsg,
      sybilProof,
      tokenKeyId,
      () => this.getKeyDiscoveryMetadata(),
      () => this.refreshKeyDiscoveryMetadata()
    );
  }
  /**
   * Issues a complete V5 public bearer pass in one call.
   *
   * `msg` is the message to be blindly signed (typically the output of
   * `crypto.buildPublicBearerMessage(nonce, tokenKeyId, issuerId)`). The
   * caller supplies the nonce, token key ID, and issuer ID via `opts`, which
   * are also embedded in the returned pass.
   *
   * The blinding factor is held only in memory for the duration of the call
   * and is never persisted.
   */
  async issuePublicToken(msg, opts) {
    const { nonce, tokenKeyId, issuerId, sybilProof } = opts;
    const metadata = await this.getKeyDiscoveryMetadata();
    const key = metadata.public.find((candidate) => candidate.token_key_id === tokenKeyId);
    if (!key)
      throw new DiscoveryError("No V5 public bearer key is available");
    const { blinded, state } = await rsaBlind(base64UrlToBytes2(key.pubkey_spki_b64), msg);
    const resp = await issuePublicBlindSignature(
      this.state,
      blinded,
      sybilProof,
      tokenKeyId,
      () => this.getKeyDiscoveryMetadata(),
      () => this.refreshKeyDiscoveryMetadata()
    );
    if (resp.token_key_id !== tokenKeyId || resp.issuer_id !== issuerId) {
      throw new DiscoveryError("Issuer metadata changed during public issuance");
    }
    const signature = await rsaUnblind(
      state,
      base64UrlToBytes2(resp.blind_signature_b64)
    );
    return buildPublicBearerPass(nonce, tokenKeyIdFromHex(tokenKeyId), issuerId, signature);
  }
  /**
   * Issues a batch of V5 public bearer passes in one call.
   *
   * Each `msgs[i]` is the message to be blindly signed (typically the output of
   * `crypto.buildPublicBearerMessage(nonces[i], tokenKeyId, issuerId)`).
   * `opts.nonces[i]` and `opts.issuerId` are embedded in the returned pass.
   * Inputs larger than 10_000 are chunked into multiple requests.
   */
  async issuePublicTokens(msgs, opts) {
    return issuePublicTokens(
      this.state,
      msgs,
      opts,
      () => this.getKeyDiscoveryMetadata(),
      () => this.refreshKeyDiscoveryMetadata()
    );
  }
  /**
   * Locally verifies the RSA-PSS signature of a V5 public bearer pass against
   * the given public key.
   *
   * NOTE: local verification checks only cryptographic validity. It does NOT
   * check spend status (whether the pass has already been used). Only the
   * verifier's `/v1/verify` endpoint enforces single-use replay protection.
   */
  async verifyPublicBearerPassLocally(pass, keyInfo) {
    const { nonce, tokenKeyId, issuerId, signature } = parsePublicBearerPass(pass);
    const msg = buildPublicBearerMessage(nonce, tokenKeyId, issuerId);
    return rsaVerify(base64UrlToBytes2(keyInfo.pubkey_spki_b64), msg, signature);
  }
  /** Resolves an explicit immutable graph and transition selection. */
  async selectExchangeTransition(graphId, transitionId) {
    return selectExchangeTransition(
      () => this.getKeyDiscoveryMetadata(),
      graphId,
      transitionId
    );
  }
  /** Starts or exactly retries a V2 public bearer exchange operation. */
  async exchange(request, statusCapability) {
    return exchange(
      this.state,
      request,
      statusCapability,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId),
      (submittedRequest) => this.exchangeRequestDigest(submittedRequest)
    );
  }
  async getExchangeStatus(publicOperationIdOrRequest, statusCapability, request) {
    return getExchangeStatus(
      this.state,
      publicOperationIdOrRequest,
      statusCapability,
      request,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId),
      (submittedRequest) => this.exchangeRequestDigest(submittedRequest)
    );
  }
  exchangeRequestDigest(request) {
    return exchangeRequestDigest(request);
  }
  /** Generates a canonical 16-byte base64url exchange operation id. */
  generateOperationId() {
    return generateOperationId();
  }
  /** Generates a canonical 32-byte base64url exchange status capability. */
  generateStatusCapability() {
    return generateStatusCapability();
  }
  /**
   * Assembles a valid V2 `ExchangeRequest` from an explicit graph/transition
   * selection, blinding the output slots with the target descriptors' keys.
   */
  async exchangePasses(sources, transition, opts = {}) {
    return exchangePasses(
      sources,
      transition,
      opts,
      (graphId, transitionId) => this.selectExchangeTransition(graphId, transitionId)
    );
  }
  /** Resolves one current graph issuance policy. */
  async selectGraphIssuancePolicy(policyId) {
    return selectGraphIssuancePolicy(this.state, policyId);
  }
  /** Starts a fresh policy-authorized graph blind issuance operation. */
  async issueGraphBlindSignature(request, statusCapability) {
    return issueGraphBlindSignature(
      this.state,
      request,
      statusCapability,
      (policyId) => this.selectGraphIssuancePolicy(policyId),
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest)
    );
  }
  /** Retries an already-created graph issuance operation. */
  async retryGraphBlindSignature(context) {
    return retryGraphBlindSignature(
      this.state,
      context,
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest)
    );
  }
  /** Alias with the protocol name used by recovery callers. */
  async retryGraphIssuance(context) {
    return this.retryGraphBlindSignature(context);
  }
  /** Builds a complete context suitable for durable recovery. */
  async createGraphIssuanceRecoveryContext(request, statusCapability, expectedTokenKeyId, blindingState) {
    return createGraphIssuanceRecoveryContext(
      request,
      statusCapability,
      expectedTokenKeyId,
      blindingState,
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest)
    );
  }
  /** Observes a graph issuance result using persisted recovery context. */
  async getGraphIssuanceStatus(context) {
    return getGraphIssuanceStatus(
      this.state,
      context,
      (graphRequest) => this.graphIssuanceRequestDigest(graphRequest)
    );
  }
  /**
   * Polls an exchange operation until it is committed or fails terminally.
   *
   * Retries while the status is `pending`, honoring the server's `retryAfter`
   * as the floor for the next poll. Throws {@link PollTimeoutError} on
   * `timeoutMs` and {@link PollAbortedError} on `signal` abort.
   */
  async pollExchangeStatus(request, statusCapability, options = {}) {
    return pollExchangeStatus(
      () => this.getExchangeStatus(request, statusCapability),
      options
    );
  }
  /**
   * Polls a graph issuance operation until it is committed or fails
   * terminally. Retries on retryable 503 outcomes. Throws
   * {@link PollTimeoutError} on `timeoutMs` and {@link PollAbortedError} on
   * `signal` abort.
   */
  async pollGraphIssuanceStatus(context, options = {}) {
    return pollGraphIssuanceStatus(
      () => this.getGraphIssuanceStatus(context),
      options
    );
  }
  graphIssuanceRequestDigest(request) {
    return graphIssuanceRequestDigest(request);
  }
  graphIssuanceAuthorizationBindingDigest(request) {
    return graphIssuanceAuthorizationBindingDigest(request);
  }
  /**
   * Verifies a token against the configured verifier, consuming it. Throws
   * typed errors on failure (see {@link verification.verifyToken}).
   */
  async verifyToken(token) {
    return verifyToken(this.state, token);
  }
  /**
   * Boolean convenience over {@link verifyToken}. Returns `false` for invalid
   * or replayed tokens; rethrows infrastructure errors (verifier unavailable,
   * rate limited, not configured).
   */
  async verifyTokenValid(token) {
    return verifyTokenValid(this.state, token);
  }
  /**
   * Checks token validity WITHOUT consuming it (distinct `/v1/check` endpoint).
   */
  async checkToken(token) {
    return checkToken(this.state, token);
  }
  /** Verifies a batch of tokens in one request, consuming each. */
  async verifyBatch(tokens) {
    return verifyBatch(this.state, tokens);
  }
};

// src/client/token_store.ts
function tokenId(token) {
  return token.tokenValue;
}
function isExpired(token, nowMs) {
  if (token.valid_until === void 0)
    return false;
  return token.valid_until * 1e3 <= nowMs;
}
function isToken(value) {
  return typeof value === "object" && value !== null && typeof value.tokenValue === "string" && typeof value.issuerId === "string";
}
var MemoryTokenStore = class {
  tokens = /* @__PURE__ */ new Map();
  async save(token) {
    this.tokens.set(tokenId(token), { ...token });
  }
  async load(id) {
    this.evict();
    if (id !== void 0) {
      const token = this.tokens.get(id);
      return token ? { ...token } : null;
    }
    const entries = [...this.tokens.values()];
    return entries.length ? { ...entries[entries.length - 1] } : null;
  }
  async list() {
    this.evict();
    return [...this.tokens.values()].map((token) => ({ ...token }));
  }
  async clear() {
    this.tokens.clear();
  }
  evict() {
    const now = Date.now();
    for (const [id, token] of this.tokens) {
      if (isExpired(token, now))
        this.tokens.delete(id);
    }
  }
};
var StorageTokenStore = class {
  key;
  useBrowser;
  constructor(options) {
    this.key = options.key;
    this.useBrowser = isBrowserStorageAvailable();
  }
  async save(token) {
    const tokens = await this.readAll();
    const index = tokens.findIndex((candidate) => tokenId(candidate) === tokenId(token));
    if (index >= 0)
      tokens[index] = token;
    else
      tokens.push(token);
    await this.writeAll(tokens);
  }
  async load(id) {
    const tokens = await this.readAll();
    if (id !== void 0) {
      const token = tokens.find((candidate) => tokenId(candidate) === id);
      return token ?? null;
    }
    return tokens.length ? tokens[tokens.length - 1] : null;
  }
  async list() {
    return this.readAll();
  }
  async clear() {
    if (this.useBrowser) {
      window.localStorage.removeItem(this.key);
      return;
    }
    const fs = await getFs();
    await fs.promises.rm(this.key, { force: true });
  }
  async readAll() {
    let raw;
    if (this.useBrowser) {
      raw = window.localStorage.getItem(this.key);
    } else {
      const fs = await getFs();
      try {
        raw = await fs.promises.readFile(this.key, "utf8");
      } catch (error) {
        if (error.code === "ENOENT")
          return [];
        throw error;
      }
    }
    if (!raw)
      return [];
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed))
        return [];
      const now = Date.now();
      return parsed.filter((value) => isToken(value) && !isExpired(value, now));
    } catch {
      return [];
    }
  }
  async writeAll(tokens) {
    const data = JSON.stringify(tokens);
    if (this.useBrowser) {
      window.localStorage.setItem(this.key, data);
      return;
    }
    await atomicWrite(this.key, data);
  }
};
function isBrowserStorageAvailable() {
  try {
    return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
  } catch {
    return false;
  }
}
var fsPromise = null;
function getFs() {
  if (!fsPromise)
    fsPromise = import("fs");
  return fsPromise;
}
async function atomicWrite(path, data) {
  const fs = await getFs();
  const tmp = `${path}.tmp`;
  const isUnix = typeof process !== "undefined" && process.platform !== "win32";
  const mode = isUnix ? 384 : void 0;
  const handle = await fs.promises.open(tmp, "w", mode);
  try {
    await handle.writeFile(data, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.promises.rename(tmp, path);
}

// src/crypto/graph_issuance.ts
import { hmac } from "@noble/hashes/hmac";
import { sha256 as sha2568 } from "@noble/hashes/sha256";
var HMAC_AUTHORIZATION_DOMAIN = new TextEncoder().encode(
  "freebird graph issuance hmac authorization v2\0"
);
var ascii2 = (value) => new TextEncoder().encode(value);
var concat = (...values) => {
  const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
};
var put2 = (output, value) => {
  output.push(
    value.length >>> 24 & 255,
    value.length >>> 16 & 255,
    value.length >>> 8 & 255,
    value.length & 255,
    ...value
  );
};
var toBase64Url = (value) => {
  let binary = "";
  for (const byte of value)
    binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
var fromBase64Url = (value, expectedBytes) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid canonical graph issuance HMAC authorization");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + (4 - normalized.length % 4) % 4, "=");
  let decoded;
  try {
    const binary = atob(padded);
    decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error("Invalid canonical graph issuance HMAC authorization");
  }
  if (decoded.length !== expectedBytes || toBase64Url(decoded) !== value) {
    throw new Error("Invalid canonical graph issuance HMAC authorization");
  }
  return decoded;
};
var validateFixed = (value, length, name) => {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${name} must be exactly ${length} bytes`);
  }
};
var validatePolicyId = (policyId) => {
  if (typeof policyId !== "string" || policyId.length === 0 || policyId.length > 128 || !/^[\x00-\x7F]+$/.test(policyId)) {
    throw new Error("Invalid graph issuance policy ID");
  }
};
function graphIssuanceHmacAuthorizationTranscriptV2(nonce, policyId, authorizationBindingDigest) {
  validateFixed(nonce, 32, "HMAC nonce");
  validateFixed(authorizationBindingDigest, 32, "Authorization binding digest");
  validatePolicyId(policyId);
  const framedPolicy = [];
  put2(framedPolicy, ascii2(policyId));
  return concat(
    HMAC_AUTHORIZATION_DOMAIN,
    nonce,
    new Uint8Array(framedPolicy),
    authorizationBindingDigest
  );
}
function graphIssuanceHmacAuthorizationTagV2(secret, nonce, policyId, authorizationBindingDigest) {
  if (!(secret instanceof Uint8Array) || secret.length === 0) {
    throw new Error("Invalid HMAC secret");
  }
  return hmac(sha2568, secret, graphIssuanceHmacAuthorizationTranscriptV2(
    nonce,
    policyId,
    authorizationBindingDigest
  ));
}
function buildGraphIssuanceHmacAuthorizationV2(secret, nonce, policyId, authorizationBindingDigest) {
  const tag = graphIssuanceHmacAuthorizationTagV2(
    secret,
    nonce,
    policyId,
    authorizationBindingDigest
  );
  return toBase64Url(concat(nonce, tag));
}
function parseGraphIssuanceHmacAuthorizationV2(authorization) {
  const bytes = fromBase64Url(authorization, 64);
  return { nonce: bytes.slice(0, 32), tag: bytes.slice(32) };
}
function verifyGraphIssuanceHmacAuthorizationV2(secret, policyId, authorizationBindingDigest, authorization) {
  const { nonce, tag } = parseGraphIssuanceHmacAuthorizationV2(authorization);
  const expected = graphIssuanceHmacAuthorizationTagV2(
    secret,
    nonce,
    policyId,
    authorizationBindingDigest
  );
  let difference = 0;
  for (let index = 0; index < expected.length; index++)
    difference |= expected[index] ^ tag[index];
  if (difference !== 0)
    throw new Error("Invalid graph issuance HMAC authorization");
  return nonce;
}
var hmacAuthorizationTranscriptV2 = graphIssuanceHmacAuthorizationTranscriptV2;
var hmacAuthorizationTagV2 = graphIssuanceHmacAuthorizationTagV2;
var buildHmacAuthorizationV2 = buildGraphIssuanceHmacAuthorizationV2;
var parseHmacAuthorizationV2 = parseGraphIssuanceHmacAuthorizationV2;
var verifyHmacAuthorizationV2 = verifyGraphIssuanceHmacAuthorizationV2;

// src/index.ts
var crypto2 = {
  blind,
  finalize,
  buildScopeDigest,
  buildPrivateTokenInput,
  buildRedemptionToken,
  parseRedemptionToken,
  tokenKeyIdFromSpki,
  tokenKeyIdToHex,
  tokenKeyIdFromHex,
  buildPublicBearerMessage,
  buildPublicBearerPass,
  parsePublicBearerPass,
  rsaBlind,
  rsaUnblind,
  rsaVerify,
  graphIssuanceHmacAuthorizationTranscriptV2,
  graphIssuanceHmacAuthorizationTagV2,
  buildGraphIssuanceHmacAuthorizationV2,
  parseGraphIssuanceHmacAuthorizationV2,
  verifyGraphIssuanceHmacAuthorizationV2,
  hmacAuthorizationTranscriptV2,
  hmacAuthorizationTagV2,
  buildHmacAuthorizationV2,
  parseHmacAuthorizationV2,
  verifyHmacAuthorizationV2
};
export {
  BatchIssuanceError,
  DiscoveryError,
  ExchangeError,
  FreebirdClient,
  FreebirdError,
  GraphIssuanceError,
  InvalidTokenError,
  MemoryTokenStore,
  PollAbortedError,
  PollError,
  PollTimeoutError,
  RateLimitedError,
  ReplayedTokenError,
  StorageTokenStore,
  VerificationError,
  VerifierNotConfiguredError,
  VerifierUnavailableError,
  buildBatchBinding,
  buildGraphIssuanceHmacAuthorizationV2,
  buildHmacAuthorizationV2,
  buildIssueBinding,
  buildPublicIssueBinding,
  buildRenewBinding,
  crypto2 as crypto,
  deserializeGraphIssuanceRecoveryContext,
  exchangePasses,
  generateOperationId,
  generateProofOfWork,
  generateStatusCapability,
  graphIssuanceHmacAuthorizationTagV2,
  graphIssuanceHmacAuthorizationTranscriptV2,
  hmacAuthorizationTagV2,
  hmacAuthorizationTranscriptV2,
  parseGraphIssuanceHmacAuthorizationV2,
  parseHmacAuthorizationV2,
  pollExchangeStatus,
  pollGraphIssuanceStatus,
  pollUntilTerminal,
  serializeGraphIssuanceRecoveryContext,
  tokenId,
  verifyGraphIssuanceHmacAuthorizationV2,
  verifyHmacAuthorizationV2,
  verifyPow
};
//# sourceMappingURL=index.js.map