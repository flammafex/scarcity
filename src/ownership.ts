/**
 * Scarcity ownership proofs.
 *
 * These proofs belong to Scarcity's economic layer. They prove knowledge of a
 * token secret for a specific spend nullifier without relying on Freebird.
 */

import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, bytesToHex } from '@noble/hashes/utils';

const textEncoder = new TextEncoder();

export class OwnershipProof {
  /**
   * Create a Schnorr signature-based ownership proof.
   *
   * Format: P (33 bytes) || R (33 bytes) || s (32 bytes)
   */
  static async create(secret: Uint8Array, binding: Uint8Array): Promise<Uint8Array> {
    const N = p256.CURVE.n;
    const G = p256.ProjectivePoint.BASE;

    const xHash = sha256(concatBytes(
      textEncoder.encode('SCARCITY_OWNERSHIP_SCALAR'),
      secret
    ));
    const x = BigInt('0x' + bytesToHex(xHash)) % N;
    if (x === 0n) {
      throw new Error('Derived secret scalar is zero');
    }

    const P = G.multiply(x);

    const kHash = sha256(concatBytes(
      textEncoder.encode('SCARCITY_SCHNORR_NONCE'),
      xHash,
      binding
    ));
    const k = BigInt('0x' + bytesToHex(kHash)) % N;
    if (k === 0n) {
      throw new Error('Derived nonce is zero');
    }

    const R = G.multiply(k);
    const PBytes = P.toRawBytes(true);
    const RBytes = R.toRawBytes(true);

    const cHash = sha256(concatBytes(
      textEncoder.encode('SCARCITY_SCHNORR_OWNERSHIP'),
      RBytes,
      PBytes,
      binding
    ));
    const c = BigInt('0x' + bytesToHex(cHash)) % N;
    const s = (k + c * x) % N;

    return concatBytes(PBytes, RBytes, bigintToBytes32(s));
  }

  /**
   * Verify a Schnorr ownership proof against the same binding used at creation.
   */
  static async verify(proof: Uint8Array, binding: Uint8Array): Promise<boolean> {
    if (proof.length !== 98) {
      return false;
    }

    try {
      const N = p256.CURVE.n;
      const G = p256.ProjectivePoint.BASE;

      const PBytes = proof.slice(0, 33);
      const RBytes = proof.slice(33, 66);
      const sBytes = proof.slice(66, 98);

      const P = p256.ProjectivePoint.fromHex(bytesToHex(PBytes));
      const R = p256.ProjectivePoint.fromHex(bytesToHex(RBytes));
      const s = BigInt('0x' + bytesToHex(sBytes));
      if (s === 0n || s >= N) {
        return false;
      }

      const cHash = sha256(concatBytes(
        textEncoder.encode('SCARCITY_SCHNORR_OWNERSHIP'),
        RBytes,
        PBytes,
        binding
      ));
      const c = BigInt('0x' + bytesToHex(cHash)) % N;

      return G.multiply(s).equals(R.add(P.multiply(c)));
    } catch {
      return false;
    }
  }
}

function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
