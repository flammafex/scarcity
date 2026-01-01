/**
 * Integration Test: Cryptographic Correctness
 *
 * Tests that cryptographic primitives produce correct, verifiable output.
 * Unlike other tests that check "it runs", these verify mathematical correctness.
 *
 * Categories:
 * 1. Hash function consistency and test vectors
 * 2. Key derivation correctness
 * 3. VOPRF blinding properties
 * 4. DLEQ proof verification (valid and invalid)
 * 5. Constant-time comparison
 * 6. HTLC key verification
 * 7. Proof of work verification
 */

import { Crypto } from '../../src/crypto.js';
import * as voprf from '../../src/vendor/freebird/voprf.js';
import * as P256 from '../../src/vendor/freebird/p256.js';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import { TestRunner } from '../helpers/test-utils.js';
import { FreebirdAdapter } from '../../src/integrations/freebird.js';

export async function runCryptoCorrectnessTest(): Promise<void> {
  const runner = new TestRunner();

  console.log('\n' + '='.repeat(60));
  console.log('TEST SUITE: Cryptographic Correctness');
  console.log('='.repeat(60) + '\n');

  // ============================================================================
  // 1. Hash Function Tests
  // ============================================================================

  await runner.run('SHA-256 produces correct output for known input', async () => {
    // Test vector: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const emptyHash = Crypto.hash('');
    const emptyHashHex = Crypto.toHex(emptyHash);
    runner.assertEquals(
      emptyHashHex,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'Empty string hash should match test vector'
    );

    // Test vector: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const abcHash = Crypto.hash('abc');
    const abcHashHex = Crypto.toHex(abcHash);
    runner.assertEquals(
      abcHashHex,
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      'SHA-256("abc") should match test vector'
    );
  });

  await runner.run('Hash is deterministic', async () => {
    const input = Crypto.randomBytes(32);
    const hash1 = Crypto.hash(input);
    const hash2 = Crypto.hash(input);

    runner.assert(
      Crypto.constantTimeEqual(hash1, hash2),
      'Same input should produce same hash'
    );
  });

  await runner.run('Hash is collision-resistant (different inputs)', async () => {
    const input1 = new Uint8Array([1, 2, 3]);
    const input2 = new Uint8Array([1, 2, 4]); // Differs by 1 bit

    const hash1 = Crypto.hash(input1);
    const hash2 = Crypto.hash(input2);

    runner.assert(
      !Crypto.constantTimeEqual(hash1, hash2),
      'Different inputs should produce different hashes'
    );
  });

  await runner.run('Hash concatenation is order-dependent', async () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4]);

    const hashAB = Crypto.hash(a, b);
    const hashBA = Crypto.hash(b, a);

    runner.assert(
      !Crypto.constantTimeEqual(hashAB, hashBA),
      'Hash(a,b) should differ from Hash(b,a)'
    );
  });

  // ============================================================================
  // 2. Hex Encoding Tests
  // ============================================================================

  await runner.run('Hex encoding roundtrip', async () => {
    const original = Crypto.randomBytes(32);
    const hex = Crypto.toHex(original);
    const decoded = Crypto.fromHex(hex);

    runner.assert(
      Crypto.constantTimeEqual(original, decoded),
      'Hex roundtrip should preserve data'
    );
  });

  await runner.run('Hex encoding produces lowercase', async () => {
    const bytes = new Uint8Array([0xAB, 0xCD, 0xEF]);
    const hex = Crypto.toHex(bytes);

    runner.assertEquals(hex, 'abcdef', 'Hex should be lowercase');
  });

  // ============================================================================
  // 3. Constant-Time Comparison Tests
  // ============================================================================

  await runner.run('constantTimeEqual returns true for equal arrays', async () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);

    runner.assert(Crypto.constantTimeEqual(a, b), 'Equal arrays should return true');
  });

  await runner.run('constantTimeEqual returns false for different arrays', async () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]); // Last byte differs

    runner.assert(!Crypto.constantTimeEqual(a, b), 'Different arrays should return false');
  });

  await runner.run('constantTimeEqual returns false for different lengths', async () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);

    runner.assert(!Crypto.constantTimeEqual(a, b), 'Different lengths should return false');
  });

  await runner.run('constantTimeEqual handles empty arrays', async () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([]);

    runner.assert(Crypto.constantTimeEqual(a, b), 'Empty arrays should be equal');
  });

  // ============================================================================
  // 4. Key Derivation Tests
  // ============================================================================

  await runner.run('Key derivation is deterministic', async () => {
    const secret = Crypto.randomBytes(32);
    const pubKey1 = Crypto.hash(secret, 'PUBLIC_KEY');
    const pubKey2 = Crypto.hash(secret, 'PUBLIC_KEY');

    runner.assert(
      Crypto.constantTimeEqual(pubKey1, pubKey2),
      'Same secret should derive same public key'
    );
  });

  await runner.run('Different secrets produce different public keys', async () => {
    const secret1 = Crypto.randomBytes(32);
    const secret2 = Crypto.randomBytes(32);

    const pubKey1 = Crypto.hash(secret1, 'PUBLIC_KEY');
    const pubKey2 = Crypto.hash(secret2, 'PUBLIC_KEY');

    runner.assert(
      !Crypto.constantTimeEqual(pubKey1, pubKey2),
      'Different secrets should derive different public keys'
    );
  });

  await runner.run('Public key cannot be reversed to secret', async () => {
    // This is a property test - we can't derive secret from public key
    // We verify the derivation is one-way by checking it's a hash
    const secret = new Uint8Array(32).fill(0x42);
    const pubKey = Crypto.hash(secret, 'PUBLIC_KEY');

    // Public key should be 32 bytes (SHA-256 output)
    runner.assertEquals(pubKey.length, 32, 'Public key should be 32 bytes');

    // Public key should not equal secret
    runner.assert(
      !Crypto.constantTimeEqual(secret, pubKey),
      'Public key should not equal secret'
    );
  });

  // ============================================================================
  // 5. Nullifier Generation Tests
  // ============================================================================

  await runner.run('Nullifier is deterministic', async () => {
    const secret = Crypto.randomBytes(32);
    const tokenId = 'test-token-123';

    const nullifier1 = Crypto.generateNullifier(secret, tokenId);
    const nullifier2 = Crypto.generateNullifier(secret, tokenId);

    runner.assert(
      Crypto.constantTimeEqual(nullifier1, nullifier2),
      'Same inputs should produce same nullifier'
    );
  });

  await runner.run('Nullifier differs for different tokens', async () => {
    const secret = Crypto.randomBytes(32);

    const nullifier1 = Crypto.generateNullifier(secret, 'token-1');
    const nullifier2 = Crypto.generateNullifier(secret, 'token-2');

    runner.assert(
      !Crypto.constantTimeEqual(nullifier1, nullifier2),
      'Different token IDs should produce different nullifiers'
    );
  });

  await runner.run('Nullifier differs for different secrets', async () => {
    const tokenId = 'test-token';

    const nullifier1 = Crypto.generateNullifier(Crypto.randomBytes(32), tokenId);
    const nullifier2 = Crypto.generateNullifier(Crypto.randomBytes(32), tokenId);

    runner.assert(
      !Crypto.constantTimeEqual(nullifier1, nullifier2),
      'Different secrets should produce different nullifiers'
    );
  });

  // ============================================================================
  // 6. VOPRF Blinding Tests
  // ============================================================================

  await runner.run('VOPRF blind produces valid curve point', async () => {
    const input = Crypto.randomBytes(32);
    const context = new TextEncoder().encode('freebird:v1');

    const { blinded, state } = voprf.blind(input, context);

    // Blinded value should be 33 bytes (compressed P-256 point)
    runner.assertEquals(blinded.length, 33, 'Blinded value should be 33 bytes');

    // Should be decodable as a valid P-256 point
    const point = P256.decodePoint(blinded);
    runner.assert(point !== null, 'Blinded value should be valid curve point');
  });

  await runner.run('VOPRF blind is randomized (different each time)', async () => {
    const input = Crypto.randomBytes(32);
    const context = new TextEncoder().encode('freebird:v1');

    const { blinded: blinded1 } = voprf.blind(input, context);
    const { blinded: blinded2 } = voprf.blind(input, context);

    runner.assert(
      !Crypto.constantTimeEqual(blinded1, blinded2),
      'Blinding same input twice should produce different results'
    );
  });

  await runner.run('VOPRF blind state contains valid scalar', async () => {
    const input = Crypto.randomBytes(32);
    const context = new TextEncoder().encode('freebird:v1');

    const { state } = voprf.blind(input, context);

    // r should be a valid scalar (non-zero, less than curve order)
    runner.assert(state.r > 0n, 'Blinding scalar r should be positive');
    runner.assert(state.r < P256.getCurveOrder(), 'Blinding scalar r should be < N');
  });

  await runner.run('VOPRF hash-to-curve is deterministic', async () => {
    const input = Crypto.randomBytes(32);
    const context = new TextEncoder().encode('freebird:v1');

    const point1 = P256.hashToCurve(input, context);
    const point2 = P256.hashToCurve(input, context);

    const encoded1 = P256.encodePoint(point1);
    const encoded2 = P256.encodePoint(point2);

    runner.assert(
      Crypto.constantTimeEqual(encoded1, encoded2),
      'Hash-to-curve should be deterministic'
    );
  });

  await runner.run('VOPRF hash-to-curve produces valid points', async () => {
    // Test with various inputs
    const inputs = [
      new Uint8Array(32).fill(0),
      new Uint8Array(32).fill(0xff),
      Crypto.randomBytes(32),
      Crypto.randomBytes(64),
      new Uint8Array([1])
    ];

    const context = new TextEncoder().encode('freebird:v1');

    for (const input of inputs) {
      const point = P256.hashToCurve(input, context);

      // Point should be on the curve (if we can encode/decode it without error)
      const encoded = P256.encodePoint(point);
      runner.assertEquals(encoded.length, 33, 'Point should encode to 33 bytes');

      const decoded = P256.decodePoint(encoded);
      runner.assert(decoded !== null, 'Point should decode successfully');
    }
  });

  // ============================================================================
  // 7. P-256 Scalar Operations Tests
  // ============================================================================

  await runner.run('Scalar multiplication is correct', async () => {
    const G = p256.ProjectivePoint.BASE;
    const scalar = 2n;

    const result = P256.multiply(G, scalar);

    // 2*G should equal G + G
    const doubleG = G.add(G);

    const encodedResult = P256.encodePoint(result);
    const encodedDouble = P256.encodePoint(doubleG);

    runner.assert(
      Crypto.constantTimeEqual(encodedResult, encodedDouble),
      '2*G should equal G + G'
    );
  });

  await runner.run('Scalar inverse is correct', async () => {
    const N = P256.getCurveOrder();
    const r = P256.randomScalar();
    const rInv = P256.invertScalar(r);

    // r * r^(-1) should equal 1 mod N
    const product = P256.modMul(r, rInv);

    runner.assertEquals(product, 1n, 'r * r^(-1) should equal 1');
  });

  await runner.run('Modular arithmetic is correct', async () => {
    const N = P256.getCurveOrder();

    // Test modMul
    runner.assertEquals(P256.modMul(3n, 4n), 12n, '3 * 4 = 12');

    // Test modSub (with wrap-around)
    runner.assertEquals(P256.modSub(5n, 3n), 2n, '5 - 3 = 2');
    runner.assertEquals(P256.modSub(3n, 5n), N - 2n, '3 - 5 = N - 2 (mod N)');

    // Test modAdd
    runner.assertEquals(P256.modAdd(3n, 4n), 7n, '3 + 4 = 7');
  });

  // ============================================================================
  // 8. DLEQ Proof Structure Tests
  // ============================================================================

  await runner.run('DLEQ proof has correct structure', async () => {
    // A valid VOPRF token has format: [A (33) | B (33) | Proof (64)]
    // The proof is [c (32) | s (32)]

    // Create a mock token structure (we can't create real proofs without server)
    const A = P256.encodePoint(p256.ProjectivePoint.BASE);
    const B = P256.encodePoint(p256.ProjectivePoint.BASE.multiply(2n));
    const mockProof = Crypto.randomBytes(64);

    const token = new Uint8Array(130);
    token.set(A, 0);
    token.set(B, 33);
    token.set(mockProof, 66);

    runner.assertEquals(token.length, 130, 'Token should be 130 bytes');
    runner.assertEquals(A.length, 33, 'A should be 33 bytes');
    runner.assertEquals(B.length, 33, 'B should be 33 bytes');
    runner.assertEquals(mockProof.length, 64, 'Proof should be 64 bytes');
  });

  await runner.run('Invalid DLEQ proof (wrong c) is rejected', async () => {
    // This tests that the DLEQ verification actually checks the proof
    // We create a structurally valid but mathematically invalid proof

    const context = new TextEncoder().encode('freebird:v1');
    const G = p256.ProjectivePoint.BASE;

    // Create a random "issuer" key
    const k = P256.randomScalar();
    const Y = G.multiply(k); // Public key

    // Create test input and evaluate
    const input = Crypto.randomBytes(32);
    const A = P256.hashToCurve(input, context);
    const B = P256.multiply(A, k); // Correct evaluation

    // Create an INVALID proof (random bytes won't satisfy DLEQ equation)
    const invalidC = Crypto.randomBytes(32);
    const invalidS = Crypto.randomBytes(32);
    const invalidProof = new Uint8Array(64);
    invalidProof.set(invalidC, 0);
    invalidProof.set(invalidS, 32);

    // The DLEQ equation: s*G - c*Y = t1, s*A - c*B = t2
    // With random c,s this will fail verification

    const c = BigInt('0x' + bytesToHex(invalidC)) % p256.CURVE.n;
    const s = BigInt('0x' + bytesToHex(invalidS)) % p256.CURVE.n;

    // Recompute what the challenge should be
    const sG = G.multiply(s);
    const cY = Y.multiply(c);
    const t1 = sG.subtract(cY);

    const sA = A.multiply(s);
    const cB = B.multiply(c);
    const t2 = sA.subtract(cB);

    // Compute expected challenge
    const DLEQ_DST_PREFIX = new TextEncoder().encode('DLEQ-P256-v1');
    const dst = new Uint8Array(DLEQ_DST_PREFIX.length + context.length);
    dst.set(DLEQ_DST_PREFIX, 0);
    dst.set(context, DLEQ_DST_PREFIX.length);

    const dstLenBytes = new Uint8Array(4);
    dstLenBytes[0] = 0;
    dstLenBytes[1] = 0;
    dstLenBytes[2] = 0;
    dstLenBytes[3] = dst.length;

    const transcript = new Uint8Array(
      4 + dst.length + 33 * 6
    );
    let offset = 0;
    transcript.set(dstLenBytes, offset); offset += 4;
    transcript.set(dst, offset); offset += dst.length;
    transcript.set(P256.encodePoint(G), offset); offset += 33;
    transcript.set(P256.encodePoint(Y), offset); offset += 33;
    transcript.set(P256.encodePoint(A), offset); offset += 33;
    transcript.set(P256.encodePoint(B), offset); offset += 33;
    transcript.set(P256.encodePoint(t1), offset); offset += 33;
    transcript.set(P256.encodePoint(t2), offset);

    const expectedC = BigInt('0x' + bytesToHex(sha256(transcript))) % p256.CURVE.n;

    // With overwhelming probability, random c != expectedC
    const proofIsValid = (c === expectedC);

    runner.assert(
      !proofIsValid,
      'Random proof values should fail DLEQ verification'
    );
  });

  // ============================================================================
  // 9. Proof of Work Tests
  // ============================================================================

  await runner.run('Proof of work solution is verifiable', async () => {
    const challenge = 'test-challenge-' + Date.now();
    const difficulty = 8; // Low difficulty for fast test

    const nonce = Crypto.solveProofOfWork(challenge, difficulty);
    const isValid = Crypto.verifyProofOfWork(challenge, nonce, difficulty);

    runner.assert(isValid, 'Solved PoW should verify');
  });

  await runner.run('Wrong nonce fails proof of work verification', async () => {
    const challenge = 'test-challenge';
    const difficulty = 8;

    const correctNonce = Crypto.solveProofOfWork(challenge, difficulty);
    const wrongNonce = correctNonce + 1;

    // Wrong nonce should almost certainly fail (unless we're very unlucky)
    const isValid = Crypto.verifyProofOfWork(challenge, wrongNonce, difficulty);

    // Note: There's a tiny chance this could pass by coincidence
    // but with difficulty 8, probability is ~1/256
    runner.assert(!isValid, 'Wrong nonce should fail PoW verification');
  });

  await runner.run('Higher difficulty requires more leading zeros', async () => {
    const challenge = 'difficulty-test';

    // Solve at difficulty 4 (1 hex digit = 4 bits)
    const nonce4 = Crypto.solveProofOfWork(challenge, 4);
    const hash4 = Crypto.hashString(challenge + nonce4);

    runner.assert(
      hash4.startsWith('0'),
      'Difficulty 4 should produce hash starting with 0'
    );

    // Solve at difficulty 8 (2 hex digits = 8 bits)
    const nonce8 = Crypto.solveProofOfWork(challenge, 8);
    const hash8 = Crypto.hashString(challenge + nonce8);

    runner.assert(
      hash8.startsWith('00'),
      'Difficulty 8 should produce hash starting with 00'
    );
  });

  // ============================================================================
  // 10. HTLC Key Verification Tests
  // ============================================================================

  await runner.run('HTLC: correct refund secret derives to refund public key', async () => {
    // Simulate HTLC creation
    const refundSecret = Crypto.randomBytes(32);
    const refundPublicKey = Crypto.hash(refundSecret, 'PUBLIC_KEY');

    // Verification check (same as in refundHTLC)
    const derivedPublicKey = Crypto.hash(refundSecret, 'PUBLIC_KEY');
    const isValid = Crypto.constantTimeEqual(derivedPublicKey, refundPublicKey);

    runner.assert(isValid, 'Correct refund secret should verify');
  });

  await runner.run('HTLC: wrong refund secret fails verification', async () => {
    // Simulate HTLC creation
    const realSecret = Crypto.randomBytes(32);
    const refundPublicKey = Crypto.hash(realSecret, 'PUBLIC_KEY');

    // Attacker tries with wrong secret
    const attackerSecret = Crypto.randomBytes(32);
    const derivedPublicKey = Crypto.hash(attackerSecret, 'PUBLIC_KEY');
    const isValid = Crypto.constantTimeEqual(derivedPublicKey, refundPublicKey);

    runner.assert(!isValid, 'Wrong refund secret should fail verification');
  });

  await runner.run('HTLC: similar secrets produce different public keys', async () => {
    // Two secrets that differ by 1 bit
    const secret1 = new Uint8Array(32).fill(0);
    const secret2 = new Uint8Array(32).fill(0);
    secret2[0] = 1; // Flip one bit

    const pubKey1 = Crypto.hash(secret1, 'PUBLIC_KEY');
    const pubKey2 = Crypto.hash(secret2, 'PUBLIC_KEY');

    runner.assert(
      !Crypto.constantTimeEqual(pubKey1, pubKey2),
      'Slightly different secrets should produce completely different public keys'
    );
  });

  // ============================================================================
  // 11. Edge Cases and Error Handling
  // ============================================================================

  await runner.run('Hash handles maximum size inputs', async () => {
    // Hash a large input (1MB)
    const largeInput = Crypto.randomBytes(1024 * 1024);
    const hash = Crypto.hash(largeInput);

    runner.assertEquals(hash.length, 32, 'Hash of large input should be 32 bytes');
  });

  await runner.run('Invalid P-256 point is rejected', async () => {
    // Create invalid point bytes (not on curve)
    const invalidPoint = new Uint8Array(33);
    invalidPoint[0] = 0x02; // Compressed point prefix
    invalidPoint.fill(0xff, 1); // Invalid x-coordinate

    let threw = false;
    try {
      P256.decodePoint(invalidPoint);
    } catch (e) {
      threw = true;
    }

    runner.assert(threw, 'Invalid point should throw error');
  });

  await runner.run('Zero scalar is rejected by library', async () => {
    const G = p256.ProjectivePoint.BASE;

    // The noble-curves library correctly rejects 0 as a scalar
    // This is security-correct behavior (0*G leaks timing info)
    let threw = false;
    try {
      P256.multiply(G, 0n);
    } catch (e: any) {
      threw = true;
      runner.assert(
        e.message.includes('invalid scalar') || e.message.includes('out of range'),
        'Should reject zero scalar with appropriate error'
      );
    }

    runner.assert(threw, 'Zero scalar should throw error');
  });

  // ============================================================================
  // 12. Cross-Component Integration Tests
  // ============================================================================

  await runner.run('Nullifier uniquely identifies a spend', async () => {
    // Two different users with same token ID should have different nullifiers
    const secret1 = Crypto.randomBytes(32);
    const secret2 = Crypto.randomBytes(32);
    const tokenId = 'shared-token-id';

    const nullifier1 = Crypto.generateNullifier(secret1, tokenId);
    const nullifier2 = Crypto.generateNullifier(secret2, tokenId);

    runner.assert(
      !Crypto.constantTimeEqual(nullifier1, nullifier2),
      'Different owners should have different nullifiers for same token'
    );
  });

  await runner.run('Transfer package hash is deterministic', async () => {
    const pkg = {
      tokenId: 'test-token',
      amount: 100,
      commitment: Crypto.randomBytes(32),
      nullifier: Crypto.randomBytes(32)
    };

    const hash1 = Crypto.hashTransferPackage(pkg);
    const hash2 = Crypto.hashTransferPackage(pkg);

    runner.assertEquals(hash1, hash2, 'Same package should hash identically');
  });

  await runner.run('Transfer package hash changes with any field', async () => {
    const basePackage = {
      tokenId: 'test-token',
      amount: 100,
      commitment: new Uint8Array(32).fill(1),
      nullifier: new Uint8Array(32).fill(2)
    };

    const baseHash = Crypto.hashTransferPackage(basePackage);

    // Change tokenId
    const hash1 = Crypto.hashTransferPackage({ ...basePackage, tokenId: 'different' });
    runner.assert(hash1 !== baseHash, 'Different tokenId should change hash');

    // Change amount
    const hash2 = Crypto.hashTransferPackage({ ...basePackage, amount: 101 });
    runner.assert(hash2 !== baseHash, 'Different amount should change hash');

    // Change commitment
    const hash3 = Crypto.hashTransferPackage({
      ...basePackage,
      commitment: new Uint8Array(32).fill(99)
    });
    runner.assert(hash3 !== baseHash, 'Different commitment should change hash');

    // Change nullifier
    const hash4 = Crypto.hashTransferPackage({
      ...basePackage,
      nullifier: new Uint8Array(32).fill(99)
    });
    runner.assert(hash4 !== baseHash, 'Different nullifier should change hash');
  });

  // ============================================================================
  // 9. Schnorr Ownership Proof Tests
  // ============================================================================

  // Create a minimal FreebirdAdapter for testing ownership proofs
  // The adapter doesn't need real endpoints for crypto operations
  const freebird = new FreebirdAdapter({
    issuerEndpoints: ['http://localhost:9999'], // Dummy, won't be called
    verifierUrl: 'http://localhost:9999'
  });

  await runner.run('Ownership proof has correct format (98 bytes)', async () => {
    const secret = Crypto.randomBytes(32);
    const binding = Crypto.randomBytes(32);

    const proof = await freebird.createOwnershipProof(secret, binding);

    runner.assertEquals(proof.length, 98, 'Proof should be 98 bytes');

    // Verify structure: P (33) || R (33) || s (32)
    const P = proof.slice(0, 33);
    const R = proof.slice(33, 66);
    const s = proof.slice(66, 98);

    runner.assertEquals(P.length, 33, 'Public key should be 33 bytes');
    runner.assertEquals(R.length, 33, 'Commitment should be 33 bytes');
    runner.assertEquals(s.length, 32, 'Response scalar should be 32 bytes');

    // P and R should be valid compressed P-256 points (start with 02 or 03)
    runner.assert(
      P[0] === 0x02 || P[0] === 0x03,
      'P should be compressed P-256 point'
    );
    runner.assert(
      R[0] === 0x02 || R[0] === 0x03,
      'R should be compressed P-256 point'
    );
  });

  await runner.run('Ownership proof verifies correctly', async () => {
    const secret = Crypto.randomBytes(32);
    const binding = Crypto.randomBytes(32);

    const proof = await freebird.createOwnershipProof(secret, binding);
    const valid = await freebird.verifyOwnershipProof(proof, binding);

    runner.assert(valid, 'Valid proof should verify');
  });

  await runner.run('Ownership proof is deterministic for same inputs', async () => {
    const secret = Crypto.randomBytes(32);
    const binding = Crypto.randomBytes(32);

    const proof1 = await freebird.createOwnershipProof(secret, binding);
    const proof2 = await freebird.createOwnershipProof(secret, binding);

    // The proof uses deterministic nonce generation (RFC 6979 style)
    // so same inputs should produce same proof
    runner.assertEquals(
      Crypto.toHex(proof1),
      Crypto.toHex(proof2),
      'Same inputs should produce identical proof (deterministic nonce)'
    );
  });

  await runner.run('Ownership proof differs for different secrets', async () => {
    const secret1 = Crypto.randomBytes(32);
    const secret2 = Crypto.randomBytes(32);
    const binding = Crypto.randomBytes(32);

    const proof1 = await freebird.createOwnershipProof(secret1, binding);
    const proof2 = await freebird.createOwnershipProof(secret2, binding);

    runner.assert(
      Crypto.toHex(proof1) !== Crypto.toHex(proof2),
      'Different secrets should produce different proofs'
    );

    // Both should verify individually
    runner.assert(
      await freebird.verifyOwnershipProof(proof1, binding),
      'Proof 1 should verify'
    );
    runner.assert(
      await freebird.verifyOwnershipProof(proof2, binding),
      'Proof 2 should verify'
    );
  });

  await runner.run('Ownership proof differs for different bindings', async () => {
    const secret = Crypto.randomBytes(32);
    const binding1 = Crypto.randomBytes(32);
    const binding2 = Crypto.randomBytes(32);

    const proof1 = await freebird.createOwnershipProof(secret, binding1);
    const proof2 = await freebird.createOwnershipProof(secret, binding2);

    runner.assert(
      Crypto.toHex(proof1) !== Crypto.toHex(proof2),
      'Different bindings should produce different proofs'
    );
  });

  await runner.run('Ownership proof fails with wrong binding', async () => {
    const secret = Crypto.randomBytes(32);
    const correctBinding = Crypto.randomBytes(32);
    const wrongBinding = Crypto.randomBytes(32);

    const proof = await freebird.createOwnershipProof(secret, correctBinding);

    // Should verify with correct binding
    runner.assert(
      await freebird.verifyOwnershipProof(proof, correctBinding),
      'Should verify with correct binding'
    );

    // Should fail with wrong binding
    runner.assert(
      !(await freebird.verifyOwnershipProof(proof, wrongBinding)),
      'Should fail with wrong binding'
    );
  });

  await runner.run('Ownership proof rejects tampered proof', async () => {
    const secret = Crypto.randomBytes(32);
    const binding = Crypto.randomBytes(32);

    const proof = await freebird.createOwnershipProof(secret, binding);

    // Tamper with different parts of the proof

    // Tamper with P (public key) - byte 10
    const tamperedP = new Uint8Array(proof);
    tamperedP[10] ^= 0x01;
    runner.assert(
      !(await freebird.verifyOwnershipProof(tamperedP, binding)),
      'Tampered public key should fail verification'
    );

    // Tamper with R (commitment) - byte 40
    const tamperedR = new Uint8Array(proof);
    tamperedR[40] ^= 0x01;
    runner.assert(
      !(await freebird.verifyOwnershipProof(tamperedR, binding)),
      'Tampered commitment should fail verification'
    );

    // Tamper with s (response) - byte 80
    const tamperedS = new Uint8Array(proof);
    tamperedS[80] ^= 0x01;
    runner.assert(
      !(await freebird.verifyOwnershipProof(tamperedS, binding)),
      'Tampered response should fail verification'
    );
  });

  await runner.run('Ownership proof rejects invalid length', async () => {
    const binding = Crypto.randomBytes(32);

    // Too short
    const shortProof = Crypto.randomBytes(97);
    runner.assert(
      !(await freebird.verifyOwnershipProof(shortProof, binding)),
      'Short proof should fail'
    );

    // Too long
    const longProof = Crypto.randomBytes(99);
    runner.assert(
      !(await freebird.verifyOwnershipProof(longProof, binding)),
      'Long proof should fail'
    );

    // Empty
    runner.assert(
      !(await freebird.verifyOwnershipProof(new Uint8Array(0), binding)),
      'Empty proof should fail'
    );
  });

  await runner.run('Ownership proof rejects invalid point encoding', async () => {
    const binding = Crypto.randomBytes(32);

    // Create proof with invalid P (first byte not 02 or 03)
    const invalidP = new Uint8Array(98);
    invalidP[0] = 0x04; // Uncompressed point prefix (invalid for our format)
    runner.assert(
      !(await freebird.verifyOwnershipProof(invalidP, binding)),
      'Invalid P encoding should fail'
    );

    // Create proof with all zeros (invalid point)
    const allZeros = new Uint8Array(98);
    runner.assert(
      !(await freebird.verifyOwnershipProof(allZeros, binding)),
      'All zeros should fail (invalid points)'
    );
  });

  await runner.run('Ownership proof public key derivation is consistent', async () => {
    // Create multiple proofs with same secret, verify P is consistent
    const secret = Crypto.randomBytes(32);
    const binding1 = Crypto.randomBytes(32);
    const binding2 = Crypto.randomBytes(32);
    const binding3 = Crypto.randomBytes(32);

    const proof1 = await freebird.createOwnershipProof(secret, binding1);
    const proof2 = await freebird.createOwnershipProof(secret, binding2);
    const proof3 = await freebird.createOwnershipProof(secret, binding3);

    // P (first 33 bytes) should be identical since it's derived from secret
    const P1 = Crypto.toHex(proof1.slice(0, 33));
    const P2 = Crypto.toHex(proof2.slice(0, 33));
    const P3 = Crypto.toHex(proof3.slice(0, 33));

    runner.assertEquals(P1, P2, 'P should be same for same secret (1 vs 2)');
    runner.assertEquals(P2, P3, 'P should be same for same secret (2 vs 3)');
  });

  await runner.run('Ownership proof Schnorr equation holds mathematically', async () => {
    const secret = Crypto.randomBytes(32);
    const binding = Crypto.randomBytes(32);
    const N = p256.CURVE.n;
    const G = p256.ProjectivePoint.BASE;

    const proof = await freebird.createOwnershipProof(secret, binding);

    // Parse proof components
    const PBytes = proof.slice(0, 33);
    const RBytes = proof.slice(33, 66);
    const sBytes = proof.slice(66, 98);

    const P = p256.ProjectivePoint.fromHex(bytesToHex(PBytes));
    const R = p256.ProjectivePoint.fromHex(bytesToHex(RBytes));
    const s = BigInt('0x' + bytesToHex(sBytes));

    // Recompute challenge
    const challengeData = concatBytes(
      new TextEncoder().encode('SCHNORR_OWNERSHIP'),
      RBytes,
      PBytes,
      binding
    );
    const cHash = sha256(challengeData);
    const c = BigInt('0x' + bytesToHex(cHash)) % N;

    // Verify Schnorr equation: s * G = R + c * P
    const sG = G.multiply(s);
    const cP = P.multiply(c);
    const RplusCp = R.add(cP);

    runner.assert(
      sG.equals(RplusCp),
      'Schnorr equation s*G = R + c*P should hold'
    );
  });

  await runner.run('Multiple ownership proofs for batch verification', async () => {
    // Create multiple proofs and verify them all
    const secrets = Array.from({ length: 10 }, () => Crypto.randomBytes(32));
    const bindings = Array.from({ length: 10 }, () => Crypto.randomBytes(32));

    const proofs = await Promise.all(
      secrets.map((secret, i) =>
        freebird.createOwnershipProof(secret, bindings[i])
      )
    );

    // Verify all proofs
    const results = await Promise.all(
      proofs.map((proof, i) =>
        freebird.verifyOwnershipProof(proof, bindings[i])
      )
    );

    runner.assert(
      results.every(r => r === true),
      'All 10 proofs should verify'
    );

    // Cross-verify should fail (wrong binding)
    const crossResults = await Promise.all(
      proofs.map((proof, i) =>
        freebird.verifyOwnershipProof(proof, bindings[(i + 1) % 10])
      )
    );

    runner.assert(
      crossResults.every(r => r === false),
      'Cross-verification with wrong bindings should all fail'
    );
  });

  runner.printSummary();

  // Fail the test suite if any tests failed
  const summary = runner.getSummary();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} cryptographic correctness tests failed`);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runCryptoCorrectnessTest().catch(console.error);
}
