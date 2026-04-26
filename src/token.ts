/**
 * ScarbuckToken: Privacy-preserving P2P value transfer
 */

import { Crypto } from './crypto.js';
import { DEFAULT_TOKEN_VALIDITY_MS } from './constants.js';
import { OwnershipProof } from './ownership.js';
import type {
  PublicKey,
  TransferPackage,
  SplitPackage,
  MergePackage,
  MultiPartyTransfer,
  HTLCPackage,
  HTLCCondition,
  AdmissionClient,
  WitnessClient,
  GossipNetwork
} from './types.js';

export interface ScarbuckTokenConfig {
  readonly id: string;
  readonly amount: number;
  readonly secret: Uint8Array;
  readonly auth?: AdmissionClient;
  /** @deprecated Freebird is now admission infrastructure only; use auth. */
  readonly freebird?: AdmissionClient;
  readonly witness: WitnessClient;
  readonly gossip: GossipNetwork;
  readonly createdAt?: number;
  readonly maxTokenAge?: number;
}

export interface ScarbuckTokenPersistentState {
  readonly id: string;
  readonly amount: number;
  readonly secret: Uint8Array;
  readonly spent: boolean;
  readonly createdAt?: number;
}

export class ScarbuckToken {
  private readonly id: string;
  private readonly amount: number;
  private readonly secret: Uint8Array;
  private readonly auth: AdmissionClient;
  private readonly witness: WitnessClient;
  private readonly gossip: GossipNetwork;
  private readonly createdAt: number;
  private readonly maxTokenAge: number;
  private spent: boolean = false;

  constructor(config: ScarbuckTokenConfig) {
    this.id = config.id;
    this.amount = config.amount;
    this.secret = config.secret;
    this.auth = config.auth ?? config.freebird!;
    if (!this.auth) {
      throw new Error('ScarbuckToken requires an admission/auth client');
    }
    this.witness = config.witness;
    this.gossip = config.gossip;
    this.createdAt = config.createdAt ?? Date.now();
    this.maxTokenAge = config.maxTokenAge ?? DEFAULT_TOKEN_VALIDITY_MS;
  }

  private assertSpendable(): void {
    if (this.spent) {
      throw new Error('Token already spent');
    }

    const age = Date.now() - this.createdAt;
    if (age > this.maxTokenAge) {
      throw new Error(
        `Token expired. Age (${(age / 3600000).toFixed(1)}h) exceeds Scarcity validity window.`
      );
    }
  }

  private async createRecipientCommitment(to: PublicKey): Promise<Uint8Array> {
    return Crypto.createCommitment(to.bytes);
  }

  private static assertSourceWasSpendable(sourceCreatedAt: number, spendTimestamp: number): void {
    if (typeof sourceCreatedAt !== 'number' || !Number.isFinite(sourceCreatedAt)) {
      throw new Error('Missing Scarcity source creation timestamp');
    }

    const sourceAgeAtSpend = spendTimestamp - sourceCreatedAt;
    if (sourceAgeAtSpend < -300_000) {
      throw new Error('Invalid Scarcity source creation timestamp');
    }

    if (sourceAgeAtSpend > DEFAULT_TOKEN_VALIDITY_MS) {
      throw new Error(
        `Source token expired before spend. Age (${(sourceAgeAtSpend / 3600000).toFixed(1)}h) exceeds Scarcity validity window.`
      );
    }
  }

  private static assertProofCoversHash(actualHash: string, expectedHash: string, label: string): void {
    if (actualHash !== expectedHash) {
      throw new Error(`${label} proof does not match package contents`);
    }
  }

  private static hashSplitPackage(pkg: SplitPackage): string {
    return Crypto.hashString(JSON.stringify({
      sourceTokenId: pkg.sourceTokenId,
      sourceAmount: pkg.sourceAmount,
      sourceCreatedAt: pkg.sourceCreatedAt,
      splits: pkg.splits,
      nullifier: pkg.nullifier
    }));
  }

  private static hashMergePackage(pkg: MergePackage): string {
    return Crypto.hashString(JSON.stringify({
      targetTokenId: pkg.targetTokenId,
      targetAmount: pkg.targetAmount,
      commitment: pkg.commitment,
      authToken: pkg.authToken,
      sources: pkg.sources
    }));
  }

  private static hashMultiPartyPackage(pkg: MultiPartyTransfer): string {
    return Crypto.hashString(JSON.stringify({
      sourceTokenId: pkg.sourceTokenId,
      sourceAmount: pkg.sourceAmount,
      sourceCreatedAt: pkg.sourceCreatedAt,
      recipients: pkg.recipients,
      nullifier: pkg.nullifier
    }));
  }

  private static hashHTLCPackage(pkg: HTLCPackage): string {
    return Crypto.hashString(JSON.stringify({
      tokenId: pkg.tokenId,
      amount: pkg.amount,
      sourceCreatedAt: pkg.sourceCreatedAt,
      commitment: pkg.commitment,
      authToken: pkg.authToken,
      nullifier: pkg.nullifier,
      condition: pkg.condition,
      refundPublicKey: pkg.refundPublicKey
    }));
  }

  /**
   * Transfer token to new owner
   *
   * Protocol:
   * 1. Generate nullifier (prevents double-spend)
   * 2. Create blinded commitment to recipient (privacy)
   * 3. Package transfer data
   * 4. Timestamp with Witness (proof of order)
   * 5. Broadcast nullifier to gossip network
   *
   * @param to - Recipient's public key
   * @returns Transfer package for recipient
   */
  async transfer(to: PublicKey): Promise<TransferPackage> {
    this.assertSpendable();

    // A. Create nullifier (unique spend identifier)
    const nullifier = Crypto.hash(
      this.secret,
      this.id
    );

    // B. Create a Scarcity-owned recipient commitment.
    const commitment = await this.createRecipientCommitment(to);

    // C. Issue an admission token via Freebird. This authorizes access only.
    const authToken = await this.auth.issueAdmissionToken();

    // D. Create Scarcity ownership proof bound to nullifier.
    const ownershipProof = await OwnershipProof.create(this.secret, nullifier);

    // E. Package transfer data
    const pkg = {
      tokenId: this.id,
      amount: this.amount,
      sourceCreatedAt: this.createdAt,
      commitment,
      authToken,
      nullifier
    };

    // F. Hash package for timestamping
    const pkgHash = Crypto.hashTransferPackage(pkg);

    // G. Timestamp the transfer with Witness (proof of order)
    const proof = await this.witness.timestamp(pkgHash);

    // H. Broadcast nullifier to gossip network (fast propagation)
    await this.gossip.publish(nullifier, proof);

    // I. Mark as spent
    this.spent = true;

    // J. Return complete transfer package
    return {
      ...pkg,
      proof,
      ownershipProof
    };
  }

  /**
   * Split token into multiple smaller tokens
   *
   * Splits this token into multiple new tokens with specified amounts.
   * The sum of split amounts must equal the original token amount.
   *
   * @param amounts - Array of amounts for each split token
   * @param recipients - Array of recipient public keys (one per split)
   * @returns Split package containing all new token data
   */
  async split(amounts: number[], recipients: PublicKey[]): Promise<SplitPackage> {
    this.assertSpendable();

    if (amounts.length !== recipients.length) {
      throw new Error('Number of amounts must match number of recipients');
    }

    // Verify sum of amounts equals token amount
    const totalAmount = amounts.reduce((sum, amt) => sum + amt, 0);
    if (totalAmount !== this.amount) {
      throw new Error(`Split amounts (${totalAmount}) must equal token amount (${this.amount})`);
    }

    // Verify all amounts are positive
    if (amounts.some(amt => amt <= 0)) {
      throw new Error('All split amounts must be positive');
    }

    // Generate nullifier for source token
    const nullifier = Crypto.hash(this.secret, this.id);

    // Create Scarcity commitments and Freebird admission tokens for each recipient
    const splits = await Promise.all(
      amounts.map(async (amount, i) => {
        const tokenId = Crypto.toHex(Crypto.randomBytes(32));
        const commitment = await this.createRecipientCommitment(recipients[i]);
        const authToken = await this.auth.issueAdmissionToken();
        return { tokenId, amount, commitment, authToken };
      })
    );

    // Create Scarcity ownership proof bound to nullifier
    const ownershipProof = await OwnershipProof.create(this.secret, nullifier);

    // Package split data
    const pkg = {
      sourceTokenId: this.id,
      sourceAmount: this.amount,
      sourceCreatedAt: this.createdAt,
      splits,
      nullifier
    };

    // Hash package for timestamping
    const pkgHash = Crypto.hashString(JSON.stringify(pkg));

    // Timestamp with Witness
    const proof = await this.witness.timestamp(pkgHash);

    // Broadcast nullifier
    await this.gossip.publish(nullifier, proof);

    // Mark as spent
    this.spent = true;

    return {
      ...pkg,
      proof,
      ownershipProof
    };
  }

  /**
   * Merge multiple tokens into a single token
   *
   * Static method that combines multiple tokens into one larger token.
   * All source tokens must be owned by the same entity.
   *
   * @param tokens - Array of tokens to merge
   * @param recipientKey - Public key of recipient of merged token
   * @returns Merge package containing the new combined token data
   */
  static async merge(
    tokens: ScarbuckToken[],
    recipientKey: PublicKey
  ): Promise<MergePackage> {
    if (tokens.length === 0) {
      throw new Error('Must provide at least one token to merge');
    }

    // Verify all tokens use same infrastructure
    const auth = tokens[0].auth;
    const witness = tokens[0].witness;
    const gossip = tokens[0].gossip;

    tokens.forEach(token => token.assertSpendable());
    const tokenStates = tokens.map((token) => token.getPersistentState());

    // Verify no tokens are already spent
    const spentTokens = tokenStates.filter((state) => state.spent);
    if (spentTokens.length > 0) {
      throw new Error(`Cannot merge spent tokens: ${spentTokens.map((state) => state.id).join(', ')}`);
    }

    // Calculate total amount
    const targetAmount = tokenStates.reduce((sum, state) => sum + state.amount, 0);

    // Generate new token ID
    const targetTokenId = Crypto.toHex(Crypto.randomBytes(32));

    // Create Scarcity recipient commitment and Freebird admission token
    const commitment = await Crypto.createCommitment(recipientKey.bytes);
    const authToken = await auth.issueAdmissionToken();

    // Generate nullifiers and ownership proofs for all source tokens
    const sources = await Promise.all(
      tokenStates.map(async (state) => {
        const nullifier = Crypto.hash(state.secret, state.id);
        return {
          tokenId: state.id,
          amount: state.amount,
          createdAt: state.createdAt ?? Date.now(),
          nullifier
        };
      })
    );

    // Create Scarcity ownership proofs for each token, bound to its nullifier
    const ownershipProofs = await Promise.all(
      tokenStates.map((state, i) =>
        OwnershipProof.create(state.secret, sources[i].nullifier)
      )
    );

    // Package merge data
    const pkg = {
      targetTokenId,
      targetAmount,
      commitment,
      authToken,
      sources
    };

    // Hash package for timestamping
    const pkgHash = Crypto.hashString(JSON.stringify(pkg));

    // Timestamp with Witness
    const proof = await witness.timestamp(pkgHash);

    // Broadcast all nullifiers
    await Promise.all(
      sources.map(source => gossip.publish(source.nullifier, proof))
    );

    // Mark all tokens as spent
    tokens.forEach(token => {
      token.markSpent();
    });

    return {
      ...pkg,
      proof,
      ownershipProofs
    };
  }

  /**
   * Create a new token from scratch (minting)
   *
   * @param amount - Token amount
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance
   */
  static mint(
    amount: number,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): ScarbuckToken {
    const id = Crypto.toHex(Crypto.randomBytes(32));
    const secret = Crypto.randomBytes(32);

    return new ScarbuckToken({
      id,
      amount,
      secret,
      auth,
      witness,
      gossip,
      createdAt: Date.now()
    });
  }

  /**
   * Restore a token from previously persisted state.
   */
  static fromPersistentState(
    state: ScarbuckTokenPersistentState,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): ScarbuckToken {
    const token = new ScarbuckToken({
      id: state.id,
      amount: state.amount,
      secret: state.secret,
      auth,
      witness,
      gossip,
      createdAt: state.createdAt
    });
    if (state.spent) {
      token.markSpent();
    }
    return token;
  }

  /**
   * Receive a token from transfer package
   *
   * @param pkg - Transfer package from sender
   * @param recipientSecret - Recipient's secret key
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receive(
    pkg: TransferPackage,
    recipientSecret: Uint8Array,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid transfer proof');
    }
    ScarbuckToken.assertProofCoversHash(
      pkg.proof.hash,
      Crypto.hashTransferPackage(pkg),
      'Transfer'
    );

    // Verify Freebird admission token is present. Single-use verification
    // happens in TransferValidator, not here.
    if (!pkg.authToken || pkg.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token');
    }

    // Verify ownership proof
    if (!pkg.ownershipProof) {
      throw new Error('Missing required ownership proof');
    }
    const ownershipValid = await OwnershipProof.verify(pkg.ownershipProof, pkg.nullifier);
    if (!ownershipValid) {
      throw new Error('Invalid ownership proof');
    }

    ScarbuckToken.assertSourceWasSpendable(pkg.sourceCreatedAt, pkg.proof.timestamp);

    // Create new token for recipient
    return new ScarbuckToken({
      id: pkg.tokenId,
      amount: pkg.amount,
      secret: recipientSecret,
      auth,
      witness,
      gossip,
      createdAt: pkg.proof.timestamp
    });
  }

  /**
   * Receive tokens from a split package
   *
   * @param pkg - Split package from sender
   * @param recipientSecret - Recipient's secret key
   * @param splitIndex - Index of the split to receive (0-based)
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receiveSplit(
    pkg: SplitPackage,
    recipientSecret: Uint8Array,
    splitIndex: number,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify split index is valid
    if (splitIndex < 0 || splitIndex >= pkg.splits.length) {
      throw new Error(`Invalid split index: ${splitIndex}`);
    }

    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid split proof');
    }
    ScarbuckToken.assertProofCoversHash(
      pkg.proof.hash,
      ScarbuckToken.hashSplitPackage(pkg),
      'Split'
    );

    // Verify Freebird admission token is present. Single-use verification
    // happens at validation boundaries.
    const split = pkg.splits[splitIndex];
    if (!split.authToken || split.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token for split');
    }

    // Verify ownership proof
    if (!pkg.ownershipProof) {
      throw new Error('Missing required ownership proof');
    }
    const ownershipValid = await OwnershipProof.verify(pkg.ownershipProof, pkg.nullifier);
    if (!ownershipValid) {
      throw new Error('Invalid ownership proof');
    }

    ScarbuckToken.assertSourceWasSpendable(pkg.sourceCreatedAt, pkg.proof.timestamp);

    // Create new token for recipient
    return new ScarbuckToken({
      id: split.tokenId,
      amount: split.amount,
      secret: recipientSecret,
      auth,
      witness,
      gossip,
      createdAt: pkg.proof.timestamp
    });
  }

  /**
   * Receive merged token from merge package
   *
   * @param pkg - Merge package
   * @param recipientSecret - Recipient's secret key
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance with combined amount
   */
  static async receiveMerge(
    pkg: MergePackage,
    recipientSecret: Uint8Array,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid merge proof');
    }
    ScarbuckToken.assertProofCoversHash(
      pkg.proof.hash,
      ScarbuckToken.hashMergePackage(pkg),
      'Merge'
    );

    // Verify Freebird admission token is present. Single-use verification
    // happens at validation boundaries.
    if (!pkg.authToken || pkg.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token for merge');
    }

    // Verify ownership proofs
    if (!pkg.ownershipProofs || pkg.ownershipProofs.length !== pkg.sources.length) {
      throw new Error('Missing required ownership proofs for merge');
    }
    const validations = await Promise.all(
      pkg.ownershipProofs.map((proof, i) =>
        OwnershipProof.verify(proof, pkg.sources[i].nullifier)
      )
    );
    if (validations.some(v => !v)) {
      throw new Error('Invalid ownership proofs in merge');
    }

    for (const source of pkg.sources) {
      ScarbuckToken.assertSourceWasSpendable(source.createdAt, pkg.proof.timestamp);
    }

    // Create new token for recipient
    return new ScarbuckToken({
      id: pkg.targetTokenId,
      amount: pkg.targetAmount,
      secret: recipientSecret,
      auth,
      witness,
      gossip,
      createdAt: pkg.proof.timestamp
    });
  }

  /**
   * Multi-party transfer - transfer to multiple recipients atomically
   *
   * @param recipients - Array of {publicKey, amount} for each recipient
   * @returns Multi-party transfer package
   */
  async transferMultiParty(
    recipients: Array<{ publicKey: PublicKey; amount: number }>
  ): Promise<MultiPartyTransfer> {
    this.assertSpendable();

    if (recipients.length === 0) {
      throw new Error('Must provide at least one recipient');
    }

    // Verify sum of amounts equals token amount
    const totalAmount = recipients.reduce((sum, r) => sum + r.amount, 0);
    if (totalAmount !== this.amount) {
      throw new Error(`Recipient amounts (${totalAmount}) must equal token amount (${this.amount})`);
    }

    // Verify all amounts are positive
    if (recipients.some(r => r.amount <= 0)) {
      throw new Error('All recipient amounts must be positive');
    }

    // Generate nullifier for source token
    const nullifier = Crypto.hash(this.secret, this.id);

    // Create Scarcity commitments and Freebird admission tokens for each recipient
    const recipientData = await Promise.all(
      recipients.map(async (recipient) => {
        const tokenId = Crypto.toHex(Crypto.randomBytes(32));
        const commitment = await this.createRecipientCommitment(recipient.publicKey);
        const authToken = await this.auth.issueAdmissionToken();
        return {
          publicKey: recipient.publicKey,
          amount: recipient.amount,
          commitment,
          authToken,
          tokenId
        };
      })
    );

    // Create Scarcity ownership proof bound to nullifier
    const ownershipProof = await OwnershipProof.create(this.secret, nullifier);

    // Package multi-party transfer data
    const pkg = {
      sourceTokenId: this.id,
      sourceAmount: this.amount,
      sourceCreatedAt: this.createdAt,
      recipients: recipientData,
      nullifier
    };

    // Hash package for timestamping
    const pkgHash = Crypto.hashString(JSON.stringify(pkg));

    // Timestamp with Witness
    const proof = await this.witness.timestamp(pkgHash);

    // Broadcast nullifier
    await this.gossip.publish(nullifier, proof);

    // Mark as spent
    this.spent = true;

    return {
      ...pkg,
      proof,
      ownershipProof
    };
  }

  /**
   * Receive token from multi-party transfer
   *
   * @param pkg - Multi-party transfer package
   * @param recipientSecret - Recipient's secret key
   * @param recipientIndex - Index of recipient in the package (0-based)
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receiveMultiParty(
    pkg: MultiPartyTransfer,
    recipientSecret: Uint8Array,
    recipientIndex: number,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify recipient index is valid
    if (recipientIndex < 0 || recipientIndex >= pkg.recipients.length) {
      throw new Error(`Invalid recipient index: ${recipientIndex}`);
    }

    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid multi-party transfer proof');
    }
    ScarbuckToken.assertProofCoversHash(
      pkg.proof.hash,
      ScarbuckToken.hashMultiPartyPackage(pkg),
      'Multi-party transfer'
    );

    // Verify Freebird admission token is present. Single-use verification
    // happens at validation boundaries.
    const recipient = pkg.recipients[recipientIndex];
    if (!recipient.authToken || recipient.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token for recipient');
    }

    // Verify ownership proof
    if (!pkg.ownershipProof) {
      throw new Error('Missing required ownership proof');
    }
    const ownershipValid = await OwnershipProof.verify(pkg.ownershipProof, pkg.nullifier);
    if (!ownershipValid) {
      throw new Error('Invalid ownership proof');
    }

    ScarbuckToken.assertSourceWasSpendable(pkg.sourceCreatedAt, pkg.proof.timestamp);

    // Create new token for recipient
    return new ScarbuckToken({
      id: recipient.tokenId,
      amount: recipient.amount,
      secret: recipientSecret,
      auth,
      witness,
      gossip,
      createdAt: pkg.proof.timestamp
    });
  }

  /**
   * Get token metadata (safe to share)
   */
  getMetadata() {
    return {
      id: this.id,
      amount: this.amount,
      spent: this.spent,
      createdAt: this.createdAt,
      expiresAt: this.createdAt + this.maxTokenAge
    };
  }

  /**
   * Export minimal state needed for local persistence.
   * Secret is returned as a copy.
   */
  getPersistentState(): ScarbuckTokenPersistentState {
    return {
      id: this.id,
      amount: this.amount,
      secret: new Uint8Array(this.secret),
      spent: this.spent,
      createdAt: this.createdAt
    };
  }

  /**
   * Check if token has been spent
   */
  isSpent(): boolean {
    return this.spent;
  }

  /**
   * Mark token as spent.
   * Intended for flows that consume a token outside transfer/split/merge (e.g. bridging).
   */
  markSpent(): void {
    this.spent = true;
  }

  /**
   * Create a Hash Time-Locked Contract (HTLC) transfer
   *
   * Conditional payment that can be unlocked with a hash preimage
   * or refunded after a timeout.
   *
   * @param to - Recipient's public key
   * @param condition - HTLC condition (hash or time lock)
   * @param refundKey - Public key for refund (if timelock expires)
   * @returns HTLC package
   */
  async transferHTLC(
    to: PublicKey,
    condition: HTLCCondition,
    refundKey?: PublicKey
  ): Promise<HTLCPackage> {
    this.assertSpendable();

    // Validate condition
    if (condition.type === 'hash') {
      if (!condition.hashlock) {
        throw new Error('Hash condition requires hashlock');
      }
    } else if (condition.type === 'time') {
      if (!condition.timelock) {
        throw new Error('Time condition requires timelock');
      }
      if (condition.timelock <= Date.now()) {
        throw new Error('Timelock must be in the future');
      }
      if (!refundKey) {
        throw new Error('Time-locked transfers require refundKey');
      }
    }

    // Generate nullifier
    const nullifier = Crypto.hash(this.secret, this.id);

    // Create Scarcity recipient commitment and Freebird admission token
    const commitment = await this.createRecipientCommitment(to);
    const authToken = await this.auth.issueAdmissionToken();

    // Create Scarcity ownership proof bound to nullifier
    const ownershipProof = await OwnershipProof.create(this.secret, nullifier);

    // Package HTLC data
    const pkg = {
      tokenId: this.id,
      amount: this.amount,
      sourceCreatedAt: this.createdAt,
      commitment,
      authToken,
      nullifier,
      condition,
      refundPublicKey: refundKey
    };

    // Hash package for timestamping
    const pkgHash = Crypto.hashString(JSON.stringify(pkg));

    // Timestamp with Witness
    const proof = await this.witness.timestamp(pkgHash);

    // NOTE: Do NOT publish nullifier here. HTLC is a two-phase protocol:
    //   Phase 1 (now): Lock funds — token is marked spent locally but nullifier
    //     is NOT broadcast. This preserves the ability to refund.
    //   Phase 2 (receiveHTLC or refundHTLC): The nullifier is published when
    //     the HTLC is resolved, preventing double-spend at settlement time.
    // Publishing at lock time would make refunds impossible since the gossip
    // network would already consider the token spent.

    // Mark as spent locally (prevents sender from double-spending)
    this.spent = true;

    return {
      ...pkg,
      proof,
      ownershipProof
    };
  }

  /**
   * Receive and unlock an HTLC transfer
   *
   * @param pkg - HTLC package
   * @param recipientSecret - Recipient's secret key
   * @param preimage - Hash preimage to unlock (for hash-locked HTLCs)
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receiveHTLC(
    pkg: HTLCPackage,
    recipientSecret: Uint8Array,
    preimage: Uint8Array | undefined,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid HTLC proof');
    }
    ScarbuckToken.assertProofCoversHash(
      pkg.proof.hash,
      ScarbuckToken.hashHTLCPackage(pkg),
      'HTLC'
    );

    // Verify Freebird admission token is present. Single-use verification
    // happens at validation boundaries.
    if (!pkg.authToken || pkg.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token for HTLC');
    }

    // Verify ownership proof
    if (!pkg.ownershipProof) {
      throw new Error('Missing required ownership proof');
    }
    const ownershipValid = await OwnershipProof.verify(pkg.ownershipProof, pkg.nullifier);
    if (!ownershipValid) {
      throw new Error('Invalid ownership proof');
    }

    ScarbuckToken.assertSourceWasSpendable(pkg.sourceCreatedAt, pkg.proof.timestamp);

    // Check condition
    if (pkg.condition.type === 'hash') {
      // Hash-locked: verify preimage
      if (!preimage) {
        throw new Error('Preimage required for hash-locked HTLC');
      }

      const hash = Crypto.hashString(Crypto.toHex(preimage));
      if (hash !== pkg.condition.hashlock) {
        throw new Error('Invalid preimage for hashlock');
      }
    } else if (pkg.condition.type === 'time') {
      // Time-locked: check if timelock has expired for recipient
      // Recipient can claim before expiry, refunder can claim after expiry
      if (pkg.condition.timelock && Date.now() < pkg.condition.timelock) {
        // Timelock hasn't expired - recipient can claim
        // This is the normal case
      } else {
        throw new Error('Timelock expired - use refundHTLC instead');
      }
    }

    // Phase 2: Publish nullifier now that the HTLC is being claimed.
    // This prevents the sender from also refunding the same HTLC.
    await gossip.publish(pkg.nullifier, pkg.proof);

    // Create new token for recipient
    return new ScarbuckToken({
      id: pkg.tokenId,
      amount: pkg.amount,
      secret: recipientSecret,
      auth,
      witness,
      gossip,
      createdAt: pkg.proof.timestamp
    });
  }

  /**
   * Refund an HTLC transfer after timelock expires
   *
   * @param pkg - HTLC package
   * @param refundSecret - Refund key's secret
   * @param auth - Admission authorization client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for refund recipient
   */
  static async refundHTLC(
    pkg: HTLCPackage,
    refundSecret: Uint8Array,
    auth: AdmissionClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid HTLC proof');
    }
    ScarbuckToken.assertProofCoversHash(
      pkg.proof.hash,
      ScarbuckToken.hashHTLCPackage(pkg),
      'HTLC'
    );

    // Verify Freebird admission token is present. Single-use verification
    // happens in TransferValidator.
    if (!pkg.authToken || pkg.authToken.length === 0) {
      throw new Error('Missing required Freebird authorization token for HTLC refund');
    }

    ScarbuckToken.assertSourceWasSpendable(pkg.sourceCreatedAt, pkg.proof.timestamp);

    // Verify this is a time-locked HTLC
    if (pkg.condition.type !== 'time') {
      throw new Error('Only time-locked HTLCs can be refunded');
    }

    // Verify timelock has expired
    if (!pkg.condition.timelock || Date.now() < pkg.condition.timelock) {
      throw new Error('Timelock has not expired yet');
    }

    if (!pkg.refundPublicKey) {
      throw new Error('No refund key specified in HTLC');
    }

    // Verify refundSecret corresponds to refundPublicKey
    const derivedPublicKey = Crypto.hash(refundSecret, 'PUBLIC_KEY');
    if (!Crypto.constantTimeEqual(derivedPublicKey, pkg.refundPublicKey.bytes)) {
      throw new Error('Invalid refund key: secret does not match refundPublicKey');
    }

    // Phase 2: Publish nullifier now that the HTLC is being refunded.
    // This prevents the recipient from also claiming the same HTLC.
    await gossip.publish(pkg.nullifier, pkg.proof);

    // Create new token for refund recipient
    return new ScarbuckToken({
      id: pkg.tokenId,
      amount: pkg.amount,
      secret: refundSecret,
      auth,
      witness,
      gossip,
      createdAt: pkg.proof.timestamp
    });
  }
}
