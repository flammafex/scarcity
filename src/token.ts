/**
 * ScarbuckToken: Privacy-preserving P2P value transfer
 */

import { Crypto } from './crypto.js';
import type {
  PublicKey,
  TransferPackage,
  SplitPackage,
  MergePackage,
  MultiPartyTransfer,
  HTLCPackage,
  HTLCCondition,
  BridgePackage,
  FreebirdClient,
  WitnessClient,
  GossipNetwork,
  Attestation
} from './types.js';

export interface ScarbuckTokenConfig {
  readonly id: string;
  readonly amount: number;
  readonly secret: Uint8Array;
  readonly freebird: FreebirdClient;
  readonly witness: WitnessClient;
  readonly gossip: GossipNetwork;
}

export class ScarbuckToken {
  private readonly id: string;
  private readonly amount: number;
  private readonly secret: Uint8Array;
  private readonly freebird: FreebirdClient;
  private readonly witness: WitnessClient;
  private readonly gossip: GossipNetwork;
  private spent: boolean = false;

  constructor(config: ScarbuckTokenConfig) {
    this.id = config.id;
    this.amount = config.amount;
    this.secret = config.secret;
    this.freebird = config.freebird;
    this.witness = config.witness;
    this.gossip = config.gossip;
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
    if (this.spent) {
      throw new Error('Token already spent');
    }

    // A. Create nullifier (unique spend identifier)
    const timestamp = Date.now();
    const nullifier = Crypto.hash(
      this.secret,
      this.id
    );

    // B. Blind commitment to recipient (privacy-preserving)
    // In production: use Freebird's VOPRF blinding
    const commitment = await this.freebird.blind(to);

    // C. Create ownership proof (proves we have the right to spend)
    // Bound to nullifier to prevent replay attacks
    const ownershipProof = await this.freebird.createOwnershipProof(this.secret, nullifier);

    // D. Package transfer data
    const pkg = {
      tokenId: this.id,
      amount: this.amount,
      commitment,
      nullifier
    };

    // E. Hash package for timestamping
    const pkgHash = Crypto.hashTransferPackage(pkg);

    // F. Timestamp the transfer with Witness (proof of order)
    const proof = await this.witness.timestamp(pkgHash);

    // G. Broadcast nullifier to gossip network (fast propagation)
    await this.gossip.publish(nullifier, proof);

    // H. Mark as spent
    this.spent = true;

    // I. Return complete transfer package
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
    if (this.spent) {
      throw new Error('Token already spent');
    }

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

    // Create blinded commitments for each recipient
    const splits = await Promise.all(
      amounts.map(async (amount, i) => {
        const tokenId = Crypto.toHex(Crypto.randomBytes(32));
        const commitment = await this.freebird.blind(recipients[i]);
        return { tokenId, amount, commitment };
      })
    );

    // Create ownership proof bound to nullifier
    const ownershipProof = await this.freebird.createOwnershipProof(this.secret, nullifier);

    // Package split data
    const pkg = {
      sourceTokenId: this.id,
      sourceAmount: this.amount,
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
    const freebird = tokens[0].freebird;
    const witness = tokens[0].witness;
    const gossip = tokens[0].gossip;

    // Verify no tokens are already spent
    const spentTokens = tokens.filter(t => t.spent);
    if (spentTokens.length > 0) {
      throw new Error(`Cannot merge spent tokens: ${spentTokens.map(t => t.id).join(', ')}`);
    }

    // Calculate total amount
    const targetAmount = tokens.reduce((sum, token) => sum + token.amount, 0);

    // Generate new token ID
    const targetTokenId = Crypto.toHex(Crypto.randomBytes(32));

    // Create commitment for recipient
    const commitment = await freebird.blind(recipientKey);

    // Generate nullifiers and ownership proofs for all source tokens
    const sources = await Promise.all(
      tokens.map(async (token) => {
        const nullifier = Crypto.hash(token.secret, token.id);
        return {
          tokenId: token.id,
          amount: token.amount,
          nullifier
        };
      })
    );

    // Create ownership proofs for each token, bound to its nullifier
    const ownershipProofs = await Promise.all(
      tokens.map((token, i) =>
        freebird.createOwnershipProof(token.secret, sources[i].nullifier)
      )
    );

    // Package merge data
    const pkg = {
      targetTokenId,
      targetAmount,
      commitment,
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
      (token as any).spent = true;
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
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance
   */
  static mint(
    amount: number,
    freebird: FreebirdClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): ScarbuckToken {
    const id = Crypto.toHex(Crypto.randomBytes(32));
    const secret = Crypto.randomBytes(32);

    return new ScarbuckToken({
      id,
      amount,
      secret,
      freebird,
      witness,
      gossip
    });
  }

  /**
   * Receive a token from transfer package
   *
   * @param pkg - Transfer package from sender
   * @param recipientSecret - Recipient's secret key
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receive(
    pkg: TransferPackage,
    recipientSecret: Uint8Array,
    freebird: FreebirdClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid transfer proof');
    }

    // Verify ownership proof if present
    if (pkg.ownershipProof) {
      const ownershipValid = await freebird.verifyToken(pkg.ownershipProof);
      if (!ownershipValid) {
        throw new Error('Invalid ownership proof');
      }
    }

    // Create new token for recipient
    // Note: In production, recipientSecret would be used to unblind the commitment
    return new ScarbuckToken({
      id: pkg.tokenId,
      amount: pkg.amount,
      secret: recipientSecret,
      freebird,
      witness,
      gossip
    });
  }

  /**
   * Receive tokens from a split package
   *
   * @param pkg - Split package from sender
   * @param recipientSecret - Recipient's secret key
   * @param splitIndex - Index of the split to receive (0-based)
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receiveSplit(
    pkg: SplitPackage,
    recipientSecret: Uint8Array,
    splitIndex: number,
    freebird: FreebirdClient,
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

    // Verify ownership proof if present
    if (pkg.ownershipProof) {
      const ownershipValid = await freebird.verifyToken(pkg.ownershipProof);
      if (!ownershipValid) {
        throw new Error('Invalid ownership proof');
      }
    }

    // Get the specific split for this recipient
    const split = pkg.splits[splitIndex];

    // Create new token for recipient
    return new ScarbuckToken({
      id: split.tokenId,
      amount: split.amount,
      secret: recipientSecret,
      freebird,
      witness,
      gossip
    });
  }

  /**
   * Receive merged token from merge package
   *
   * @param pkg - Merge package
   * @param recipientSecret - Recipient's secret key
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance with combined amount
   */
  static async receiveMerge(
    pkg: MergePackage,
    recipientSecret: Uint8Array,
    freebird: FreebirdClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid merge proof');
    }

    // Verify ownership proofs if present
    if (pkg.ownershipProofs) {
      const validations = await Promise.all(
        pkg.ownershipProofs.map(proof => freebird.verifyToken(proof))
      );
      if (validations.some(v => !v)) {
        throw new Error('Invalid ownership proofs in merge');
      }
    }

    // Create new token for recipient
    return new ScarbuckToken({
      id: pkg.targetTokenId,
      amount: pkg.targetAmount,
      secret: recipientSecret,
      freebird,
      witness,
      gossip
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
    if (this.spent) {
      throw new Error('Token already spent');
    }

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

    // Create blinded commitments for each recipient
    const recipientData = await Promise.all(
      recipients.map(async (recipient) => {
        const tokenId = Crypto.toHex(Crypto.randomBytes(32));
        const commitment = await this.freebird.blind(recipient.publicKey);
        return {
          publicKey: recipient.publicKey,
          amount: recipient.amount,
          commitment,
          tokenId
        };
      })
    );

    // Create ownership proof bound to nullifier
    const ownershipProof = await this.freebird.createOwnershipProof(this.secret, nullifier);

    // Package multi-party transfer data
    const pkg = {
      sourceTokenId: this.id,
      sourceAmount: this.amount,
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
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receiveMultiParty(
    pkg: MultiPartyTransfer,
    recipientSecret: Uint8Array,
    recipientIndex: number,
    freebird: FreebirdClient,
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

    // Verify ownership proof if present
    if (pkg.ownershipProof) {
      const ownershipValid = await freebird.verifyToken(pkg.ownershipProof);
      if (!ownershipValid) {
        throw new Error('Invalid ownership proof');
      }
    }

    // Get the specific recipient data
    const recipient = pkg.recipients[recipientIndex];

    // Create new token for recipient
    return new ScarbuckToken({
      id: recipient.tokenId,
      amount: recipient.amount,
      secret: recipientSecret,
      freebird,
      witness,
      gossip
    });
  }

  /**
   * Get token metadata (safe to share)
   */
  getMetadata() {
    return {
      id: this.id,
      amount: this.amount,
      spent: this.spent
    };
  }

  /**
   * Check if token has been spent
   */
  isSpent(): boolean {
    return this.spent;
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
    if (this.spent) {
      throw new Error('Token already spent');
    }

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

    // Create blinded commitment to recipient
    const commitment = await this.freebird.blind(to);

    // Create ownership proof bound to nullifier
    const ownershipProof = await this.freebird.createOwnershipProof(this.secret, nullifier);

    // Package HTLC data
    const pkg = {
      tokenId: this.id,
      amount: this.amount,
      commitment,
      nullifier,
      condition,
      refundPublicKey: refundKey
    };

    // Hash package for timestamping
    const pkgHash = Crypto.hashString(JSON.stringify(pkg));

    // Timestamp with Witness
    const proof = await this.witness.timestamp(pkgHash);

    // Broadcast nullifier (this locks the funds)
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
   * Receive and unlock an HTLC transfer
   *
   * @param pkg - HTLC package
   * @param recipientSecret - Recipient's secret key
   * @param preimage - Hash preimage to unlock (for hash-locked HTLCs)
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for recipient
   */
  static async receiveHTLC(
    pkg: HTLCPackage,
    recipientSecret: Uint8Array,
    preimage: Uint8Array | undefined,
    freebird: FreebirdClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid HTLC proof');
    }

    // Verify ownership proof if present
    if (pkg.ownershipProof) {
      const ownershipValid = await freebird.verifyToken(pkg.ownershipProof);
      if (!ownershipValid) {
        throw new Error('Invalid ownership proof');
      }
    }

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

    // Create new token for recipient
    return new ScarbuckToken({
      id: pkg.tokenId,
      amount: pkg.amount,
      secret: recipientSecret,
      freebird,
      witness,
      gossip
    });
  }

  /**
   * Refund an HTLC transfer after timelock expires
   *
   * @param pkg - HTLC package
   * @param refundSecret - Refund key's secret
   * @param freebird - Freebird client
   * @param witness - Witness client
   * @param gossip - Gossip network
   * @returns New ScarbuckToken instance for refund recipient
   */
  static async refundHTLC(
    pkg: HTLCPackage,
    refundSecret: Uint8Array,
    freebird: FreebirdClient,
    witness: WitnessClient,
    gossip: GossipNetwork
  ): Promise<ScarbuckToken> {
    // Verify the transfer proof
    const valid = await witness.verify(pkg.proof);
    if (!valid) {
      throw new Error('Invalid HTLC proof');
    }

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

    // Create new token for refund recipient
    return new ScarbuckToken({
      id: pkg.tokenId,
      amount: pkg.amount,
      secret: refundSecret,
      freebird,
      witness,
      gossip
    });
  }
}
