/**
 * Core type definitions for Scarcity protocol
 */

export interface PublicKey {
  readonly bytes: Uint8Array;
}

export interface PrivateKey {
  readonly bytes: Uint8Array;
}

export interface KeyPair {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
}

export type SophiaWitnessSignatures =
  | {
      readonly kind: 'multisig';
      readonly signatures: ReadonlyArray<{
        readonly witness_id: string;
        readonly signature: string;
      }>;
    }
  | {
      readonly kind: 'aggregated';
      readonly signature: string;
      readonly signers: readonly string[];
    };

export interface SophiaWitnessSignedAttestation {
  readonly contract_version: 'sophia/v1';
  readonly artifact_type: 'witness.signed_attestation';
  readonly attestation: {
    readonly hash: string;
    readonly timestamp: number;
    readonly network_id: string;
    readonly sequence: number;
  };
  readonly signatures: SophiaWitnessSignatures;
}

export interface Attestation {
  readonly hash: string;
  readonly timestamp: number;
  readonly signatures: string[];
  readonly witnessIds: string[];
  readonly canonical?: SophiaWitnessSignedAttestation;
  /** Deprecated compatibility cache; prefer canonical. */
  readonly raw?: any;
}

export interface TransferPackage {
  readonly tokenId: string;
  readonly amount: number;
  /** Scarcity economic timestamp for the token being spent. */
  readonly sourceCreatedAt: number;
  readonly commitment: Uint8Array;
  readonly authToken?: Uint8Array;
  readonly nullifier: Uint8Array;
  readonly proof: Attestation;
  readonly ownershipProof?: Uint8Array;
}

export interface SplitPackage {
  readonly sourceTokenId: string;
  readonly sourceAmount: number;
  /** Scarcity economic timestamp for the token being split. */
  readonly sourceCreatedAt: number;
  readonly splits: Array<{
    tokenId: string;
    amount: number;
    commitment: Uint8Array;
    authToken?: Uint8Array;
  }>;
  readonly nullifier: Uint8Array;
  readonly proof: Attestation;
  readonly ownershipProof?: Uint8Array;
}

export interface MergePackage {
  readonly targetTokenId: string;
  readonly targetAmount: number;
  readonly commitment: Uint8Array;
  readonly authToken?: Uint8Array;
  readonly sources: Array<{
    tokenId: string;
    amount: number;
    /** Scarcity economic timestamp for the source token. */
    createdAt: number;
    nullifier: Uint8Array;
  }>;
  readonly proof: Attestation;
  readonly ownershipProofs?: Uint8Array[];
}

export interface MultiPartyTransfer {
  readonly sourceTokenId: string;
  readonly sourceAmount: number;
  /** Scarcity economic timestamp for the token being spent. */
  readonly sourceCreatedAt: number;
  readonly recipients: Array<{
    publicKey: PublicKey;
    amount: number;
    commitment: Uint8Array;
    authToken?: Uint8Array;
    tokenId: string;
  }>;
  readonly nullifier: Uint8Array;
  readonly proof: Attestation;
  readonly ownershipProof?: Uint8Array;
}

export interface HTLCCondition {
  readonly type: 'hash' | 'time';
  readonly hashlock?: string;  // SHA-256 hash for hash-locked
  readonly timelock?: number;  // Unix timestamp for time-locked
  readonly preimage?: Uint8Array;  // Secret preimage for unlocking
}

export interface HTLCPackage {
  readonly tokenId: string;
  readonly amount: number;
  /** Scarcity economic timestamp for the token being locked. */
  readonly sourceCreatedAt: number;
  readonly commitment: Uint8Array;
  readonly authToken?: Uint8Array;
  readonly nullifier: Uint8Array;
  readonly condition: HTLCCondition;
  readonly proof: Attestation;
  readonly ownershipProof?: Uint8Array;
  readonly refundPublicKey?: PublicKey;  // For refunds after timelock
}

export interface BridgePackage {
  readonly sourceTokenId: string;
  /** Scarcity economic timestamp for the token being bridged. */
  readonly sourceCreatedAt: number;
  readonly sourceFederation: string;
  readonly targetFederation: string;
  readonly amount: number;
  readonly commitment: Uint8Array;
  readonly authToken?: Uint8Array;
  readonly nullifier: Uint8Array;
  readonly sourceProof: Attestation;
  readonly targetProof?: Attestation;
  readonly ownershipProof?: Uint8Array;
}

export interface PeerConnection {
  readonly id: string;
  readonly direction?: 'inbound' | 'outbound'; // Connection direction for trust scoring
  readonly remoteAddress?: string; // Remote IP for diversity checks
  send(data: GossipMessage): Promise<void>;
  isConnected(): boolean;
  setMessageHandler?(handler: (data: GossipMessage) => void): void;
  disconnect?(): void;
}

export interface GossipMessage {
  readonly type: 'nullifier' | 'ping' | 'pong';
  readonly nullifier?: Uint8Array;
  readonly proof?: Attestation;
  readonly timestamp: number;
  readonly ownershipProof?: Uint8Array;  // Optional Scarcity ownership proof for spam resistance
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly confidence: number;
  readonly reason?: string;
}

export interface ConfidenceParams {
  readonly gossipPeers: number;
  readonly witnessDepth: number;
  readonly waitTime: number;
}

// Integration interfaces for external services

export interface AdmissionClient {
  /**
   * Issue an authorization/admission credential for a Scarcity operation.
   *
   * The credential authorizes access to Scarcity infrastructure but carries no
   * Scarcity economic state: no amount, token ID, owner, demurrage timestamp, or
   * split/merge relationship.
   */
  issueAdmissionToken(): Promise<Uint8Array>;
  verifyAdmissionToken(token: Uint8Array): Promise<boolean>;
}

export interface FreebirdClient extends AdmissionClient {}

export interface WitnessClient {
  timestamp(hash: string): Promise<Attestation>;
  verify(attestation: Attestation): Promise<boolean>;
  checkNullifier(nullifier: Uint8Array): Promise<number>;
}

export interface GossipNetwork {
  publish(nullifier: Uint8Array, proof: Attestation): Promise<void>;
  checkNullifier(nullifier: Uint8Array): Promise<number>;
  setReceiveHandler(handler: (data: GossipMessage) => Promise<void>): void;
  readonly peers: PeerConnection[];
}
