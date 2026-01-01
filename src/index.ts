/**
 * Scarcity: Privacy-preserving P2P value transfer protocol
 *
 * A gossip-based cryptocurrency with double-spend prevention
 * through distributed nullifier sets and threshold timestamping.
 *
 * @module scarcity
 */

export { ScarbuckToken } from './token.js';
export { NullifierGossip } from './gossip.js';
export { TransferValidator } from './validator.js';
export { Crypto } from './crypto.js';
export { FederationBridge } from './bridge.js';

export { FreebirdAdapter } from './integrations/freebird.js';
export { WitnessAdapter } from './integrations/witness.js';
export { HyperTokenAdapter } from './integrations/hypertoken.js';

export { TorProxy, configureTor, getTorProxy, torFetch } from './tor.js';

export type {
  PublicKey,
  PrivateKey,
  KeyPair,
  Attestation,
  TransferPackage,
  SplitPackage,
  MergePackage,
  MultiPartyTransfer,
  HTLCCondition,
  HTLCPackage,
  BridgePackage,
  PeerConnection,
  GossipMessage,
  ValidationResult,
  ConfidenceParams,
  FreebirdClient,
  WitnessClient,
  GossipNetwork,
  TorConfig
} from './types.js';

export type { ScarbuckTokenConfig } from './token.js';
export type { ValidatorConfig } from './validator.js';
export type { GossipConfig } from './gossip.js';
export type { BridgeConfig } from './bridge.js';
export type { FreebirdAdapterConfig } from './integrations/freebird.js';
export type { WitnessAdapterConfig } from './integrations/witness.js';
export type { HyperTokenAdapterConfig } from './integrations/hypertoken.js';
