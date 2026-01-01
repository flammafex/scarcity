/**
 * Type declarations for hypertoken-monorepo
 *
 * Provides minimal type definitions to avoid type errors from
 * internal hypertoken modules we don't directly use.
 */

declare module 'hypertoken-monorepo/core/EventBus.js' {
  export class EventBus {
    emit(event: string, data?: any): void;
    on(event: string, handler: (data: any) => void): void;
  }
}

declare module 'hypertoken-monorepo/network/PeerConnection.js' {
  export interface NetworkMessage {
    type: string;
    payload?: any;
    targetPeerId?: string;
    fromPeerId?: string;
  }

  export class PeerConnection {
    url: string;
    engine: any | null;
    socket: WebSocket | null;
    connected: boolean;
    peerId: string | null;
    peers: Set<string>;

    constructor(url: string, engine?: any | null);
    connect(): void;
    disconnect(): void;
    sendToPeer(targetPeerId: string, payload: any): void;
    broadcast(type: string, payload?: any): void;
    on(event: string, handler: (evt: any) => void): this;
    off(event: string, handler: (evt: any) => void): this;
    emit(event: string, payload?: any): boolean;
  }

  export const NetworkInterface: typeof PeerConnection;
}
