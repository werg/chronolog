/** A bounded connection-owned lane. Sending is local dispatch, not delivery. */
export interface PeerFrameLane {
  send(frame: Uint8Array, options?: { readonly signal?: AbortSignal }): Promise<void>
  frames(signal?: AbortSignal): AsyncIterable<Uint8Array>
  close(): Promise<void>
}

/** Independent disposable traffic with no queued retry on congestion. */
export interface PeerLiveLane {
  readonly signal: AbortSignal
  /** False means no bytes were queued or dispatched. Actual failures throw. */
  trySend(frame: Uint8Array, options?: { readonly signal?: AbortSignal }): Promise<boolean>
  frames(signal?: AbortSignal): AsyncIterable<Uint8Array>
  close(): Promise<void>
}

export interface FramedPeerConnection extends PeerFrameLane {
  /** Ends before frame readers finish; preserves the physical failure or close reason. */
  readonly signal: AbortSignal
  /** Never multiplex disposable traffic into reliable history. */
  readonly live?: PeerLiveLane
}
