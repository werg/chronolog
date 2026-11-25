import type { PeerMessageChannel } from '@chronolog/records'

/** The small browser/native WebRTC surface used by the transport. */
export interface RtcDataChannel extends PeerMessageChannel {
  readonly label: string
  readonly ordered: boolean
  readonly maxPacketLifeTime: number | null
  readonly maxRetransmits: number | null
}

export interface PeerIceCandidate {
  readonly candidate: string
  readonly sdpMid?: string | null
  readonly sdpMLineIndex?: number | null
  readonly usernameFragment?: string | null
}

export interface PeerDescription {
  readonly type: 'offer' | 'answer'
  readonly sdp: string
}

export type PeerSignalingMessage =
  | PeerDescription
  | { readonly kind: 'candidate'; readonly candidate: PeerIceCandidate | null }
  | { readonly kind: 'connected' }

export type RtcSignalMessage =
  | { readonly kind: 'description'; readonly description: PeerDescription }
  | { readonly kind: 'candidate'; readonly candidate: PeerIceCandidate | null }

export interface RtcDataChannelOptions {
  readonly ordered: boolean
  readonly protocol?: string
  readonly negotiated?: boolean
  readonly id?: number
  readonly maxRetransmits?: number
  readonly maxPacketLifeTime?: number
}

export interface RtcPeerConnection {
  readonly localDescription: { readonly type: string; readonly sdp: string } | null
  readonly iceGatheringState: string
  readonly connectionState: string
  readonly signalingState?: string
  readonly iceConnectionState?: string
  /** Optional on adapters; unavailable observations must remain unknown. */
  getStats?(): Promise<{ forEach(callback: (value: unknown) => void): void }>
  createDataChannel(label: string, options: RtcDataChannelOptions): RtcDataChannel
  createOffer(options?: { readonly iceRestart?: boolean }): Promise<RTCSessionDescriptionInit>
  createAnswer(): Promise<RTCSessionDescriptionInit>
  setLocalDescription(description?: RTCSessionDescriptionInit | { readonly type: 'rollback' }): Promise<void>
  setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void>
  addIceCandidate?(candidate: PeerIceCandidate | null): Promise<void>
  restartIce?(): void
  addTrack?(track: unknown, ...streams: unknown[]): unknown
  removeTrack?(sender: unknown): void
  addTransceiver?(kindOrTrack: unknown, init?: Record<string, unknown>): unknown
  getTransceivers?(): readonly unknown[]
  getSenders?(): readonly unknown[]
  getReceivers?(): readonly unknown[]
  close(): void | Promise<void>
  addEventListener(type: string, listener: EventListener): void
  removeEventListener(type: string, listener: EventListener): void
}

/** Signaling carries bounded SDP descriptions and optional trickle ICE candidates. */
export interface PeerSignaling {
  readonly messages: AsyncIterable<PeerSignalingMessage>
  send(message: PeerSignalingMessage): Promise<void>
  close(): void | Promise<void>
}

export interface WebRtcOptions {
  readonly role: 'offerer' | 'answerer'
  readonly signaling: PeerSignaling
  readonly configuration?: RTCConfiguration
  readonly createPeerConnection?: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
  /** Batch ICE budget when trickle ICE is disabled; defaults to WEBRTC_LIMITS.gatheringMs. */
  readonly gatheringTimeoutMs?: number
  /** Enable trickle ICE during initial rendezvous (default: true when adapter supports addIceCandidate). */
  readonly trickle?: boolean
}

/** Two independent SCTP streams belonging to one authenticated peer session. */
export interface WebRtcChannels {
  readonly reliable: RtcDataChannel
  readonly live: RtcDataChannel
}

export interface PeerDataStreamOptions {
  readonly ordered?: boolean
  readonly maxRetransmits?: number
  readonly maxPacketLifeTime?: number
}

export interface PeerDataStream {
  readonly label: string
  readonly ordered: boolean
  readonly readyState: string
  readonly bufferedAmount: number
  readonly signal: AbortSignal
  send(data: Uint8Array | string): void
  messages(signal?: AbortSignal): AsyncIterable<Uint8Array | string>
  close(): void
}

export interface PeerTrackEvent {
  readonly track: unknown
  readonly streams: readonly unknown[]
  readonly transceiver?: unknown
}

export interface PeerMediaController {
  readonly available: boolean
  readonly unavailableReason?: 'relay' | 'unsupported' | 'closed' | undefined
  addTrack(track: unknown, ...streams: unknown[]): unknown
  removeTrack(sender: unknown): void
  addTransceiver(kindOrTrack: unknown, init?: Record<string, unknown>): unknown
  getTransceivers(): readonly unknown[]
  onTrack(listener: (event: PeerTrackEvent) => void): () => void
  restartIce(): Promise<void>
}

export interface PeerStreamsController {
  readonly available: boolean
  readonly unavailableReason?: 'relay' | 'unsupported' | 'closed' | undefined
  open(label: string, options?: PeerDataStreamOptions): PeerDataStream
  onStream(listener: (stream: PeerDataStream) => void): () => void
}

export interface InBandSignalingOptions {
  readonly polite: boolean
  readonly send: (message: RtcSignalMessage) => Promise<void>
  readonly onError?: (error: unknown) => void
}

export interface InBandSignalingHandle {
  receive(message: RtcSignalMessage): Promise<void>
  close(): void
}

export interface WebRtcSession {
  readonly connection: RtcPeerConnection
  readonly signal: AbortSignal
  readonly signaling: { readonly sentMessages: number; readonly receivedMessages: number; readonly sentBytes: number; readonly receivedBytes: number }
  readonly media: PeerMediaController
  readonly streams: PeerStreamsController
  attachInBandSignaling(options: InBandSignalingOptions): InBandSignalingHandle
  /** Observes the currently selected ICE pair without exposing its addresses. */
  getRoute(): Promise<WebRtcRoute>
  close(): Promise<void>
}

export type IceCandidateType = 'host' | 'srflx' | 'prflx' | 'relay'
export interface WebRtcRoute {
  readonly route: 'direct' | 'relay' | 'unknown'
  readonly localCandidateType: IceCandidateType | null
  readonly remoteCandidateType: IceCandidateType | null
}
