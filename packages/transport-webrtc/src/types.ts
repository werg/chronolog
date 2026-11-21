import type { PeerMessageChannel } from '@chronolog/records'

/** The small browser/native WebRTC surface used by the transport. */
export interface RtcDataChannel extends PeerMessageChannel {
  readonly label: string
  readonly ordered: boolean
  readonly maxPacketLifeTime: number | null
  readonly maxRetransmits: number | null
}

export interface RtcPeerConnection {
  readonly localDescription: { readonly type: string; readonly sdp: string } | null
  readonly iceGatheringState: string
  readonly connectionState: string
  /** Optional on adapters; unavailable observations must remain unknown. */
  getStats?(): Promise<{ forEach(callback: (value: unknown) => void): void }>
  createDataChannel(label: string, options: {
    readonly ordered: boolean
    readonly protocol: string
    readonly negotiated: true
    readonly id: number
    readonly maxRetransmits?: number
  }): RtcDataChannel
  createOffer(): Promise<RTCSessionDescriptionInit>
  createAnswer(): Promise<RTCSessionDescriptionInit>
  setLocalDescription(description: RTCSessionDescriptionInit): Promise<void>
  setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void>
  close(): void | Promise<void>
  addEventListener(type: string, listener: EventListener): void
  removeEventListener(type: string, listener: EventListener): void
}

export interface PeerDescription { readonly type: 'offer' | 'answer'; readonly sdp: string }

/** Signaling carries exactly one bounded batch SDP per peer and never application bytes. */
export interface PeerSignaling {
  readonly messages: AsyncIterable<PeerDescription>
  send(description: PeerDescription): Promise<void>
  close(): void | Promise<void>
}

export interface WebRtcOptions {
  readonly role: 'offerer' | 'answerer'
  readonly signaling: PeerSignaling
  readonly configuration?: RTCConfiguration
  readonly createPeerConnection?: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
  /** Batch ICE budget; defaults to WEBRTC_LIMITS.gatheringMs, within timeoutMs.
   * Current usable candidates are published if gathering is still incomplete.
   * Later candidates are not trickled; choose a longer budget when required. */
  readonly gatheringTimeoutMs?: number
}

/** Two independent SCTP streams belonging to one authenticated peer session. */
export interface WebRtcChannels {
  readonly reliable: RtcDataChannel
  readonly live: RtcDataChannel
}

export interface WebRtcSession {
  readonly connection: RtcPeerConnection
  readonly signal: AbortSignal
  readonly signaling: { readonly sentMessages: number; readonly receivedMessages: number; readonly sentBytes: number; readonly receivedBytes: number }
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
