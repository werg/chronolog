/** The small browser/native WebRTC surface used by the transport. */
export interface RtcDataChannel {
  readonly label: string
  readonly ordered: boolean
  readonly maxPacketLifeTime: number | null
  readonly maxRetransmits: number | null
  readonly readyState: string
  readonly bufferedAmount: number
  bufferedAmountLowThreshold: number
  binaryType: string
  send(data: ArrayBuffer): void
  close(): void
  addEventListener(type: string, listener: EventListener): void
  removeEventListener(type: string, listener: EventListener): void
}

export interface RtcPeerConnection {
  readonly localDescription: { readonly type: string; readonly sdp: string } | null
  readonly iceGatheringState: string
  readonly connectionState: string
  createDataChannel(label: string, options: { readonly ordered: boolean; readonly protocol: string }): RtcDataChannel
  createOffer(): Promise<RTCSessionDescriptionInit>
  createAnswer(): Promise<RTCSessionDescriptionInit>
  setLocalDescription(description: RTCSessionDescriptionInit): Promise<void>
  setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void>
  close(): void | Promise<void>
  addEventListener(type: string, listener: EventListener): void
  removeEventListener(type: string, listener: EventListener): void
}

export interface PeerDescription { readonly type: 'offer' | 'answer'; readonly sdp: string }

/** Signaling carries exactly one complete SDP per peer and never application bytes. */
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
}

export interface WebRtcSession {
  readonly connection: RtcPeerConnection
  readonly signal: AbortSignal
  readonly signaling: { readonly sentMessages: number; readonly receivedMessages: number; readonly sentBytes: number; readonly receivedBytes: number }
  close(): Promise<void>
}
