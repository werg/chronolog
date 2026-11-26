# `@chronolog/transport-webrtc`

Implements `FramedPeerConnection` over WebRTC for browser and native (`werift`) peers using two fixed SCTP channels (`chronolog.peer.v2`): stream 0 for reliable ordered history/control and stream 1 for unordered disposable live signals, plus in-band W3C Perfect Negotiation for mid-session RTP media tracks and dynamic `app:*` binary/text DataChannels.

## How it integrates with `ApplicationSession`

Every peer link authenticated by `session.connectPeer({ connection, peerIdentity })` shares one `RTCPeerConnection`:

- **Authentication & encryption**: Chronolog membership and `ApplicationSecureChannel` authenticate `peerId` and encrypt both CRDT replication and in-band renegotiation control frames (`kind: 'rtc'`).
- **Mid-session tracks & custom channels**: After initial connection, adding/removing RTP tracks (`addTrack` / `removeTrack` / `onTrack`) or opening custom DataChannels whose labels start with `app:` (`openDataChannel` / `onDataChannel`) negotiates entirely peer-to-peer over the authenticated `ApplicationSecureChannel`—no extra external signaling round-trips.
- **Session inspection**: Native and owned sessions expose active links via `session.peerLinks()` and `session.onPeerLink(listener)`.
- **Browser Worker bridge**: In browsers, the active tab's Window owns `RTCPeerConnection` and local `MediaStreamTrack`s while its dedicated Worker owns keys, storage, and Chronolog execution. `serveWorkerWebRtcConnections(endpoint)` registers live `PagePeerHandle`s on the Window (`peers()`, `onPeer(listener)`) and bridges Chronolog's fixed SCTP streams plus in-band `rtc` frames to `openWorkerWebRtcConnection(endpoint, options)` in the Worker (from `@chronolog/peer-session/webrtc`).

## Native peer connection

```ts
import { openWebRtcConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection, createNativeAudioTrack } from '@chronolog/transport-webrtc/native'

const connection = await openWebRtcConnection({
  role: 'answerer',
  signaling,
  configuration: { iceServers },
  createPeerConnection: config => createNativePeerConnection(config),
  signal: lifetime,
})
const peer = await session.connectPeer({ connection, signal: lifetime })
await peer.synchronize()
```

`./native` wraps `werift` (including `createNativeAudioTrack()` for outbound Opus RTP) and is excluded from browser bundles. No default STUN/TURN server is chosen implicitly.

## Direct HTTP introductions

A reachable native peer can accept SDP offers over HTTPS via `createWebRtcOfferHandler({ allowedOrigins, authorize, configuration, createPeerConnection, accept, onError })`; callers use `createHttpWebRtcSignaling({ url, headers, signal })`. Established RTC connections continue after signaling closes.

## Negotiation and framing bounds

- **Trickle ICE initial handshake**: Exchanges bounded SDP descriptions (max 64 KiB) and trickled ICE candidates (`sendCandidate` / `onCandidate`), signaling `markConnected()` once ICE connects; falls back cleanly to gathered-offer behavior when a signaling adapter does not support trickle candidates.
- **In-band Perfect Negotiation & ICE restart**: Deterministic polite/impolite role assignment (tie-broken by peer identity), glare rollback, and debounced ICE restart on transient `disconnected`/`failed` states.
- **Flow control**: Reliable stream enforces bounded message sizes, credit-based backpressure, and write deadlines via `@chronolog/records`.
- **Live lane**: `live.trySend()` returns `false` on congestion rather than queuing retries.
- **Route inspection**: `connection.getRoute()` reports `direct`, `relay`, or `unknown` without exposing IP addresses.

Use the maintained `session.connectPeer()` and browser/native RTC adapters from `@chronolog/peer-session`. Product-owned discovery/residency code chooses reconnects and an explicit WebSocket relay fallback; those choices do not assign application operation order. See [attachment boundaries and lifetime](../peer-session/README.md#attachment-boundaries-and-lifetime).
