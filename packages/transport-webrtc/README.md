# `@chronolog/transport-webrtc`

Implements `FramedPeerConnection` over WebRTC for browser and native peers using two fixed SCTP channels (`chronolog.peer.v2`): stream 0 for reliable ordered history/control and stream 1 for unordered disposable live signals.

## Native peer connection

```ts
import { openWebRtcConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

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

`./native` wraps Werift and is excluded from browser bundles. No default STUN/TURN server is chosen implicitly.

## Direct HTTP introductions

A reachable native peer can accept batch SDP offers over HTTPS via `createWebRtcOfferHandler({ allowedOrigins, authorize, configuration, createPeerConnection, accept, onError })`; callers use `createHttpWebRtcSignaling({ url, headers, signal })`. Established RTC connections continue after signaling closes.

## Browser Worker bridge

In browsers, the Window owns `RTCPeerConnection` while the Worker owns keys, storage, and authentication. Use `serveWorkerWebRtcConnections(endpoint)` on the page and `openWorkerWebRtcConnection(endpoint, options)` in the Worker (from `@chronolog/peer-session/webrtc`).

## Negotiation and framing bounds

- **Batch SDP**: exchanges one bounded SDP (max 64 KiB) per peer. Gathering waits until completion or `gatheringTimeoutMs` (default `WEBRTC_LIMITS.gatheringMs = 1000` ms). Fails with `WEBRTC_ICE_CANDIDATES_UNAVAILABLE` if no usable candidate was gathered.
- **Flow control**: reliable stream enforces bounded message sizes, credit-based backpressure, and write deadlines via `@chronolog/records`.
- **Live lane**: `live.trySend()` returns `false` on congestion rather than queuing retries.
- **Route inspection**: `connection.getRoute()` reports `direct`, `relay`, or `unknown` without exposing IP addresses.

Use the maintained `session.connectPeer()` and browser/native RTC adapters from `@chronolog/peer-session`. Product-owned discovery/residency code chooses reconnects and an explicit WebSocket relay fallback; those choices do not assign application operation order. See [attachment boundaries and lifetime](../peer-session/README.md#attachment-boundaries-and-lifetime).
