# WebRTC peer transport

This package implements the `FramedPeerConnection` used by an ordinary Chronolog
application session. Browser and native peers use the same connection,
authentication, commands, history synchronization and content protocol. WebRTC
supplies two independent channels: reliable ordered application/control traffic
and disposable live traffic.

RTC negotiation supplies its channels to the transport-neutral framing, flow
control and lifetime owner in `@chronolog/records`, also used by the WebSocket
adapter. The application session authenticates and encrypts both lanes through
one channel implementation, checking signing keys, current grants, update scope
and signatures. Successful HTTP admission or ICE negotiation never grants access to
application data. A hosted control participant attaches through
`session.connectControlParticipant({ exchange })`; its restricted HTTP transport
does not carry the peer's database or ordinary content traffic.

## Native connection

Supply a signaling port and deployment ICE configuration, then attach the
resulting connection to the same application session that owns commands and
views:

```ts
import { openWebRtcConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

const connection = await openWebRtcConnection({
  role: 'answerer',
  signaling,
  configuration: { iceServers },
  createPeerConnection: configuration => createNativePeerConnection(configuration),
  signal: applicationLifetime,
})
const peer = await session.connectPeer({ connection, signal: applicationLifetime })
await peer.synchronize()
// The owning application lifetime eventually closes peer and connection.
```

The optional `./native` entrypoint adapts the pinned Werift implementation.
Browser imports never include Werift or Node modules. No STUN or TURN server is
selected implicitly. Native interface bindings and port ranges can be supplied
as the factory's second argument. The maintained fallback uses two independent
WebSockets through the host relay; it does not require a TURN service. See the
[session connection guide](../peer-session/README.md#owned-participation-and-recovery)
for direct and relay openers under the same participation owner.

## Direct HTTP introduction

A reachable peer can accept one complete offer and return one answer. Mount the
portable `Request`/`Response` handler in the deployment's HTTPS server:

```ts
import { createWebRtcOfferHandler } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

const introductions = createWebRtcOfferHandler({
  allowedOrigins: ['https://application.example'],
  authorize: (request, signal) => admission.authorizeIntroduction(request, signal),
  configuration: { iceServers },
  createPeerConnection: configuration => createNativePeerConnection(configuration),
  accept: (connection, signal) => session.connectPeer({ connection, signal }),
  onError: reportPeerFailure,
})
// Serve introductions.fetch(request) at the published HTTPS address.
// Final application shutdown awaits introductions.close().
```

The answer is returned before ICE, DTLS and Chronolog authentication complete so
that a cold caller can finish connecting. The handler bounds request bytes,
concurrent introductions, accepted connections, authorization and connection
waits. Deployment supplies HTTPS, admission and allowed origins. Admission must
return exactly `true`. Native clients without an `Origin` header still undergo
authorization.

An initiating peer uses `createHttpWebRtcSignaling({ url, headers, signal })` as
its signaling port. The wire protocol performs one JSON POST and one answer;
credentials are omitted, redirects are refused and admission headers are
explicit. Endpoint URLs require HTTPS without credentials, query or fragment;
HTTP is restricted to loopback qualification. Signaling closes after negotiation.
An established RTC connection continues after the signaling endpoint stops.
Closing the introduction handler explicitly closes the peers it accepted.

A hosted rendezvous can also implement `PeerSignaling` by exposing
`messages`, `send(description)` and `close()`. It carries the two bounded batch SDP
descriptions. Application frames always use the resulting peer connection.

## Browser ownership

The Window owns `RTCPeerConnection` and raw framing through
`openWebRtcConnection`. The maintained Worker bridge is
`serveWorkerWebRtcConnections(endpoint)` on the page and
`openWorkerWebRtcConnection(endpoint, options)` in the owning Worker, exported by
`@chronolog/peer-session/webrtc`. It sends bounded opaque frames and ACKs over an
ordered authenticated endpoint, without creating or transferring ports or
RTCDataChannels. This works with DedicatedWorkers, started SharedWorker ports and
virtual authenticated endpoints. Keys, storage, peer authentication and
application state remain in the Worker. The raw RTC callbacks do not move an
application participant onto the page.

See [the portable endpoint contract](../peer-session/README.md#owned-participation-and-recovery)
for endpoint ownership, bounds, cancellation, route diagnostics and actual browser
qualification. Each replacement connection performs a fresh Chronolog handshake.

## Connection lifecycle and retry

`session.participate()` in `@chronolog/peer-session` owns discovery, connection
attempts, reconnect grace, bounded backoff and verified recovery policy. Inject
this package's `openWebRtcConnection` as the raw opener. The common session
authenticates each result and verifies history before considering it a recovery
candidate. A transport supplies delivery and cancellation; it has no second
retry controller or authority policy.

In a browser, use the session package's `openWorkerWebRtcConnection` with the
page's `serveWorkerWebRtcConnections` bridge. Discovery, signaling, authentication
and recovery remain with the owning Worker. The page supplies RTC mechanics.
See [owned participation](../peer-session/README.md#owned-participation-and-recovery)
for the common native and browser lifecycle contract.

## Bounded reliable and live lanes

Negotiation exchanges one bounded batch SDP per peer, with a 64 KiB maximum,
a whole-attempt deadline and cancellation. Gathering waits for completion or
`gatheringTimeoutMs`, whichever comes first. The exported `WEBRTC_LIMITS.gatheringMs`
is the single default (1,000 ms); the native adapter derives its default Werift
STUN timeout from that constant in seconds. An explicit batch budget must be a
positive integer within `timeoutMs`. The owning-Worker bridge forwards this option.

If gathering is incomplete at the budget, negotiation publishes the current SDP
only when it contains a usable candidate allowed by `iceTransportPolicy`; otherwise
it fails with `WEBRTC_ICE_CANDIDATES_UNAVAILABLE`. The entire current SDP is kept,
including host, server-reflexive and relay candidates already gathered. STUN/TURN
configuration is preserved. This is batch signaling, not trickle ICE: candidates
arriving after publication are not exchanged. A network needing slower STUN/TURN
must choose a longer batch and whole-attempt budget (and, for the native factory,
an appropriate explicit `iceStunGatherTimeout`/TURN connect timeout). A host-only
partial batch does not establish public-NAT reachability. No polling or additional
signaling service is introduced.

Fixed negotiated SCTP channels use protocol
`chronolog.peer.v2`: stream 0 is reliable and ordered; stream 1 is unordered with
`maxRetransmits: 0`. Unexpected remotely opened channels are refused.

Shared reliable framing limits complete messages, packet sizes, partial frames, queued
sends and receiver credit. Credit is returned only after the reader advances
past the processed frame. Queued writes capture their input and have deadlines.
Closing the connection rejects pending writes and releases blocked readers.

The live lane has independent receive and buffered-amount budgets.
`live.trySend(frame, { signal })` returns `false` before dispatch when congested;
actual failures throw. It never queues a reliable retry. Slow receivers drop
old disposable datagrams while reliable replication continues. Both lanes share
the network and SCTP association, so independent queues do not reserve bandwidth.

The session authenticates every live update and enforces current permissions,
application scope, replay protection and expiry. It bounds concurrent live
verification. A live lane cannot replace a missing durable record and is never
multiplexed into reliable history.

## Route observation and qualification

`WebRtcSession.getRoute()` observes the selected ICE candidate pair on demand.
It reports `direct`, `relay` or `unknown` and candidate types without exposing
network addresses. A relay candidate indicates TURN; incomplete or ambiguous
statistics remain unknown. A successful handshake alone does not establish a
direct route. Route observations, logical payload bytes and signaling counts
are separate measurements.

The package tests cover exact framing, credit, cancellation, live congestion,
retry ownership, route evidence, HTTP admission and actual loopback
ICE/DTLS/SCTP exchange after signaling closes:

```sh
pnpm exec vitest run packages/transport-webrtc/src
```

The maintained application qualification uses the packed common session through
`tools/test-peer-session-webrtc.ts` and the contrib native/browser fixtures.
Browser qualification bridges opaque RTC frames to the owning Worker,
continues application work after the host stops, verifies retained history and
checks signals and encrypted content through that same session. Loopback gates
do not establish Internet NAT success rates or TURN interoperability.
