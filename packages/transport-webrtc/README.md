# WebRTC peer transport

This package carries Chronolog's existing authenticated peer protocol over a
reliable ordered WebRTC data channel. The page host introduces peers with one
complete offer and one complete answer. Once connected, records, finality
proofs, detached application bodies and ephemeral signals travel over WebRTC.
Stopping the signaling host does not stop an established peer connection.

The transport has no Cloudflare, Tendriller, database, enrollment or application
write semantics. `openAuthenticatedPeerLink` still authenticates signing keys
and checks current reader capabilities before serving data. An authenticated
host account or successful ICE connection does not authorize database reads.

## Native peer

The optional `./native` entrypoint adapts pinned Werift 0.27.0. Browser bundles
import only the main entrypoint and never include Werift or Node modules.

```ts
import { openWebRtcConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

const connection = await openWebRtcConnection({
  role: 'answerer',
  signaling, // PeerSignaling: messages, send(description), close().
  configuration: { iceServers },
  createPeerConnection: configuration => createNativePeerConnection(configuration),
  signal,
})
const session = await agent.context.connectPeer({ connection })
// The ordinary native inclusion service consumes replicated proposals and
// shares immutable certificates/closures through this same connection.
```

No public STUN/TURN server is selected implicitly. Supply the deployment's ICE
servers explicitly. Native network binding and port ranges can be passed as the
factory's second argument. TURN, if configured, is transport relay capacity; it
is separate from the page host and does not change Chronolog authorization or
finality. The direct-connect success rate depends on the deployed network and
must be measured. If a connection fails, create a fresh signaling session; this
transport does not silently switch to an application-data host relay.

## Browser ownership

`RTCPeerConnection` negotiation belongs to the Window. Transfer its data channel
immediately to the exclusive Chronolog Worker, which retains private keys,
OPFS, authentication, frame processing and synchronization:

```ts
// Window. A rendezvous assigns the role for this particular session.
const session = await negotiateWebRtc({
  role,
  signaling,
  configuration: { iceServers },
  onDataChannel(channel) {
    const transferable = channel as RTCDataChannel
    worker.postMessage({ type: 'peer-channel', channel: transferable }, [transferable])
  },
  signal,
})

// DedicatedWorker, receiving the transferred RTCDataChannel.
const connection = frameRtcDataChannel(channel)
await connection.ready
const authenticated = await openAuthenticatedPeerLink({
  connection, local: transport.asLink(), groupId, identity, grantId,
  authorizePeer,
})
const detach = transport.connect(authenticated.link)
void authenticated.completion.finally(detach).catch(reportConnectionFailure)
```

The handoff callback must be synchronous. Do not send, await, delay, wrap the
callback in a Promise, or store a data channel for later transfer. The WebRTC
transfer operation is only valid immediately after creation or receipt. A
browser without channel-transfer support fails explicitly. `session.close()`
closes the underlying peer connection; release the authenticated Worker session
and its feed attachment as part of the same application lifecycle.

Tendriller's `peers.rendezvous(channel, peerId)` can implement the signaling
port. Await `rendezvous.ready` to obtain `role`; pass the rendezvous object as
`signaling`. No Tendriller imports are required here. Signaling is closed when
negotiation completes or fails. A new connection receives a new session and
must perform a new Chronolog nonce/signature handshake.

## Bounded protocol

`PeerSignaling` exchanges exactly one complete SDP per peer, with a 64 KiB UTF-8
maximum. Both sides wait for ICE gathering completion. A negotiation has an
explicit deadline and cancellation signal; it cannot wait forever for a lost
answer or abandoned channel.

The data channel uses protocol `chronolog.peer.v1`, reliable delivery and
ordered messages. Each packet is at most 16 KiB. The framing header commits a
protocol version, message kind, complete frame size and exact fragment offset.
Unexpected messages, fragments, credit, partial frames and unreliable channels
fail visibly.

Whole-frame credit limits receiver allocations to 4 MiB and 16 pending frames.
Credit is returned only when the consumer advances its iterator after processing
a frame. This bounds both payload memory and object count. Send queues have the
same limits, and the RTC `bufferedAmount` budget separately bounds queued SCTP
writes. Individual Chronolog frames are limited to 1 MiB plus 64 KiB. Queued
sends snapshot their input, preserve order and have a deadline. Closing the
channel rejects pending sends and wakes blocked readers. These bounds are local
resource guarantees; protocol authentication remains the responsibility of the
Chronolog session above them.

`ready` requires both local and remote framing HELLO messages. Its 10-second
HELLO deadline starts after the local channel opens, allowing ICE negotiation
to finish first. Worker consumers await `ready` before starting Chronolog's
separate authenticated-session handshake deadline.

## Verification

`packages/transport-webrtc/src/channel.test.ts` checks fragmentation, exact bytes,
credit/backpressure, invalid frames and close behavior. `native.test.ts` connects
two real Werift implementations over loopback ICE/DTLS/SCTP and exchanges large
frames after signaling closes.

```sh
pnpm exec vitest run packages/transport-webrtc/src
CHRONOLOG_CHROMIUM_EXECUTABLE=/path/to/chromium \
  node --import tsx tools/test-browser-webrtc.ts --output artifacts/browser-webrtc
```

The browser gate runs a real native governed finality service and a Chromium
OPFS event peer. It transfers the RTCDataChannel into the owning Worker, closes
the loopback HTTP page/signaling host, publishes from both peers, retries an
original operation, transfers a 512 KiB content-addressed body and compares
final events plus original-record digests. Its JSON report records exact source
state, runtime versions, signaling counters, post-close RTC bytes and payload
hashes. `--build-only` only compiles and audits the browser graph; it does not
produce a passing runtime report. The gate does not establish Internet NAT
success rates, TURN interoperability, packaged Tendriller host behavior or
provider cost savings.
