# WebRTC peer transport

This package carries Chronolog's existing authenticated peer protocol over a
reliable ordered WebRTC data channel. A reachable resident accepts one HTTPS
offer and returns one answer; the page host need not participate. An explicitly
coordinated pair can also use a separate signaling service. Once connected, records, finality
proofs, detached application bodies and ephemeral signals travel over WebRTC.
Stopping the signaling host does not stop an established peer connection.

The transport has no Cloudflare, Tendriller, database, enrollment or application
write semantics. `openAuthenticatedPeerLink` still authenticates signing keys
and checks current reader capabilities before serving data. An authenticated
host account or successful ICE connection does not authorize database reads.

## Cold connection to a resident

Publish the resident's HTTPS introduction address in the initial page or
deployment configuration. A new browser can then contact the running resident
directly. The resident does not need a Cloudflare socket, a polling loop, a
model turn, or a test fixture to notice that browser.

The resident mounts this portable `Request`/`Response` handler on its own HTTPS
server. Its `accept` port fits the ordinary `AgentApplicationContext`:

```ts
import { createWebRtcOfferHandler } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

const introductions = createWebRtcOfferHandler({
  allowedOrigins: ['https://application.example'],
  authorize: (request, signal) => admission.authorizeIntroduction(request, signal),
  configuration: { iceServers },
  createPeerConnection: configuration => createNativePeerConnection(configuration),
  accept: connection => context.connectPeer({ connection }),
  onError: reportPeerFailure,
})
// Mount introductions.fetch(request) at the published resident HTTPS address.
// The resident's final shutdown awaits introductions.close().
```

`authorize` is required and must return exactly `true`; it admits an introduction,
not database access. Deployment supplies its admission mechanism. Exact allowed
browser origins and a bounded preflight are checked separately. Native clients
without an `Origin` header still undergo authorization. Once the channel exists,
`context.connectPeer` performs the Chronolog nonce/signature handshake and checks
current reader capabilities before serving application data.

The Window uses the public HTTP signaling adapter with the existing synchronous
Worker handoff:

```ts
import { createHttpWebRtcSignaling, negotiateWebRtc } from '@chronolog/transport-webrtc'

const signaling = createHttpWebRtcSignaling({
  url: deployment.residentIntroductionUrl,
  headers: introductionAdmissionHeaders,
})
const session = await negotiateWebRtc({
  role: 'offerer', signaling, configuration: { iceServers },
  onDataChannel(channel) {
    const transferable = channel as RTCDataChannel
    worker.postMessage({ type: 'peer-channel', channel: transferable }, [transferable])
  },
})
```

The wire protocol is `chronolog.webrtc.v1`: one JSON POST containing a complete
offer, and one JSON answer response. The resident returns the answer **before**
waiting for ICE/DTLS or the Chronolog handshake; waiting for connection completion
before answering would deadlock a cold browser. HTTP credentials are omitted,
redirects are rejected, and admission headers are explicit. Endpoint URLs require
HTTPS without credentials, query or fragment; HTTP is restricted to loopback
qualification. The public Node-only `@chronolog/transport-webrtc/resident`
entrypoint exports `createWebRtcHttpsListener({ endpoint, listen, tls,
...introductionOptions })`. Its `run(signal)` owns the HTTPS listener and
accepted peers until cancellation; deployment supplies TLS credentials, bind
address, allowed origins and admission. The contrib cookbook supplies application
composition around this transport, including a resident task and synchronous
Worker handoff.

The handler defaults to eight pending introductions, 32 total pending/live
connections and a 30-second deadline covering introduction and authentication.
Each JSON message is limited to 128 KiB and each SDP to 64 KiB. Request buffers
and stream fragment counts have fixed bounds; authorization and connection waits
have deadlines. Closing native connections retain their capacity slots until cleanup finishes.
Application acceptance receives a cancellation signal and late accepted sessions
are closed. `stats` exposes pending/live counts and introduction outcomes.

Completing an HTTP response, closing the client's signaling adapter, or stopping
only the HTTPS listener does not close an established RTC connection. Closing
the handler is the resident shutdown operation and closes its accepted peers.
No application frame is carried through the introduction endpoint.

Cold connection requires a resident HTTPS endpoint reachable by the browser and
an available ICE route. An unreachable resident needs an explicit wake or
discovery arrangement or an existing peer connection. This package does not
create an idle host subscription to conceal that reachability requirement.

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

## Owning reconnection

`supervisePeerSession` owns a connector's attempt/session lifetime and explicit
retry policy. An example for a native transport client is:

```ts
import { createHttpWebRtcSignaling, openWebRtcConnection, supervisePeerSession } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

const connections = supervisePeerSession({
  readiness: 'transport',
  retry: { initialDelayMs: 500, maxDelayMs: 15_000, maxAttempts: 8, jitter: 0.2, resetAfterMs: 30_000 },
  signal: applicationLifetime,
  async connect(signal) {
    const connection = await openWebRtcConnection({
      role: 'offerer', signal, configuration: { iceServers },
      signaling: createHttpWebRtcSignaling({ url: residentIntroductionUrl, headers: introductionAdmissionHeaders, signal }),
      createPeerConnection: configuration => createNativePeerConnection(configuration),
    })
    return { signal: connection.session.signal, transport: connection, close: () => connection.close() }
  },
})
await connections.ready
// Later callers need current readiness, not the already resolved first session.
const current = await connections.waitForSession({ signal: operationLifetime })
console.log(await current.transport.session.getRoute())
// The application lifetime closes the attempt and current session together.
await connections.close()
```

The connector receives a fresh cancellation signal and returns a session with
`signal` and `close()`. It must honor cancellation and close partially acquired
resources on failure. The supervisor fences a cancelled attempt and closes a
late successful result, even if that connector ignored cancellation. Session
loss aborts the attempt signal before asynchronous cleanup, so a stale Worker
attachment cannot become the next session. Only one attempt/session is owned at
a time. State observers cannot interrupt cleanup.

The states are `connecting`, `connected`, `waiting` and `stopped`, with an
attempt count, error and scheduled retry time. The first successful session
resolves `ready`; `waitForSession` returns the current live session or waits for
the next one. A waiter's cancellation does not cancel the shared connection.
`completion` rejects on retry exhaustion. `close()` cancels a pending retry or
dial; replacing the supervisor is an explicit manual retry.

A healthy session has no supervisor timer, heartbeat, host subscription or
discovery request. Only failures schedule bounded exponential retry with jitter.
Brief connections consume the existing attempt budget; it resets only after
`resetAfterMs` of connected time, measured when a session ends. This prevents a
flapping resident from creating an unbounded stream of introductions. The
policy should target the configured resident directly; it does not turn the
coordinated Tendriller rendezvous into a resident polling service.

Readiness is explicit. `transport` means negotiation completed. For
`authenticated`, the connector must await its native peer or owning Worker's
Chronolog authentication and attachment before returning. In a browser it still
transfers the untouched data channel synchronously. Neither readiness level
claims that durable history replay, SQL materialization or finality has caught
up; those belong to the replica's progress APIs.

## Observing the actual route

`WebRtcSession.getRoute()` observes the selected ICE pair through browser or
native WebRTC statistics. It returns `route: 'direct' | 'relay' | 'unknown'` and
the local/remote candidate types, without exposing network addresses. A selected
`relay` candidate on either endpoint means TURN is carrying traffic. Both known
nonrelay candidates establish a direct route. Missing, ambiguous or unavailable
selected-pair evidence remains `unknown`; neither a successful handshake nor
the absence of configured TURN is used to invent a direct-route result.

This is an on-demand observation, with no background statistics poll. Framing
byte counters still measure logical payload bytes, excluding ICE, SCTP, DTLS,
IP and relay billing overhead. Route observations and payload counters should
be reported separately from signaling counts and provider billing.

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
frames after signaling closes and verifies their measured direct route.
`supervisor.test.ts` checks bounded retry, flapping sessions, independent waiter
cancellation, immediate attempt fencing and late-result disposal. `route.test.ts`
covers selected direct/relay pairs and incomplete observations. `http.test.ts` checks admission, origins, body and
concurrency limits, stalled request cancellation, native cleanup, and a real
HTTP cold introduction followed by RTC exchange after its listener stops.

```sh
pnpm exec vitest run packages/transport-webrtc/src
CHRONOLOG_CHROMIUM_EXECUTABLE=/path/to/chromium \
  node --import tsx tools/test-browser-webrtc.ts \
  --contrib /checkout/tendriller-contrib --output artifacts/browser-webrtc
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
