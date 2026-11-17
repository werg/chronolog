# Live signals

`@chronolog/signals` is a standalone messaging primitive for data useful only
while peers are connected: presence, typing, pointers, previews, response chunks,
device readings and progress. It has **no database, record log, SQL, grant,
validator or finality dependency**. It uses WebCrypto and JSON values.

Use `send(topic, payload, { ttlMs?, signal? })` and
`subscribe({ topics?, mode?, signal? })` everywhere. The same `Signals` interface
is exposed by the Chronolog client, browser peer, resident agent context, and
Tendriller's independently installed signal binding.

Unknown options, including operation IDs, retry flags and replay cursors, fail
with `signal_options_invalid`; they cannot silently imply durable semantics.

```ts
import { SignalChannel, generateSignalIdentity } from '@chronolog/signals'

const identity = await generateSignalIdentity()
const signals = new SignalChannel({
  scope: 'studio:rehearsal',
  identity,
  // Application policy, independent of any database or connection identity.
  authorize: ({ authorId, topic }) => members.has(authorId) && topics.has(topic),
})

// An admitted encrypted transport supplies this small adapter. A route belongs
// to one connection lifetime; closing cancels its pending verification.
const route = signals.attachRoute({
  send: (frame, { signal }) => connection.send(frame, { signal }),
  close: () => connection.close(),
})
connection.onFrame(frame => route.receive(frame))
connection.onClose(() => route.close())

await signals.send('typing', { active: true }, { ttlMs: 1500 })
for await (const message of signals.subscribe({ topics: ['typing'], mode: 'latest', signal: viewLifetime })) {
  showTyping(message.authorId, message.sessionId, message.payload, message.expiresAtMs)
}
```

The envelope contains `scope`, `authorId`, `sessionId`, `sequence`, `topic`,
`payload`, `issuedAtMs`, and `expiresAtMs`. `authorId` is the lowercase hexadecimal
Ed25519 public key. A random session ID and positive sequence identify messages
within this live channel lifetime. They are not durable operation IDs or cursors.
`generateSignalIdentity()` supplies a non-extractable signing key; applications
can instead supply their own existing WebCrypto signing identity.

## Delivery choices

| Mode | Contract | Typical use |
| --- | --- | --- |
| `all` (default) | Bounded FIFO in receive order. Distinct messages are never silently coalesced. | Preview chunks, transient actions, sensor samples |
| `latest` | Replace pending values for the same author, session and topic. Delayed older values cannot regress an already consumed newer value. | Presence, pointers, typing, current progress |

Subscriptions are live from their first iterator `next()` call and do not replay
earlier messages. RPC or transport setup may still be asynchronous: creating an
iterator is not a cross-peer readiness acknowledgment. A local send is not
echoed back as a received message; use its returned envelope for optimistic
local display. Consumers see only unexpired messages. When the FIFO or latest-key bound is exceeded, that
subscription ends with `signal_subscription_overflow`; it cannot falsely appear
complete after silently losing a queued chunk. Latest mode keeps independent
senders and independent sessions separate.

Send completion means dispatch on at least one attached live route, not remote
receipt, processing or dispatch to every peer. A stalled route does not delay a
healthy route's dispatch. Partial route failures are visible
through `onError`. Zero routes, total route failure, overload and cancellation
reject the call. A send uses the routes attached when it began; it never waits
for a reconnect, switches to a replacement route, or enters a persistent outbox.
Cancellation stops waiting and cancels route work. Bytes already handed to a
transport cannot be unsent. Routes must honor their abort signal. A transport may refuse before accepting bytes with
`SignalError('signal_route_backpressure')`; this preserves the route and does not
queue a retry. A failed or noncooperative write retires that route and invokes its optional `close()` hook.
Unsettled writes and policy callbacks keep their capacity slots even after
cancellation; replacing the connection cannot evade these bounds.

Direct channels throw `SignalError` with a typed `SignalErrorCode`. The RPC client
maps these to actionable RPC categories such as `permission_denied`,
`transport_unavailable`, `resource_exhausted` and `invalid_argument`, preserves
the original code in `details.signalCode`, and marks them `retryable: false`.
The application may send a new current observation after recovery; an old live
message is not a durable operation to retry.

Loss, disconnect and expiration remain possible even on a reliable transport.
Use application sequence numbers when a preview must detect a missing chunk,
and replace an incomplete preview with the durable completed result. Use durable
events when every item must survive recovery.

## Peer forwarding, trust and resource limits

Every message is signed over a separate `signal/1` envelope. Set `relay: true`
explicitly to forward accepted originals to other attached routes; a standalone
channel does not relay by default. Receiving verifies
the signature, scope, expiry and current authorization before delivering or
forwarding. Relays preserve the original bytes and author; duplicate paths return
`null` from `receive()` and cannot create echo loops. Expired valid messages also
return `null`. Each transport uses its returned route's `receive()` so
connection close cancels pending verification before admission. Concurrent verification and policy checks retain receive-call order at admission.
FIFO delivery admits distinct out-of-order messages; a high sequence number does not silently discard an older
unseen event. Duplicate protection retains entries through expiry and refuses
new entries when full, rather than evicting protection for live messages. A full
shared receive-work budget rejects `route.receive()` with `signal_backpressure`
before admission; it does not retain the frame for retry. The governed peer
adapter treats that refused live datagram separately from reliable replication.

Signatures authenticate author and contents. **Confidentiality and recipient
admission belong to the transport.** A message topic or a payload claiming a role
grants no authority. A scope is an application isolation name, not a secret.

The default limits are 16 KiB per signed message, 30-second maximum TTL,
5-second default TTL, 2-second clock skew, 32 pending sends, 32 pending receives,
one in-flight send per route, 32 routes and outstanding route operations,
16 subscriptions, 64 pending messages or latest keys per subscription,
256 KiB queued bytes per subscription, and 4096 live duplicate entries. Send deadlines
default to 5 seconds and cover asynchronous authorization as well as transport
dispatch. Receive verification and authorization have their own 5-second deadline
and are interrupted by channel or source-route closure. Iterator return and
subscription abort release their quota even when a consumer is idle or paused at
a yielded value. Local time never moves backward after expiry has been observed. Bounds are configurable; TTL and deadlines cannot exceed five
minutes. Validate deployment clock synchronization for the configured skew.

An expired message is not evidence of another peer's disconnect. Applications
expire their own presence or progress display at `expiresAtMs`. Slow or offline
peers have only the authorization state they already know.

## Chronolog composition

`createCapabilitySignals()` in `@chronolog/capabilities` adapts already
verified group membership to this standalone primitive. It checks the original
signer's current signal-topic rights. It creates no proposal, receipt, event
cursor or durable write, and does not request finality. SQL and durable topic
rights remain independent; a signal-only writer grant can set `sql: false` and
`topics: []`. A read-only device can receive without having send rights.

`peer.connectPeer({ connection })` in both browser profiles, and resident
`context.connectPeer({ connection })`, attach the same governed connection
composition, `createGovernedPeerService()` from
`@chronolog/agent-service/governed-peer`. An optional `signal` owns authentication
and the whole session; `peerIdentity` pins a specific endpoint. They authenticate current reader rights, attach record replication,
and attach signal routes only when the connection provides an independent live
lane. They relay verified originals and retire both attachments on close. The
channel and its subscriptions outlive individual routes; losing one route does
not end delivery from other peers. Reconnect creates a fresh route with no signal replay. Applications
call `peer.signals`, `client.signals`, or `context.signals`; they do not manage
grant IDs, signatures, packet forwarding or private keys themselves.

The governed service binds each endpoint's signing key and advertised feed to
its current reader grant. Compact finalized membership controls can establish
these permissions before application history is applied. Constructing the
service requires no writer grant; sending still requires current signal-topic
rights.

Signal policy can use known membership while a finality provider is unavailable.
That does not make a new governance revision active or make a pending durable
transaction final. A receiving agent must separately decide whether the original
sender has permission to request an external action. Recovery-sensitive effects
start from final accepted durable intent; never replay signals in a projection.

## Packaging and verification

`pnpm package:signals` builds a dependency-free ESM package, TypeScript
declarations, exact input/module provenance and a local npm archive. It rejects
dirty source unless `--allow-dirty` is supplied for local development. The build
audits that every runtime input belongs to this package and that the output has
no imports. Packing does not publish anything. `pnpm test:signals-package`
installs that exact tarball offline into a fresh directory, checks an ordinary
Node consumer, typechecks portable declarations, and bundles the installed public
browser entry without workspace aliases or dependencies.

The standalone tests exercise delivery, reordered paths, expiry, replay bounds,
authorization, overload and cancellation. Governed composition tests connect
three real framed peers, relay original messages, and require zero durable
history reads even when history and finality providers are unavailable. The
contrib `share-live-signals` check independently consumes the built public module
without a database or finality service.
