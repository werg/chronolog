# `@chronolog/signals`

Portable, signed, bounded ephemeral JSON signal channel. No database, durable outbox, or SQL dependency.

```ts
await signals.send('typing', { active: true }, { ttlMs: 2500, signal })
for await (const msg of signals.subscribe({ topics: ['typing'], mode: 'latest', signal })) {
  render(msg.authorId, msg.payload, msg.expiresAtMs)
}
```

## Key properties

- Every message carries `scope`, `authorId`, `sessionId`, `sequence`, `topic`, `payload`, `issuedAtMs`, and `expiresAtMs`, signed with Ed25519.
- Payloads are bounded canonical JSON (max 16 KiB frame, 32 depth, 4,096 nodes).
- `mode: 'all'` delivers bounded FIFO; `mode: 'latest'` coalesces to the highest sequence per `(author, session, topic, stream)`. Overflow fails with `SIGNAL_SUBSCRIPTION_OVERFLOW`.
- Busy routes return `false` immediately; if all routes refuse, `send()` rejects with `SIGNAL_BACKPRESSURE` without queuing retries.
- Replay caches and pending budgets are strictly bounded. Unauthorized, duplicate, or expired valid frames return `null` without tearing down the route.

## Standalone usage

```ts
const channel = new SignalChannel({ scope, identity, authorize })
const route = channel.attachRoute({ trySend, close })
// Pass inbound frames to route.receive(frame); close route on disconnect.
```

Set `relay: true` to forward verified frames to sibling routes (`delivery: 'application'`), and `localEcho: true` to deliver local sends to local subscribers.

## Receive freshness and diagnostics

`maxClockSkewMs` defaults to 2,000 ms and accepts values from 0 through
10,000 ms. After verifying the signature and current authorization, a receiver
drops a frame whose `issuedAtMs` is more than that tolerance ahead of its local
clock, or whose `expiresAtMs` has already passed. These freshness drops return
`null`; they do not close an attached peer's reliable replication lane. Changing
the tolerance does not synchronize clocks. A sender sufficiently behind the
receiver can still produce already-expired frames.

Malformed timestamp/sequence/TTL fields, invalid signatures, oversized frames,
and actual transport failures retain their explicit error paths. They are not
reclassified as harmless clock skew. Dropped frames are neither delivered nor
relayed, and do not consume replay identities.

`route.diagnostics` returns a detached snapshot of nonfatal drops with fixed counters:
`{ total, clockSkew, expired, unauthorized, duplicate, capacity }`. Every counter
saturates at `Number.MAX_SAFE_INTEGER`. Fatal errors retain their failure path and
are not counted as these drops. Counters describe this receive route,
contain no signal payloads or per-author history, and are not an estimate of a
remote clock offset. These counters are available on the owning `SignalRoute` and
an instrumented `ApplicationPeerLink.stats.signalRejections` or `session.diagnostics()`
entry. Receive snapshots are detached and contain no payloads. A link without an
instrumented live route omits these fields; implementations must not invent counters.

A successful `send()` confirms only the configured local/route dispatch.
`localEcho: true` can succeed from local delivery even without a remote route;
it never establishes remote receipt or processing. Work that must survive an
absent receiver belongs in durable application commands/events.

## Worker presence

A presence signal is an expiring statement by its authenticated signer, not proof
that a particular request was read or answered. A native session owner, transport
forwarder and assistant worker may share that signer while having different
lifetimes. Advertise only the consumer/run and request topics that the actual
worker can handle. Stop publishing when that worker exits, even if the owning
session and other workers remain connected.

Filter availability by verified `authorId` plus the intended consumer and handled
topic; never let a payload's `author` replace authenticated origin. Bind timers,
subscriptions and sends to the worker's cancellation scope. Send a stopped state
on graceful shutdown when possible, and expire stale observations after a crash.
Use receipt and answer commands for durable handling evidence; periodic durable
heartbeats are unnecessary for an idle presence indicator. Neither a delivered
signal nor an open peer route wakes an ended model conversation.

When several local workers share the same signal topic, use stream context to
keep their latest values independent before consumer-side filtering.

## Stream context (`v2`)

When multiple local endpoints or runs share one signing identity, attach `stream: { streamId, endpointId, endpointIncarnation, target }` to `send()` and filter with `streams: [...]` in `subscribe()`. Coalescing and filtering apply per stream before queuing.

## Inside `ApplicationSession`

`session.signals` uses the owned signing device, application scope and `$signal_policy` authorization cached per `stateRoot`. Authenticated `session.connectPeer()` links attach the independent live lane; the session forwards application-scoped signals and allows local echo without opening a network route. The page facade provides bounded `send`/`subscribe` RPCs and owner-bound endpoint context, without receiving the private key. For other standalone dispatch policies, configure `SignalChannel` directly. See [the peer-session API](../peer-session/README.md#core-session-api).

## Packaging

```sh
pnpm package:signals
pnpm test:signals-package
```
