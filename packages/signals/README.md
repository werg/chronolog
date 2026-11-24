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
remote clock offset. The same optional `signalRejections` snapshot is available
on `ApplicationPeerLink.stats` and each `session.participation.diagnostics()`
connection. A missing field means that implementation does not report it.

A successful `send()` confirms only the configured local/route dispatch.
`localEcho: true` can succeed from local delivery even without a remote route;
it never establishes remote receipt or processing. Work that must survive an
absent receiver belongs in durable application commands/events.

## Stream context (`v2`)

When multiple local endpoints or runs share one signing identity, attach `stream: { streamId, endpointId, endpointIncarnation, target }` to `send()` and filter with `streams: [...]` in `subscribe()`. Coalescing and filtering apply per stream before queuing.

## Inside `ApplicationSession`

`session.signals` uses the session's signing device, application scope, and verified reader grants. `session.participate()` attaches live peer lanes automatically. Configure delivery with `openPeerApplication({ signals: { delivery: 'neighbors' | 'application', localEcho: false } })`. See [owned participation](../peer-session/README.md#owned-participation-and-recovery).

## Packaging

```sh
pnpm package:signals
pnpm test:signals-package
```
