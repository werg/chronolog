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

## Stream context (`v2`)

When multiple local endpoints or runs share one signing identity, attach `stream: { streamId, endpointId, endpointIncarnation, target }` to `send()` and filter with `streams: [...]` in `subscribe()`. Coalescing and filtering apply per stream before queuing.

## Inside `ApplicationSession`

`session.signals` uses the session's signing device, application scope, and verified reader grants. `session.participate()` attaches live peer lanes automatically. Configure delivery with `openPeerApplication({ signals: { delivery: 'neighbors' | 'application', localEcho: false } })`. See [owned participation](../peer-session/README.md#owned-participation-and-recovery).

## Packaging

```sh
pnpm package:signals
pnpm test:signals-package
```
