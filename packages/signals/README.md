# Ephemeral signals

`@chronolog/signals` sends small live messages without a database. Use it for
presence, cursors, typing, live previews, progress, sensor samples, notifications
that may be missed, and transient stream chunks. It depends on the portable
canonical byte codec only. It does not open a log, store an operation, load SQL,
wait for finality, contact an authority, or replay after reconnect.

```ts
import { SignalChannel, generateSignalIdentity } from '@chronolog/signals'

const signals = new SignalChannel({
  scope: 'workshop-room',
  identity: await generateSignalIdentity(),
  // This example intentionally admits every signed identity in this room.
  // Private applications supply their own allowlist or credential policy.
  authorize: () => true,
  send: async (frame, { signal }) => transport.send(frame, { signal }),
})
transport.onFrame(frame => signals.receive(frame))

await signals.send('progress', { completed: 7, total: 10 }, { ttlMs: 5_000 })
for await (const message of signals.subscribe({ topics: ['progress'], signal })) {
  renderProgress(message.payload)
}
```

`transport` is an application-owned byte transport; it must provide transport
confidentiality when payloads are private. Signatures authenticate the original
sender and the exact scope, topic, payload, expiry, session and sequence. They do
not encrypt the message or grant access. The required `authorize` callback is an
explicit application policy. Optional `credential` bytes are opaque to this
package; a callback can choose current credentials for each outgoing topic. A
receiver verifies the signature before checking its current authorization policy.

Start a subscription before the messages you want to observe. Each channel owns
only live subscribers. It retains no last value for a newly opened subscriber.
Returning an iterator cancels its pending read and releases its subscription, even
while the channel is idle; an `AbortSignal` provides the same explicit lifetime.
Subscriptions do not receive the channel's own outgoing messages; use the result
of `send` for local optimistic display.

## One application interface

```ts
interface Signals {
  send(topic, payload, { ttlMs?, signal? }?): Promise<EphemeralSignal>
  subscribe({ topics?, mode?: 'all' | 'latest', signal? }?): AsyncIterable<EphemeralSignal>
}
```

An `EphemeralSignal` contains `scope`, `topic`, JSON `payload`, the original
`authorId` and `sessionId` as 64-character lowercase hex strings, positive safe
integer `sequence`, and `issuedAtMs` / `expiresAtMs`. Its identity is the tuple
`(scope, authorId, sessionId, sequence)`. It has no durable operation ID, event
cursor, transaction outcome or finality status.

| Choice | Meaning |
| --- | --- |
| `mode: 'all'` (default) | Keep every accepted unexpired message in the subscriber's bounded FIFO. If the consumer falls behind its limit, end that subscription with `SIGNAL_SUBSCRIPTION_OVERFLOW`. |
| `mode: 'latest'` | Keep the newest received value per author, session and topic. Intermediate values and oldest keys may be discarded under pressure. Use this for replaceable state. |
| `send()` resolves | At least one currently attached local route completed dispatch. This does not prove a remote subscriber received or acted on the message. |
| No route | `send()` rejects `SIGNAL_DISCONNECTED`. No message is saved for later delivery. |
| Reconnect | Attach a new route and send fresh presence/progress. There is no catch-up or automatic resend. |

`all` is not reliable delivery: a transport or overloaded receiving peer can drop
messages before acceptance, disconnected peers miss them, and expired values are
discarded. FIFO describes one subscriber's accepted-message queue; signals have
no global order. Async verification or multiple routes can reorder messages.
Applications needing every stream chunk should detect gaps themselves or use a
reliable stream; applications needing an auditable final result should publish
that result as a durable event. A successful local dispatch never authorizes an
external effect that requires a durable decision.

For typing and cursors, choose `latest`, key UI state by the original author and session, and
remove it at `expiresAtMs`. Receipt and dequeue both reject expired messages;
already rendered UI still needs its own expiry timer. Explicit `false` / cleared
payloads can remove state sooner. Disconnection does not synthesize an offline
message. Clear connection-local UI on disconnect and accept fresh state after
reconnection.

## Connections and relays

`channel.attach(sendFrame)` adds a live route and returns a detach function bound
to that attachment. A delayed detach cannot remove a replacement route. The
optional constructor `send` is one initially attached route. The channel signs
each outgoing message once and distributes those bytes over the attached routes.

`relay: true` additionally forwards a verified incoming frame to live routes.
Relays preserve its original signature and sender; they cannot re-author it as
themselves. Session replay windows stop loops. Relay permission is explicit, and
the transport adapter must recheck recipient access before releasing bytes.
Receiving applications must still authorize the original sender.

`close()` aborts pending sends, ends subscriptions, detaches routes and discards
replay state. Reopening starts a fresh random session; it never reloads messages.
Caller cancellation interrupts a send but cannot retract bytes already handed
to a transport. A route should honor the provided `AbortSignal`. Each route permits only one outstanding dispatch. Busy routes are skipped and
aborted or timed-out routes are detached, bounding further work even when a route
ignores cancellation. A healthy route can complete a send while another route is
still slow; one peer cannot disable the other routes.

## Bounds and replay protection

The entire signed frame is at most 16 KiB. Topics use
`[A-Za-z0-9][A-Za-z0-9._/-]*` and at most 128 characters. Scopes contain 1–256
UTF-8 bytes. Payloads are strict JSON with finite numbers, depth at most 32 and at
most 4,096 nodes. Credentials are at most 1,024 bytes. Larger stream/media data
belongs in a suitable transport or a blob reference.

TTL starts at `send()` invocation, including queued and authorization work; a
late send cannot refresh stale data into a new message. Default TTL is five seconds. The channel's default maximum TTL is 30 seconds,
configurable up to 60 seconds; default admitted future clock skew is two seconds,
configurable up to ten seconds. Peers need reasonably synchronized clocks. These
timestamps bound transient usability; they never close durable history.

Each author/session retains a 256-message replay bitmap, allowing bounded
out-of-order verification while rejecting duplicates and values older than that
window. A replay floor remains until every formerly admissible frame has expired,
even if a newer message had a shorter TTL. The default session limit is 1,024;
live replay protection is never evicted to admit another session.

Default bounds are 32 pending sends, 32 receives, 64 subscriptions, 64 messages
per subscription, and 32 attached routes. Each has an explicit constructor
option and hard upper bound. Overload is bounded failure or best-effort loss,
never unbounded memory growth or a durable queue.

## Chronolog group integration

`createCapabilitySignals` from `@chronolog/capabilities` supplies the group policy.
It selects an active grant for the requested topic at each send and checks the
original author's current signal right on receipt. The group scope is the hex
group ID. `program.signals` grants are independent from SQL and durable event
rights: a writer-role grant with `sql: false`, `topics: []`, and
`signals: ['typing']` permits typing only. Reading a group alone does not silently
grant signal publication. Grant changes affect known current policy; an offline
peer cannot know a revocation it has not received.

Governed browser peers expose `peer.signals` and `peer.connectPeer({ connection })`;
the latter attaches both replication and signals to an authenticated peer link.
`ChronologClient.signals` exposes the same application interface through the
public Worker or native RPC transport, with no automatic resend or subscription
replay. Trusted native modules use `context.signals`; `context.connectPeer` wires
their live routes and the resident relays original verified signals. Private keys
remain in the owner Worker or native process.

These adapters add group access control and connectivity. Standalone callers
remain free to use another authorization policy and byte transport with no
Chronolog membership, history, SQL or finality protocol.
