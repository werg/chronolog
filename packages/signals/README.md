# Live signals

`@chronolog/signals` is a portable signed JSON channel. It has no database,
governance, SQL engine, finality provider, durable identity or reconnect outbox.
Its `Signals` interface matches the application port exposed by Tendriller:

```ts
await signals.send('typing', { active: true }, { ttlMs: 2500, signal })
for await (const message of signals.subscribe({ topics: ['typing'], mode: 'latest', signal })) {
  render(message.authorId, message.payload, message.expiresAtMs)
}
```

Each authenticated message contains string `scope`, `authorId` and `sessionId`
(the latter two are 64-character lowercase hex identifiers),
plus `sequence`, `topic`, `payload`, `issuedAtMs` and `expiresAtMs`. Payloads are
bounded canonical JSON. The signing key and an optional opaque credential are
bound into the wire signature; the supplied authorization callback interprets
that credential and checks the current topic policy.

## Build and consume the standalone package

This package is not yet published to npm. The source workspace and the native
distribution already include it; an independent browser/Node package is built
deliberately from a source checkout:

```sh
pnpm install --frozen-lockfile
pnpm package:signals
pnpm test:signals-package
```

Run these commands from the Chronolog repository root with its pinned pnpm.
Packaging requires committed package inputs and creates
`artifacts/signals/chronolog-signals-<commit8>.tgz`. The archive contains a bundled
ES module, public TypeScript declarations, this guide and source provenance with
content hashes. It has no runtime, optional or peer dependencies. It needs no
workspace aliases, TypeScript loader, database or Chronolog protocol package.
The repository's CI and release-evidence workflows build and verify this same
archive and preserve it as a workflow artifact. They do not publish it to npm.

`test:signals-package` installs the current commit's tarball in a separate
directory with an empty npm cache and offline mode. It verifies signed delivery
from ordinary Node ESM, compiles a strict TypeScript consumer, checks the content
hashes and bundles the installed browser entry. Pass `--artifact /path/package.tgz`
to qualify another exact archive. For local debugging, pass `--allow-dirty` to
`package:signals`, then select its `-dirty.tgz` archive with
`test:signals-package --artifact /path/package-dirty.tgz --allow-dirty`. These
packages are explicitly marked dirty and are not release evidence.

Install an exact archive into the consuming application, then use the imports
shown below:

```sh
npm install --offline --ignore-scripts --no-audit --no-fund "/absolute/path/chronolog-signals-<commit8>.tgz"
```

Use Node.js 22 or newer, or a browser with WebCrypto Ed25519 and the standard
`AbortSignal` APIs. Browser applications bundle the package through its public
ESM export. The package uses platform cryptography and has no Node-specific code.

## Standalone composition

Construct `new SignalChannel({ scope, identity, authorize })` with an Ed25519
identity and the application's current authorization policy. Use
`generateSignalIdentity()` for a fresh standalone key; persisting or restoring
that key belongs to the application. The package depends only on canonical
encoding and browser WebCrypto, with its own strict JSON payload validation. An
optional `credential` may be fixed bytes or a function that selects the current
credential for each topic. Both `authorize(input, { signal })` and
`credential(topic, { signal })` receive the attempt's `AbortSignal`: pass it to
network policy/credential requests so caller cancellation, expiry and channel
closure release their work promptly. Check current authorization when that work
completes. An optional `trySend` callback supplies a standalone
outgoing transport; pass its incoming frames to `channel.receive(frame)`.

For bidirectional routes, call `channel.attachRoute({ trySend, close })` and give
incoming frames to that returned route's `receive(frame)`. The transport hook
returns `Promise<boolean>`: `true` means local dispatch, and `false` refuses the
attempt before queueing or dispatching any bytes. Refuse immediately when the
live lane is busy; do not retain the value for retry. Actual transport failures
throw. This byte-transport contract has no dependency on Chronolog errors,
governance or finality. Successful application `signals.send` returns the
authenticated envelope after at least one route dispatches.

Verified, currently authorized messages are delivered locally. Set `relay: true`
to relay their original signed bytes to other live routes; standalone relay is
disabled by default. Close the route when its connection ends. Distinct fresh
sequences may arrive out of order through different paths; duplicate
author/session/sequence identities are suppressed. The bounded replay cache
drops incoming messages when full instead of evicting protection for still-fresh
messages.

`receive()` and an attached route's `receive()` return `null` for duplicate,
expired or currently unauthorized valid messages, and for input dropped at the
shared receive-work or replay-memory bound. A busy receive queue drops before
verification; a current policy denial is checked after signature verification.
None of these drops retains a retry, delivers or relays the message, or closes
the route. Writer revocation can therefore discard an in-flight observation
without disrupting a still-authorized reader's history replication. Malformed
frames, invalid signatures and exceptions from the policy remain errors. Reader
connection admission is enforced independently by the connection owner.

Start a subscription before the messages it should observe. A new subscriber
receives no earlier value, and a channel does not echo its own outgoing messages
to its subscriptions; use the result of `send()` for optimistic local display.
Returning an iterator cancels even an idle pending read. Closing and reopening a
channel creates a fresh random session with no retained outbox.

The transport supplies confidentiality and connection access. Signatures alone
do not encrypt a message or authorize a connection to read a database.

## Delivery and bounds

`subscribe()` defaults to `mode: 'all'`, a bounded FIFO in local admission order.
`mode: 'latest'` keeps the highest sequence for the same author/session/topic,
including after that value is consumed, so a reordered older message cannot
replace a newer one. Its bounded per-key sequence memory lasts for the maximum
remaining signal lifetime. Both
modes fail the subscriber with `SIGNAL_SUBSCRIPTION_OVERFLOW` when the selected
queue cannot hold another distinct value. Consumers must treat that failure as a
gap. Cancellation releases the subscription even when its consumer is paused.

| Bound | Default |
| --- | --- |
| Encoded frame / credential | 16 KiB / 1 KiB |
| Maximum TTL / tolerated future clock skew | 30 seconds / 2 seconds |
| Outgoing attempt timeout | 10 seconds, also bounded by the message TTL |
| Pending sends / receives | 32 / 32 |
| Live routes / subscriptions | 64 / 16 |
| Queue per subscription / remembered latest keys | 64 messages and 256 KiB / 64 keys |
| Sender sessions / distinct remembered identities | 1,024 / 8,192 |
| Distinct remembered identities per sender session | 1,024 |

Topics contain at most 128 characters matching `[A-Za-z0-9][A-Za-z0-9._/-]*`.
Scopes contain 1–256 UTF-8 bytes. JSON payloads permit finite numbers, at most
32 nesting levels and 4,096 nodes, without accessors, sparse arrays or lossy
serialization.

These `SignalLimits` are independently configurable within fixed upper bounds.
Governed composition accepts the same options through
`createGovernedPeerService({ ..., signalLimits })`; configuring live budgets does
not alter the group's durable protocol or permission grants. The
maximum configurable TTL is 60 seconds. Queueing does not restart a message's
TTL, and a local clock rollback cannot revive an expired frame.

A send captures its eligible routes when called; receiving a frame captures its
eligible relay routes before verification. Closing a route removes it from that
attempt, and a replacement connection can receive only later attempts. Resolution
means at least one route accepted local dispatch; it does not acknowledge remote receipt
or application processing. A healthy route can complete a send while another
route remains busy. Each route permits at most one unsettled dispatch and has
its own deadline. Policy and credential work that ignores cancellation stays
counted against its work quota until it actually settles. A detached busy route
also occupies its route slot until the underlying work settles, so repeatedly
replacing stalled routes cannot create unbounded work. Existing healthy routes
remain usable.

If every route is busy or explicitly returns `false`, public `send` rejects with
`SIGNAL_BACKPRESSURE`. Congestion creates a live delivery gap; it does not retire
healthy routes or interrupt durable replication. A new send is a fresh
observation, and the channel never retries a discarded one. `true` and `false`
are the only valid transport results. A transport exception or invalid result
retires that route and invokes its optional `close()` callback; the connection
owner should close its underlying session there. A dispatched write that ignores
cancellation is also retired. Some routes may have dispatched before an attempt
later rejects, and cancellation cannot recall those bytes. Reconnect never
resends prior messages.

## Owned application sessions

`ApplicationSession` from `@chronolog/peer-session` exposes `session.signals`
using the session's durable signing identity and application scope:

```ts
// Bind this callback to the UI event handler.
function onTyping(active: boolean) {
  return session.signals.send('typing', { active }, { ttlMs: 2500 })
}

for await (const message of session.signals.subscribe({
  topics: ['typing'], mode: 'latest', signal: viewLifetime,
})) {
  render(message.authorId, message.payload)
}

```

The session checks authors against its current verified reader grants. Durable
writer and coordinator permissions remain separate. A newly granted reader can
establish its rights through the shared authenticated peer handshake, and reader
removal retires its connection when the verified control update arrives.
An offline device can only enforce authority it has already received.

`session.participate()` owns discovery, connection replacement and recovery.
Authenticated connections attach their separate bounded live lanes to the same
signal channel. Reconnection starts fresh signal delivery, and closing the
session closes its routes and subscriptions. The host control participant's
interest policy keeps ordinary live signals on peer connections. Signals leave
application history and its applied revision unchanged.

See [owned participation](../peer-session/README.md#owned-participation-and-recovery)
for the common native and browser lifecycle.

### Concurrent endpoint and run streams

Use the versioned signed stream context when several runs or local endpoints share
one signing participant and topic:

```ts
await signals.send('progress', { completed: 3 }, {
  stream: { streamId: retainedRunId, endpointId, endpointIncarnation, target: 'reviewer' },
});
for await (const progress of signals.subscribe({
  topics: ['progress'], streams: [{ streamId: retainedRunId }], mode: 'latest',
})) { /* Update only this run. */ }
```

Selectors are an OR of at most 64 exact field matches and run **before** queueing
or coalescing. Replacement keys include verified author, channel session, topic,
endpoint/incarnation, stream ID and recipient scope. A stream cannot replace a
sibling run's pending progress. The existing per-subscription cardinality and byte
budgets still apply. Endpoint ID and incarnation must be supplied together. A
session owner replaces client-supplied endpoint fields with its actual port binding;
a standalone signer attests its own context. Context is not an independent identity
grant or a privacy boundary.

Unaddressed frames retain the v1 wire format. Addressed stream frames use
`chronolog/signal/v2` and sign the complete bounded context. Receiving and
forwarding preserve the original signer. Unsupported older readers reject v2;
applications must negotiate a compatible artifact instead of silently discarding
stream attribution.

`SignalChannel.delivery` reports `neighbors` by default, or `application` when
bounded forwarding is explicitly enabled using `relay: true`. Forwarding preserves
expiry and replay checks and never creates a durable delivery guarantee. One route
accepting dispatch does not prove all intended recipients received it. An owner can
opt into `localEcho: true` for local attachments, including signal-only operation
without a network route. It uses the same bounded subscriber queues. In a peer
session, configure these deliberately through `openPeerApplication({ signals:
{ delivery: 'neighbors', localEcho: true } })`; `delivery: 'application'` explicitly
enables the forwarding mode. Durable results belong in application history.
