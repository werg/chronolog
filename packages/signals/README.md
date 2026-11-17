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
completes. An optional `send` callback supplies a standalone
outgoing transport; pass its incoming frames to `channel.receive(frame)`.

For bidirectional routes, call `channel.attachRoute({ send })` and give incoming
frames to that returned route's `receive(frame)`. A transport's `send` returns
`Promise<void>` and resolves after local dispatch. If a bounded queue is full,
throw `SignalBackpressureError` before accepting any bytes. Do not queue the
refused message for later; the channel preserves the healthy route for a fresh
intent. Successful application `signals.send` returns the authenticated envelope.
`SignalBackpressureError.is(error)` recognizes the stable `SIGNAL_BACKPRESSURE`
code and explicit `dispatched: false` marker across independently bundled
adapters. A matching code alone never proves that dispatch was refused.

Verified messages are delivered locally. Set `relay: true` to relay their
original signed bytes to other live routes; standalone relay is disabled by
default. Close the route when its connection ends. Distinct fresh sequences may
arrive out of order through different paths; duplicate author/session/sequence
identities are suppressed. A bounded replay cache reports
`SignalBackpressureError` when full instead of evicting protection for still-fresh
messages. That incoming attempt was not admitted; a disposable transport can
drop it while preserving the connection and existing duplicate protection.
`receive()` returns `null` for a duplicate or an otherwise valid, authorized
expired message. Ordinary expiry neither relays a frame nor tears down its
connection. Invalid signatures, malformed frames and failed current
authorization remain errors.

An attached route also returns `null` when the channel's shared receive-work
capacity is full. This is a drop before admission: it does not authenticate,
deliver, remember or relay that frame, and it does not close the route. The
direct `channel.receive(frame)` port instead rejects with `SIGNAL_BACKPRESSURE`
at capacity so its caller can choose its own admission policy. Neither port
retains a frame for later replay.

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

A send is one attempt on the currently attached routes. Resolution means at
least one route accepted local dispatch; it does not acknowledge remote receipt
or application processing. A healthy route can complete a send while another
route remains busy; every route permits at most one unsettled dispatch and has
its own deadline. Policy work that ignores cancellation stays counted against
its work quota until it settles. A low-level transport may throw
`SignalBackpressureError` only when that attempt queued and dispatched no frame.
The application send rejects visibly while the route stays usable for a
later fresh message; nothing retries the refused value. Normal dispatch resolves
without a return value. Any other return value is a transport error. Some
routes can receive a message even when the operation later rejects; cancellation
cannot recall bytes already handed to a transport. When every available route is busy, the public send rejects with
`SIGNAL_BACKPRESSURE`. Congestion creates a live delivery gap without retiring
healthy routes or interrupting durable replication. A fresh send is a new
observation; the channel never retries a discarded one. A failed publication does
not revoke healthy routes. A transport failure or a dispatched write that ignores
cancellation retires that route and invokes its optional `close()` callback;
the connection owner should close its underlying session there. The explicit
`dispatched: false` marker distinguishes a healthy refusal from an arbitrary
transport error. It must never describe a partially dispatched frame or a
closed or failed transport. Reconnect never resends prior messages.

## Governed replicas

`createCapabilitySignals` from `@chronolog/capabilities` supplies the current
membership authorization adapter. `createGovernedPeerService` from
`@chronolog/agent-service/governed-peer` uses that adapter with authenticated
replication routes and relay enabled. It dynamically
selects a current writer-kind capability with the requested signal topic. A
read-only or unenrolled replica can construct the service without publisher
rights; a send fails while those rights are absent.

The service binds the peer's signing key and advertised feed to its current
reader capability. It owns signal routes, replication attachment and session
replacement. Each session exposes `signal`, `completion` and `close()`. Compact
membership controls can establish these permissions before application history
is applied. Rights are evaluated against the latest verified local membership;
an offline replica cannot know a revocation it has not yet received. Signal traffic never advances an application frontier or finality.
