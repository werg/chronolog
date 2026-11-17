# Chronolog

Chronolog is an owned application session for browser Workers and native peers.
One eligible peer orders commands. All readers verify the original author,
selected order and execution contract, then materialize the same history.

The application API has one command journal, one query and event model, and one
replication and recovery lifecycle. Participant roles determine what a participant
may receive or do. Transports deliver those same scoped messages. A server can
participate in control, discovery and signed code publication without receiving
application bodies or executing ordinary commands.

This is prerelease software. Breaking changes update every maintained consumer;
there are no alternate legacy applications, profile selectors or migration layers.

## Application contract

- `command()` saves one signed, encrypted attempt before sending it. An exact
  retry preserves the original bytes and operation identity.
- `applied()` reports acceptance or rejection at a generation and sequence.
  `shared()` reports independently retained copies of that prefix.
- `query()` and `readView()` capture coherent state. SQL, events, outcomes and
  revision switch together during recovery.
- A signed control transition selects a replacement coordinator. It may adopt
  an earlier surviving prefix. Excluded work remains inspectable and requires
  deliberate reapplication with a new linked identity.
- Revocation and other control state do not roll back with application data.
  Reader, writer, coordinator, recovery and administration rights are explicit.
- Live signals and encrypted chunked content use the same session identity,
  ownership and lifetime. They do not create another outbox or host data path.
- Irreversible external effects require an explicit protected service. Applying
  an ordinary command never dispatches such an effect automatically.

A healthy generation continues with every host endpoint blocked. If both the
coordinator and control service are unavailable, commands stay saved locally.
The system does not fabricate a successor or promise that all data copies survive.

## Start with the public session

See the [session guide](packages/peer-session/README.md) for application
definitions, owned storage, enrollment, network connections, Worker ownership,
control attachment, publication, content, recovery and local agent tools.

```ts
const session = await openNativeApplication({ device, definition, authority })
const control = session.connectControlParticipant({ exchange })
try {
  const before = await session.query('messages', null)
  const operation = await session.command('say', { text: 'Hello' }, {
    operationId: crypto.randomUUID(), basedOn: before.revision,
  })
  const result = await operation.applied()
  console.log(result.generation, result.sequence, result.outcome)
} finally {
  await session.close()
}
```

`definition` is the shared schema-validated command/query declaration. `device`
is explicitly created or enrolled and then resumed; missing keys never silently
create a replacement identity. `authority` is the signed descriptor, controls and
generation chain. `exchange` is the hosted participant transport. Attaching it
performs no I/O and does not give the host reader access.

A browser uses the same session in an owning Worker, with OPFS and a Web Lock.
Native storage uses SQLite and an exclusive writer lock. The page facade forwards
to that owner. Closing the session releases owned transports, streams and storage.

## Package boundaries

| Package | Responsibility |
| --- | --- |
| `peer-session` | Public lifecycle, commands, queries, operation journal, recovery, content, keys and tools |
| `peer-generation` | Signed authority, ordering, selected ancestry, replica verification and participant protocol |
| `records` | Shared byte store, native/browser ownership and bounded transport framing |
| `materializer` | Execution contract and SQL-free event implementation |
| `materializer-doltlite` | Deterministic SQL execution with native and WASM engine adapters |
| `transport-webrtc` | RTC connections, bounded delivery and signaling mechanics |
| `signals` | Replaceable, bounded ephemeral application signals |
| `protocol`, `crypto`, `canonical` | Programs, canonical encodings, digests and cryptography |
| `conformance` | Execution equivalence, crash/reopen and resource qualification |

`peer-generation-v1` is the immutable signed record format identifier. It does
not select a different application runtime or public API. SQL availability is an
explicit engine capability; participant transport and role do not alter replay.

## Build and qualify

Use Node 24 and the pinned package manager:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm lint
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
corepack pnpm docs:check
```

Package the supported composition from clean source:

```sh
node tools/package-peer-session.mjs
node tools/package-peer-session.mjs --native-rtc --output artifacts/peer-session-rtc
node tools/package-peer-session.mjs --sql-native --output artifacts/peer-session-sql
node tools/package-peer-session.mjs --sql-browser --output artifacts/peer-session-sql-browser
node tools/package-peer-generation-control.mjs
```

Archives include self-contained declarations, shared ESM chunks and exact source,
tree, input and artifact hashes. Native SQL packaging requires the exact patched
engine. The default browser/native session archive remains SQL-free. A development
archive requires explicit `--allow-dirty` and records that fact.

The [independent Tendriller recipes](https://github.com/werg/tendriller-contrib/tree/refactor/owned-peer-data-plane/cookbooks/run-a-peer-application)
consume these packages and qualify conversation, guarded tasks, native RTC,
browser ownership and actual hosted control/publication. CI pins exact consumer
commits. Loopback and local Worker results do not establish Internet reachability,
TURN behavior, browser suspension, or provider cost savings.

Read the [architecture](docs/peer-generation-v1.md), [SQL contract](docs/implementation-specs/10-deterministic-sql-transactions.md)
and [qualification guide](docs/release-hardening.md) for the trust and operating
limits. There is no mandatory permanent resident or hosted command executor.
