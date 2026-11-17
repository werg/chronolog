# Portable peers, history policies, and live enrollment

Chronolog executes SQL locally on each replica. Signed records, governance,
proposal identity, finality, and SQL replay are shared between the native daemon
and the browser Worker. Ordering is always the protocol's deterministic
chronological comparator. The group signs its inclusion/finality provider into
genesis. Tendriller is an optional receipt store and finality-service host.

This is an unreleased architecture. New groups use the current format directly;
there is no compatibility decoder or data migration path for earlier prototypes.

## Package boundaries

| Package | Owns |
| --- | --- |
| `@chronolog/records` | Original signed feed records, continuity, immutable evidence, durable storage contract, range synchronization, streams, in-process connections, and injected cryptography. |
| `@chronolog/transport-ssb` | Native SQLite storage and authenticated SSB connections using the common record verifier and synchronization machinery. |
| `@chronolog/node-core` | Exact durable proposals, membership, the two history policies, certificates, live enrollment, and the `createGovernedNode` composition. |
| `@chronolog/control-store` | The derived admission/order index and durable validator signing cutoffs. |
| `@chronolog/materializer-doltlite` | One SQL reducer, ownership checks, checkpoints, replay, and separate immutable local/final readers. Native and browser entrypoints inject their engine driver. |
| `@chronolog/runtime-browser` | An owning Worker, OPFS storage, Web Lock ownership, real patched DoltLite WASM, and the shared RPC contract over Worker messages. |
| `@chronolog/transport-webrtc` | Provider-independent WebRTC negotiation, bounded data channels, direct Worker ownership and optional native Werift adapter. |
| `@chronolog/transport-tendriller` | An optional adapter and on-demand prefix authority composed with public Tendriller packages. |
| `@chronolog/client`, `@chronolog/rpc` | The common application interface across native HTTP, embedded peers, and browser Workers. |

Tendriller's own core owns opaque bytes, exact-byte deduplication, rolling roots,
retained reads, quotas, and host access control. It has no Chronolog membership,
SQL engine, or certificate interpretation. The authority reads its own committed
head and signs the immutable group/history configuration plus that head. It does
not execute SQL, accept a caller-selected root, or put certificates into the log
being certified.

## One ordering rule, pluggable finality

| Property | Peer validators | Signed inclusion service |
| --- | --- | --- |
| Admission | The signed fixed-validator policy. | Verified inclusion plus the original signature, permission and dependency checks. |
| SQL/event order | Author timestamp, signing key, stable proposal identity. | Exactly the same comparator. Receipt position is never execution order. |
| Late delivery | Can change a tentative suffix through replay. | A new proposal at or below its first inclusion's already-closed time is rejected. Exact retries keep their result. |
| Finality | Complete validator feeds, admission references and cutoff promises. | Complete inclusion evidence and signed closure history, all needed bodies/keys, and local application through the closed timestamp. |
| Membership activation | Signed old-revision closures with complete validator evidence. | Signed membership predecessor chain activated at its proved closed timestamp boundary. |
| Provider outage | Progress depends on the required validators. | New closures stop; existing certified history remains usable. |

The core always sorts with `compareTransactionOrder`. The materializer executes
that order; a finality plugin cannot supply a sorter. An old capability cannot be
revived by backdating a transaction or by regranting a new capability to the same
key. Each governed proposal binds its exact writer capability ID. See the
[provider contract](pluggable-finality.md) for injected verifiers and closure proofs.

Validators, validation policy, root issuer, administration feed, execution
profile, and coordinated authority/history are fixed for this initial scope.
Reader/writer membership and encryption keys remain live. Authoring unsupported
consensus reconfiguration is rejected before signing or publication.

## Identity, retries, and retained evidence

Three identities answer different questions:

| Identity | Meaning |
| --- | --- |
| Signed feed record ID | The exact original author, feed sequence, predecessor, and payload. Relaying preserves these fields. |
| Proposal ID | A digest of the canonical signed transaction payload. Re-encapsulation does not create another SQL operation. |
| Log position and root | The proposal envelope's position in one retained canonical history. Exact bytes recover their original append receipt. |

A caller operation ID is durable local state. Before sending, the operation
journal persists the exact canonical proposal and signed envelope, including the
chosen timestamp, nonce, grant, and encryption envelope. After a lost response,
recovery finds the original locally authored record and completes publication of
the same bytes. Reusing an operation ID with different input is an error. Completed
operations remain addressable after reconnect, process restart, and revocation;
a new operation still requires current write authority.

Ordered-entry mappings and prefix certificates are immutable evidence on the
ordinary peer record substrate. The native and browser transports exchange that
evidence over the same range/stream connection used for signed feeds. A peer that
has the evidence and keys can rebuild final SQL without contacting the authority.
Head notifications are hints; they never advance applied cursors themselves.
Rollback, conflicting history, and nonprogressing retained reads stop recovery
with a visible error.

## Local and final SQL are different readers

```ts
import { TransactionRejectedError } from '@chronolog/client'

const handle = await client.transaction([
  { sql: "SELECT chronolog_assert((SELECT claimed_by FROM tasks WHERE id = ?) IS NULL, 'already_claimed')", params: [taskId] },
  { sql: 'UPDATE tasks SET claimed_by = ? WHERE id = ?', params: [workerName, taskId] },
], { operationId: operationId })

const provisional = await handle.local()
const finalOutcome = await handle.final({ signal })
if (finalOutcome.outcome.type === 'rejected') {
  throw new TransactionRejectedError(handle.transactionId, finalOutcome.outcome.rejection)
}
const finalRows = await client.query('SELECT * FROM tasks ORDER BY id', [], {
  view: 'final',
})
```

`local()` returns the executed result at its current position in the local order.
Both live proof providers allow provisional execution before inclusion; later
eligible history can change that tentative outcome.
`final()` waits for the transaction's actual locally applied final position.
SQL reads default to the final view; choose `view: 'local'` explicitly for
optimistic state.
`query(..., { view: 'final' })` reads a separately pinned SQL revision; it does
not read tentative rows and attach final metadata to them. Live queries include
the selected view in their identity and resume after finality-only events too.

A deterministic SQL failure rejects the whole transaction and records its code
and failing step. Missing history, an unavailable epoch key or engine profile,
and storage/engine failures block progress. They are not fabricated application
rejections. Replaying an already final prefix cannot alter its SQL outcome.

## Compose a governed replica

The runtime supplies durable storage, identity, connection, and engine adapters.
The shared composition owns their protocol relationship:

```ts
import { createGovernedNode } from '@chronolog/node-core'

const peer = await createGovernedNode({
  genesis,                  // Verified signed group configuration.
  groupRoute,
  identity,                 // This device's durable Ed25519 identity.
  transport,                // Original signed records plus immutable evidence.
  operationStore,           // Atomic persistent local values; one storage owner.
  controlStore,             // Persistent admission index and signing cutoffs.
  materialization,          // createDoltLiteMaterializationRuntime(...).
  recipient: { id: identity.publicKeyBytes, privateKey: readerPrivateKey },
})
await peer.start()
```

The native daemon uses this composition. Browser code imports its browser
entrypoint and uses `openBrowserPeer` to create the identity, records, operation
journal, control database, and SQL engine inside the owner Worker. The same
configuration and client contract apply; private keys stay inside that Worker.
See the [browser runtime](../packages/runtime-browser/README.md) for its build,
headers, ownership, and qualification commands.

## WebRTC data plane

[WebRTC transport](../packages/transport-webrtc/README.md) introduces peers with one
complete SDP offer and answer, then closes signaling. The browser transfers its
reliable and live data channels together into the owning Worker. Native peers use the optional
Werift adapter. The existing authenticated peer session exchanges original
records, detached bodies and finality evidence on the reliable lane, with
separately bounded expiring signals on the live lane; the host does not carry ordinary
application frames. STUN/TURN configuration and reconnection are explicit.

`tools/test-browser-webrtc.ts` verifies actual native/Chromium interoperability,
OPFS ownership, final event convergence, large payloads and original retries
after the page/signaling host has stopped. This loopback gate does not establish
Internet direct-connect rates or provider savings.

## Live reader/writer enrollment

Enrollment uses the running device's durable signer, reader key, and original
feed identity. The request binds the group, signed genesis, history policy,
execution profile, requested roles, and exact request ID. It never transmits a
private key.

1. Initialize the new replica with the group's public descriptor and connect it.
2. The new replica calls `client.enrollment.createRequest` with a durable request
   ID and requested reader/writer roles.
3. The root approves those exact signed bytes with a durable operation ID and an
   explicit `grantFullHistory` decision.
4. The new replica imports the signed approval through `getStatus`, receives its
   grants and keys, and applies the captured final target.

Readiness distinguishes requested, approved, authorized but disconnected,
awaiting keys, awaiting history, unsupported engine, revoked, and ready states.
A grant alone is not readiness. Required historical keys and actual final SQL
application are checked independently. Reader/writer enrollment never adds a
validator. See the [client guide](../packages/client/README.md) for complete API
examples.

Receiving administrative records and activating them are separate operations.
A late coordinated reader can receive a verified historical-key grant from later
in the certified prefix before decrypting earlier SQL. Membership still activates
at the grant's proved chronological closure boundary. Peer governance closes the old
revision through signed validator promises and complete feed scans; receipt of a
new snapshot alone does not establish a revocation boundary.

## Verification map

| Acceptance concern | Executable evidence |
| --- | --- |
| Original signed bytes, feed continuity, common replication and evidence | `packages/records/src/*.test.ts`; `packages/transport-ssb/src/feed-transport.test.ts` |
| Durable proposal identity through a lost response and whole-node reopen | `test/rpc-durable-submit.e2e.test.ts` |
| Complete startup restoration and health recovery after transient SQL failures | `test/node-recovery.e2e.test.ts` |
| Final readers, final waits, and finality-only live-query updates | `test/sql-client-node.e2e.test.ts`; `packages/client/src/transaction-handle.test.ts` |
| Signed closure barriers and interrupted validator publication | `packages/node-core/src/peer-governance.test.ts`; `validator-closures.test.ts` |
| Live native enrollment, historical keys, revocation and retained final SQL | `test/governed-peer.e2e.test.ts` |
| Canonical activation, backdating/regrant attacks, reopen, and relay-only key recovery | `packages/node-core/src/coordinated-governed.integration.test.ts` |
| Packed public Tendriller API, retry/restore errors, contested collective SQL and offline third-peer replay | `packages/transport-tendriller/src/*.test.ts` |
| Native/WASM replay hashes, outcome equality, SQL policy and reopen | `packages/runtime-browser/src/wasm-conformance.test.ts` |
| Real Chromium Worker, OPFS, exclusive owner, public client, final SQL and termination recovery | `tools/test-browser-peer.ts`; `test/browser/page.ts`; `test/browser/peer-worker.ts` |
| Combined browser/native public enrollment, collective claim, reload retry and offline third-peer replay | `tools/test-browser-bridge.ts`; `tools/browser-bridge-fixture.ts`; `test/browser/bridge-worker.ts` |
| Native abrupt process death at each publication boundary | `test/materializer-publication-crash.integration.test.ts` |

The initial scope does not add log compaction, authority failover, dynamic
validator sets, root/authority rotation, multiple issuers, bearer invitations,
execution-engine upgrades. Existing native snapshot tools
are separate from this full-history portable path.
