# Local replica RPC

`@chronolog/rpc` exposes the same replica service to native applications and
browser Workers. [contract.ts](src/contract.ts) defines the method mapping and
[types.ts](src/types.ts) defines requests and responses. These TypeScript types
are the implemented API; there is no separate generated RPC schema.

`NodeRpcService` depends on a small structural node interface. It selects SQL
readers, forwards durable publication to the node, and reports outcomes and
enrollment progress. Signed consensus records and history-policy evidence use
their own canonical codecs in `@chronolog/protocol` and `@chronolog/node-core`.

## Live signals

`NodeRpcService({ node, signals })` exposes an injected portable `Signals` port.
Governed native and browser peers wire their owned signal service automatically.
RPC checks the selected group and forwards the caller's cancellation; it does
not author another signal identity, persist an outbox or choose a relay policy.
Closing RPC cancels its live work while the owning peer controls the channel's
lifetime.

| Method | Behavior |
| --- | --- |
| `signals.send` | Sends one topic/payload with optional `ttlMs`, returning its signed signal's public fields. The client makes one attempt. |
| `signals.subscribe` | Streams future live signals with optional topics and `mode: 'all' \| 'latest'`. There is no resume or replay cursor. |

Both methods run through in-process, HTTP and the existing pull-based Worker
transport. Signal identities use string `scope`, `authorId` and `sessionId`;
payloads are JSON values. Authorization, expiry, duplicate suppression, bounded
queues and unchanged-byte forwarding belong to the peer's signal service. A
subscription failure is visible to the caller; reconnecting durable event
streams does not reconnect live signal subscriptions.

## Transports

- `InProcessRpcTransport` runs the service in the same process with copied
  request/response values, cancellation and optional interceptors.
- Native `HttpRpcServer` and `HttpRpcTransport` expose unary JSON requests at
  `POST /rpc/unary/<method>` and streaming JSON lines at
  `POST /rpc/stream/<method>`. The server defaults to `127.0.0.1:8787` and accepts
  a bearer-token configuration.
- `@chronolog/rpc/browser` exports the service, contracts and in-process
  transport without importing native HTTP modules. `WorkerRpcTransport` in
  `@chronolog/runtime-browser` carries that service across a Worker boundary;
  SQL executes in the browser's local owned replica.

SQL BLOBs are `Uint8Array` in the TypeScript API. The HTTP adapter preserves them
with its explicit JSON byte encoding. Digests, public keys, signed enrollment
requests and signed approvals use canonical unpadded base64url strings.

### Limited publisher ingress

An operator can set `HttpRpcServer({ service, token, publisherIngress: true })`
(daemon environment `CHRONOLOG_PUBLISHER_INGRESS=true`) to accept anonymous
**only** at the exact `POST /rpc/unary/ingress.submit` route. Enabling it requires
a non-empty owner RPC token. Read, query, enrollment, governance and local
authoring routes still require that token. The ordinary body bound still
applies. The node validates the original proposal's signature, group, execution
profile and granted topic scope; this route never signs on the publisher's
behalf. A submitted receipt reports durable ingress, not final acceptance.

The browser-safe helper exposes no general RPC or bearer-token parameter:

```ts
import { createHttpPublisherIngress } from '@chronolog/rpc/browser'
import { createLimitedPublisher } from '@chronolog/node-core/browser'

const ingress = createHttpPublisherIngress({ baseUrl: 'https://replica.example', groupId })
const publisher = await createLimitedPublisher({
  descriptor, request, approval, identity, store,
  send: signed => ingress.submitSigned(signed),
})
await publisher.publish('conversation', message, { operationId })
```

The helper omits ambient credentials and rejects redirects. Retry belongs to
the publisher's durable original-signer outbox. Do not give a limited publisher
the owner bearer token or a full `ChronologClient`; those authorize other local
replica operations. A cross-origin deployment must separately configure its
HTTP gateway's allowed origins; the library does not install permissive CORS.

## Queries and immutable results

`query.localSql` and `query.liveSql` accept `view: 'local' | 'final'`; the default
is `final`, matching `view.open`, `view.changes` and durable event reads.
Select `view: 'local'` explicitly when a caller wants a provisional preview.
Final reads return the currently applied prefix; they do not wait for pending
writes to finish.

| View | Reader | Meaning |
| --- | --- | --- |
| `local` | Current locally materialized SQL revision | Includes the selected provisional suffix; synchronization can replay or remove it. |
| `final` | Separate SQL reader pinned to the locally applied immutable prefix | Contains only policy-final transactions that this replica has applied. |

Both views return revision metadata:

- `view` identifies the selected reader.
- `materializedRevision` and `publishedOrderLength` describe that reader.
- `finalRevision` and `finalOrderLength` describe the applied immutable prefix.
- `eventSetRevision` is a local observation cursor, not a consensus proof or a
  portable global sequence.
- `executionManifestDigest` identifies the exact execution profile.

`atRevision` pins a one-shot query to the selected reader's current revision;
an unavailable revision fails instead of silently selecting another view.
Live-query digests bind SQL, parameters, view and row limit. Each selected-reader
revision produces a snapshot/change event, including revisions whose rows are
unchanged. Switching a cursor to a different query or view is rejected.

`view.open` captures SQL, effective events and revision metadata from one locally
applied application prefix. `view.query` and `view.events` use that same capture
until `view.release` or lease expiry. Both final and local captures stay coherent
while the replica receives newer proof or replays its speculative suffix. Leases
are bounded and belong to the RPC principal that opened them; expired views fail
with `revision_unavailable` so the caller can capture a fresh view.

Transaction outcomes contain a separate `final` boolean. `accepted` or
`rejected` alone describes the current program execution result. `final: true`
requires the transaction's stable result to be applied in the local immutable
prefix. Acceptance, rejection, revision and finality are read together without
an intervening asynchronous status query.

Outcome, status, settlement and replication streams start with the complete
current state and then follow live changes. The service subscribes before
reading that state. Resume cursors are hints: a cursor from a previous process
cannot suppress newer finality after the local event counter restarts. Ending
the iterator cancels its node subscription.

Effective events retain `origin` reconstructed from the verified canonical
proposal: the original group, signing author, operation ID, author timestamp,
membership revision and exact writer capability. Captured views, event streams
and HTTP/Worker serialization preserve those facts. Payload fields do not supply
provenance. Effect workers retain the same origin in their durable checkpoints
and apply their own dispatch policy before performing an external action.
Ephemeral messages remain separate `signals.send` calls with no durable event
cursor or automatic retry.

## Application view invalidation and captured reads

`view.changes` accepts `{ groupId, view?: 'local' | 'final' }`, defaults to
`final`, and streams `{ view, revision, finalRevision }`. It uses the normal
authenticated in-process, HTTP and Worker routes. The service validates the
group and view, forwards cancellation, and ends its subscriptions on close.
It delegates directly to the node's applied-view port; opening the stream does
not acquire a read lease, execute SQL or poll the page host.

The first value describes the current successfully published materializer
snapshot. Later values are bounded, coalesced invalidations. Final-only streams
do not report speculative work. Local streams also report final-prefix changes
even when only `finalRevision` changes. Admission, receipt and transport status
alone do not invalidate application data. After reconnect, a fresh subscription
gets current state; this method has no durable cursor.

These `revision` and `finalRevision` strings are the opaque tokens returned by
`view.open`, rather than the numeric materializer revisions in query metadata.
Use `view.open` to capture coherent SQL and events, `view.query` and `view.events`
to read that capture, and `view.release` when finished. The capture may be newer
than a notification; its own tokens identify its data. Incomplete or uncertain
publication cannot expose changed data under an old token. Durable event
processing remains the separate `events.subscribe` contract.

## Durable transaction submission

`change.submit` accepts one canonical `ChangeProgram`, a `requestId`, and the
application's required `operationId`. SQL, platform operations, durable events
and mixed programs all use this one authoring path. The service derives one
stable durable identity from the caller principal, group and `operationId`.
The request ID identifies a transport call and never changes business identity.

The node's durable operation journal owns the mapping from that identity to the
canonical signed proposal. It persists the exact prepared bytes before append
and recovers an interrupted append before authoring its successor. The RPC
service has no expiring publication cache and does not reserve a new timestamp
or nonce on retry.

The same identity and canonical program return the original transaction ID,
digest, timestamp, nonce and manifest after a facade or process restart. This
also works after the writer's grant is revoked. New operations still require a
live writer grant. Reusing an identity for different steps produces
`already_exists`; a new unauthorized write produces `failed_precondition`.
`publishedAt` is the stable ISO rendering of the signed author timestamp.

`durableLocalAppend: true` reports durable publication. Admission, SQL execution
and finality are observed separately through `transaction.getOutcome` or
`transaction.streamOutcome`.

## Reader and writer enrollment

Configure `NodeRpcService({ node, enrollment })` with the shared
`createEnrollmentService` from `@chronolog/node-core`. Both native and browser
composition use the running replica's durable signer, reader key and feed.

| Method | Request identity and result |
| --- | --- |
| `enrollment.createRequest` | A durable device `requestId` and requested reader/writer roles produce a signed request. |
| `enrollment.approveRequest` | An issuer's durable approval `requestId`, the signed request, approved roles and explicit `grantFullHistory` produce a signed receipt. |
| `enrollment.getStatus` | The original device `requestId` and optional signed approval persist the receipt and report local readiness. |

The signed request binds the group, genesis, history policy, execution manifest,
signing key, reader key, transport author, requested roles and full-history
intent. Approval can grant a subset of the requested roles, with reader access
required for the replica workflow. It does not enroll validators or governance
administrators. The issuer explicitly decides whether to grant full history.

Readiness states distinguish request/approval progress, disconnected authorized
devices, missing epoch keys, incomplete final history, unsupported engines,
revoked grants and `ready`. Receiving a receipt or all currently delivered
records is insufficient: the exact active grants, every required epoch key,
matching engine and the approval's captured final target must all be usable.
Only the device that created the request can claim its local readiness.

## Method groups

| Group | Unary methods | Streams |
| --- | --- | --- |
| Node | `node.getStatus`, `node.getReplicationStatus` | `node.streamStatus`, `node.streamReplicationStatus` |
| Application | `change.submit`, `ingress.submit`, `operation.get` | `operation.subscribe` |
| Durable events | `events.read` | `events.subscribe` |
| Captured views | `view.open`, `view.query`, `view.events`, `view.release` | `view.changes` |
| Live signals | `signals.send` | `signals.subscribe` |
| SQL | `query.localSql` | `query.liveSql` |
| Transactions | `transaction.getOutcome` | `transaction.streamOutcome` |
| Evidence | `evidence.getSettlement`, `evidence.getValidatorWatermark` | `evidence.streamSettlement` |
| Governance | `governance.getStatus`, `governance.grantCapability`, `governance.revokeCapabilities`, `governance.rotateEpoch`, `governance.grantHistoricalAccess` | — |
| Enrollment | `enrollment.createRequest`, `enrollment.approveRequest`, `enrollment.getStatus` | — |

Governance and enrollment require explicitly configured local services. Missing
services fail with `failed_precondition`. Application row sharing and teams are
ordinary signed platform transactions, separate from replica enrollment.

## Verification

[node-service.test.ts](src/node-service.test.ts) exercises view selection,
enrollment dispatch, atomic outcome/finality observation and reconnect cursors.
[rpc-durable-submit.e2e.test.ts](../../test/rpc-durable-submit.e2e.test.ts) loses a
durable append response, reopens the real node, SQLite journal and signed feed,
then verifies exact retries after writer revocation. The
[SQL client integration suite](../../test/sql-client-node.e2e.test.ts) verifies
actual final SQL isolation and live final progress against native DoltLite.
