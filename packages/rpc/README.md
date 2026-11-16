# Local replica RPC

`@chronolog/rpc` exposes the same replica service to native applications and
browser Workers. [contract.ts](src/contract.ts) defines the method mapping and
[types.ts](src/types.ts) defines requests and responses. These TypeScript types
are the implemented API; there is no separate generated RPC schema.

`NodeRpcService` depends on a small structural node interface. It selects SQL
readers, forwards durable publication to the node, and reports outcomes and
enrollment progress. Signed consensus records and history-policy evidence use
their own canonical codecs in `@chronolog/protocol` and `@chronolog/node-core`.

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

## Queries and immutable results

`query.localSql` and `query.liveSql` accept `view: 'local' | 'final'`; the default
is `local`.

| View | Reader | Meaning |
| --- | --- | --- |
| `local` | Current locally materialized SQL revision | Includes admitted speculative work; synchronization can replay it. |
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

Transaction outcomes contain a separate `final` boolean. `accepted` or
`rejected` alone describes the current SQL execution result. `final: true`
requires the transaction's stable result to be applied in the local immutable
prefix. Acceptance, rejection, revision and finality are read together without
an intervening asynchronous status query.

Outcome, status, settlement and replication streams start with the complete
current state and then follow live changes. The service subscribes before
reading that state. Resume cursors are hints: a cursor from a previous process
cannot suppress newer finality after the local event counter restarts. Ending
the iterator cancels its node subscription.

## Durable transaction submission

`transaction.submit` accepts SQL/platform steps, a `requestId`, and an optional
`idempotencyKey`. The service derives one stable operation identity from the
caller principal, group and `idempotencyKey ?? requestId`.

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
| SQL | `query.localSql` | `query.liveSql` |
| Transactions | `transaction.submit`, `transaction.getOutcome` | `transaction.streamOutcome` |
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
