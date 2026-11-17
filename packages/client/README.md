# Chronolog client

`ChronologClient` provides SQL, durable events, live signals, transaction outcomes, ownership
operations and reader/writer enrollment over the shared
[replica RPC contract](../rpc/README.md). The same client talks to an embedded
node, a native daemon, or a browser Worker running a local replica.

## Connect to a replica

For a native daemon:

```ts
import { ChronologClient } from '@chronolog/client'
import { HttpRpcTransport } from '@chronolog/rpc'

const client = new ChronologClient({
  groupId, // the group's canonical base64url identity
  transport: new HttpRpcTransport({ baseUrl: 'http://127.0.0.1:8787' }),
  token: localRpcToken,
})
```

For an initialized local browser peer Worker:

```ts
import { ChronologClient } from '@chronolog/client'
import { WorkerRpcTransport } from '@chronolog/runtime-browser'

const client = new ChronologClient({
  groupId,
  transport: new WorkerRpcTransport(worker),
})
```

The Worker owns its signer, durable records, control state and SQL engine. The
client forwards calls to that local replica; the browser runtime handles peer
synchronization and history verification.

## Send and observe live signals

`client.signals` implements the portable `Signals` contract from
`@chronolog/signals`. A governed peer supplies it automatically through the same
local RPC and Worker bridge used by the rest of the client:

```ts
await client.signals.send('typing', { active: true }, { ttlMs: 2500 })

for await (const message of client.signals.subscribe({
  topics: ['typing'], mode: 'latest', signal: pageLifetime.signal,
})) {
  // Keep independent authors/sessions separate and expire rendered state.
  showTyping(message.authorId, message.sessionId, message.payload, message.expiresAtMs)
}
```

Signals are best-effort live messages, separate from retained events and atomic
programs. `send()` has no operation ID and never waits for finality; it confirms
local dispatch only. The peer signs each signal, checks the current writer's
topic rights, and routes it through authenticated reader connections. Public
`scope`, `authorId` and `sessionId` values are strings. Signed expiry remains
unchanged across relay hops. Expired updates are discarded.

`subscribe()` defaults to `mode: 'all'`, preserving accepted unexpired messages
in a bounded FIFO; overflow fails that subscription explicitly. `latest`
coalesces queued updates by author, session and topic, retaining the newest
sequence for each key. Subscribers need no writer grant; publication requires
a current signal topic right. A signal-only writer grant need not permit SQL
or durable events.

Each send makes one attempt, even when the client's durable unary retries are
enabled. A lost reply does not resend a typing or presence update. Without an
attached live route, sending fails immediately rather than saving an outbox.
Subscriptions have no replay cursor and surface RPC stream failures; a new
subscription observes new live traffic. A retained local subscription can
observe future traffic after peer routes reconnect. The Worker pulls only when
the page advances its iterator and forwards cancellation. Closing the client
cancels its live sends and streams. Durable application events use
`client.events` and stable operation identities.

For standalone use without any Chronolog database, use
[`SignalChannel`](../signals/README.md) with your own transport and authorization.

## Observe application views and authenticated events

`client.changes({ view, signal })` yields a current `{ view, revision,
finalRevision }` snapshot and coalesces later invalidations. It defaults to
`final`. SQL-only writes, a provisional rebase, and finality advancing without
changed rows can all invalidate the selected view. Capture SQL and events
together and release the read lease after rendering:

```ts
for await (const change of client.changes({ view: 'local', signal: pageLifetime.signal })) {
  const view = await client.readView({ view: change.view })
  try {
    render(await view.query('SELECT id, title FROM tasks ORDER BY id'), await view.readEvents())
  } finally { await view.release() }
}
```

Invalidations have no replay cursor and may skip intermediate views. A
reconnection reads current state. Use `client.events.subscribe()` for durable
processing: it delivers whole final event batches and advances received progress
only on the next pull. Persist the processed cursor together with derived state.

Each effective event includes authenticated `origin`, derived from its signed
proposal rather than its payload. `origin.authorId` is the same lowercase hex
public key used by signals. Chronolog also exposes `groupId`, `operationId`,
`authorTimestampMs` as a decimal string, `membershipRevision` and the exact
`writerCapability` (null only for static membership). These facts survive
HTTP/Worker serialization and replica restart. They describe the original
author's signed intent; they do not replace the handler's application-specific
authorization for an external action. Payload fields claiming a role or author
are not authenticated provenance.

The Tendriller adapter exposes these same ports. Operation lifecycle
`queued | provisional | final` is independent of `accepted | rejected` outcome;
an exact retry of a final rejection returns `status: 'final', outcome:
'rejected'` immediately.


## Submit SQL and wait for the result you need

```ts
const transaction = await client.transaction([
  {
    sql: "SELECT chronolog_assert((SELECT balance FROM accounts WHERE id = ?) >= ?, 'insufficient_balance')",
    params: [accountId, amount],
  },
  {
    sql: 'UPDATE accounts SET balance = balance - ? WHERE id = ?',
    params: [amount, accountId],
  },
], { idempotencyKey: durableApplicationOperationId })

const result = await transaction.final({ signal: AbortSignal.timeout(30_000) })
if (result.outcome.type === 'rejected') {
  // A final rejection is also immutable. Inspect its code/statementIndex.
  handleRejection(result.outcome.rejection)
} else if (result.outcome.type === 'accepted') {
  // Application work that depends on this committed change can proceed.
  await continueAfterPayment()
}
transaction.dispose()
```

A transaction is one atomic program of SQL statements and/or platform
operations. A failed statement rejects and rolls back the whole program.
Bindings preserve SQLite storage classes; use `bigint` for exact integers,
`Uint8Array` for BLOBs and `sqlValue.real(...)` when an integral JavaScript number
must remain REAL. Put assumptions in SQL with `chronolog_assert`.

| API | What it waits for |
| --- | --- |
| `client.transaction(...)` | Durable local publication of the signed proposal. |
| `handle.local()` | The current accepted/rejected SQL result, which can still change through replay. |
| `handle.final()` | The immutable accepted/rejected result after its policy-final prefix is applied locally. |

`local()` and `final()` both return rejections as well as acceptances. Always inspect
`outcome.type` before starting dependent application work. Waiting can be
cancelled even while the stream is quiet; cancellation stops that waiter, not
the transaction. A final result may wait indefinitely while required validators,
certificates, records or keys are unavailable.

Execution and finality are independent fields, without a second phase enum.
`outcome.type === 'pending'` means no executed result is available; an accepted
or rejected result with `final: false` is provisional. `final: true` identifies
the immutable executed result. `admissible` separately reports inclusion under
the selected policy; it does not turn a SQL rejection into a success.

The `idempotencyKey` is the application's durable operation identity. Persist
and reuse it with the same program after a lost response or client/process
restart. A retry returns the original proposal, even if its author was later
revoked. A changed program under the same identity fails with `already_exists`.
Without a supplied key, each `transaction()` call generates a fresh request ID;
automatic retries of that call reuse it, while a new call is a new operation.

## Read local or final SQL explicitly

```ts
const local = await client.query('SELECT id, balance FROM accounts ORDER BY id')
const final = await client.query(
  'SELECT id, balance FROM accounts ORDER BY id',
  [],
  { view: 'final' },
)

console.log(final.revision.view)             // 'final'
console.log(final.revision.finalOrderLength) // decimal string
```

The default `local` reader includes authorized proposals with the inputs needed
for execution, even before an inclusion receipt or validator quorum. The `final`
reader is a separate SQL snapshot of the locally applied immutable prefix.
Both carry view, selected revision, order length, final-prefix metadata and
execution-manifest identity. A final replica can still be behind other peers.

`liveQuery(sql, parameters, { view })` follows the chosen reader and returns a
lazy `StreamResource`. Subscribe for snapshot updates or iterate it; dispose
the resource when no longer needed. Final live queries advance only when that
replica applies a larger final prefix. React's `useChronologQuery` accepts the
same `view` option and includes it in the resource identity.

## Enroll a reader or writer

The joining device creates a durable signed request with its existing keys:

```ts
const { signedRequest } = await joiningDevice.enrollment.createRequest({
  requestId: durableDeviceJoinId,
  roles: ['reader', 'writer'],
  writerProgram: { sql: true, topics: ['tasks/changed'], signals: ['presence'] },
})
```

Pass those signed bytes to an authorized issuer through the application's
chosen invitation channel. The issuer explicitly approves roles and historical
access:

```ts
const { signedApproval } = await issuer.enrollment.approveRequest({
  operationId: durableApprovalId,
  signedRequest,
  roles: ['reader', 'writer'],
  grantFullHistory: true,
  writerProgram: { sql: true, topics: ['tasks/changed'], signals: ['presence'] },
})
```

Return the signed approval to the joining device. It stores the receipt before
checking readiness:

```ts
const status = await joiningDevice.enrollment.getStatus(durableDeviceJoinId, {
  signedApproval,
})
// Later checks can omit signedApproval; it is already durable locally.
const refreshed = await joiningDevice.enrollment.getStatus(durableDeviceJoinId)
```

Keep both operation identities stable across retries. Approval is a resumable
workflow that publishes grants and explicitly wraps historical epoch keys; it
does not silently create another device signer or grant validator/admin roles.
`ready` means the device has its exact active grants, required keys, matching
engine, connection and applied final target. Earlier states expose missing
keys/history, disconnection, unsupported engines or revoked grants. The issuer
can go offline once the signed records and receipt have been retained for the
joining device to synchronize.

Writer requests and approvals require explicit `writerProgram` rights. Use
`sql: false` with empty durable topics for a signal-only sender, or empty signals
for a durable-event-only publisher. Missing rights never imply SQL permission.
An approval may narrow the requested SQL, topic, signal and forwarding rights;
it cannot widen them. `ProgramRights` is the shared exported type. Membership
administration belongs to the genesis root key, independently of these grants.

`client.ownership` handles row grants, teams and ownership transfers. Those are
application transactions, separate from group enrollment. Their handles offer
the same `local()` and `final()` distinction; inspect the returned `outcome.type`.

Close the client with `await client.close()` to dispose its live resources and
close its transport. See [client.ts](src/client.ts) for the complete typed API.
