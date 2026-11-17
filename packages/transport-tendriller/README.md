# Tendriller application adapter and optional retained finality

## Bind a peer application's history

`createChronologApplicationBackend` exposes an existing native node or public
Chronolog client through Tendriller's application contract. It does not open a
second database, send application work to the host, allocate replacement
operations, or select the group's finality provider.

```ts
import { createChronologApplicationBackend } from '@chronolog/transport-tendriller'

// Install live messaging before durable catch-up when the UI needs it.
tendril.signals.install(client.signals)
const backend = createChronologApplicationBackend({
  id: tendril.application.selection.id, replica: client, sql: true,
})
tendril.application.install(backend)

for await (const change of backend.changes({ view: 'final', signal })) {
  const view = await backend.readView({ view: change.view })
  try { render(await view.query('SELECT id, status FROM tasks'), await view.readEvents()) }
  finally { await view.release() }
}
```

`changes` begins with the current revision and coalesces display invalidations,
including SQL-only changes and finality-only advances. It holds no SQL lease or
durable cursor and makes no page-host polls. Reconnection observes current state. A worker uses `events.subscribe` and commits its
processed cursor with its own state. `readView` pins queries and events to one
coherent revision. The default is final state; an explicitly selected local view
may rebase as earlier eligible history arrives.

This adapter exposes Chronolog's chronological history through `local` and
`final` views. It rejects `applied` and other view names before observing or
capturing the replica. The common `basedOn` ordering barrier is unsupported:
`submit` and `events.publish` reject it before authoring any proposal. Use
Chronolog program preconditions for state-dependent writes.

`submit` and `events.publish` return the current operation snapshot. Its `status`
is `queued`, `provisional`, or `final`; executed results separately identify an
`accepted` or `rejected` `outcome`. A final rejection is terminal. An exact retry
can return either original final outcome without queueing another proposal.
`operations.subscribe({operationId})` observes the same identity through replay
and finality. Authenticated `event.origin` passes through unchanged from the
verified signed proposal, including after replica restart.

The `sql` option describes the execution profile, never a permission grant.
An event-only backend rejects SQL queries and uses the same event, operation and
view contract. Live signals need neither profile and are installed separately.

## Connect an optional hosted receipt log

The package also supplies a public record-log adapter and signed
inclusion/closure endpoint for deployments that select hosted finality. The
portable record store, Chronolog protocol and history policy remain usable
independently. `coordinated` names the signed-inclusion protocol; replicas execute
the same signed author-time order with deterministic tie-breakers.

Create the ordinary durable transport first, using `PortableFeedTransport` in a
browser or the native transport. Both expose the immutable evidence methods that
the adapter requires. Pass the Tendriller public record client, the group's fixed
coordinated configuration and its envelope route:

```ts
import { createRecordLogClient } from '@tendriller/core/records'
import {
  createCertificateFetcher,
  TendrillerTransport,
} from '@chronolog/transport-tendriller'

const records = createRecordLogClient({
  base: tendrilApiUrl,
  headers: () => ({ Authorization: `Bearer ${agentToken}` }),
})
const transport = new TendrillerTransport({
  local: durableTransport,
  records,
  configuration: descriptorHistoryConfiguration,
  groupRoute,
  certificate: createCertificateFetcher({
    url: certificateUrl,
    headers: () => ({ Authorization: `Bearer ${agentToken}` }),
  }),
})
```

The hosted Cloudflare page runtime's `tendril.records` and the native client's `client.records`
implement the same public record client contract. A page can pass
`tendril.records` directly to reuse its existing authenticated connection and
head-change hints. Peer-selected pages deliberately disable hosted record APIs;
their application adapter above uses the replica's selected transport instead.
The deployment authenticates certificate requests separately
with the same owner or authorized-agent policy; a database membership grant does
not grant Tendriller administration or access.

The resident Tendril must have a provisioned record history. Bind its returned
history ID, the authority public key, group ID, signed genesis digest and execution
manifest digest into the coordinated configuration before accepting any work.
Treat that configuration as immutable. A different authority or a recreated log
requires an intentionally different group/history configuration.

## Durable submission and recovery

The existing local signed-record store is the durable source of pending work.
The adapter does not create another outbox or author records on behalf of other
devices. It submits exact locally authored candidate, capability and epoch-manifest
envelopes for the configured group, in their original local feed order. Heartbeats,
attestations, other groups and returned proofs do not enter this log.

`publish()` saves the original signed feed record before appending its exact
envelope bytes. A lost append reply leaves that original record available for
recovery. Retrying the same payload reuses the record; `ensurePublished(record)`
retries an already durable original and resolves only after its append and returned
entry evidence are durable. Governance uses that barrier before publishing a
dependent revision. Tendriller's exact-byte deduplication preserves the original
position even after process restart.

Each returned entry and prefix certificate is encoded as immutable evidence in
the same local record store. Other peer connections relay these bytes without
changing their identity or adding a new proof-author feed. A peer can verify and
apply complete certified history while Tendriller is unavailable. New coordinated
finality still needs a valid covering certificate, every preceding receipt and
the signed author-time closures retained among those records.

`catchUp()` reads retained ranges from the public API, checks the shared hash chain,
saves the entries and requests an authenticated certificate. The replica's history
provider verifies the complete inclusion and closure evidence. The replica
applies the resulting closed prefix in canonical author-time order. The
adapter never equates an append acknowledgment with final SQL success. Reopening
revalidates retained history from genesis; its in-memory cursor is only an
optimization. Watch hints and polling trigger catch-up, and transient failures
retry even if the committed head has not changed. With `watch: true`,
`finalityPollIntervalMs` also requests closure while no new proposal arrives
(one second by default). Set `watch: false` when the host
owns scheduling. Relay failures are exposed through `status().lastCatchUpError`.

## Compose the finality service with the public engine

Use Tendriller's public engine handler in the trusted host deployment. Keep one
stable authority signing key and one fixed group-to-history configuration. This
package does not modify Tendriller core or access its private SQL tables.

```ts
import engine from '@tendriller/engine'
import {
  authorizeThroughRecordLog,
  withTendrillerFinality,
  type FinalityHttp,
} from '@chronolog/transport-tendriller'

// Use this deployment's Worker Request/Response globals and declarations.
const http: FinalityHttp<Request, Response> = {
  request: (url, init) => new Request(url, init),
  response: (body, init) => new Response(body, init),
}

export default await withTendrillerFinality(engine, {
  descriptor,
  identity: stableAuthorityKey,
  records: authenticatedRecordsClient,
  http,
  authorize: authorizeThroughRecordLog(engine, {
    base: fixedTendrilRecordApiBase,
    historyId: descriptor.history.historyId,
    http,
  }),
})
```

The descriptor must select the signed-inclusion provider. Initialization verifies
its genesis and derives cutoff lag and the future-admission window from that
signed policy; no local timing override can disagree with replicas. The host
must supply `authorize`. Omission fails closed. The helper dispatches an
authenticated read to the fixed public record route using the original request's
credentials, so the existing owner/agent checks decide access. It does not create
another identity registry. The small `http` port preserves the deployment's own
Web API types, including Cloudflare-specific request/response properties, without
casting them to browser DOM types. Authorization runs before
reading the head or signing. The default endpoint is `POST /_chronolog/certificate`
with no request body; a caller cannot supply a root to sign. The service reads
its own configured log's committed prefix through the public record API. It
derives a monotone timestamp cutoff from `now` and signed `cutoffLagMs`, signs a closure
marker for that exact predecessor and appends it using the public generic
`expectedHead` condition. A concurrent append causes a reread and retry, without
retaining a marker for the wrong predecessor. The marker is durable before the
covering CBOR prefix certificate is returned. The complete marker history makes
late-proposal decisions recoverable after restart. Ordinary requests and additional handler methods
such as scheduled work remain delegated to the supplied engine. Signing does not
execute SQL. Prefix certificates stay outside the log; closure markers are
ordinary retained opaque bytes. Receipt positions never select SQL order.

Both the service and replicas derive the future-admission window from signed
genesis `maxFutureSkewMs + cutoffLagMs`. Replicas reject
author timestamps beyond the first covering closure plus that window. The provider
can then stop idle closure markers after that bounded horizon, without reading
application bodies. Empty histories add no marker. Restart recovers the bound
from retained closure history; an unchanged verified head reuses its evaluated
snapshot. Receipt hints and repeated certificate polling cannot grow a fully
closed idle history.

## Public artifact boundary and verification

The package consumes the public `@tendriller/core/records` subpath. Tests install
built SDK and engine archives pinned to a Tendriller source commit in
`test/artifacts`; each adjacent provenance file records the exact source commit,
build command and SHA-256. The artifact hashes are checked by the test suite. A
strict declaration consumer checks composition against the actual packaged engine
types. No sibling Tendriller checkout or private source import is needed to install
or run the adapter tests.

The adapter tests exercise real signed portable feed records and durable evidence
against an independent reference log through the packed public SDK. They cover
lost replies and reopen, governance ordering, offline proof relay, authority access
checks and delegation. The SQL integration test runs two independent native peers,
creates an explicit shared collective, accepts its invitation and has both members
claim one task with author time reversed relative to receipt order. Both replicas
choose the earlier authored claim and agree on one accepted transaction, one deterministic
SQL assertion rejection and the actual final SQL revision. Re-encapsulating the
same signed proposal does not repeat its SQL effects. A fresh third replica then
rebuilds those outcomes through an ordinary peer link with the hub unavailable.
Tendriller's own Worker suite separately covers transactional append, quota,
restart, owner/agent authorization and the public HTTP routes.
