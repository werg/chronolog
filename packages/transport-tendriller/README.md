# Tendriller application adapter and optional finality provider

## Compose a peer application

The ordinary peer deployment uses `createChronologApplicationBackend` to expose
an already opened Chronolog replica through Tendriller's application contract.
The adapter creates no second outbox, authority, finality policy or host request.
Chronolog keeps the keys, original operations, state and event history.

```ts
import { createChronologApplicationBackend } from '@chronolog/transport-tendriller'

const application = createChronologApplicationBackend({
  id: tendril.application.selection.id,
  replica: client, // The public client of the owning Worker or resident peer.
  sql: true,
})
tendril.application.install(application)
tendril.signals.install(client.signals)

for await (const change of application.changes({ view: 'local', signal })) {
  const view = await application.readView({ view: change.view })
  try { render(await view.query('SELECT id, status FROM tasks'), view.revision) }
  finally { await view.release() }
}
```

`changes` starts with the current revision, then coalesces view invalidations,
including state-only operations, provisional rollback/redo and finality progress.
Read a captured view for data. `events.subscribe` instead processes accepted final
events with a durable processed cursor; it must not double as a UI invalidation
channel. Every event retains its authenticated `origin`, separate from its payload.

`operations.get` and `operations.subscribe` expose independent lifecycle and
acceptance: `status` is `queued`, `provisional` or `final`; an available `outcome`
is `accepted` or `rejected`. A final rejection has `status:'final'` and
`outcome:'rejected'`. Exact retries preserve the original program and operation ID.
Signals remain independently usable without installing an application backend.

Application peer traffic uses `@chronolog/transport-webrtc` and the replica's
`connectPeer({ connection })`. Tendriller's `peers.rendezvous` can introduce peers
by exchanging SDP; it carries no application records or signals. Signal framing
belongs to the live channel, independently of this retained-log adapter.

## Optional retained-log finality

The package also supplies an optional connection for the coordinated
history policy. The portable record store, Chronolog protocol and history policy
remain usable without it. Tendriller stores opaque bytes and supplies a retained,
receipt log; this package supplies wire adaptation and an optional signed
inclusion/closure endpoint. `coordinated` names the signed-inclusion protocol,
not a different execution order. All replicas execute the same signed author-time
order with deterministic tie-breakers.

## Connect an optional retained log

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

The Cloudflare page runtime's `tendril.records` and the native host SDK's
`client.records` implement the same public record client contract. A Cloudflare
page can pass `tendril.records` directly to reuse its existing authenticated
connection and head-change hints. Peer pages do not expose hosted record access;
their selected Chronolog backend owns application history. The deployment
authenticates certificate requests separately
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
