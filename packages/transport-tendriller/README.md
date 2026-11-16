# Tendriller connection and prefix authority

`@chronolog/transport-tendriller` is an optional connection for the coordinated
history policy. The portable record store, Chronolog protocol and history policy
remain usable without it. Tendriller stores opaque bytes and supplies a retained,
ordered log; this package supplies the wire adaptation and the optional signed
prefix endpoint.

## Connect a replica

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

The page runtime's `tendril.records` and the native client's `client.records`
implement the same public record client contract. A page can pass
`tendril.records` directly to reuse its existing authenticated connection and
head-change hints. The deployment authenticates certificate requests separately
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
finality still needs a valid covering certificate and every preceding record.

`catchUp()` reads retained ranges from the public API, checks the shared hash chain,
saves the entries and requests an authenticated certificate. The replica's history
policy verifies that certificate and decides which complete prefix is final. The
adapter never equates an append acknowledgment with final SQL success. Reopening
revalidates retained history from genesis; its in-memory cursor is only an
optimization. Watch hints and polling trigger catch-up, and transient failures
retry even if the committed head has not changed. Set `watch: false` when the host
owns scheduling. Relay failures are exposed through `status().lastCatchUpError`.

## Compose the authority with the public engine

Use Tendriller's public engine handler in the trusted host deployment. Keep one
stable authority signing key and one fixed group-to-history configuration. This
package does not modify Tendriller core or access its private SQL tables.

```ts
import engine from '@tendriller/engine'
import {
  authorizeThroughRecordLog,
  withTendrillerAuthority,
} from '@chronolog/transport-tendriller'

export default withTendrillerAuthority(engine, {
  configuration,
  identity: stableAuthorityKey,
  records: authenticatedRecordsClient,
  authorize: authorizeThroughRecordLog(engine, {
    base: fixedTendrilRecordApiBase,
    historyId: configuration.historyId,
  }),
})
```

The host must supply `authorize`. Omission fails closed. The helper dispatches an
authenticated read to the fixed public record route using the original request's
credentials, so the existing owner/agent checks decide access. It does not create
another identity registry. Authorization runs before
reading the head or signing. The default endpoint is `POST /_chronolog/certificate`
with no request body; a caller cannot supply a root to sign. The authority reads
its own configured log's committed head through the public record API and returns
a signed CBOR prefix certificate. Ordinary requests and additional handler methods
such as scheduled work remain delegated to the supplied engine. Signing does not
execute SQL and certificates never enter the log they certify.

## Public artifact boundary and verification

The package consumes the public `@tendriller/core/records` subpath. Tests install a
built SDK archive pinned to a Tendriller source commit in `test/artifacts`; its
adjacent provenance file records the exact source commit, build command and SHA-256.
The artifact hash is checked by the test suite. No sibling Tendriller checkout or
private source import is needed to install or run the adapter tests.

The adapter tests exercise real signed portable feed records and durable evidence
against an independent reference log through the packed public SDK. They cover
lost replies and reopen, governance ordering, offline proof relay, authority access
checks and delegation. Tendriller's own Worker suite separately covers transactional
append, quota, restart, owner/agent authorization and the public HTTP routes.
