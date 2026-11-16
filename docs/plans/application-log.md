# Application log follow-up: implementation and qualification

The 16 November 2026 follow-up extends portable peer core with one signed
application history for SQL, durable events and resident agent work. New pilot
groups select a fixed authority on durable native agent storage. Tendriller hosts
the application and supplies a connection adapter; its retained Cloudflare log
remains an optional authority adapter for a separately selected deployment.

This is a recovery map for
[Chronolog PR #1](https://github.com/werg/chronolog-db/pull/1),
[Tendriller PR #35](https://github.com/werg/tendriller/pull/35), and
[contrib PR #13](https://github.com/werg/tendriller-contrib/pull/13).
A component commit, an asset build and a passing deployed scenario are different
evidence. The user explicitly requested clean prerelease breaking changes:
there are no compatibility program decoders, legacy imports, dual outboxes,
bidirectional old/new mirrors, or automatic authority/policy cutovers.

## Delivery phases

| Roadmap phase | Implemented boundary | Evidence and next qualification |
| --- | --- | --- |
| A. Native authority placement | Fixed native authority, pinned profile, atomic fenced store, exact append retries, retained certificate/range exchange and ordinary reader/writer enrollment. | Actual native store/daemon/framed fixtures. Volume loss and restore remain [contrib #16](https://github.com/werg/tendriller-contrib/issues/16). |
| B. General durable events | Version 3 `ChangeProgram` contains SQL, platform operations and bounded literal emits. Event-only and mixed execution, stable event IDs and final durable cursors. | Actual native SQL rollback/reopen and event-only restart. Actual SQL-free Chromium/OPFS qualification passed at the recorded head below. |
| C. Projections, workers and timers | Pinned combined views, keyed operation status, atomic projection checkpoints, final-intent worker journal, explicit provider recovery, signed signals and generation-fenced SQL timer publication. | Native rebase/finality, SQLite checkpoint rollback, worker ambiguity/deadline and SQL timer integration. Complete two-layout UI gate is separately reported. |
| D. Production connection path | Bounded framing and mutual grant-checked sessions carry records, evidence, wake hints and ephemeral frames. Real loopback HTTP fixture; Tendriller bounded hosted peer relay. | This proves the protocol over actual native/browser streams, not public-network NAT traversal. Select production direct/fallback routes through [contrib #14](https://github.com/werg/tendriller-contrib/issues/14). |
| E. New-page backend cutover | Immutable selected application backend, public Chronolog adapter, conversation/task/job vocabulary, consumer/timer APIs and two contrib layouts. Hosted application writes are guarded for peer pages. | Public-runtime pilot disables host application writes. Captures/bytes retain explicit host storage and authorization; this does not claim every hosted feature has been ported. The prerelease instruction removes legacy conversion work. |
| F. Measured optimization | Full retained history with explicit bounds/quotas, bounded consumers and small replaceable signals. | No cost saving or direct-connect rate is inferred. Paired workload and route-byte measurement remain [contrib #15](https://github.com/werg/tendriller-contrib/issues/15). |

Automatic authority failover, dynamic validator sets, compaction/archives,
arbitrary-code consensus, global pub/sub discovery, per-topic consensus/private
sublogs and full meshes remain outside this first scope. Authority loss pauses
new coordinated finality while peers retain local reads and certified history.
An outage never changes history lineage implicitly.

## Public application model

The authoring surface is `program(...steps)`, `sqlStatement(sql, bindings)` and
`emit(topic, payload)` from `@chronolog/protocol`. A single program can assert
that a task is unclaimed, update its owner field and emit a task event. Failure
rolls back both SQL and effective events. JSON events are literal bounded data;
application callbacks do not become consensus code.

| Public operation | Meaning |
| --- | --- |
| `client.submit(program, { operationId })` | Durable canonical authoring; returns a transaction handle. |
| `client.events.publish(topic, payload, { operationId })` | Event-only convenience using the same outbox. |
| `client.events.read({ cursor, topics, limit })` | Final accepted events grouped by proposal, with `scannedThrough`, `hasMore` and opaque revision. |
| `client.events.subscribe(options)` | Pull-based durable catch-up/live continuation; no snapshot coalescing. |
| `client.operations.get(operationId)` / `.subscribe({ operationId, signal })` | Current original proposal/outcome/finality for a retained caller operation. |
| `client.readView({ view: 'local' \| 'final' })` | Captured immutable revision with SQL, event range and explicit release. |
| `createChronologApplicationBackend({ id, replica, sql })` | Public `@chronolog/transport-tendriller` node/client adapter; SQL primitives and queued/provisional/final/rejected status. |
| `tendril.application.ready()` | Awaits the single installed backend selected for the page. |

See [RPC contracts](../../packages/rpc/README.md),
[client](../../packages/client/src/client.ts),
[adapter](../../packages/transport-tendriller/src/application.ts), and
[browser runtime](../../packages/runtime-browser/README.md).

Allocate `operationId` before submission and retain its reviewed meaning.
Chronolog's durable original-signer journal owns signed proposal, timestamp,
nonce and retry recovery. Same identity/content returns the original accepted or
rejected proposal even after revocation; changed content conflicts and a fresh
write needs current rights. A receipt proves durable publication, not final
accepted execution. The caller disposes its transaction handle after observation.

An event-only execution profile does not load the application SQL engine and
refuses SQL programs/queries. It is not a partial verifier of a mixed SQL history.
Profile capability and a writer's SQL permission are separate decisions.

### Durable event and view invariants

Effective event identity is proposal plus emitted ordinal. Failed mixed programs
contribute no partial SQL or effective domain event; signed rejection stays
auditable. Ordered history is not proof of successful execution. Missing bytes,
keys, engine support, unresolved outcomes and infrastructure failure block
application instead of inventing rejection or advancing the applied frontier.

Batches never split a proposal's matching events. Program size, batch size and
scan work are bounded. `scannedThrough` advances across resolved nonmatching and
rejected/no-op entries, including empty topic batches, but never unresolved
inputs. Opaque continuations bind group/history, exact prefix and normalized
topic filter. A changed filter fails explicitly. Reducer/filter versions also
belong to the checkpoint binding; changed application projections deliberately
rebuild instead of skipping newly relevant old input.

Delivery is at least once. `events.subscribe` reconnects from received progress;
a consumer that has not committed processing restarts from its own processed
cursor. A delivery acknowledgement is not a processing commit. `DurableProjection`
atomically replaces state, revision and processed cursor using store
compare-and-swap. Its IndexedDB store is browser safe. Native integration rolls
back an actual SQLite transaction after writing a new checkpoint body, then
reopens and proves replay starts from the old state/cursor pair.

A read handle captures SQL and events from one revision and stays pinned across
rebase or finality advance. RPC handles are caller-bound bounded leases (default
32 handles, 30 seconds); expiry/release fails explicitly and shutdown releases
them. Applications finish required projections before publishing one coherent
replacement. Finality/status changes notify even when SQL rows stay equal.
Provisional rejection can change during rebase; only final rejection is terminal.

## Native agent service, effects and timers

The [agent service](../../packages/agent-service/README.md) supplies independent
resident loops, fenced authority, final event source, atomic checkpoints,
effect worker, timers and framed peers. Trusted `CHRONOLOG_AGENT_MODULE` code
describes handlers/tasks; it must not await final publication before the
authority loops start. Persistence and synchronization do not depend on model
turns.

The [resident example](../../examples/resident-agent.ts) consumes final
`job-requests`, reads the final shared task and returns a bounded task summary.
The worker emits `effect.completed` on `job-results`, with original event,
handler identity/version and application result. Contrib joins results by
`originEventId`; duplicate display job IDs cannot merge effects. Browser grants
allow requests, while only the designated worker publishes results. UI replay
does not execute that worker.

The effect journal persists dispatch intent before calling a provider, result
before publishing and processed cursor only after final accepted result
publication. Recovery requires real provider idempotency, reconciliation or
manual uncertainty. Bounded deadlines and shutdown abort stop waiting even when
a provider ignores cancellation, leaving ambiguous dispatch state for recovery.
A local key or timeout does not prove exactly-once external action. Actual
provider guarantees remain a deployment test.

`createSqlTimerPublisher` admits configuration, cancellation and occurrence via
ordinary SQL plus emits in the same history. A preallocated generation avoids a
content-hash self-reference; `configurationEventId` separately records audit
provenance. Occurrence identity and observed time survive retries. SQL checks
active generation, exact next due time and payload before inserting, advancing
and emitting. Cancellation ordered first emits no occurrence; an accepted exact
retry keeps its result after later cancellation. Only the defined inactive
generation assertion maps to `cancelled`; unrelated SQL/permission/overflow
errors stay visible. An old cancellation cannot cancel a replacement and the
generation ledger prevents reuse. Already-final intent needs its provider's
external cancellation policy.

### File and capture metadata

The application-only [blob metadata recipe](../../examples/blob-metadata.ts)
uses ordinary SQL plus `files` emits, with a real
[native integration test](../../test/blob-metadata.integration.test.ts).
`createBlobMetadataRecipe` stages an immutable upload through the existing host
uploader, retains the exact completion receipt, then commits path/version
metadata with an expected-revision SQL guard and one stable operation ID.
Files and reviewed captures use the same reference model. A stale path revision
rejects atomically; retry uses the original staged upload and proposal.

The reference records location, content hash, size, media type, actual host
receipt, observed time and explicit retention/pin policy. It says additional
durable copies are unknown. Metadata finality is not proof of current byte
availability, a second replica or a backup. An uploaded object whose metadata
commit loses a race remains under the documented host/orphan policy; it is not
silently deleted. Private bytes need their existing authorized store or separate
group, not a topic-name convention. This recipe supplies an application pattern
without adding a second core upload/outbox protocol.

## Membership, limited publishers and transient signals

Signed writer grants independently describe SQL, event-topic, ephemeral-signal
and original-signer forwarding rights. Full enrollment carries requested writer
programs and issuer-approved subsets. Host sessions and transport endpoint
identity never confer application membership. Topics are filters, not privacy
boundaries.

A limited publisher keeps its own durable signer/outbox and receives only
approved publication scopes, without reader/history keys. `node.submitSigned`
preserves and validates the original signed candidate. The opt-in HTTP setting
`publisherIngress: true` / `CHRONOLOG_PUBLISHER_INGRESS=true` requires a non-empty
owner token and exempts only exact `POST /rpc/unary/ingress.submit`. Other
read/query/enrollment/admin/local-signing routes remain protected.
`createHttpPublisherIngress` exposes only `submitSigned`, omits ambient
credentials and rejects redirects. The owner bearer must never be given to a
limited publisher. Cross-origin allowlists belong to the deployment gateway.

`EphemeralChannel` signs a separate group/topic/grant/session/sequence/expiry
domain, validates the receiver's known active membership and bounds replay
state, pending work and coalescing queues. It never persists signals or advances
a durable cursor. The fixture forwards verified original bytes; typing ends at
its signed expiry. An offline receiver cannot know of revocations it has not
received.

## Executable public-runtime pilot

[tools/application-pilot.ts](../../tools/application-pilot.ts) builds the public
authoring bundle and real Worker bootstrap, copies packaged Tendriller runtime
assets and pinned WASM, then invokes contrib's complete two-entry page builder.
It does not import Tendriller's private runtime source. The temporary deployment
issues explicit fixture grants, creates real collective ownership/invitations
and runs the native authority and resident sample handler. Two independent
Chromium contexts own separate OPFS stores and durable signing identities.

```sh
node --import tsx tools/application-pilot.ts \
  --contrib /exact/tendriller-contrib \
  --tendriller-runtime /exact/tendriller/dist/runtime \
  --wasm /exact/chronolog/artifacts/wasm \
  --output /new/application-pilot-evidence
```

Use a new output directory. `--browser` selects an executable. `--build-only`
checks the full graph and explicitly marks browser scenarios not run. Contrib's
`npm run test:peer-application` wrapper invokes this command with explicit paths.

The actual gate exercises a shared team-owned task, ephemeral typing without log
growth, offline competing claims, one final winner and retained rejection, no
intent after failed SQL, one native worker result, denial of forged results,
newer typing during delayed reply, no regression of final status after that
reply, abrupt Worker reload, original operation/proposal recovery, and both
layouts rebuilding without redispatch or host application writes. Only reply
delivery is delayed; signing, durable storage, SQL, ordering and worker execution
use the real implementation.

Reports preserve source heads/dirty flags, runtime/WASM/bundle hashes, complete
specimen manifest, browser version, scenario outcomes and screenshots. Failure
writes `passed: false` before exit. Local core and contrib wrapper builds passed
with 62 assets. Local Chromium launch failed with `socket() failed: Operation
not permitted`; that is not a browser pass. The paired CI workflow runs the
actual gate on an environment that can launch Chromium.

## Recorded evidence and acceptance map

At immutable Chronolog head `98dffed4b44e1ef49d5823586114f7bda011793f`:

- The [native quality job](https://github.com/werg/chronolog-db/actions/runs/43922334294/job/133492604239)
  succeeded: 606 tests passed, four optional WASM tests skipped, 110 files passed.
  The separate native SSB gate passed eight tests and Ubuntu conformance passed.
  Coverage was 78.04% statements/lines, 81.64% branches and 83.98% functions.
  Later commits require their own CI result.
- The [browser job](https://github.com/werg/chronolog-db/actions/runs/43922334173/job/133492598759)
  passed all seven SQL-free Chromium/OPFS scenarios and four actual native/WASM
  comparison tests using Chromium 158.0.8127.18. The mixed SQL/event gate also
  passed ownership/client, atomic rollback, pinned view, native hash, reopen,
  prepared-write crash and cutoff checks before a subsequent push canceled the
  workflow. This is not a complete green workflow or a completed pilot run.

| Acceptance item | Executable evidence | Qualification boundary |
| --- | --- | --- |
| Event-only replay/reopen without application SQL | [Native public integration](../../test/application-log.integration.test.ts), [SQL-free browser gate](../../tools/test-browser-events.ts) | Actual browser pass is tied to the CI head above. |
| Mixed atomicity; exact accepted/rejected retry after revocation/reopen | [Native integration](../../test/application-log.integration.test.ts), [publisher tests](../../packages/node-core/src/publisher.test.ts) | Real deterministic engine and persistent stores, not provider actions. |
| Rebase, combined pinned view and finality-only status | Native integration, [RPC tests](../../packages/rpc/src/application.test.ts) | Complete two-layout browser behavior separately gated. |
| Durable batches, empty scan progress, filter mismatch, bounded scans | [Reader tests](../../packages/node-core/src/events.test.ts), [client tests](../../packages/client/src/application.test.ts) | Full history retained; no long-history cost claim. |
| Atomic projection/checkpoint and reducer invalidation | [Projection tests](../../packages/client/src/projections.test.ts), actual SQLite rollback/reopen, actual OPFS browser gate | Consumer must use an atomic state/cursor store. |
| Limited publisher and anonymous HTTP boundary | Publisher tests, [HTTP tests](../../packages/rpc/src/publisher-http.test.ts) | TLS/CORS/device storage remain explicit deployment decisions. |
| Native fencing, lost acknowledgement, quota and continuity refusal | [Authority tests](../../packages/agent-service/src/native-authority.test.ts) | Disk loss and independent backup freshness remain contrib #16. |
| Original records/certificates across authenticated byte streams | [Link tests](../../packages/agent-service/src/peer-link.test.ts), [HTTP fixture integration](../../test/browser/event-fixture.test.ts) | No home/mobile/corporate direct byte-route claim. |
| Final intent, uncertain effects, exact result retry and deadlines | [Worker tests](../../packages/agent-service/src/effect-worker.test.ts), daemon composition | Controlled provider fixtures cannot establish a real provider promise. |
| Timer race, replacement generation and accepted retry after cancellation | [Scheduler tests](../../packages/agent-service/src/timers.test.ts), [real SQL integration](../../test/sql-timers.integration.test.ts) | External action cancellation remains a provider contract. |
| Ephemeral expiry/replay and backpressure | [Signals](../../packages/agent-service/src/signals.test.ts), [framing](../../packages/agent-service/src/framing.test.ts), pilot | Known membership is local; no instantaneous offline revocation knowledge. |
| Public consumption and peer-only page behavior | Tendriller release consumers, [adapter tests](../../packages/transport-tendriller/src/application.test.ts), pilot | Runtime is packaged; production network qualification stays open. |

Contrib's [complete scenario matrix](https://github.com/werg/tendriller-contrib/blob/feat/chronolog-application-log/cookbooks/run-a-peer-application/notes/implementation-and-qualification.md)
also covers old-scope rejection in the separately hosted backend and metadata
versus byte availability. Its 19 page/model tests cover pure projection,
draft/receipt behavior and content boundaries, not native/browser semantics.

## Operational work is issued, not fabricated

- [Contrib #14](https://github.com/werg/tendriller-contrib/issues/14): actual
  browser/native direct/fallback routes on home/mobile/corporate networks,
  interruption/suspension, warm hosting outage and direct/relayed byte accounting.
- [Contrib #15](https://github.com/werg/tendriller-contrib/issues/15): paired hosted
  and peer workloads, request/storage/relay costs, startup/catch-up/replay,
  latency and memory. Moving authority does not establish transport savings.
- [Contrib #16](https://github.com/werg/tendriller-contrib/issues/16): persistent
  volume fencing, commit/ack crash, disk loss, trusted independent continuity,
  backup restoration and explicit new-lineage decisions.
- [Contrib #17](https://github.com/werg/tendriller-contrib/issues/17): deployed
  enrollment, device suspension/OPFS/quota/clearing, publisher/signal grant
  boundaries, private context/bytes and backup availability.

These issues contain concrete completion criteria and remain open until actual
deployment evidence is attached. A fixture, screenshot or passing local unit
test does not close them.
