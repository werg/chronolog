# Application log follow-up: implementation and qualification

## Architecture correction: deterministic order, pluggable finality

The current follow-up separates inclusion/finality from ordering. All providers
use the core chronological comparator. A native or hosted service certifies
inclusion and durable closed-time promises; its receipt positions never choose
SQL/event order. Membership and epoch controls remain signed ledger kinds, with
causal-chain validation and author-time activation boundaries. See the current
[contract and regression map](../pluggable-finality.md).

The qualification reports below describe their exact historical source pins.
Reports which used receipt-order execution are not evidence for the corrected
semantics; new qualification must run against the changed public artifacts.

The 16 November 2026 follow-up extends portable peer core with one signed
application history for SQL, durable events and resident agent work. The revised
deployment places portable membership administration on Cloudflare by default,
with a separate fixed native ordering authority and full application replicas.
Small typed descriptors commit detached application envelopes; capability and
epoch records stay inline. Full peers fetch the application bodies through their
authorized peer path. The earlier event/application qualification is retained
below with its original scope; it does not qualify this new placement.

This is a recovery map for
[Chronolog PR #1](https://github.com/werg/chronolog-db/pull/1),
[Tendriller PR #35](https://github.com/werg/tendriller/pull/35), and
[contrib PR #13](https://github.com/werg/tendriller-contrib/pull/13).
A component commit, an asset build and a passing deployed scenario are different
evidence. The user explicitly requested clean prerelease breaking changes:
there are no compatibility program decoders, legacy imports, dual outboxes,
bidirectional old/new mirrors, or automatic authority/policy cutovers.

## Review and upstream-integration checkpoints

This review extends the already implemented roadmap with small pushed fixes.
The complete `5cfa0444` / `43cac4e7` qualification below remains evidence for
those exact inputs. It is not relabeled as a result for these later changes.

| Checkpoint | Correctness change | Executable evidence |
| --- | --- | --- |
| `a895a4dd` — committed payload metadata | A missing or corrupt provider response remains pending. Once exact hash-committed bytes are available, a contradictory envelope/length/epoch is a deterministic invalid position; later valid history advances without inventing a proposal outcome. | [Ledger codec](../../packages/node-core/src/ledger-record.test.ts), [canonical admission/reopen](../../packages/node-core/src/canonical-epoch.integration.test.ts). |
| `668c44cf` — immutable governance | A root-signed attempt to change fixed history configuration is rejected before received or canonical membership mutates. A later valid revision still progresses. | [Governance regressions](../../packages/node-core/src/governance.test.ts). |
| `b80d20b4` — restored fork quarantine | Durable losing records are replayed into the fork registry after reopen and to new subscribers, preserving quarantine across portable and native transports. | [Full-node fork replay](../../test/feed-fork-replay.integration.test.ts), [portable store](../../packages/records/src/store.test.ts), [required native SSB gate](../../packages/transport-ssb/src/feed-transport.test.ts). |
| `3067dc6d` — canonical epoch availability | An epoch never issued before a certified position is invalid there, even if its manifest arrives later. A genuinely issued epoch with a missing local key continues to block until authorized key delivery. | [Canonical epoch integration](../../packages/node-core/src/canonical-epoch.integration.test.ts). |
| `e855e1d0` — captured scope generation | The built contrib recipe carries the generation captured when an intent is authored. A durably queued old-generation edit rejects after reset; an already accepted exact retry retains its proposal and adds no record or event. | [Real SQL/public adapter qualification](../../tools/lib/application-scope.ts), invoked by the [application pilot](../../tools/application-pilot.ts). |
| `cc18d15e` and `1834de1e` — upstream engine integration | Sealed values, lossless typed row keys, exact comparisons and transfer snapshots use the current v3 program and portable byte/hash APIs. Native/WASM transaction context and sealed lifecycle behavior agree; the complete program budget still bounds sealed writes. | [Sealed client](../../packages/client/src/sealed.test.ts), [native sealed execution](../../packages/materializer-doltlite/src/sealed.integration.test.ts), [six native/WASM comparisons](../../packages/runtime-browser/src/wasm-conformance.test.ts). |

The merged native implementation passed 279 focused tests, full typecheck, lint,
build and documentation checks. The subsequent engine integration passed all six
actual native/WASM comparisons, and the native captured-scope scenario passed.
The clean membership package was built from `cc18d15e` with 56 runtime inputs
and no application engine dependency. These are local integration results.
The integration pin checkpoint `764a57d1` consumes public Tendriller
`283f210c1fb9dc2c1d27e9bbd9e8813234a40a70`, embedding that membership package,
and contrib `8449017159b2657a2b0d9bde398322dac78ee2d1`. The eighteen public-adapter
tests, both independent bundle builds and the exact built scope recipe passed
with those inputs; the application build contains 63 explicit assets.
Complete qualification passed for authored head
`1b5b8f26c0e36c7cff3534d4ae465eaa57154c9c` as clean PR merge
`3780499f18435a8eddfa3dcecf511ca908e57087`. The subsequent evidence checkpoint
only records these results; it does not change runtime or package inputs.

| Required gate | Observed result |
| --- | --- |
| [Quality and tests](https://github.com/werg/chronolog-db/actions/runs/43957113773) | 772 tests passed; six WASM tests skipped in this job and passed in the browser gate. All nine native SSB tests, including durable fork replay, passed. Lint, types, build, documentation links and coverage passed; statements/lines 79.63%, branches 82.44%, functions 85.06%. |
| Linux/macOS replay comparison in that workflow | Linux x64 and macOS arm64 produced identical execution, replay and portable semantic digests. Portable semantic digest: `224e7ee7691e7cbe579478171c9493c8d543870398f4eedfe8cd7611f579150e`. |
| [Browser, application and thin administrator](https://github.com/werg/chronolog-db/actions/runs/43957113710) | Six native/WASM comparisons, seven SQL-free checks, eight SQL/OPFS checks and five enrolled public-bridge checks passed. The application report has nine checks: build, native captured-scope qualification and seven browser/runtime assertions. Thin membership passed seven runtime assertions plus its independent build/import audit. |
| [Container chaos](https://github.com/werg/chronolog-db/actions/runs/43957113669) | Three nodes and six controlled SSB links healed and converged; all fourteen invariants passed. All 79 published workload operations resolved. Three other submissions failed locally during the deliberate restart, out of 82 attempted publications. |

Both application reports record no page errors. The task/chat pilot dispatched
one effect with zero host application writes. Its native scope result retained
three effective events at generation 1, rejected the stale proposal with
`assert:scope_generation_changed`, and added zero records for the accepted exact
retry. The thin administrator received zero application-envelope bytes across
21 signed native requests. Four large application envelopes totaled 789,092
bytes while their candidate descriptors totaled 576 bytes; descriptor and key-wrap
traffic still grows with operation and recipient counts.

[Artifact 14273111973](https://github.com/werg/chronolog-db/actions/runs/43957113710/artifacts/14273111973)
has SHA-256 `0be4f8fdbad4bfb47b0db0cc8c35528f62c27cdc1ebe178807ca476c95ca7d48`.
The [durable contrib review note](https://github.com/werg/tendriller-contrib/blob/feat/chronolog-application-log/cookbooks/run-a-peer-application/notes/qualification-review-43957113710.md)
preserves the exact new reports, package hashes, scope diagnostics and traffic
limits separately from the historical pairing below. These are actual local
workerd/native/Chromium scenarios with synthetic authenticated accounts, not a
deployed Cloudflare or public-network measurement. Public-network, recovery and
deployed application gates remain in the contrib issues below.

## Delivery phases

| Roadmap phase | Implemented boundary | Evidence and next qualification |
| --- | --- | --- |
| A. Authority and administration placement | Fixed native ordering authority, portable Cloudflare membership administrator, separately signed schema administrator, typed descriptor history and detached envelopes. | Native late-join/revocation and exact-retry fixture; complete packaged workerd/native/fresh-browser gate passed in [run 43940378818](https://github.com/werg/chronolog-db/actions/runs/43940378818), authored head `5cfa04440029c24d4313e7b8e88e593952180adb`. Separate administrator/native volume recovery remains [contrib #16](https://github.com/werg/tendriller-contrib/issues/16). |
| B. General durable events | Version 3 `ChangeProgram` contains SQL, platform operations and bounded literal emits. Event-only and mixed execution, stable event IDs and final durable cursors. | Actual native SQL rollback/reopen and event-only restart. Actual SQL-free Chromium/OPFS qualification passed at the recorded head below. |
| C. Projections, workers and timers | Pinned combined views, keyed operation status, atomic projection checkpoints, final-intent worker journal, explicit provider recovery, signed signals and generation-fenced SQL timer publication. | Native rebase/finality, SQLite checkpoint rollback, worker ambiguity/deadline and SQL timer integration. Complete two-layout UI gate is separately reported. |
| D. Production connection path | Bounded WebRTC framing and mutual grant-checked sessions carry records, evidence, wake hints and ephemeral frames. Cold browsers contact a configured resident HTTPS introduction endpoint; an explicitly coordinated pair may use Tendriller's short-lived SDP rendezvous. The browser Worker owns authentication, storage and replay. | Actual native/Chromium RTC gates measure continued application exchange after signaling closes and the host listener stops. See [the current qualification runbook](../route-qualification.md). Public-network reachability, optional TURN and provider measurements remain [contrib #14](https://github.com/werg/tendriller-contrib/issues/14). |
| E. New-page backend cutover | Immutable selected application backend, public Chronolog adapter, conversation/task/job vocabulary, consumer/timer APIs and two contrib layouts. Hosted application writes are guarded for peer pages. | Public-runtime pilot disables host application writes. Captures/bytes retain explicit host storage and authorization; this does not claim every hosted feature has been ported. The prerelease instruction removes legacy conversion work. |
| F. Measured optimization | Full retained history with explicit bounds/quotas, bounded consumers and small replaceable signals. | No cost saving or direct-connect rate is inferred. Paired workload and route-byte measurement remain [contrib #15](https://github.com/werg/tendriller-contrib/issues/15). |

Automatic authority failover, dynamic validator sets, compaction/archives,
arbitrary-code consensus, global pub/sub discovery, per-topic consensus/private
sublogs and full meshes remain outside this first scope. Authority loss pauses
new coordinated finality while peers retain local reads and certified history.
An outage never changes history lineage implicitly.

## Revised thin-administration boundary

The [typed ledger format](../typed-ledger-records.md) commits exact application
envelope hash, length, group route, record type and epoch. Candidate bodies are
detached; small signed capability/epoch envelopes are inline and verified against
their descriptor. This replaces opaque payload-sized entries directly. There is
no legacy decoder fallback, mirrored log, new page outbox or automatic policy
switch.

The portable `MembershipAdministrator` verifies cumulative signed control proofs,
applies their original-cutoff governance records, retains exact approval/revocation decisions and
distributes authorized epoch material. It has no application-body fetch port or
application SQL engine. Its default Tendriller host supplies authenticated
owner/device routes and a durable private metadata store. Cloudflare's SQLite
storage for that metadata is distinct from the application materializer.

Signed genesis independently names `rootAdminPublicKey` for membership and
`schemaAdminPublicKey` for the initial application schema group administrator.
Every full replica initializes application ownership from the latter key. A
separate native schema signer can create tables without turning the Cloudflare
root into an application group member or SQL writer. A local-only materializer
override would break deterministic agreement and is not permitted.

| Public boundary | Responsibility |
| --- | --- |
| `@chronolog/node-core/ledger` | Canonical descriptors, exact envelope binding and verified detached-body resolution. |
| `@chronolog/node-core/membership` and independently packed `@chronolog/membership` | Portable provisioning, administrator, enrollment verification and signed bounded ledger protocol. |
| `@tendriller/core/members` | Public host client for configuration, account-bound requests, owner approval/revocation, status and certified control-history pages. |
| `PUT /members`, then `POST /members/sync` | Persist the host root and signed descriptor before starting the native participant; then open administration and synchronize control history. |
| `GET /members/history` | Approved reader account or administrator obtains bounded certified compact control history to bootstrap device verification. |
| Signed `POST /_chronolog/membership` on the native host | Authenticate the immutable root signer, read bounded controls and cumulative checkpoints, or append exact inline control records. No local SQL signing or application body route is granted. |

A joining device generates its own signing and reader keys. Its signed request
binds the authenticated host account prefix; another logged-in account cannot
reassign it by forwarding the same signature. An approval receipt alone is not
readiness. The device first verifies certified controls and its grant/key wraps,
then opens its reader-authenticated peer connection and fetches the missing
application receipt descriptors and envelopes. Governance can advance through
the compact control proof while full application replay is pending. Each candidate still authorizes
against membership at its own canonical position, so later revocation cannot
rewrite an older final result.

Missing payloads remain explicit `LEDGER_PAYLOAD_UNAVAILABLE` progress. They do
not become rejection or permit an applied event cursor to skip the missing
input. The qualification handles only this typed unavailable condition while
asserting verified grant/key readiness; it preserves all other integrity,
key, materialization and infrastructure failures.

The [native qualification](../../test/thin-membership-native.integration.test.ts)
uses actual durable administrator storage, the signed HTTP handler, a separate
native SQL authority and a late full SQL replica. It exercises large envelopes,
small descriptors, lost append/reopen/exact approval retry, membership activation
before body catch-up, direct writer revocation, accepted retry after revocation,
and reader removal followed by a future epoch. It also queries the actual SQL
group to distinguish the schema administrator from the membership root. This
native boundary is not evidence of Cloudflare or Chromium execution.

The complete public host/browser gate is
[tools/thin-membership-pilot.ts](../../tools/thin-membership-pilot.ts):

```sh
node --import tsx tools/thin-membership-pilot.ts \
  --tendriller-artifacts /exact/tendriller-public-dist \
  --wasm /exact/chronolog-wasm-artifacts \
  --output /new/thin-membership-evidence
```

It installs copied SDK/engine tarballs into an independent consumer, checks the
engine's exact membership provenance/import audit, runs the real default host
provider in workerd, and uses an actual Chromium/OPFS device. The fixture does
not inject capabilities, raw epoch keys or a replacement roster provider.
Candidate count and payload size vary independently. Reports retain encoded
descriptor/control and full-peer payload counters, exact package hashes,
per-stage evidence and failures. `--build-only` explicitly records that workerd
and browser scenarios were not run. The complete gate passed in
[CI run 43940378818](https://github.com/werg/chronolog-db/actions/runs/43940378818)
on clean tested merge `43efd510001c2608bc1e28ee4c7d100cb34c773b` of authored head
`5cfa04440029c24d4313e7b8e88e593952180adb`, consuming Tendriller
`43cac4e75b0bbe1e422f4879b7249d6db5988440` with clean embedded membership source
`46b72ebc1c69f71b4cabab744ef19c6a4e50dfec`. Its report records seven runtime
assertions plus the independent build/import audit, Chromium `158.0.8127.18`,
zero application envelope bytes on the administrator path and no page errors.
Four small candidate envelopes totaled 2,668 bytes with 568 descriptor bytes;
four large envelopes totaled 789,092 bytes with 576 descriptor bytes. Doubling
the small candidate count doubled descriptor bytes to 1,136. The same run's
separate pregranted two-layout application fixture passed eight checks with one
effect dispatch and zero host application writes. Artifact `14262634338` has
SHA-256 `910ac51584c70818dcbf93c945a0766abc01ecaa16c168f80b7cf6810e2b877d`;
the [contrib evidence](https://github.com/werg/tendriller-contrib/blob/feat/chronolog-application-log/cookbooks/run-a-peer-application/notes/thin-membership-administration.md)
retains the exact reports and per-scenario limits. Deployment evidence stays in
the contrib issues.

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
| `createChronologApplicationBackend({ id, replica, sql })` | Public `@chronolog/transport-tendriller` node/client adapter; SQL primitives, queued/provisional/final status, and separate accepted/rejected outcome. |
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

The standalone [`SignalChannel`](../../packages/signals/README.md) has no
database, record codec, grant or finality dependency. Its `send`/`subscribe`
interface uses bounded FIFO delivery by default and explicit `latest` delivery
for replaceable author/session/topic values. `createCapabilitySignals` adapts
already verified group signal rights; the shared native/browser connection
composition forwards verified original bytes and retires routes on disconnect.
No signal persists or advances a durable cursor. An offline receiver cannot
know of revocations it has not received.

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
writes `passed: false` before exit. Earlier local core and contrib wrapper builds passed
with 62 assets. The corresponding local Chromium launch failed with `socket() failed: Operation
not permitted`; that is not a browser pass. The paired CI workflow runs the
actual gate on an environment that can launch Chromium.

## Recorded evidence and acceptance map

The prior event/application qualification completed at authored Chronolog head
`db235e61231ed5b41b785390cfb15d6eea3371c6`, tested clean merge
`f6a6b63bb9bed7f8d224450ffccbc3100aa55a91`. This is historical evidence for the
earlier administration/record format, not the new thin-membership gate.

- [Quality and cross-platform conformance](https://github.com/werg/chronolog-db/actions/runs/43925461758)
  passed 631 tests, the eight-test native SSB gate, Linux/macOS conformance and
  their digest comparison.
- The complete [browser workflow](https://github.com/werg/chronolog-db/actions/runs/43925461545)
  passed four actual native/WASM comparison tests, seven SQL-free OPFS scenarios,
  eight mixed SQL/OPFS scenarios, five public bridge checks and all eight
  two-layout task/chat pilot checks. The pilot observed one worker dispatch,
  zero host application-state writes and no page errors in Chromium
  158.0.8127.18. Native final result took 224 ms and the browser applied frontiers
  took 7,524 and 8,841 ms; these are run observations, not a production promise.
- Exact public inputs were Tendriller
  `4eb9a4fec0892378574324675611d0e0e3eecb55` and contrib
  `41f0f44b7dd48e80f049d38dad7f8d6c0e452ae8`. The workflow's artifact
  `14256401547` has SHA-256
  `b1d7bedb51f4d5cf25bc14cb7cd4dfc8645ca2aace71680ed393d7d9eeff8dcc`.
- [Chaos qualification](https://github.com/werg/chronolog-db/actions/runs/43925461418)
  also passed at that head. Every later core/format change requires its own
  regression result; earlier browser evidence is not relabeled.

| Acceptance item | Executable evidence | Qualification boundary |
| --- | --- | --- |
| Event-only replay/reopen without application SQL | [Native public integration](../../test/application-log.integration.test.ts), [SQL-free browser gate](../../tools/test-browser-events.ts) | Actual browser pass is tied to the CI head above. |
| Mixed atomicity; exact accepted/rejected retry after revocation/reopen | [Native integration](../../test/application-log.integration.test.ts), [publisher tests](../../packages/node-core/src/publisher.test.ts) | Real deterministic engine and persistent stores, not provider actions. |
| Rebase, combined pinned view and finality-only status | Native integration, [RPC tests](../../packages/rpc/src/application.test.ts) | Complete two-layout browser behavior separately gated. |
| Durable batches, empty scan progress, filter mismatch, bounded scans | [Reader tests](../../packages/node-core/src/events.test.ts), [client tests](../../packages/client/src/application.test.ts) | Full history retained; no long-history cost claim. |
| Atomic projection/checkpoint and reducer invalidation | [Projection tests](../../packages/client/src/projections.test.ts), actual SQLite rollback/reopen, actual OPFS browser gate | Consumer must use an atomic state/cursor store. |
| Limited publisher and anonymous HTTP boundary | Publisher tests, [HTTP tests](../../packages/rpc/src/publisher-http.test.ts) | TLS/CORS/device storage remain explicit deployment decisions. |
| Native fencing, lost acknowledgement, quota and continuity refusal | [Authority tests](../../packages/agent-service/src/native-finality.test.ts) | Disk loss and independent backup freshness remain contrib #16. |
| Original records/certificates across authenticated byte streams | [Link tests](../../packages/agent-service/src/peer-link.test.ts), [HTTP fixture integration](../../test/browser/event-fixture.test.ts) | No home/mobile/corporate direct byte-route claim. |
| Final intent, uncertain effects, exact result retry and deadlines | [Worker tests](../../packages/agent-service/src/effect-worker.test.ts), daemon composition | Controlled provider fixtures cannot establish a real provider promise. |
| Timer race, replacement generation and accepted retry after cancellation | [Scheduler tests](../../packages/agent-service/src/timers.test.ts), [real SQL integration](../../test/sql-timers.integration.test.ts) | External action cancellation remains a provider contract. |
| Ephemeral expiry/replay and backpressure | [Signals](../../packages/signals/src/channel.test.ts), [framing](../../packages/agent-service/src/framing.test.ts), pilot | Known membership is local; no instantaneous offline revocation knowledge. |
| Public consumption and peer-only page behavior | Tendriller release consumers, [adapter tests](../../packages/transport-tendriller/src/application.test.ts), pilot | Runtime is packaged; production network qualification stays open. |

Contrib's [complete scenario matrix](https://github.com/werg/tendriller-contrib/blob/feat/chronolog-application-log/cookbooks/run-a-peer-application/notes/implementation-and-qualification.md)
also covers old-scope rejection in the separately hosted backend and metadata
versus byte availability. Its 19 page/model tests cover pure projection,
draft/receipt behavior and content boundaries, not native/browser semantics.

## Operational work is issued, not fabricated

- [Contrib #14](https://github.com/werg/tendriller-contrib/issues/14): actual
  browser/native direct/fallback routes on home/mobile/corporate networks,
  interruption/suspension, warm hosting outage and direct/relayed byte accounting.
  Count descriptor/inline-control traffic separately from detached envelopes.
- [Contrib #15](https://github.com/werg/tendriller-contrib/issues/15): paired hosted
  and peer workloads, request/storage/relay costs, startup/catch-up/replay,
  latency and memory. Moving authority does not establish transport savings.
  Include administrator metadata cost and separate size/count workloads.
- [Contrib #16](https://github.com/werg/tendriller-contrib/issues/16): persistent
  volume fencing, commit/ack crash, disk loss, trusted independent continuity,
  backup restoration and explicit new-lineage decisions.
  Rehearse Cloudflare root/roster recovery separately from native ordering and
  detached payload recovery.
- [Contrib #17](https://github.com/werg/tendriller-contrib/issues/17): deployed
  enrollment, device suspension/OPFS/quota/clearing, publisher/signal grant
  boundaries, private context/bytes and backup availability.
  Include live Cloudflare approval, direct writer revocation despite valid host
  login, reader future-key removal and browser readiness after certified bootstrap.

These issues contain concrete completion criteria and remain open until actual
deployment evidence is attached. A fixture, screenshot or passing local unit
test does not close them.
