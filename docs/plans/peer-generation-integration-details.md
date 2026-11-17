# Integration details for the unified peer-generation model

These notes carry implementation findings into the adopted peer-generation
refactor. They describe code reviewed through `3187d9df` and supporting fixes.
The generation implementation owns the public session API. Its
[selected-history contract](../peer-generation-v1.md) already implements signed
prefix adoption, exclusion of abandoned suffixes, immutable exact retries,
deliberate reapplication, protected recovery floors and coherent captured views.
Owned bootstrap now handles first publication, reader join and cached reopen.
The Worker host bridge supplies host access from the page's existing authenticated
connection while signing keys and durable work remain with the device owner.
The session also supplies an owned Worker facade and a network owner for discovery,
invitations, reconnect and permitted takeover, plus its Tendriller backend binding,
encrypted epoch enrollment and opt-in native and browser SQL packaging. The browser
archive includes verified compiled WASM assets whose source identity, deterministic
hooks and runtime versions match the pinned native engine. The remaining integration
work below concerns reset-aware consumers and deployment evidence; those
implemented mechanisms do not by themselves qualify a deployment.

## Completion and recovery

The implemented application waits are `applied()` for accepted or rejected
execution in the selected history, and `shared()` for independently retained
coverage. Explicit recovery may abandon recent work after either observation.
A proposed vocabulary using `local()` and `final()` remains an unimplemented
API design question; application code and current documentation use the public
methods above. A method name alone cannot supply an across-recovery guarantee.

Do not add an extra execution stage just to make two wait methods differ. A
completion wait still returns an accepted or rejected result. An exact retry
retains the original operation, generation, bytes and guards. Reapplication
after abandonment is a deliberate new attempt linked to the original intent.
One command journal owns those identities.

The session also owns its signed recovery-request journal. A lost control reply
uses the same transition identity after restart. Applications and agent tools
should use that owner rather than creating their own retry queue.

Previously returned results remain observations of their original history.
Operation inspection and view-change notifications must expose a later
abandonment/reset explicitly. A returned result must not silently become a new
operation in a different generation.

## Signals stay independent

The standalone signal channel needs neither a database nor an ordering/finality
provider. Keep that separation when adding the generation session. TTL,
authorization, bounded queues and `trySend(): Promise<boolean>` govern live
delivery. `false` means no frame was dispatched; a healthy congested route
remains usable. Reconnection publishes fresh observations without an outbox.

Application previews can carry their operation/generation context as data so
the UI can discard an obsolete preview. This does not require putting the
generation protocol into the generic signal channel. Current signal permission
checks must use current authority even when application data is recovered.

See [the signal contract](../../packages/signals/README.md).

## Rebuild views without erasing external facts

Preserve the materializer's single atomic publication of SQL, events, outcomes
and view metadata. A recovery must replace these together. An already captured
read view stays internally coherent; subsequent captures use the selected
history. Ambiguous storage acknowledgements require reopening the committed
state before another publication can overwrite it.

The current `DurableProjection`, `DurableTimerScheduler` and `DurableEffectWorker`
assume an append-only source. Their checkpoints have no reset protocol. Merely
matching the structural `read`/`subscribe` interface does not adapt them to
generation recovery. The simple starting point for derived application state
is rebuilding it from the recovered history rather than reusing an unrelated
cursor or inventing another command outbox.

Dispatch journals record external facts and need a different recovery rule.
Retain the original effect identity, authenticated requester, provider retry key
and uncertain/completed dispatch state. Before starting an undispatched action,
check that its intent is still applicable and currently authorized. A provider
call that already happened may outlive its abandoned application record;
recovery cannot undo it or justify automatically sending it again. Use the
provider's idempotency/reconciliation contract for uncertain calls.

The same distinction applies to timers: rebuild scheduling from the recovered
application state, while retaining the original configuration/event identity
and caller provenance for an occurrence already dispatched. A scheduler's
signature attests its derived event; copying an origin-shaped payload does not
authenticate the original request.

See [consumer contracts](../../packages/agent-service/src/event-source.ts),
[effect checkpoints](../../packages/agent-service/src/effect-worker.ts),
[timer checkpoints](../../packages/agent-service/src/timers.ts), and
[applied SQL publication](../../packages/materializer-doltlite/src/materializer.ts).

## Account for SQL permissions during recovery

Membership revisions and key epochs have their own authenticated control chain.
The reserved application collective now projects its data roles from that chain:
inherited commands execute under their historical control revision, then the
latest signed control is reapplied before publishing the recovered view. This
keeps a revoked shared-data role revoked when application history moves backward.
Sequencing and recovery rights remain independent of that data role.

The current generation verifier rejects platform operations, ordinary SQL runs
with protected changes disabled, and the signed schema bootstrap precedes
application history. Other mutable SQL controls are therefore not yet exposed
through ordinary generation commands.

When integrating those controls, account for the security decisions that the
existing SQL executor stores in the same Dolt branch as application data:

| Replayed state | What an older snapshot can restore |
| --- | --- |
| Row/table grants and collective membership, including schema administrators | Revoked write access, removed members or demoted administrators |
| Row owners and transfer offers | A former owner's direct authority, or a cancelled transfer offer |
| Sealed-reader policies, registered keys and policy versions | An obsolete reader/key set used to encrypt new data |
| Schema restrictions, lifecycle invalidations and fork seeding state | Removed restrictions, invalidated grants/offers, or earlier seeding privileges |

The current generation fence prevents ordinary commands from making these
protected changes. This is a requirement for enabling mutable SQL controls,
not a demonstrated recovery bypass in the current implementation.

Where the control contract promises that an access change survives recovery,
the simplest integration with the existing executor is a protected recovery
floor covering the complete accepted program and its dependencies. Selection
must preserve that state or refuse the older candidate. Ordinary application
work beyond the protected point can retain the relaxed recovery contract. A
second copy of every permission table is not needed merely to provide this
selection rule.

Preserving only revoked grant IDs would be insufficient: owner checks bypass
grant lookup, collective membership controls schema authority, and encryption
selects readers before a later SQL compare-and-swap can reject a candidate.
Keeping only a maximum reader-policy version also loses the actual audience
and key commitments. Ownership transfer deliberately does not change the
explicit sealed-reader list; name both decisions when both should change.

Relevant implementation: [platform tables](../../packages/materializer-doltlite/src/platform/schema.ts),
[current shared-data control projection](../../packages/materializer-doltlite/src/peer-controls.ts),
[authority operations](../../packages/materializer-doltlite/src/platform/session.ts),
[owner/lifecycle triggers](../../packages/materializer-doltlite/src/platform/tables.ts),
[reader policies](../../packages/materializer-doltlite/src/platform/sealed.ts), and
[encryption preflight](../../packages/client/src/sealed.ts).

## Package and qualification boundaries

Capability revision wire v2 removes mutable validator policy fields and changes
the epoch field's encoding. A membership archive built from the earlier wire
cannot approve/revoke members for a v2 core. Rebuild the portable membership
archive and its Tendriller engine consumer as a pair. Genesis/configuration
success alone cannot establish that later approvals and revocations interoperate.

Useful acceptance checks for the refactor are:

- Standalone signals work without SQL, membership history or an ordering service.
- The actual hosted membership package and native/browser core exchange an
  approval, writer revocation, reader revocation/epoch change and restart.
- Recovery reports abandoned attempts, preserves inherited identities, and
  permits deliberate reapplication without silently changing an exact retry.
- A fresh peer can hydrate the selected prefix from a complete follower or a
  peer still using the previous generation. It exposes no readable view before
  verification and does not restore the source's excluded suffix or old controls.
- A reset publishes one coherent SQL/event/outcome view and rebuilds derived
  projections; dispatch journals retain uncertain external calls.
- Capturing that view performs no history-wide outcome scan; bounded reads use
  the same immutable indexed snapshot, including after recovery and restart.
- When mutable SQL controls are enabled, both users remain valid group writers
  while a row/collective/reader-policy revocation is tested across recovery.
  Global group removal must not stand in for preserving the narrower decision.
- A returning old coordinator cannot readopt a previously excluded branch.

Record the source, packages and recovery contract for each result. Historical
chronological/native/WASM checks establish useful component behavior; they do
not by themselves establish generation recovery or deployed-network behavior.
