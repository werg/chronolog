# Peer generations: selected history with tolerant recovery

Status: implemented peer-generation preview; wider qualification is in progress.
The authenticated history profile is `peer-generation-v1`, with the bounded
`eligible-members-v1` authority policy. The selected-history target uses
`local()` for applied-here results and `final()` for committed/applied results,
with an explicit recovery exception that can abandon a recent suffix. The
current public preview still exposes `applied()`; it exports no local/final
aliases. Historical chronological immutability comes from that older
implementation, not from the name of a wait method.

## Implementation boundary

The private `@chronolog/peer-generation` workspace package implements signed
control verification, `PeerAuthority`, a generation registry and an encrypted
replica with selected-history replay and recovery. The public
[`@chronolog/peer-session` preview](../packages/peer-session/README.md) composes that
replica into commands, queries, operation inspection, applied/shared waits,
reapplication, live signals and coherent change notifications. It supplies native
and browser device entries, a maintained in-process link, authenticated framed
network transport and native/browser RTC composition. SQL applications project
signed data-collective membership separately from sequencing/control rights.
Consumers use an explicitly built, source-pinned package archive during
prerelease qualification.

Tendriller implements the hosted control registry and lifecycle API using the
same verifier. That service selects authenticated generations; it does not
execute application commands. The new session does not reinterpret existing
`chronologd` or chronological browser histories. The [older chronological
application primitives](application-primitives.md) retain their existing APIs,
immutable final-prefix guarantee and original evidence. They are historical
implementation semantics, not a second architecture mandate for new applications.

The preserved [independent native/events development run](https://github.com/werg/tendriller-contrib/blob/5dc62b8d1fd6bb323bf6ca272cb21064f33ab318/cookbooks/run-a-peer-application/notes/peer-generation-qualification.md)
uses a packed public session, separate durable stores and the in-process link.
It records lost-reply retry, blocked portable control calls, older-prefix recovery,
fresh replay, excluded-branch isolation, linked reapplication and reopen. Both
source checkouts were dirty. That evidence does not qualify a clean release,
Tendriller HTTP control routes, physical WebRTC, browser storage, SQL replay,
deployed networks or a universal recovery-age bound. The maintained native RTC
consumer now exercises the same scenario over the public network composition;
its exact clean-archive result remains a separate gate, and loopback RTC evidence
cannot establish Internet or deployed behavior.

## Decision

One replaceable peer sequences ordinary application commands. Every peer verifies
the author's original signed, encrypted attempt, the selected coordinator's order,
and the execution manifest, then independently executes that order. Author time is
provenance, not the order comparator. Local persistence precedes acknowledgment.
No command requires a host request, second-copy acknowledgment or finality service.

The host is a control participant. It retains the signed application descriptor,
monotonic controls and generation selections and atomically chooses successors.
It sees prefix proofs and delegated order headers at transitions, not application
bodies or SQL. Existing generations continue while all host endpoints are blocked.
If both host and coordinator are unavailable, attempts stay saved locally until a
valid successor can be selected. No peer creates an authoritative generation alone.

The default trusts the control service not to equivocate and the selected peer to
sequence consistently. Peers detect conflicting signed orders and fence their
session. This is not Byzantine consensus. Cached delegations have no heartbeat
renewal requirement; an isolated old coordinator can temporarily produce a branch.

## Four separate authority concerns

| Concern | Contract |
| --- | --- |
| Authorship and authorization | The actual signing device and its reader/writer grant remain visible. SQL ownership and schema rights are separate. |
| Sequencing | A signed generation delegates ordering to one eligible reader. It grants no author or SQL administrator impersonation rights. |
| Recovery | The requester needs explicit recovery permission; the candidate separately needs coordinator eligibility. A stored replica or writer grant alone is insufficient. |
| Retention and settlement | A durable retained-prefix acknowledgment reports a copy. It grants no authority and makes no global-finality promise. |

The application descriptor pins the control key, policy, definition, execution
manifest and schema authority. Account login and directory advertisements are
routing/enrollment inputs, never generation or author authority. Applications can
grant ordinary participants both recovery and coordinator eligibility explicitly;
no creator or native process has an implicit permanent role.

## Selection and ancestry

A signed transition binds an exact transition identity, expected selected
generation, requester, candidate, control revision, reason and complete adopted
prefix. Compare-and-swap selects one successor. Exact retries recover the same
selection even when subsequent generations exist. Reusing the identity for a
different request fails.

Each successor adopts a prefix of the *currently selected history*. A prefix in an
inherited generation carries a chain of signed order headers connecting it to that
generation's exclusion cutoff. If G2 adopts G1 through 80, G3 can never inherit
G1's positions 81–100. A valid old signature does not erase this cutoff. All
native, browser and hosted registry consumers use the shared `PeerAuthority`
verifier for these checks. Consumers must not replace its decisions with
application callbacks. Shared implementation does not transfer native test
evidence to browser or deployed-network qualification.

Recovery preserves original bytes and operation identities in the adopted prefix.
Available excluded history is quarantined. There is no automatic branch merge or
automatic resubmission. Deliberate reapplication creates a newly signed attempt,
linked to the old intent, under current controls and freshly selected domain guards.

## Honest application results

An operation can be saved, applied (accepted or rejected), shared, abandoned, or
need reapplication. `applied` includes its generation and position. It remains
stable while that history is selected; it is not irreversible across recovery.
The current preview spells its wait `applied()`, not `final()`. The unified target's
selected-history final result still has the explicit recovery exception above.
Neither spelling makes the existing immutable-history `FinalEventSource` adapter
safe for generation resets without a recovery-aware consumer contract.
Wait cancellation does not cancel or reject the saved command. An exact retry
retains the original bytes, identity, guards, and result.

SQL, effective events, outcomes and view revisions switch together at recovery.
A view from an excluded suffix produces an explicit reread/reset condition. An
inherited view remains an ordering barrier; business assertions still determine
whether an intervening edit invalidates a command.

## Controls, keys and protected work

Controls are a separate signed monotonic chain, activated with a generation.
Revoking a reader requires a fresh encryption epoch and key commitment. Inherited
commands use historical grants; successor commands use the successor revision.
Timestamps cannot regain revoked permissions. Retained plaintext cannot be revoked.

The signed grant's `dataRole` controls application-collective membership separately
from coordinator or control-administrator rights. Replay authorizes original
programs under their authenticated historical role. Before publishing the current
view, the replica reapplies current control membership, including control changes
that contain no application command. A control-only device gains no SQL data role.

Ordinary lossy commands cannot change SQL ownership, permissions, schema or policy.
These require protected administrative handling. A protected recovery floor cannot
regress or disappear; a candidate missing its prefix is unavailable. Introducing a
new floor binds it to the exact adopted base. Control-state loss never silently
creates a replacement signing root or empty registry.

Effects require explicit dispatch policy, a journal that handles recovery resets,
stable effect identity, provider idempotency where available and reconciliation of
uncertain outcomes. The preview does not automatically dispatch irreversible
actions. Protect the complete accepted prerequisite program and dependencies only
when the application requires them to survive recovery. An unavailable protected
prefix blocks that action, not unrelated collaboration; it does not require a
second default architecture.

## Required storage and qualification

Retain complete replayable history initially. Peer recovery requires verified
original bodies, contiguous order evidence, controls, keys and operation identity;
metadata or a SQL cache alone is insufficient. A remote database image is never
accepted merely because a peer signed it. Recovery replays retained evidence.

Replication is prompt and asynchronous. Aim for a second independently stored
complete prefix when another peer is available. Five minutes is the initial
freshness qualification target under a declared two-peer workload, not a universal
loss bound. Reports name the adopted point, known abandoned work and unknown loss.
Do not convert last-seen directory timestamps into an invented loss estimate.

Qualify signed/encrypted model traces, actual deterministic SQL/events replay,
host-blocked commands, lost replies, crashes, incomplete tails, competing successors,
three-generation exclusion, restrictive controls, reopened independent stores and
packed external consumers. Loopback tests do not establish Internet connectivity,
provider savings, deployment authentication, browser suspension behavior or a
production operating envelope. Those require separately recorded deployment runs.

There is no migration or backward-compatibility layer in this prerelease change.
History profiles are authenticated and immutable; old histories are never silently
reinterpreted as peer-generation histories.
