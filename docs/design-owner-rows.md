# Row ownership and application membership

The signing device is the actor for each application program. A coordinator
orders that original signed program; sequencing authority does not let it replace
the author, impersonate an administrator or gain permission to edit a row.

## Shared data and distinct authority

The reserved `APPLICATION_COLLECTIVE_ID` owns application-wide SQL data.
Membership comes from the signed control revision's `dataRole`. Reader, writer,
coordinator, recovery and control-administrator grants are separate concerns.
A control-only server has no implicit SQL data membership.

Replay evaluates a program under its authenticated historical control revision.
Before publishing the coherent current view, the materializer reapplies the newest
control projection, including changes with no application command. Recovering an
earlier data prefix cannot restore revoked access or an older membership table.

The control projection pins the schema administrator and application collective.
Once installed it cannot be omitted. Ordinary application commands cannot change
schema, platform ownership, memberships or permissions. Initial schema is separately
signed and verified against the application descriptor before materialization.

## Enforcement

Application tables carry an owner column maintained by platform triggers.
Statements execute under the real author and the deterministic transaction
context. Row and collective permissions authorize modifications; ordinary SQL
cannot impersonate an actor, bypass the generated triggers, or modify reserved
platform tables.

Application triggers and `chronolog_assert` can narrow business behavior. They
cannot enlarge a participant's grant. Every accepted program publishes its SQL
changes and effective events atomically; a rejected program publishes neither.

Immutable reads capture one materialized revision. A recovery either retains that
view or makes its excluded ancestry explicit, requiring a reread. Read access to
a replica includes public stored values and ciphertext; row write ownership is
not a confidentiality boundary.

## Confidentiality

[Sealed values](sealed-data.md) encrypt private fields for explicit recipients.
Application history is separately encrypted under reader epoch keys. Removing a
reader requires a new committed epoch. A device that retained old plaintext or
keys cannot be made to forget them.

See the [SQL contract](implementation-specs/10-deterministic-sql-transactions.md)
for program encoding, owner-aware statements, platform operations and the pinned
execution manifest. The public session exposes one application API regardless of
which transport delivers those programs.
