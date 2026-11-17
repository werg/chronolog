# Owned rows in application code

How an app built on `@chronolog/client` and `@chronolog/react` works with
owner-controlled rows. The rules themselves are in
[design-owner-rows.md](design-owner-rows.md). The runnable version of this page
is [`examples/shared-notes.ts`](../examples/shared-notes.ts)
(`pnpm demo:ownership`).
That walkthrough intentionally inspects provisional local outcomes with
`provisional()`; applications use `accepted()` when later work requires immutable
success.

## The model in four sentences

- Your node signs every transaction with its key. The rows it inserts belong
  to that key.
- Only the owner, active members of an owning team (as that team's governance
  allows), and grantees may change a row. Anything else rejects the whole
  transaction. Nothing is skipped silently.
- Every member of a group can read every row. Ownership controls writes only.
  Use a separate group for data some members must not see.
- Group admins are the schema administrators. Only they run DDL, including
  app triggers.

## Who am I, and who owns this row?

```ts
const me = await client.identity()          // 32-byte signing key
const mine = await client.query(
  `SELECT id, body FROM notes AS n WHERE ${ownerKeySql('n')} = ?`, [me])
```

`chronolog_owner` stores a small principal id, not the key. `ownerKeySql(alias)`
turns it back into the key. To insert a row owned by a team you belong to, use
`OWNER_FOR_KEY_SQL`:

```ts
await client.transaction([{
  sql: `INSERT INTO notes (id, body, chronolog_owner) VALUES (?, ?, ${OWNER_FOR_KEY_SQL})`,
  params: [2n, 'Book the venue', teamId],
}])
```

## Knowing why a write failed

`handle.accepted()` waits for final acceptance and throws a `TransactionRejectedError`
on final rejection. A provisional outcome keeps waiting. `error.reason` says what went wrong:

| `reason.kind` | Meaning |
| --- | --- |
| `policy` | You may not `operation` that row of `table`. |
| `platform` | A sharing, team or transfer step was refused (`reason`: `not_owner`, `offer_closed`, `last_admin`, …). |
| `assert` | Your `chronolog_assert(condition, code)` failed. |
| `schema` | DDL left a table without an owner column or primary key (`schema_unregistered`), or a trigger used `RAISE(IGNORE)`. |
| `engine` | SQLite refused the statement: `constraint`, `denied`, `step_limit`, … |

`error.stepIndex` is the failing step. This outcome is immutable.
`handle.provisional()` separately observes the current position, which a late
predecessor can change through replay (`TransactionOutcome.changedByReplay`).

## Sharing, teams and transfers

Each `client.ownership` call submits one transaction and returns
`{ handle, id }`. `id` is the id of the grant, team or offer it creates.

```ts
// Let Bob update the status of row 1 (omit `row` for all your rows; omit `columns` for every column).
const { id: grantId } = await client.ownership.share({ table: 'notes', with: bob, operations: ['update'], row: [1n], columns: ['status'] })
await client.ownership.revoke(grantId)       // the grantee may also renounce

// Teams: you are the admin; invitees join by accepting.
const { id: teamId } = await client.ownership.createTeam({ invite: [bob] })   // members insert/update, admins delete
await bobClient.ownership.acceptInvitation(teamId)
await client.ownership.invite(teamId, [carol], 'admin')
await client.ownership.removeMembers(teamId, [carol])

// Transfers move ownership when the recipient accepts.
const { id: offerId } = await client.ownership.offerRow({ table: 'notes', row: [1n], to: bob, carry: true })
await bobClient.ownership.acceptOffer(offerId)
await client.ownership.offerAll({ to: newKey })   // snapshot of the rows you currently own
// Either endpoint may cancel/decline an open offer:
await client.ownership.cancelOffer(otherOfferId)
```

Offers bind the current row contents and dependent set. Changing an offered
row cancels the offer; acquiring another row cancels a bulk offer. If a parent
acquires a new dependent, acceptance rejects the stale snapshot. Create a new
offer after the data is ready. A transfer closes competing offers and ends
row-specific grants, so an old offer cannot revive after ownership returns.
Deleting/replacing a row or changing its primary key also ends row-specific
grants. Whole-table grants continue to apply to that owner's current rows.

While acceptance runs, captured rows cannot be deleted or have their non-owner
primary-key components changed by application triggers. The source and
destination keys are also reserved against inserts and rekeying other rows into
them, including owner-composite keys, so a trigger cannot substitute a different
row for one the sender offered. Before accepting, the platform verifies that
every captured row reached its destination owner and left any old owner-specific
key. A skipped update, including one suppressed by `ON CONFLICT IGNORE`, rejects
the entire acceptance. Ordinary ownership cascades still work.

Column grants compare exact stored values: a case change in a NOCASE column,
or a numeric storage-type change, needs permission for that column too.

To combine these with SQL in one transaction, use the step builders
(`ownershipSteps.share(…)` or `platformOp.*`) inside `client.transaction([...])`.
Then `handle.createdId(stepIndex)` gives the created id.

## Listing ownership state

`ownershipQueries` returns local-read queries with typed decoders:

- `teams(me)` and `invitations(me)`;
- `members(teamId)`;
- `grantsReceived(me)` and `grantsGiven(owner)`;
- `incomingOffers(me)` and `outgoingOffers(owner)`;
- `schemaAdmin(me)`.

```ts
const query = ownershipQueries.incomingOffers(me)
const offers = query.decode((await client.query(query.sql, query.parameters)).result)
```

In React, the hooks take this node's key from `useChronologIdentity()` and stay
live:

```tsx
const teams = useMyTeams()               // { status, rows: TeamMembership[] }
const invitations = useTeamInvitations()
const offers = useIncomingOffers()
const received = useGrantsReceived()
const members = useTeamMembers(teamId)
```

Rows keep their last value while a stream reconnects. Any other ownership
query works with `useOwnershipQuery(query)`.

## Schema

- Tables need a non-NULL primary key (at most 64 columns). SQLite's
  `INTEGER PRIMARY KEY` rowid alias is implicitly non-NULL; use explicit
  `NOT NULL` for other keys. Grants and transfers name rows by their actual
  primary-key values. Query results expose an opaque `rk1:` typed key, which
  preserves NUL text and exact numeric values; do not parse it as SQL literals.
- `chronolog_owner` is added automatically: to an empty table, or declared as
  `chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id())`.
- A child table that should move with its parent on transfer references it
  with an owner-composite key:
  `FOREIGN KEY (parent_id, chronolog_owner) REFERENCES parents (id, chronolog_owner) ON UPDATE CASCADE`.
  Other foreign keys may not cascade.
- App triggers can add checks (narrowing), but their writes are owner-checked
  like any other write, and `RAISE(IGNORE)` is refused.
