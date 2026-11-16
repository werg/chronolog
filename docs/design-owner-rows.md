# Owner-Controlled Rows in Replicated SQL

Status: **implemented (2026-11-13)**. The Step 8 benchmark is within budget;
the Step 9 chaos run found two transport bugs, now fixed, and is to be rerun
(§11). It ports the
write half of Namlu's design K (`~/namlu/docs/design-K-owner-rows.md`,
"Owner-Controlled Rows") to Chronolog. A row-ownership system, enforced by the
pinned engine on every replica, replaces "any writer may write anything".
The whole plan is built in one pass (§10). Where the work shows the design is
wrong, this document is changed first and the change is logged (§11).

Written against the simplified core (commits `1fb41d8`–`a8e5954`), where:

- membership is four roles (writer, validator, reader, administrator);
- a program was `{version: 1, statements}` (now `{version: 3, steps}`);
- node state and feeds live in SQLite.

The normative contract is
[Specification 10](implementation-specs/10-deterministic-sql-transactions.md).

**Owner decisions (2026-11-13):**

- Each authored change has one signed participant identity; there are no
  per-session identities impersonating the replica. The application-log
  extension admits original-signer proposals through an explicitly authorized
  forwarding feed. Row ownership always uses that original signer, and a
  limited publisher receives no reader keys or history access.
- Policy violations abort the transaction. Nothing is skipped silently.
- `recursive_triggers` is on during consensus execution, so `REPLACE` is
  subject to delete checks.
- A planned key change is a bulk transfer of the old key's rows.
- App triggers stay allowed. Only `group` admins may create them, and
  `RAISE(IGNORE)` is refused.

## 0. Goal and scope

**Goal.** Every application table has a fixed, platform-generated write check
that defers to the row's owner. Only the owner, or someone the owner granted
access, can update or delete the row. The root administrator and schema
administrators cannot widen that. They can narrow it with ordinary app
triggers.

**Reads are out of scope, deliberately.** Every participant runs a node, and
every reader node decrypts the whole log and materializes every row. Read
policies would restrict no one: anyone they could filter already holds the
data. "Reader" means "trusted with every row". Confidentiality between
participants would need per-audience encryption, which needs its own design
(§8).

What carries over from Namlu:

| Namlu K | Here |
| --- | --- |
| Owner column, stamped from verified identity | `chronolog_owner`, stamped from the signing key (§2) |
| Base permissive policies for insert/update/delete | Generated platform triggers (§4) |
| App restrictive policies, declarative integrity, no app triggers | **Ordinary app triggers** written by schema admins (§5). They can narrow access but cannot widen it. |
| Owner floor (owners can always delete) | Dropped: schema admins may narrow anything |
| Grants, collectives, transfer | Yes (§3, §6) |
| Read policies, table classes, sharing rules, consent, moderation hide, blocks | Dropped: they only matter for reads |
| Proxy-injected claims | Not needed: the actor is the transaction's signer |

## 1. Why this fits Chronolog

- **The actor comes from a signature.** Namlu has to trust its proxy to inject
  claims. Here the actor is the key that signed the transaction.
  - Checks are deterministic functions of that key and the replicated state.
  - Every replica therefore enforces them identically during replay.
  - An out-of-policy write is rejected everywhere, including by the author's
    own node.
- **The engine stays.** SQLite has no row-level security. What it has is
  enough to build it:
  - triggers with `RAISE(ABORT)`;
  - the consensus authorizer;
  - the native binding patch, which already implements `chronolog_assert`
    in C;
  - the deterministic context.
- **Admission stays in the protocol.** Validators attest inclusion by
  timestamp, and a transaction's order position must not depend on
  materialized state. So the four capability roles are unchanged.
  - The `writer` grant still decides who may author at all. That is spam and
    Sybil control.
  - Data authorization lives in the database.

| Concern | Today | Proposed |
| --- | --- | --- |
| Admin, validators, readers, writer admission | capability log | **unchanged** |
| Who may run DDL (including triggers) | any writer | admins of the `group` collective (§3) |
| Which rows a writer may insert, update or delete | any | owner, collectives, grants (§4, §6), narrowed by app triggers (§5) |

## 2. Identity: the owner is the signing key

`chronolog_actor()` returns the transaction's `authorId`: the signing public
key of the node that authored it.

- It is set from the signed core in `setDeterministicContext`, next to the
  clock and PRNG seed.
- It is implemented in C in the native patch, like `chronolog_assert`.
  Checked 2026-11-13: the binding's `createFunction` is an upstream stub that
  registers nothing, so a JS-defined function is not an option. Every
  platform SQL function is native.
- Outside consensus execution it returns NULL.
- `chronolog_actor_id()` returns the same signer's **principal id**: the
  small integer that stands for its key in this database (§3). It is pinned
  in the same context, and is the owner column's default.

Using the key itself means an administrator cannot pair your identity with
their key. This is unlike the administrator-assigned
`CapabilityGrant.subjectId`. They can admit or revoke your node, but they
cannot act as you.

Consequences:

- **One node, one owner.** Rows written by two nodes belong to two owners,
  even if both nodes belong to the same company. To share ownership, use a
  collective (§3), or grant each other write access.
- **A planned key change** is a bulk transfer (§6) of every row the old key
  owns to the new key. The old key signs it.
- **A lost or compromised key** gets no in-protocol recovery. Its rows stay
  with it, and the group forks out of band if that matters.
- **Revoking a node's `writer` grant** stops its new writes. Its rows stay
  owned by its key: they are neither deleted nor transferred.

## 3. Data model

Every *registered* application table carries:

```sql
chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id())   -- principal id of a node key or a collective
```

- **Principals.** Owners are stored as integers, not 32-byte keys:
  `chronolog_principals (id INTEGER PRIMARY KEY, key BLOB UNIQUE)` maps each
  id to its key. The `group` collective is 1 and the root administrator 2; any
  other key gets the next id when it first signs a transaction, a collective
  when it is created, and a seeded owner when it is seeded. Ids never change,
  and their assignment is deterministic because execution is. Platform tables
  (collectives, members, grants, offers) keep keys; only owner columns, the
  lookup views and transfer exemptions use ids. To name an owner by key in
  SQL: `(SELECT id FROM chronolog_principals WHERE key = ?)`.

- **The column.** `chronolog_*` is already a reserved prefix. App SQL may
  reference the column, for example in owner-composite foreign keys. Writes
  to it are checked (§4).
- **Stamping by default.** Verified on SQLite 3.46 and DoltLite 0.11.29:
  - A non-constant `DEFAULT` (`random()`, `strftime(…)`, and the native
    `chronolog_actor_id()`) works in `CREATE TABLE`, and in
    `ALTER TABLE ADD COLUMN` on an *empty* table.
  - On a non-empty table both refuse with "Cannot add a column with
    non-constant default".
  - So a table is registered (put under owner checks) by the statement that
    creates it, while it is still empty.
- **Row identity.** Grants and transfers name a row by its primary key, as
  `quote(pk1) || ',' || quote(pk2) …` (the `rowKey` of an operation is the
  key's values). So a registered table needs a declared primary key.
- **Every table is registered automatically.** There is no registration
  step. Reconciliation runs right after every statement that changed the
  schema, so a new table is owner-checked from the next statement on. It
  registers each new application table: it adds the owner column if missing,
  lints the foreign keys, checks that existing rows are ones the signer could
  have inserted, and generates the platform triggers. A table that cannot be
  owner-checked fails the transaction: `platform:no_primary_key` (for example
  `CREATE TABLE … AS SELECT`), `platform:table_not_empty` (rows but no owner
  column), `platform:owner_column_invalid`,
  `platform:fk_action` or `platform:foreign_owner`. The transaction also
  fails with `schema_unregistered` when:
  - a registered table is missing its platform triggers, its owner column or
    its primary key;
  - a `chronolog_*` trigger or view is not the platform's own.
  - Virtual tables (FTS5, R-tree, sqlite-vec) cannot carry triggers, so they
    carry no owner checks. Instead, **app SQL may write them only from app
    triggers**: a top-level `INSERT`, `UPDATE` or `DELETE` on a virtual table
    (or on sqlite-vec's chunk tables) is denied, for every signer. Their
    contents are therefore written only by sync triggers on registered tables,
    which fire on owner-checked writes. The sync triggers are app triggers,
    written by schema administrators.
  - Their shadow tables are exempt from registration, and so are sqlite-vec's
    `<table>_vector_chunksNN` tables, which SQLite cannot mark as shadow
    tables (it finds a shadow table's parent at the last underscore). A chunk
    table is recognized by its vec0 parent, a chunk number below the parent's
    vector-column count, and vec0's exact two columns.
  - The engine marks vec0 innocuous (as FTS5 and R-tree already are), so it
    can be used in triggers with `trusted_schema` off.
  - Reconciliation also regenerates a registered table's platform triggers
    when its columns changed (an admin's `ADD`, `RENAME` or `DROP COLUMN`),
    because the update trigger lists the columns for grant caps. Dropping a
    registered table unregisters it, revokes its grants and cancels its open
    offers. Renaming one moves its registration, grants and open offers to
    the new name and regenerates its triggers (SQLite moves the triggers with
    the table, which is how a rename is recognized).

**Platform tables.** These are replicated, readable by transactions, and
writable only by platform operations:

```text
chronolog_platform           (root_admin, seeding_open)
chronolog_tables             (name, registered_at_tx)
chronolog_collectives        (collective_id, kind: group|team, insert_role, update_role, delete_role, created_tx)
chronolog_collective_members (collective_id, member_key, role: admin|member, state: invited|active|left, joined_tx, left_tx)
chronolog_grants             (grant_id, tbl, grantor, grantee_key, row_key NULL, op_insert, op_update, op_delete, columns NULL, created_tx, revoked_tx)
chronolog_transfers          (offer_id, tbl NULL, row_key NULL, from_owner, to_owner, carry, state: open|accepted|cancelled, created_tx, closed_tx)
chronolog_exemptions         (kind, tbl, row_key, from_owner, to_owner)   -- empty between steps
```

A collective's governance names the least role (`member` or `admin`) for
inserting, updating and deleting its rows. Grant, collective and offer ids
are derived from the creating transaction id and step index.

**Lookup views** are generated, named `chronolog_*`, and filtered by
`chronolog_actor()`:

- `chronolog_my_owner_ids_insert`, `_update` and `_delete`: the principal ids
  of the actor and of the collectives whose governance lets the actor perform
  that operation.
- `chronolog_grants_to_me_insert`, `_update` and `_delete`: live grants to
  the actor, with the grantor as a principal id (`grantor`) and a key
  (`grantor_key`); `row_key` is NULL for a whole-table grant.

App triggers and app SQL can use these views too.

**The `group` collective** (id: 32 zero bytes) is created at genesis, with
the explicit `schemaAdminPublicKey` as its admin and admin-only governance. The
materializer is opened with that SQL administrator key (from the signed
genesis, or `rootAdministrator` in a static membership file), stores it in
`chronolog_platform`, and refuses to reopen the database with another. Its
admins are the schema administrators. The roster issuer `rootAdminPublicKey`
is a separate authority and does not implicitly join this collective.
They may run DDL, including creating tables (registered automatically) and app
triggers.

- `team` collectives are optional shared owners. A member creates one, and
  others join by accepting.
- Membership changes are platform operations, governed by the collective's
  own rules.

## 4. Write enforcement: generated platform triggers

For each registered table `T`, the platform generates one trigger per event:
`chronolog_k_T_ins`, `_upd` and `_del`, all `BEFORE`.

```sql
CREATE TRIGGER chronolog_k_T_upd BEFORE UPDATE ON T BEGIN
  SELECT chronolog_policy_violation('T', 'update') WHERE CASE
    -- ownership changes only by transfer
    WHEN NEW.chronolog_owner IS OLD.chronolog_owner AND OLD.chronolog_owner = chronolog_actor_id() THEN 0
    WHEN NEW.chronolog_owner IS OLD.chronolog_owner
      AND EXISTS (SELECT 1 FROM chronolog_my_owner_ids_update WHERE id = OLD.chronolog_owner) THEN 0
    WHEN NEW.chronolog_owner IS OLD.chronolog_owner
      AND EXISTS (SELECT 1 FROM chronolog_grants_to_me_update g
                   WHERE g.tbl = 'T' AND g.grantor = OLD.chronolog_owner
                     AND (g.row_key IS NULL OR g.row_key = <OLD row key>)
                     AND <every changed column is in g.columns, if set>) THEN 0
    WHEN <an exemption admits this owner change: the accepted offer's rows> THEN 0
    ELSE 1 END;
END;
```

The checks are a `CASE` chain, so SQLite stops at the first arm that holds:
the common case, the signer owning the row, costs one comparison. They fail
closed: a NULL arm does not match, so a NULL owner is a policy rejection.

`chronolog_policy_violation(table, command)` is a native function in the
patch, like `chronolog_assert`. It fails the statement with
`SQLITE_CONSTRAINT_FUNCTION` and the message `chronolog_policy:<table>:<command>`.

- The consensus authorizer allows calls to it only when the innermost trigger
  or view is a `chronolog_*` object. App code cannot create those.
- Checked on DoltLite 0.11.29: the authorizer's `FUNCTION` callback reports
  the calling trigger (`app_t` and `chronolog_k_t_upd`, as appropriate), the
  calling view, or NULL for a direct call.
- So apps cannot imitate a policy rejection, and no message lint is needed.

**The per-operation checks:**

- **Insert:** `NEW.chronolog_owner` must be one of the actor's owner ids, or a
  grantor who granted `insert` on `T`. The default stamps the actor itself.
  During `SeedRows`, an exemption admits the seeded owners.
- **Delete:** the actor must be the owner (or act for an owning collective)
  or hold a `delete` grant on the table or the row from the owner.

**Interaction with app triggers.**

- Every write is checked against the transaction's signer, including writes
  made by app triggers. So an app trigger can never do more than the signer
  could.
- Verified on SQLite 3.46 and DoltLite 0.11.29: Alice updates her row in `a`.
  An app trigger on `a` then writes Bob's row in `b`. The write hits `b`'s
  owner check, and the whole transaction aborts.
- When several triggers fire on one event, SQLite's order is fixed by the
  pinned engine and the schema, so it is deterministic. The outcome does not
  depend on that order anyway, because any failure rolls back the whole
  transaction.

**No silent skips.**

- Every violation aborts the whole transaction.
  - `UPDATE t SET …` matching another owner's row is rejected; it does not
    quietly change only the actor's rows.
  - Apps target their own rows explicitly, for example
    `WHERE chronolog_owner IN (SELECT id FROM chronolog_my_owner_ids_write)`.
- Every row is readable during execution, so aborting reveals nothing.
- `INSERT OR IGNORE` and `ON CONFLICT DO NOTHING` remain allowed. They are
  explicit conflict handling that the statement asks for. They never write
  the conflicting row, so they are not permission skips. On DoltLite, both
  leave Bob's row untouched when Alice runs them.
- The platform never generates `RAISE(IGNORE)`, and app triggers containing it
  are refused (§5).

**Foreign-key actions fire child triggers.** A cascade from A's parent into B's
child rows therefore aborts A's transaction. Verified on DoltLite: deleting
Alice's parent with Bob's `CASCADE` child aborts with the child's delete
policy, and with a `SET NULL` child it aborts with the child's update policy.
An owner-composite FK refuses a child whose owner differs from the parent's,
and cascades through Alice's own children.

- Reconciliation lints `pragma_foreign_key_list`
  (`platform:fk_action`). An owner-composite FK, for example
  `FOREIGN KEY (parent_id, chronolog_owner) REFERENCES parent(id, chronolog_owner)`,
  must be `ON UPDATE CASCADE`, so a transfer carries the child, and may be
  `ON DELETE CASCADE`. `SET NULL` is refused even there: it would null the
  child's owner column.
- Every other FK, including cross-owner references, is `RESTRICT` or
  `NO ACTION`; use a soft delete where a cascade is wanted.

**`REPLACE` and `recursive_triggers`.**

- `REPLACE` deletes the conflicting row. SQLite fires delete triggers for that
  deletion only when `recursive_triggers` is on.
- Consensus execution enables the pragma (D3). Verified on SQLite 3.46 and
  DoltLite 0.11.29:
  - with the pragma on, `INSERT OR REPLACE` and `UPDATE OR REPLACE` over Bob's
    row by Alice abort with the delete policy;
  - with it off (SQLite 3.46), the replace succeeds and takes over the row.
- The other write paths were verified on DoltLite with the pragma on:
  - UPSERT `DO UPDATE` onto Bob's row aborts with the update policy, and on
    Alice's own row succeeds, including `RETURNING`;
  - `INSERT … SELECT` copying Bob's owner value is refused;
  - an update that changes the owner column is refused.
- With the pragma on, an app trigger that updates its own table fires again.
  - An unguarded one aborts deterministically with "too many levels of trigger
    recursion". That is `SQLITE_ERROR`, which maps to the existing `error`
    rejection. The depth is the profile's trigger-depth limit of 16.
  - A `WHEN`-guarded one runs once. Both cases were verified on DoltLite.
  - App authors write guarded self-updating triggers, as in any SQLite app
    with recursive triggers.

**Platform operations and app triggers.** Some platform operations write app
tables:

- `TransferAccept` rewrites `chronolog_owner`;
- `SeedRows` (§7) writes seeded rows.

App triggers on those tables fire too. Platform operations therefore never
run with an elevated actor:

- `chronolog_actor()` stays the transaction's signer, for example the
  recipient accepting a transfer.
- The platform trigger admits the owner-column change under an exemption
  (a row of `chronolog_exemptions`, written and deleted inside the operation)
  keyed to the offer's row, its old and new owner, and each same-owner
  dependent found by walking owner-composite FKs. A bulk transfer's
  exemption covers every row of the old owner, per table.
- Every other write, including writes by app triggers, is checked as the
  signer.
- Platform statements run under a `platform` authorizer mode that may write
  `chronolog_*` objects. App triggers they fire are compiled inside them, and
  the authorizer applies the consensus rules to anything an app trigger or app
  view does.

**Authorizer changes** in consensus mode:

- Deny all DDL unless the actor is a `group` admin. This includes
  `CREATE TRIGGER`, `DROP TRIGGER` and `DROP TABLE`. The callback reads a
  cached admin set that is refreshed after platform operations.
- Deny creating or dropping `chronolog_*` triggers and views, and dropping
  `chronolog_owner` (`DROP COLUMN` reports the column to the authorizer). A
  `DROP TABLE` reports a `DROP_TRIGGER` for each of the table's triggers, so a
  `chronolog_*` trigger may be dropped only by its own table's `DROP TABLE`
  in the same statement. Renaming the owner column is caught by
  reconciliation. Only the platform-internal mode, inside platform
  operations, bypasses the reserved prefix.

**Rejection codes.** These are added to Specification 10 §4:

- `policy:<table>:<command>`;
- `platform:<reason>`;
- `schema_unregistered`;
- `trigger_ignore`.

`rejectionFor` in `materializer-doltlite/src/sql-executor.ts` maps
`SQLITE_CONSTRAINT_FUNCTION` with the `chronolog_policy:` message to
`policy:…`, exactly like the existing `chronolog_assert:` branch.

App `RAISE(ABORT, …)` stays `SQLITE_CONSTRAINT_TRIGGER` (extended code 1811
on DoltLite), which maps to `constraint`, as it does today.

## 5. App triggers (narrowing, integrity, indexes)

Schema admins (`group` admins) write ordinary SQLite triggers for everything
Namlu needed restrictive policies and declarative integrity for:

- **Narrowing who may write.** For example, only `group` members may insert
  into `listings`:
  `SELECT RAISE(ABORT, 'listings_members_only') WHERE chronolog_actor() NOT IN (SELECT member_key FROM chronolog_collective_members WHERE …)`.
- **State machines.** For example, `status` only moves forward, or columns
  freeze after submission.
- **Cross-row invariants.** For example, no overlapping bookings:
  `BEFORE INSERT … WHERE EXISTS (…overlapping row…)`. SQLite has no
  `EXCLUDE` constraint, so a trigger (or a `chronolog_assert` in the writing
  transaction) is the way to enforce this.
- **Derived data.** FTS5, R-tree and sqlite-vec sync triggers, `updated_at`
  touch, and counters. Writes to registered tables are checked as the signer,
  so a counter row that many owners update must be owned by a collective they
  belong to, or covered by a grant. Virtual tables can only be written this
  way (§3).

**`RAISE(IGNORE)` is refused.** It silently skips the row being written,
which contradicts the no-silent-skips decision.

- Verified on DoltLite: an app `BEFORE UPDATE` trigger with `RAISE(IGNORE)`
  makes an update report success while the row is left unchanged.
- Reconciliation scans the SQL of every app trigger in `sqlite_schema`, using
  **SQLite's own tokenizer**. Any `RAISE ( IGNORE` token sequence fails the
  transaction with `trigger_ignore`.
  - The patch exports a native `chronologTriggerUsesIgnore(sql)`. It calls
    `chronolog_sql_uses_raise_ignore`, a small C function that the patched
    `build-amalgamation.js` appends to the generated `doltlite.c`, next to
    the pager stub it already appends, so it can call the static
    `sqlite3GetToken`. The pinned-source check covers the downloaded
    tarball, so it is unaffected.
  - The build does not define `SQLITE_ENABLE_NORMALIZE`, so
    `sqlite3_normalized_sql` is unavailable, and a hand-written TS tokenizer
    would be a second grammar to keep in sync.
- A false negative would let an app skip rows silently, but could never widen
  anyone's write rights. So this lint is a policy check, not a security
  boundary.

**What app triggers cannot do:**

- widen anyone's rights, because every write is checked as the signer (§4);
- write platform tables, which the authorizer denies;
- change `chronolog_owner`, which only the platform trigger may allow;
- skip rows.

**What they can do is block owners.** A trigger may refuse an owner's own
update or delete. That is narrowing, and Chronolog accepts it: schema admins
are trusted to shape the schema, not to own data. Namlu's owner floor is not
kept.

## 6. Platform operations

Platform state changes need trusted code with typed inputs. The signed program
becomes:

```text
ChangeProgram { version: 3, steps: Step[] }       // 1..256
Step = SqlStatement | PlatformOp | EmitStep
PlatformOp =
  | Grant            { table, grantee, grantor?, rowKey?, operations, columns? } | RevokeGrant { grantId }
  | CreateCollective { governance, invitees } | AcceptMembership { collectiveId } | Leave { collectiveId }
  | SetMembers       { collectiveId, changes }                // admins; new keys are invited
  | TransferOffer    { scope: row(table, rowKey) | all, fromOwner?, toOwner, carry } | TransferAccept { offerId }
  | SeedRows         { table, columns, rows }                 // fork seeding only (§7)
  | EndSeeding       { }                                      // closes fork seeding (§7)
```

Over RPC a platform step travels as its canonical CBOR (`{ platform: bytes }`);
the CLI takes readable JSON (`{"platform": "grant", …}`).

- **Execution.** Each operation runs in step order in the transaction's
  savepoint, as trusted deterministic TypeScript. It checks its authority from
  replicated state and `chronolog_actor()`, writes platform tables, and
  regenerates the affected platform triggers and views.
- **Failures** are deterministic rejections, for example `platform:not_owner`.
- **Manifest.** The platform code determines replicated state, so it goes into
  the execution manifest.
  - `ExecutionManifest` is now version 2:
    `{version, profile, engine, engineDigest, programVersion: 3, platformDigest, recursiveTriggers: true, limits}`.
  - `platformDigest` is SHA-256 over `PLATFORM_CODE_VERSION` (bumped with any
    change to what an operation checks or writes), the platform schema and
    views, and the triggers generated for a fixed reference table.
  - A replica already rejects a candidate whose manifest it does not run
    (`manifest_mismatch`).
- **Tooling.** The client SDK and CLI get typed builders.

**Grants** are given by an owner, or a collective admin, to another key.

- A grant covers a table or a single row, a set of operations
  (`insert|update|delete`), and optionally a list of columns that may be
  changed (which requires `update`). A row grant's grantor is the row's owner
  and cannot include `insert`. A table grant is on the signer's rows unless
  `grantor` names a collective the signer administers.
- The grantor (or an admin of a grantor collective) revokes; the grantee may
  renounce. Revocation takes effect from the next step in the order.
- A row grant ends when the row is transferred.

**Transfer** is an offer by the owner plus acceptance by the recipient.

- Same-owner dependents move along through owner-composite
  `ON UPDATE CASCADE` FKs, when the offer says `carry`; otherwise a row with
  such dependents cannot be transferred (`platform:has_dependents`). At
  acceptance the row must still belong to the offer's owner
  (`platform:offer_stale`).
- `scope: all` transfers every row the old key owns *when the offer is
  accepted*, across all registered tables, parent tables first, including
  rows written after the offer was made. It re-points the live grants the old
  key **gave** (it is their grantor) to the new key. This is the key-change
  path (§2).
  - Grants the old key **received** do not move: the recipient of a bulk
    transfer need not be the same person, and moving them would give it
    rights their grantors never gave. Grantors grant the new key again.
  - Collective memberships are not transferred either; the new key is invited
    again.

## 7. Interactions

- **Snapshots and forks.** `chronolog_owner`, the platform tables and app
  triggers are ordinary replicated state, so they survive `snapshot export`
  and `group fork`. Owners are node keys, and members keep their keys in the
  fork; principal ids are local to each group, so forks carry owners as keys.
- **Fork seeding.** Today the seed plan (`chronolog-fork-seed-v2`) is ordinary
  transactions submitted by the new root. That would stamp every row with the
  root as owner, and app triggers would fire during seeding.
  - `SeedRows` takes each row's owner as a key, writes it as the fork's
    principal id for that key, and keeps the `fork_seed_applied` per-batch
    guard.
  - It is allowed only in a **fork** (a group whose genesis names a source
    group), only for the initial schema administrator, and only until seeding ends. Seeding
    ends at the root's `EndSeeding` step, which is the seed plan's last
    batch, or at the first accepted transaction by any other author, if that
    comes first. After that not even the root can seed. In every other group
    seeding is never open.
  - It also seeds `chronolog_collectives`, `chronolog_collective_members`,
    `chronolog_grants` and `chronolog_transfers` verbatim, except the `group`
    collective, which the fork's root administers.
  - App triggers are created after the rows are seeded, as fork-seed already
    orders views and triggers after data.
- **Validators** are unaffected. They attest inclusion, not policy outcomes.
- **Determinism.**
  - The pinned engine covers SQL triggers, both platform and app.
  - `platformDigest` covers the platform code.
  - Chaos invariants gain two checks: equal platform-trigger digests across
    replicas, and every `chronolog_owner` being a known key or collective.
- **workerd** executes no SQL today (its runtime only coordinates
  materialization), so nothing changes there. If it ever executes programs,
  it needs the actor in its deterministic context and the platform code in
  its bundle; that code does no I/O.
- **RPC, client and React** gain typed builders for platform operations.
  Reads are unchanged.

## 8. Out of scope: confidentiality between nodes

Hiding an owned row from another reader node requires encrypting it to its
audience. Two candidate approaches:

- per-collective subgroups with their own epochs;
- sealed columns, which are opaque to SQL.

Either needs a separate design if it is ever wanted.

## 9. Differences from Namlu

| Namlu | Here | Why |
| --- | --- | --- |
| Reads filtered by RLS | No read policies | Every node holds every row (§0) |
| `USING`-filtered `UPDATE`/`DELETE` (silent skip) | Abort on any non-writable target row | No silent skips (Namlu should follow, keeping invisible rows excluded) |
| No app triggers; restrictive policies and declarative integrity | App triggers by schema admins, minus `RAISE(IGNORE)` | Every write is checked as the signer, so triggers can only narrow |
| Owner floor | None | Narrowing by schema admins is accepted |
| `EXCLUDE` constraints | App trigger or `chronolog_assert` | SQLite has no exclusion constraints |
| Migration DML banned | Allowed, and checked | Admins are ordinary actors under the platform triggers |
| Persons, agents, `act_for` | One key per node | Single participant per node |

## 10. Work plan

All of this is in scope and is built in one pass, in the order below. Nothing
here is optional or left for a later release. Each step ends with its tests
passing.

**How the plan changes.** Sometimes a step shows that this design is wrong or
incomplete: a SQLite or DoltLite behaviour differs from what is written here,
a cost is too high, or a case is not covered. When that happens:

1. Stop that step.
2. Change the affected sections of this document, and add an entry to the
   plan-change log (§11) saying what was found and what changed.
3. If the change needs a choice only the owner can make, ask before
   continuing.

Then carry on with the revised plan. Problems are not worked around in code
while this document still describes something else.

Each step below lists the findings that would force such a change.

### Step 1: engine — native functions and the profile pragma

- **Native functions.** In the DoltLite patch, next to `chronolog_assert`, add:
  - `chronolog_actor()`, by extending `setDeterministicContext` with the
    author key and clearing it with the rest of the context;
  - `chronolog_policy_violation(table, command)`;
  - the exported `chronologTriggerUsesIgnore(sql)`, built on SQLite's own
    tokenizer.
- **Profile.** Enable `recursive_triggers` on the consensus connection, and
  record it in the execution profile.
- **Authorizer.** Allow `chronolog_policy_violation` only inside `chronolog_*`
  triggers and views.
- **Regression tests.** Turn the 2026-11-13 DoltLite checks (§11 log) into
  tests in `materializer-doltlite`:
  - the DEFAULT behaviour;
  - `REPLACE`, UPSERT, `INSERT … SELECT` and `RETURNING`;
  - FK cascade and set-null;
  - app-trigger writes being checked;
  - recursion;
  - `RAISE(IGNORE)` skipping when not linted;
  - authorizer trigger attribution;
  - the same DEFAULT check with the native `chronolog_actor()`.

Findings that change the plan:

- **A native function cannot be used in a column `DEFAULT`** (all of the
  built-in non-constant functions can). Owner stamping is then redesigned in
  §3–4. The likely replacement is an explicit owner value checked by the
  insert trigger.
- **The tokenizer cannot be exported without patching `doltlite.c` in a way
  that breaks the pinned-source digest check.** The lint moves to a vendored
  copy of `normalize.c`, compiled into the addon as its own source file.

### Step 2: protocol and manifest

- **Program v3.** `ChangeProgram { version: 3, steps }`, with a
  canonical CBOR codec for each `PlatformOp`, validation, fuzz tests and
  fixtures. Earlier program versions are removed; there is no compatibility path.
  Version 3 also carries literal `EmitStep` values; see [the application-log implementation](plans/application-log.md) for atomic events and durable cursors.
- **Manifest.** Add `programVersion: 3` and `platformDigest` to
  `ExecutionManifest`. The digest is computed over the platform-operation
  code and the trigger and view generators.
- **Rejection codes.** Add `policy:<table>:<command>`, `platform:<reason>`,
  `schema_unregistered` and `trigger_ignore`.
- **Specification 10** is rewritten for steps, the actor, the profile pragma,
  DDL limited to `group` admins, and the new rejection codes.

### Step 3: executor and platform-operation framework

- **Execution.** `executeTransactionProgram` runs steps in order inside the
  savepoint. SQL statements go through the existing profile, and platform
  operations run through a registry of deterministic handlers.
- **Platform-internal mode.** Handlers run under an authorizer mode that may
  write `chronolog_*` objects, while `chronolog_actor()` stays the signer.
- **Reconciliation** runs after every transaction that changed the schema:
  - registered-table and platform-trigger completeness;
  - the `chronolog_*` reserved-prefix check;
  - the native `RAISE(IGNORE)` check on new or changed app triggers.
- **Rejection mapping.** `rejectionFor` maps `chronolog_policy:` function
  failures and the platform codes.

### Step 4: ownership core

- **Platform tables and the `group` collective.** Create the platform tables,
  and seed the `group` collective with the explicit schema administrator's key at genesis.
- **Registration** (automatic since 2026-11-13; §11). It adds or checks the
  owner column, lints FK actions, and generates the three platform triggers
  and the lookup views.
- **Authorizer.** All DDL is limited to `group` admins, and `chronolog_*`
  triggers, views and the owner column are protected.
- **Tests:**
  - an administrator cannot update, delete or re-own another node's row;
  - no one can get around the checks through `REPLACE`, an FK cascade, an app
    trigger or recursion;
  - DDL by a non-admin is rejected;
  - an unregistered table is rejected;
  - an app trigger can narrow but not widen;
  - `RAISE(IGNORE)` is refused.

### Step 5: grants, collectives, transfer

- **Operations.** `Grant`/`RevokeGrant` with row scope and column caps;
  `team` collectives with `CreateCollective`, `AcceptMembership`, `Leave` and
  `SetMembers` under their governance; and `TransferOffer`/`TransferAccept`.
- **Transfer details.** Transfers carry owner-composite FK dependents. The
  bulk `rowPk: all` form is the key-change path, and the owner-column
  exemption is scoped to the accepted offer's rows.
- **Tests:**
  - grantees are limited to the granted operations and columns;
  - revocation takes effect in order;
  - collective governance is enforced;
  - a transfer needs acceptance;
  - an app trigger that fires during a transfer gets no extra rights;
  - a bulk key-change transfer moves every row.

### Step 6: forks and snapshots

- **`SeedRows`** is allowed only in a fork, only for the initial schema administrator, until
  `EndSeeding` or the first accepted transaction by another author, and
  keeps the `fork_seed_applied` guard.
- **`chronolog-fork-seed`** emits platform tables and `SeedRows`, orders
  app triggers after the data, and ends with an `EndSeeding` batch.
- **`verify-fork`** also compares owners and platform tables.
- **Snapshot export and import** carry everything; tested.

### Step 7: every existing caller of `CREATE TABLE`

Every place that creates application tables registers them. These are:

- `packages/chaos` (schema, workload);
- `packages/conformance` (report, release characterization);
- the materializer integration and security tests;
- `protocol` SQL tests;
- `apps/chronologd` fork-seed;
- `test/sql-client-node.e2e.test.ts`;
- `test/fixtures/materializer-publication-crash.ts`;
- `tools/bench-ingest.ts`;
- `examples/end-to-end.ts`.

Tables that are internal node state (feed store, control store, system log)
are not application tables and are unaffected.

The client SDK and CLI get typed builders for every platform operation. The
demo and README quick start show a registered table and an ownership
rejection.

### Step 8: cost

- **Benchmark.** Run `tools/bench-ingest.ts` (end to end) and
  `tools/bench-materialize.ts` (materializer CPU only) against the tree
  before this work (`a8e5954`). Budget, set by the owner: at most 10% slower.
  The functionality is not in question; a miss means optimize.
- **Result (2026-11-13).** End-to-end time to a materialized outcome: 254 ms
  mean, against 233 ms before (+9%, on a loaded machine with ±10% noise), so
  within budget. Materializer CPU for 300 transactions of 20 rows: insert
  ~+30%, update ~+29%, delete ~+6%. A baseline given an equal 32-byte column
  without triggers costs the same on update, and replacing the insert
  trigger's body with nothing changes nothing: what remained was the storage
  of the 32-byte owner per row, not the checks. Owners are therefore stored
  as small integer principal ids (§3; log entry below).

### Step 9: replication check and documentation

- **Chaos run.** One run with mixed authors, cleared with the owner
  beforehand. The first attempt found that the chaos image still copied
  removed packages; the second ran the workload (54 of 58 operations
  published; the 4 failures were writes to the restarting node) but node-0
  never became healthy again after the restart fault: see §11. It checks equal state digests, equal platform-trigger digests,
  and that every `chronolog_owner` is a known key or collective. The new
  invariants are added to `packages/chaos`.
- **Documentation.** Update `design.md`, `governance.md` (DDL and the `group`
  collective), `implementation-status.md`, `security-threat-review.md`, the
  README, and this document's status.

## 11. Decisions and plan changes

### Decisions


- **D1 (decided 2026-11-13):** one node is one participant; there are no
  relayed or client-signed transactions.
- **D2 (decided 2026-11-13):** app triggers are allowed, created only by
  `group` admins, with `RAISE(IGNORE)` refused. This replaces restrictive
  policies, declarative integrity and platform index declarations. There is
  no owner floor.
- **D3 (decided 2026-11-13):** `recursive_triggers` is on in consensus
  execution, and `REPLACE` is kept. Verified on SQLite 3.46 and DoltLite
  0.11.29.
- **D4 (decided 2026-11-13):** a planned key change is a bulk transfer signed
  by the old key. There is no successor-key link.

### Plan-change log

Each entry gives the date, the step, what was found, and which sections
changed.

- **2026-11-13, before Step 1.** Spikes on the pinned DoltLite 0.11.29 build.
  Platform checks were emulated with a context table, because the binding
  cannot register JS functions.
  - **Behaviour as designed.** Non-constant `DEFAULT` (`CREATE TABLE` and
    empty `ADD COLUMN`; refused on non-empty). Owner checks on
    insert/update/delete, including `RETURNING`. `REPLACE` (both forms) and
    UPSERT onto another owner's row abort. `INSERT … SELECT` cannot copy
    another owner's id. App-trigger writes are checked as the signer. FK
    cascade and set-null across owners abort; owner-composite FKs work.
    Unguarded recursion aborts; guarded recursion runs once.
  - **`RAISE(IGNORE)` skips silently**, confirming the need for the lint.
  - **Changes that followed:**
    - `createFunction` is a stub, so all platform functions are native (§2).
    - Policy failures use a native `chronolog_policy_violation` that the
      authorizer restricts by calling trigger. This replaced the message-prefix
      lint (§4).
    - The `RAISE(IGNORE)` lint uses SQLite's own tokenizer instead of a TS
      one (§5).
    - Step 1 was narrowed to building these, plus regression tests.
- **2026-11-13, Step 1.** Built `chronolog_actor()`, `chronolog_policy_violation()`
  and `chronologTriggerUsesIgnore()` in the native patch (patch profile
  `…-actor-policy-trigger-lint-v5`).
  - The native `chronolog_actor()` works as a column `DEFAULT`, as designed.
    Both functions are `SQLITE_INNOCUOUS`, so they run in triggers, views and
    defaults under `trusted_schema=OFF`.
  - **Tokenizer export.** `sqlite3GetToken` is static in the amalgamation.
    The wrapper is appended to the generated `doltlite.c` by the patched
    `build-amalgamation.js`, which already appends a pager stub there. The
    pinned-source check covers the downloaded tarball, so the plan's fallback
    (a vendored `normalize.c`) was not needed. §5 changed.
  - **sqlite-vec chunk tables.** `<table>_vector_chunksNN` are ordinary
    tables to SQLite: it finds a shadow table's parent at the last underscore,
    so they can never be shadow tables. Reconciliation exempts them by name.
    They are writable by any writer, like the vec0 table itself. §3 changed.
  - **Authorizer findings.** `DROP TABLE` reports a `DROP_TRIGGER` for each of
    the table's triggers. The authorizer is per statement and allows dropping
    `chronolog_*` triggers only after the same statement's `DROP TABLE` of
    their table. `DROP COLUMN` reports the column, so dropping
    `chronolog_owner` is denied directly. `RENAME COLUMN` is left to
    reconciliation. §4 changed.
  - **Wide tables.** The column-cap check uses a `VALUES` list, which is not
    subject to the compound-select limit of 32. It was tested with 40 columns.
- **2026-11-13, Steps 2–4.**
  - **Lookup views.** There is one `chronolog_grants_to_me_<op>` view, with a
    NULL `row_key` for table grants, instead of `grantors_to_me` and
    `granted_rows`. The owner-id views are `_insert`, `_update` and
    `_delete`; `_write` was renamed `_update`. §3–4 changed.
  - **Row identity** is the quoted primary key, so registered tables need a
    declared primary key (`platform:no_primary_key`). Operations name a row by
    `rowKey`. §3 and §6 changed.
  - **Fail closed.** The trigger conditions are wrapped in `coalesce(…, 0)`, so
    a NULL owner is a policy rejection rather than a constraint error.
  - **Reconciliation regenerates** platform triggers when an admin changes a
    registered table's columns, and unregisters dropped tables. It refuses
    only missing or foreign platform objects. §3 changed.
  - **FK lint refined.** `SET NULL` on an owner-composite FK would null the
    owner column, so it is refused. Owner-composite FKs must be
    `ON UPDATE CASCADE` so transfers can carry dependents. The lint also runs
    at reconciliation, because `ADD COLUMN … REFERENCES` can add an FK
    later. §4 changed.
  - **Pre-registration rows.** `RegisterTable` refuses a table holding rows
    the signer could not have inserted (`platform:foreign_owner`).
  - **Genesis needs the root key.** The materializer did not know it, so it
    now takes `rootAdministrator`. The daemon reads it from the genesis
    (opening the materializer after the governance bootstrap) or from a new
    `rootAdministrator` field of the static membership file. Offline tools
    read it from the database. §3 changed.
  - **App triggers inside platform operations.** They are compiled inside the
    platform's own statements, so the authorizer applies consensus rules to
    anything whose calling trigger or view is not `chronolog_*`. §4 changed.
  - **Manifest version 2** carries `platformDigest` and
    `recursiveTriggers`. `createDoltLiteExecutionManifest()` builds it.
- **2026-11-13, Step 5.**
  - `Grant` has an optional `grantor`, for table grants on a collective's
    rows. A grantee may renounce a grant.
  - Collective membership has `invited`, `active` and `left` states.
    `SetMembers` invites new keys, and a collective always keeps an active
    admin.
  - Transfer exemptions are rows of `chronolog_exemptions`, for the offer's
    row plus the dependents found by walking owner-composite FKs.
  - A bulk transfer moves parent tables first and re-points grants.
  - A row transfer revokes the row's grants. §6 changed.
- **2026-11-13, Step 6.**
  - **Seeding window.** No operation marks the end of seeding, so `SeedRows`
    closes at the first accepted transaction by an author other than the
    genesis root. Operators must seed a fork before others write.
  - **Platform tables in a fork.** Teams, memberships and grants have ids
    derived from source transaction ids, which ordinary operations cannot
    reproduce. `SeedRows` therefore also seeds the four platform tables
    verbatim, except the `group` collective.
  - The seed plan is `chronolog-fork-seed-v3`, with readable JSON platform
    steps.
  - `verify-fork` compares owners (they are row columns) and digests of the
    ownership state. §7 changed.
- **2026-11-13, Step 7.** Platform steps travel over RPC as canonical CBOR.
  The CLI takes JSON `{"platform": …}` steps. Chaos sends DDL through the root
  node, grants the other nodes `update` on the shared `accounts` rows, and
  adds an `owner_probe` operation plus invariants for platform-trigger
  digests and known owners. workerd executes no SQL, so it needed no change
  (§7).
- **2026-11-13, Step 8.** Cost, measured as in Step 8.
  - Every transaction re-prepared two platform reads and two
    `PRAGMA schema_version` reads (~1 ms). They are now one cached internal
    statement (`PlatformSession.begin()`).
  - The trigger checks were an `OR` inside `coalesce(…, 0)`, which SQLite
    computes as a value, so every arm's subquery ran for every row. They are
    now a short-circuit `CASE` chain led by `owner = chronolog_actor_id()`,
    with `EXISTS` lookups instead of `IN (view)`. Still fail closed. §4
    changed; platform code version `chronolog-platform-ops-v2`.
  - The remaining overhead is the owner column's storage (Step 8).
- **2026-11-13, Step 9.** The chaos run found two bugs in the feed transport,
  older than this work:
  - Closing a transport waited for every peer to hang up, so a stopping
    daemon hung until Docker killed it. It now closes peer connections.
  - A stream error (here, the killed peer's reset connection) was kept in
    one sticky field, so the node reported itself degraded forever after a
    peer restart. Errors are now kept per live stream and clear when that
    stream makes progress or its connection closes.
- **2026-11-13, Step 8 (owner ids).** At the owner's request, owner columns
  hold small integer principal ids instead of 32-byte keys (§2, §3, §7).
  - Native `chronolog_actor_id()`, pinned by `setDeterministicContext` next
    to `chronolog_actor()` (patch profile
    `…-actor-policy-trigger-lint-actor-id-v6`).
  - `chronolog_principals` maps ids to keys. A signer gets its id at the start
    of its first transaction, so a rejected first transaction leaves none.
  - Platform tables keep keys; the lookup views join principals, and transfer
    exemptions hold ids. Fork seeds and fork verification name owners by key,
    since each group assigns its own ids.
  - Platform code version `chronolog-platform-ops-v3`.
- **2026-11-13, review findings** (a separate review session).
  - **Seeding in ordinary groups (high).** Every database started with
    seeding open, so a root could `SeedRows` forged rows and grants in any
    group until another author wrote. Seeding now opens only for a fork
    (`forkSeeding`, set when the genesis has `forkedFrom`). It still closes at
    the first transaction by another author, not at the root's first
    non-seed step: seed batches mix SQL (schema, guards, markers) with
    `SeedRows`. §7 and Step 6 changed.
  - **Seeding window in forks (follow-up).** A fork's root could still seed
    for as long as nobody else wrote. A new `EndSeeding` platform operation
    (root only, while seeding is open) closes it, and the seed plan
    (`chronolog-fork-seed-v4`) ends with an `EndSeeding` batch, guarded like
    the others. Platform code version `chronolog-platform-ops-v4`. §6, §7 and
    Step 6 changed.
  - **Virtual tables (medium).** Under the consensus authorizer FTS5 writes,
    vec0 creation and R-tree creation all failed, and nothing stopped a
    writer from writing an index directly. Now:
    - top-level writes to virtual tables and vec0 chunk tables are denied;
      app triggers may write them (§3);
    - `sqlite_sequence` may be created (AUTOINCREMENT, vec0);
    - `PRAGMA data_version` and `page_size` are allowed only for module
      queries (no caller, no value). The authorizer cannot tell a module's
      query from top-level app SQL, so top-level SQL naming them (a `PRAGMA`
      statement or a `pragma_*` table function) is refused by its text before
      it is prepared;
    - local reads let a module prepare writes to its own shadow tables
      (R-tree does so on connect); defensive mode keeps them read-only to app
      SQL;
    - the engine declares vec0 `SQLITE_VTAB_INNOCUOUS` (patch profile
      `…-actor-id-vec-innocuous-v7`).
  - **Chunk-table exemption (low)** was by name and exact `CREATE` text. Dolt
    re-serializes that text on checkout, so it now checks the vec0 parent, the
    chunk number and the column shape.
  - **Row lookups (low)** scanned the table on `quote(pk)… = ?`. Row keys are
    parsed back into primary-key values for indexed lookups; the key is still
    compared for exactness.
  - **Bulk transfers (low, doc).** Grants the old key received do not move
    (the recipient need not be the same person), and an open `scope: all`
    offer also sweeps rows written after it was made. §6 changed.
- **2026-11-13, registration is automatic** (owner's request). The
  `RegisterTable` operation is removed. Reconciliation runs after every
  statement that changed the schema and registers each new application table
  with the same checks (primary key, owner column added only to an empty
  table, FK lint, foreign owners); DDL is still admin-only. A rename is
  recognized by the platform trigger SQLite carried to the new table, and
  moves the registration, grants and open offers. Fork-seed plan
  `chronolog-fork-seed-v5` (no registration steps); platform code version
  bumped. §3, §4, §6 and Step 4 changed.
