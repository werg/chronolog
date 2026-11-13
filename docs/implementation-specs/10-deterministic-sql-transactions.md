# Replicated SQL Transactions

Status: normative contract for the unreleased prototype. It replaces the
earlier compiler-based contract (old specifications 10 and 11) and the SQLite
compatibility ledger. Owner-controlled rows (sections 4, 6 and 7) follow
[the owner-rows design](../design-owner-rows.md).

Chronolog has no deployed protocol or user data. Formats are edited in place;
no legacy decoder, compatibility profile or migration path is kept.

## 1. Principle

A replicated transaction is **ordinary SQLite SQL**, plus typed **platform
operations** that change who owns and may write which rows. Chronolog does
not define a dialect, prove query semantics, or attach meaning to schemas.
Replay determinism comes from four facts:

1. every replica runs the **same pinned engine build** (the DoltLite native
   addon and its patch profile, recorded in the execution manifest);
2. every replica runs the **same platform code** (its digest is in the
   execution manifest);
3. every replica executes the **same steps on the same database state** in the
   same order; and
4. the engine inputs that do not come from SQL or the database (the clock,
   the random generator, the local timezone, per-connection counters and the
   signer) are **fixed from the signed transaction** before it runs.

What remains is a short block-list of operations that could escape the
database or the pinned engine (section 5). Replicas compare state digests; a
case the block-list misses shows up as a detectable divergence, not silent
corruption.

Only the database contents are replicated state. Values returned by
statements (`SELECT`, `RETURNING`) are not recorded or compared.

## 2. Values

Bindings use SQLite's own five storage classes and nothing else:

```text
SqlValue = null | integer (signed 64-bit) | real (finite binary64)
         | text (UTF-8) | blob (bytes)
```

A REAL binding is bound as a REAL even when it is integral (`1.0`), and an
empty BLOB is bound as an empty BLOB, not NULL (patched native binding).
There are no decimal, UUID, boolean, timestamp, JSON or vector value types;
applications store those as SQLite values and use SQLite's functions.

## 3. Signed program

```text
SqlTransactionProgram { version: 2, steps: Step[] }        // 1..256
Step                  = SqlStatement | PlatformOp
SqlStatement          { sql: text, bindings: SqlBinding[] }
SqlBinding            { parameter: index (1-based) | name, value: SqlValue }
PlatformOp            = RegisterTable { table }
                      | Grant { table, grantee, grantor?, rowKey?, operations, columns? }
                      | RevokeGrant { grantId }
                      | CreateCollective { governance, invitees } | AcceptMembership { collectiveId }
                      | Leave { collectiveId } | SetMembers { collectiveId, changes }
                      | TransferOffer { scope: row(table, rowKey) | all, fromOwner?, toOwner, carry }
                      | TransferAccept { offerId }
                      | SeedRows { table, columns, rows }
```

Each `sql` must contain exactly one statement (trailing comments, whitespace
and semicolons are allowed). Keys, collective ids, grant ids and offer ids
are 32 bytes. A `rowKey` is the row's primary-key values. The program is
encoded as canonical CBOR inside `TransactionCore.program`: a step is
`[0, statement]` or `[1, operation]`, and an operation is an integer-keyed map
whose key 0 is its code. Version 1 programs are not accepted.

The grant, collective or offer created by step `i` of transaction `txId` has
the id `SHA-256(domain("chronolog/platform-object") ‖ len(txId) ‖ txId ‖ u32(i))`
(`platformObjectId` in `@chronolog/protocol`).

There are no separate preconditions. A transaction is rejected when any step
fails. Assumptions about earlier state are written as ordinary statements,
normally with `chronolog_assert`:

```sql
SELECT chronolog_assert((SELECT balance FROM accounts WHERE id = :from) >= :amount, 'insufficient_funds');
SELECT chronolog_assert(NOT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = 'accounts'), 'already_created');
```

`chronolog_assert(condition, code)` returns 1 when `condition` is true
(non-zero and not NULL). Otherwise it fails the statement and the transaction
is rejected with rejection code `assert:<code>`. `code` is text of at most 128
bytes. Built-in failures (`CHECK`, `UNIQUE`, foreign keys, `RAISE()` in
triggers) reject the same way.

## 4. Execution

For each admitted transaction `T` at its position in the stable order:

1. Open a savepoint.
2. Fix the engine inputs for the duration of `T`:
   - the current time (`'now'`, `CURRENT_TIMESTAMP`, …) is
     `T.authorTimestampMs`;
   - the pseudo-random generator (`random()`, `randomblob()`, rowid choice
     after the maximum rowid) is seeded from `T.txId`;
   - the `localtime` modifier converts to UTC;
   - `last_insert_rowid()` and `changes()` start at 0;
   - `chronolog_actor()` returns `T.authorId`, the signing key, and
     `chronolog_actor_id()` its principal id (§6). Outside consensus
     execution both return NULL.
3. Execute each step in order. A SQL statement runs under the consensus
   authorizer and the deterministic step budget and is stepped to completion;
   returned rows are discarded. A platform operation runs as trusted platform
   code (section 7). Both act as `T.authorId`.
4. If the schema changed (`PRAGMA schema_version`), reconcile (section 6).
5. If every step succeeds, release the savepoint: outcome `accepted`.
   Otherwise roll back to the savepoint: outcome `rejected` with a rejection
   code and the index of the failing step (null for reconciliation).
6. Append the log row (section 8) and clear the fixed engine inputs.

`PRAGMA foreign_keys` and `PRAGMA recursive_triggers` are on. With
`recursive_triggers`, the deletion by `REPLACE` fires delete triggers, so the
owner checks apply to it. Trigger recursion is limited to depth 16.

Execution of a transaction is synchronous: no other statement runs on any
connection in the process between steps 2 and 6.

Rejection codes:

| Code | Cause |
| --- | --- |
| `assert:<code>` | `chronolog_assert` failed |
| `policy:<table>:<command>` | an owner check refused an insert, update or delete (section 6) |
| `platform:<reason>` | a platform operation refused (section 7), or `platform:fk_action` at reconciliation |
| `schema_unregistered` | reconciliation found an unregistered table or a foreign `chronolog_*` trigger or view |
| `trigger_ignore` | an app trigger uses `RAISE(IGNORE)` |
| `constraint` | `CHECK`, `UNIQUE`, `NOT NULL`, foreign key, or an app `RAISE(ABORT, …)` |
| `step_limit`, `denied`, `prepare`, `binding`, `too_large`, `mismatch`, `error` | step budget, authorizer, syntax or unknown object, bindings, size, datatype, any other deterministic SQLite error (including trigger recursion) |
| `manifest_mismatch` | authored for another execution manifest; not executed |

Operational failures (I/O, corruption, out of memory) are not outcomes; they
stop replay on that replica.

## 5. Block-list and schema administration

The consensus authorizer denies:

- `ATTACH`/`DETACH`, `load_extension`, and temporary schema objects;
- transaction control (`BEGIN`, `COMMIT`, `SAVEPOINT`, …) inside a program;
- `PRAGMA`, except read-only pragma table-valued functions on the main
  database (`pragma_table_info`, `pragma_index_list`, …);
- writes to Chronolog's own tables (`chronolog_*`), and creating, dropping or
  altering `chronolog_*` objects; dropping the `chronolog_owner` column;
- `chronolog_policy_violation()` anywhere but inside a `chronolog_*` trigger
  or view;
- Dolt functions (`dolt_*`, `doltlite_*`), `total_changes()` and
  `sqlite_offset()`, whose results depend on connection history or storage;
- **all DDL** (`CREATE`/`DROP` of tables, indexes, views, triggers and virtual
  tables, `ALTER TABLE`) unless the signer is an active admin of the `group`
  collective. `ANALYZE` and `REINDEX` are open to every writer.

Everything else the pinned engine accepts is allowed, including triggers,
views, generated columns, window functions, JSON, FTS5, R-tree and sqlite-vec.
Math functions (`sin`, `exp`, …) are not compiled into the engine.

## 6. Owner-controlled rows

Every ordinary table in the main schema, except Chronolog's, SQLite's and
Dolt's own, must be **registered** (`RegisterTable`) in the transaction that
creates it. A registered table has a declared primary key and the column

```sql
chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id())
```

The owner is a principal id: `chronolog_principals` maps each id to its
32-byte key (a node key or a collective id). `chronolog_actor_id()` is the
signer's id; a signer gets one at the start of its first transaction.

and three generated `BEFORE` triggers, `chronolog_k_<table>_ins|upd|del`. Each
raises `chronolog_policy_violation('<table>', '<command>')` (rejection
`policy:<table>:<command>`) unless:

- **insert:** the new owner is the signer, a collective whose governance lets
  the signer insert, or a grantor who granted the signer `insert` on the
  table;
- **update:** the owner is unchanged, and the old owner is the signer, a
  collective whose governance lets the signer update, or a grantor of a live
  `update` grant to the signer covering the table or this row, whose column
  list (if any) includes every column the update changes. An owner change is
  admitted only for the rows of an accepted transfer;
- **delete:** the old owner is the signer, a collective whose governance lets
  the signer delete, or a grantor of a live `delete` grant covering the table
  or this row.

These checks apply to every write: statements, `REPLACE`, upserts,
foreign-key actions, and writes by app triggers, including app triggers fired
by platform operations. A statement that would touch any row the signer may
not write aborts the transaction; rows are never skipped. `INSERT OR IGNORE`
and `ON CONFLICT DO NOTHING` remain explicit conflict handling.

A row's identity for grants and transfers is
`quote(pk1) || ',' || quote(pk2) …` over its primary key.

Generated lookup views, readable by any SQL: `chronolog_my_owner_ids_insert`,
`_update`, `_delete` (the signer plus the collectives it may act for) and
`chronolog_grants_to_me_insert`, `_update`, `_delete`.

**Reconciliation** runs at the end of every transaction that changed the
schema. It unregisters dropped tables (revoking their grants and cancelling
their offers), regenerates platform triggers whose table's columns changed,
and rejects the transaction when:

- an ordinary table is unregistered (`schema_unregistered`). Virtual tables,
  their shadow tables and sqlite-vec's `<table>_vector_chunksNN` tables are
  exempt. Virtual tables and chunk tables carry no owner checks, so app SQL
  may write them only from app triggers (top-level writes are `denied`);
- a registered table lost its owner column, its primary key or a platform
  trigger, or a `chronolog_*` trigger or view is not the platform's own
  (`schema_unregistered`);
- a foreign key cascades across owners (`platform:fk_action`): an FK whose
  columns include `chronolog_owner` mapped to the parent's `chronolog_owner`
  must be `ON UPDATE CASCADE` and may be `ON DELETE CASCADE`; every other FK
  must be `RESTRICT` or `NO ACTION`;
- an app trigger contains `RAISE ( IGNORE` per SQLite's own tokenizer
  (`trigger_ignore`).

## 7. Platform operations and platform state

Platform operations run as trusted, deterministic code inside the
transaction's savepoint. They check their authority against replicated state
and the signer, write the platform tables, and generate triggers. They are
never an elevated actor: `chronolog_actor()` stays the signer, and every app
trigger they fire is checked as the signer.

Platform tables (readable by transactions, written only by platform
operations): `chronolog_platform` (root administrator, seeding window),
`chronolog_tables`, `chronolog_collectives`, `chronolog_collective_members`,
`chronolog_grants`, `chronolog_transfers`, and `chronolog_exemptions` (empty
between steps).

| Operation | Authority and effect | Refusals (`platform:…`) |
| --- | --- | --- |
| `RegisterTable` | `group` admin. Adds the owner column to an empty table if missing, generates the triggers. Rows already in the table must be ones the signer could insert. | `not_schema_admin`, `no_such_table`, `reserved_table`, `already_registered`, `no_primary_key`, `table_not_empty`, `owner_column_invalid`, `fk_action`, `foreign_owner` |
| `Grant` | The grantor (default: the signer; for a row grant, the row's owner) is the signer or a collective it administers. `columns` require `update`; row grants cannot include `insert`. | `unregistered_table`, `no_such_row`, `row_key_arity`, `unknown_column`, `invalid_grant`, `not_owner` |
| `RevokeGrant` | The grantor (or an admin of a grantor collective), or the grantee. Effective from the next step in the order. | `no_such_grant`, `grant_revoked`, `not_owner` |
| `CreateCollective` | Any writer; creates a `team` with the signer as active admin and invitees invited. Governance names the least role (`member` or `admin`) for insert, update and delete. | `invalid_member` |
| `AcceptMembership` | The invitee. | `not_invited` |
| `Leave` | A member or invitee; a collective keeps at least one active admin. | `not_member`, `last_admin` |
| `SetMembers` | An active admin. New keys are invited and join by accepting; existing members change role or are removed. | `no_such_collective`, `not_collective_admin`, `not_member`, `last_admin` |
| `TransferOffer` | The owner (or an admin of an owner collective). `all` covers every row the owner holds in every registered table. | `unregistered_table`, `no_such_row`, `not_owner`, `invalid_transfer` |
| `TransferAccept` | The recipient (or an admin of a recipient collective). Moves the row and, with `carry`, its same-owner dependents through owner-composite FKs; a row offer revokes the row's grants. `all` moves rows parent tables first and re-points the old owner's grants. | `no_such_offer`, `offer_closed`, `not_recipient`, `offer_stale`, `has_dependents`, `fk_cycle` |
| `SeedRows` | The genesis root administrator of a fork (a genesis with `forkedFrom`), before the first accepted transaction by any other author; never in other groups. Writes rows with their owners verbatim, without app triggers; also seeds `chronolog_collectives`, `_collective_members`, `_grants` and `_transfers` (never the `group` collective). | `not_root`, `seed_closed`, `unregistered_table`, `unknown_column`, `invalid_seed` |

The `group` collective (all-zero id) exists from genesis with the root
administrator as its admin and admin-only governance. Its active admins are
the schema administrators.

## 8. Transaction log

`chronolog_transactions` is part of the replicated state and readable by
transactions:

```text
tx_id, order_index, author_id, author_timestamp_ms, author_feed_sequence,
candidate_digest, canonical_candidate,
outcome ('accepted' | 'rejected'), rejection_code, failing_statement_index
```

`failing_statement_index` is the index of the failing step.

A transaction may depend on an earlier one, for example
`SELECT chronolog_assert(EXISTS (SELECT 1 FROM chronolog_transactions WHERE
tx_id = :earlier AND outcome = 'accepted'), 'needs_earlier')`.

## 9. Local reads

Local query SQL runs on an immutable materialized revision, is not signed or
replayed, and returns plain SQLite values. It may use any read-only function,
including the real clock. There are no read policies: every reader node holds
every row. `chronolog_actor()` is NULL in local reads.

## 10. Execution manifest

Every candidate names the execution manifest digest it was authored for. The
manifest (version 2) records the engine build (DoltLite version, source
digests, patch profile), `programVersion: 2`, the `platformDigest` (SHA-256
over the platform-operation version and the generated platform schema, views
and triggers), the profile pragma `recursiveTriggers: true`, and the step and
size limits. A replica only executes transactions whose manifest it runs;
changing the engine or the platform code is a group-wide upgrade. The
materialized database also records its genesis root administrator, and a
replica refuses to open it with another.
