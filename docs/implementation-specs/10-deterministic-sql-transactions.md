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

1. every replica runs the **same pinned SQL engine profile** (DoltLite and
   sqlite-vec sources, deterministic hooks and patch profile, identified by
   the execution manifest). Native and WASM builds use different host
   adapters but share these SQL semantics;
2. every replica runs the **same platform code** (its digest is in the
   execution manifest);
3. every replica executes the **same steps on the same database state** in the
   same order; and
4. the engine inputs that do not come from SQL or the database (the clock,
   the random generator, the local timezone, per-connection counters and the
   signer) are **fixed from the signed transaction** before it runs.

What remains is a short block-list of operations that could escape the
database or observe differences between host builds (section 5). The same
versioned SQL policy applies to native and WASM execution. Replicas compare
state digests; a case the block-list misses shows up as a detectable
divergence, not silent corruption.

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
ChangeProgram { version: 3, steps: Step[] }        // 1..256
Step                  = SqlStatement | PlatformOp | EmitStep
SqlStatement          { sql: text, bindings: SqlBinding[] }
SqlBinding            { parameter: index (1-based) | name, value: SqlValue }
PlatformOp            = Grant { table, grantee, grantor?, rowKey?, operations, columns? }
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
`[0, statement]`, `[1, operation]` or `[2, topic, canonicalJson]`; an operation is an integer-keyed map whose key 0 is its code. Only version 3 programs are accepted.

`EmitStep { op: 'emit', topic, payload }` carries JSON data, never executable application code. A program has at most 256 steps, 64 emits and 262,144 canonical bytes; each payload is at most 16,384 UTF-8 bytes. Topics are bounded application labels. Event payloads use sorted object keys and finite JSON numbers; sparse arrays, accessors and non-JSON values are rejected.

The transaction core is version 2 and signs `operationId` alongside author, exact writer grant, membership revision, execution profile and program. Different proposals reusing one author/operation identity deterministically reject as `operation_conflict`. SQL/platform failure rolls back the whole program and exposes no effective emit. Accepted events are reconstructed from the canonical program and its durable outcome anchor; final readers never advance beyond missing or unresolved outcomes.

The SQL-free execution profile accepts only emits. SQL/platform steps are a deterministic `profile:sql-disabled` rejection in that profile. See [public application session](../../packages/peer-session/README.md) for cursors, coherent views and application consumers.

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

For each admitted transaction `T` at its position in the history policy's
local order:

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

The peer policy may replay a tentative suffix when earlier transactions
arrive. The coordinated policy uses certified log positions. Both preserve
the already applied final prefix; the materializer does not independently
choose or sort the history order.

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

An unavailable engine or execution profile is **blocked replay**, not a SQL
rejection. The replica verifies the execution manifest before running the
program and preserves the last published SQL revision if it cannot execute
that profile. It must not append an `accepted` or `rejected` log row for the
blocked transaction or advance the applied final prefix through it.
Operational failures (I/O, corruption, out of memory) likewise stop replay
on that replica without producing an application outcome. Missing history
or an unavailable decryption key blocks progress before SQL execution.

## 5. Block-list and schema administration

The consensus authorizer denies:

- `ATTACH`/`DETACH`, `load_extension`, and temporary schema objects;
- transaction control (`BEGIN`, `COMMIT`, `SAVEPOINT`, …) inside a program;
- `PRAGMA` and `pragma_*` table-valued functions, except the shared read-only
  schema queries `foreign_key_list`, `index_info`, `index_list`, `index_xinfo`,
  `table_info`, `table_list` and `table_xinfo`, and `quick_check` (also used
  internally by SQLite during `ALTER TABLE`). Both plain read-only pragma
  statements and their table-valued forms are allowed;
- writes to Chronolog's own tables (`chronolog_*`), and creating, dropping or
  altering `chronolog_*` objects; dropping the `chronolog_owner` column;
- `chronolog_policy_violation()` anywhere but inside a `chronolog_*` trigger
  or view;
- Dolt functions (`dolt_*`, `doltlite_*`, `active_branch()`), Dolt system
  tables, `total_changes()` and `sqlite_offset()`, whose results depend on
  connection history or storage;
- host/build introspection: `sqlite_compileoption_get()`,
  `sqlite_compileoption_used()`, `sqlite_source_id()`, and the
  `compile_options`, `function_list`, `module_list`, `pragma_list` and
  `collation_list` pragmas, including their table-valued forms;
- physical-storage or connection introspection through the `dbstat`,
  `sqlite_dbpage` and `sqlite_stmt` virtual-table modules or eponymous tables;
- **all DDL** (`CREATE`/`DROP` of tables, indexes, views, triggers and virtual
  tables, `ALTER TABLE`) unless the signer is an active admin of the `group`
  collective. `ANALYZE` and `REINDEX` are open to every writer.

Everything else the pinned engine accepts is allowed, including triggers,
views, generated columns, window functions, JSON, FTS5, R-tree and sqlite-vec.
Math functions (`sin`, `exp`, …) are not compiled into the engine.

These restrictions also apply inside application views and triggers,
including triggers fired by trusted platform operations. Replicated schema
introspection remains available through `sqlite_schema` and the permitted
schema pragmas; `sqlite_version()` is allowed because the engine version is
pinned. Function checks use SQLite's resolved names: a string literal,
alias or common-table-expression named `sqlite_compileoption_get` is not a
call to the forbidden function.

A denied function or diagnostic table produces the same `denied` outcome
when one host build omits it entirely and another exposes it to the
authorizer. This also applies when SQLite checks a forbidden function's
argument count before invoking the authorizer. Host availability must not
turn a policy denial into a distinct `prepare` outcome; invalid argument
counts for allowed functions remain prepare failures. Native and WASM
adapters share this normalization and the SQL policy version recorded
through the platform digest (section 10).

## 6. Owner-controlled rows

Every ordinary table in the main schema, except Chronolog's, SQLite's and
Dolt's own, is **registered** (put under owner checks) automatically, right
after the statement that creates it. A registered table has a declared
primary key and the column

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

A row's identity for grants, transfers and reader policies is the native
`chronolog_row_key(pk1, pk2, …)` typed binary tuple, exposed as `rk1:` plus
lowercase hex. It encodes the tuple length, each storage-class tag, exact
integer/IEEE-754 value or length-prefixed TEXT/BLOB bytes. An owner component
uses its stable 32-byte key instead of the replica's principal id. Nullable
primary-key columns are refused (the `INTEGER PRIMARY KEY` rowid alias is
implicitly non-null). Column caps use `chronolog_value_equal`, comparing exact
storage types and values independently of collation or numeric coercion.

The UPDATE/DELETE kernel invalidates row grants and impacted offers before a
replacement row can be observed by application triggers. An AFTER INSERT
lifecycle trigger invalidates bulk offers whose captured set has grown.
Table-wide grants retain their explicit meaning over future grantor-owned rows.

Generated lookup views, readable by any SQL: `chronolog_my_owner_ids_insert`,
`_update`, `_delete` (the signer plus the collectives it may act for) and
`chronolog_grants_to_me_insert`, `_update`, `_delete`.

**Reconciliation** runs right after every statement that changed the schema.
It registers new tables (adding the owner column to an empty table if missing,
generating the triggers), follows renamed tables (moving their registration,
grants and open offers), unregisters dropped tables (revoking their grants and
cancelling their offers), regenerates platform triggers whose table's columns
changed, and rejects the transaction when:

- a new table cannot be owner-checked: `platform:no_primary_key`,
  `platform:nullable_primary_key`, `platform:table_not_empty`, `platform:owner_column_invalid`, or
  `platform:foreign_owner` for rows the signer could not have inserted.
  Virtual tables, their shadow tables and sqlite-vec's
  `<table>_vector_chunksNN` tables are not registered. Virtual tables and chunk tables carry no owner checks, so app SQL
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
`chronolog_grants`, `chronolog_transfers`, `chronolog_transfer_scope`,
`chronolog_reader_keys`, `chronolog_reader_policies`,
`chronolog_policy_readers`, and `chronolog_sealed_values`.
`chronolog_exemptions` and `chronolog_sealed_write_exemptions` are empty
between steps. Exact generated lifecycle triggers also have column-scoped
permission to invalidate grants/offers and close or migrate policy bindings;
application triggers never inherit that metadata privilege.

Transfer exemptions identify both the captured source key and its destination
key. While acceptance is executing, generated guards reject deleting a captured
row, inserting at either key, or changing non-owner primary-key components into
or out of either key, including from application triggers. Ownership-only FK
cascades remain permitted. Before clearing the exemptions, the platform checks
that every destination exists with the recipient owner and every distinct
source key is absent. These guards prevent replacement generations from consuming
an offered row's exemption, and reject incomplete transfers even when schema
conflict handling silently ignores an update. Failure rolls back the entire
acceptance, including reader-policy migrations.

Authorization inventories for lifecycle triggers, virtual write protection
and shadow-table access are read from the current catalog on each use. A
rollbackable schema cookie is not a unique catalog identity and must not key
cached authorization results; fixed prepared statements may still be reused.

| Operation | Authority and effect | Refusals (`platform:…`) |
| --- | --- | --- |
| `Grant` | The grantor (default: the signer; for a row grant, the row's owner) is the signer or a collective it administers. `columns` require `update`; row grants cannot include `insert`. | `unregistered_table`, `no_such_row`, `row_key_arity`, `unknown_column`, `invalid_grant`, `not_owner` |
| `RevokeGrant` | The grantor (or an admin of a grantor collective), or the grantee. Effective from the next step in the order. | `no_such_grant`, `grant_revoked`, `not_owner` |
| `CreateCollective` | Any writer; creates a `team` with the signer as active admin and invitees invited. Governance names the least role (`member` or `admin`) for insert, update and delete. | `invalid_member` |
| `AcceptMembership` | The invitee. | `not_invited` |
| `Leave` | A member or invitee; a collective keeps at least one active admin. | `not_member`, `last_admin` |
| `SetMembers` | An active admin. New keys are invited and join by accepting; existing members change role or are removed. | `no_such_collective`, `not_collective_admin`, `not_member`, `last_admin` |
| `TransferOffer` | The owner (or an admin of an owner collective). Captures exact rows, dependents, content/schema and reader-policy state. `all` snapshots every currently owned row. | `unregistered_table`, `no_such_row`, `not_owner`, `invalid_transfer` |
| `TransferAccept` | The recipient (or an admin of a recipient collective). Requires the captured state still to match. Moves only the captured rows, revokes row grants and closes competing offers; `all` moves parent tables first and re-points whole-table grants. | `no_such_offer`, `offer_closed`, `not_recipient`, `offer_stale`, `has_dependents`, `fk_cycle` |
| `TransferCancel` | The sender or recipient, or an administrator of either owning collective. Closes an open offer permanently. | `no_such_offer`, `offer_closed`, `not_owner` |
| `RegisterReaderKey` | The signer registers/replaces its own public X25519 key. Existing reader-policy snapshots do not change. | Normal writer admission applies |
| `ReaderPolicy` | The row owner or owning collective's admin creates or replaces the explicit reader list with generation/version CAS; keys must already be registered. | `not_owner`, `no_such_row`, `reader_key_missing`, `reader_policy_stale`, `reader_policy_version_exhausted` |
| `SealedPut` | Ordinary row/column update authority; policy/data CAS, exact recipient/key set and authenticated group/policy/column/version context. Writes an actual mutable BLOB column and verifies the result after app triggers. | `reader_policy_closed`, `reader_policy_stale`, `sealed_value_stale`, `sealed_column_invalid`, `sealed_context_mismatch`, `sealed_readers_mismatch`, `sealed_no_readers`, `sealed_write_changed`, `sealed_value_version_exhausted`, plus ordinary row/app-trigger rejections |
| `SeedRows` | The initial schema administrator of a fork (the signed genesis `schemaAdminPublicKey`, with `forkedFrom`), before the first accepted transaction by any other author; never in other groups. Writes rows with their owners verbatim, without app triggers; also seeds `chronolog_collectives`, `_collective_members`, `_grants` and `_transfers` (never the `group` collective). | `not_root`, `seed_closed`, `unregistered_table`, `unknown_column`, `invalid_seed` |

The `group` collective (all-zero id) exists from genesis with the explicit
`schemaAdminPublicKey` as its admin and admin-only governance. Its active admins
are the schema administrators. The roster issuer `rootAdminPublicKey` grants
no implicit SQL membership, schema privilege or row ownership.

Sealed operation codes are 64–66; ownership codes retain their positions and
`TransferCancel` appends code 10. Reader-policy and value versions are positive
signed-int64 values. Policy IDs derive from the creating transaction ID and
step index. DELETE/rekey closes a policy generation; an ownership-only transfer
preserves its ID and explicit readers, including when the owner is part of the
PK. Table rename moves the binding; removing/renaming a sealed column closes its
generation. The [sealed-data contract](../sealed-data.md) specifies encryption,
client finality preflight and the limits of revocation after disclosure.

## 8. Transaction log

`chronolog_transactions` is part of the replicated state and readable by
transactions:

```text
tx_id, order_index, author_id, author_timestamp_ms,
candidate_digest, canonical_candidate,
outcome ('accepted' | 'rejected'), rejection_code, failing_statement_index
```

`failing_statement_index` is the index of the failing step.

A transaction may depend on an earlier one, for example
`SELECT chronolog_assert(EXISTS (SELECT 1 FROM chronolog_transactions WHERE
tx_id = :earlier AND outcome = 'accepted'), 'needs_earlier')`.

## 9. Local reads

Local query SQL runs on an immutable materialized revision, is not signed or
replayed, and returns plain SQLite values. The application captures the current applied view. A separately protected
checkpoint is an explicit materializer capability, not a second application path. Read-only host diagnostics, including the real clock and
the build and function catalogs denied during consensus execution, may be
queried locally. External effects and Dolt control functions remain denied.
There is no SELECT filtering: every reader node holds every row's stored
public fields and ciphertext. Explicit sealed-data policies control access
to encrypted plaintext. `chronolog_actor()` is NULL in local reads.

## 10. Execution manifest

Every candidate names the execution manifest digest it was authored for. The
manifest (version 2) records the engine descriptor digest (DoltLite version,
source digests and patch profile), `programVersion: 3`, the `platformDigest`,
the profile pragma `recursiveTriggers: true`, and the step and size limits.
The platform digest covers the platform-operation version, the shared SQL
portability policy version, and the generated platform schema, views and
triggers. Native and WASM reducers use the same descriptor and platform
digest; the browser loader separately verifies its WASM artifact bytes and
supported adapter profile before opening the engine.

A replica only executes transactions whose manifest it runs. An unavailable
manifest blocks replay without creating a SQL outcome (section 4). The
execution profile is fixed in the signed group configuration; live engine
or profile upgrades are outside this initial scope. The materialized
database also records its initial schema administrator, and a replica refuses
to open it with another.
