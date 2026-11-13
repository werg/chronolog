# Replicated SQL Transactions

Status: normative contract for the unreleased prototype. It replaces the
earlier compiler-based contract (old specifications 10 and 11) and the SQLite
compatibility ledger.

Chronolog has no deployed protocol or user data. Formats are edited in place;
no legacy decoder, compatibility profile or migration path is kept.

## 1. Principle

A replicated transaction is **ordinary SQLite SQL**. Chronolog does not define a
dialect, prove query semantics, or attach meaning to schemas. Replay
determinism comes from three facts:

1. every replica runs the **same pinned engine build** (the DoltLite native
   addon and its patch profile, recorded in the execution manifest);
2. every replica executes the **same statements on the same database state**
   in the same order; and
3. the few engine inputs that do not come from SQL or the database — the
   clock, the random generator, the local timezone and per-connection
   counters — are **fixed from the signed transaction** before it runs.

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
SqlTransactionProgram { version: 1, statements: SqlStatement[] }   // 1..256
SqlStatement          { sql: text, bindings: SqlBinding[] }
SqlBinding            { parameter: index (1-based) | name, value: SqlValue }
```

Each `sql` must contain exactly one statement (trailing comments, whitespace
and semicolons are allowed). The program is encoded as canonical CBOR inside
`TransactionCore.program`.

There are no separate preconditions. A transaction is rejected when any
statement fails. Assumptions about earlier state are written as ordinary
statements, normally with `chronolog_assert`:

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
   - `last_insert_rowid()` and `changes()` start at 0.
3. Execute each statement in order under the consensus authorizer and the
   deterministic step budget, stepping it to completion. Returned rows are
   discarded.
4. If every statement succeeds, release the savepoint: outcome `accepted`.
   Otherwise roll back to the savepoint: outcome `rejected` with a rejection
   code and the index of the failing statement.
5. Append the log row (section 6) and clear the fixed engine inputs.

Execution of a transaction is synchronous: no other statement runs on any
connection in the process between steps 2 and 5.

Rejection codes are `assert:<code>`, `constraint`, `step_limit`, `denied`
(authorizer), `prepare` (syntax or unknown object), `binding`, `too_large`,
`mismatch` (datatype) and `error` (any other deterministic SQLite error).
Operational failures (I/O, corruption, out of memory) are not outcomes; they
stop replay on that replica.

## 5. Block-list

The consensus authorizer denies:

- `ATTACH`/`DETACH`, `load_extension`, and temporary schema objects;
- transaction control (`BEGIN`, `COMMIT`, `SAVEPOINT`, …) inside a program;
- `PRAGMA`, except read-only pragma table-valued functions on the main
  database (`pragma_table_info`, `pragma_index_list`, …);
- writes to Chronolog's own tables (`chronolog_*`);
- Dolt functions (`dolt_*`, `doltlite_*`), `total_changes()` and
  `sqlite_offset()`, whose results depend on connection history or storage.

Everything else the pinned engine accepts is allowed, including DDL,
triggers, views, generated columns, window functions, JSON, FTS5, R-tree and
sqlite-vec. Math functions (`sin`, `exp`, …) are not compiled into the engine.

## 6. Transaction log

`chronolog_transactions` is part of the replicated state and readable by
transactions:

```text
tx_id, order_index, author_id, author_timestamp_ms, author_feed_sequence,
candidate_digest, canonical_candidate,
outcome ('accepted' | 'rejected'), rejection_code, failing_statement_index
```

A transaction may depend on an earlier one, for example
`SELECT chronolog_assert(EXISTS (SELECT 1 FROM chronolog_transactions WHERE
tx_id = :earlier AND outcome = 'accepted'), 'needs_earlier')`.

## 7. Local reads

Local query SQL runs on an immutable materialized revision, is not signed or
replayed, and returns plain SQLite values. It may use any read-only function,
including the real clock.

## 8. Execution manifest

Every candidate names the execution manifest digest it was authored for. The
manifest records the engine build (DoltLite version, source digests, patch
profile), this program version, and the step and size limits. A replica only
executes transactions whose manifest it runs; changing the engine is a
group-wide upgrade.
