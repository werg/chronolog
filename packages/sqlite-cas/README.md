# `@chronolog/sqlite-cas`

Deterministic stock SQLite + FTS5 + `sqlite-vec` compiled to static `sqlite-cas.wasm` (1.34 MB) on top of a 4 KiB Merkle-paged `ContentAddressedStore` VFS.

## Highlights

- **Content-addressed database roots:** Every `db.commit()` flushes modified 4 KiB pages into `CAS` (64-way fanout tree, depth 3 = 1 GiB) and returns a single 32-byte `dbRoot` hash. Rollback and suffix replay are O(1) pointer swaps.
- **Deterministic profile:**
  - `random()` and `randomblob()` are rejected.
  - `xCurrentTime` and `localtime` are pinned to the signed operation's UTC `op_time()`.
  - `changes()` and `last_insert_rowid()` reset on every `openDb()`.
  - `actor()`, `op_id()`, and `op_time()` are bound by the host kernel.
- **3-mode authorizer + `chronolog/rls`:** Supports `mode: 'admin' | 'user' | 'readonly'` with optional `ddl` allowlists (`createTable`, `alterTable`, `dropTable`, `indexOn`, `createView`, `dropView`), `PRAGMA recursive_triggers = ON`, and `db.validateExpr()` for validating Postgres-style write RLS triggers.
- **Cloudflare Workers ready:** Pass a static pre-compiled `WebAssembly.Module` via `createSqliteCasDriver({ wasmModule })` to avoid runtime `WebAssembly.compile()`.
