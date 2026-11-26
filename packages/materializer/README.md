# `@chronolog/materializer`

Deterministic Chronolog v2 topic kernel, QuickJS-NG WASM ESM sandbox, and audited standard modules.

## Exports

- **`TopicKernel` (`kernel.ts`):** Flat timestamp-ordered suffix-replay engine enforcing the two-way public/encrypted control partition, scoped `(visibility, author, operationId)` idempotency (`seenOpsRoot`), rolling `historyDigest`, `stateRoot`, `revision.digest`, `query()`, `describe()`, `signalPolicy()`, and `bootstrapFromCheckpoint()`.
- **`QuickJsSandbox` (`quickjs-sandbox.ts`):** Fresh `QuickJSContext` per invocation, Import-Map loader over `CAS`, uncatchable host-level `MissingDependencyError`, static `WebAssembly.Module` support for Cloudflare Workers, and `chronolog:crypto` / `chronolog:cas` / `chronolog:sqlite` builtins.
- **Standard Modules (`@chronolog/materializer/std-modules`):** `STANDARD_MODULE_SOURCES`, `STANDARD_MODULE_IMPORTS`, and `seedStandardModules()` for `chronolog/permissions`, `chronolog/keys`, `chronolog/finality`, `chronolog/publications`, and `chronolog/rls`.
