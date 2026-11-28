# `@chronolog/materializer`

Deterministic Chronolog topic kernel (`state/v3`), scoped QuickJS-NG WASM ESM sandbox, pure WebAssembly sandbox, derivation evaluator, and audited standard modules.

## Exports

- **`TopicKernel` (`kernel.ts`):** Flat timestamp-ordered O(changed) suffix-replay engine enforcing the two-way public/encrypted control partition, rolling `historyDigest`, per-topic `stateRoot` (`state/v3`), `revision.digest`, `query()`, `describe()`, `signalPolicy()`, historical reducer root pinning, and `bootstrapFromCheckpoint()`.
- **`QuickJsSandbox` (`quickjs-sandbox.ts`):** Fresh `QuickJSContext` per invocation, 2-argument scoped `chronolog-pkg/v1` module loader (diamond-dependency isolation + per-package `builtins` attenuation), lazy `readTopic` host reads, deterministic fuel metering (`limits.maxFuel`), uncatchable host-level `MissingDependencyError`, static `WebAssembly.Module` support, `ctx.mount()`/`ctx.mountQuery()`, and `chronolog:crypto` / `chronolog:cas` / `chronolog:sqlite` / `chronolog:wasm` builtins.
- **`WasmSandbox` (`wasm-sandbox.ts`):** Pure deterministic WebAssembly runtime (`runtime: 'wasm-pure'` `chronolog-wasm/v1` ABI + `chronolog:wasm` `invoke`/`invokeJson`) with per-hash compiled `WebAssembly.Module` caching and zero non-`chronolog` host imports.
- **Derivations & Attestations (`derivation.ts`):** `evaluateDerivation()`, `verifyDerivationOutput()`, `createBytesStoreDerivationMemo()`, and Ed25519 `chronolog-attestation/v1` build/audit sign & verify helpers.
- **Standard Modules (`@chronolog/materializer/std-modules`):** `STANDARD_MODULE_SOURCES`, `STANDARD_MODULE_IMPORTS`, `seedStandardModules()`, and `seedStandardPackages()` covering `chronolog/{permissions,keys,finality,finality-predicates,publications,mounts,builders,registry,sql,rls,sqlite-helpers,guards,quotas,queue,votes,schema,audit,crdt,text,ledger,workflow,fs}`.
