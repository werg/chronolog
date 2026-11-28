# Chronolog Unified CAS, Packages, Derivations & Registry

Chronolog unifies all content-addressed data — code packages, build derivations, SQLite-CAS pages, `$publications` release bundles, and public/encrypted blobs — under a single Merkle-DAG hash space:

```text
cas:sha256-<64-hex>  =  hashDomain('cas', canonicalCbor([bytes, sortedUniqueLinks]))
```

**Core Principle:** *Verification is permissionless; trust is strictly a latency/compute optimization.*

---

## 1. Canonical CAS DAG Objects (`@chronolog/records`)

All structured CAS nodes are canonical CBOR stored in `ContentAddressedStore` with explicit child hashes in `CasNode.links`:

- **`chronolog-blob/v1`:** Files $\le 64\text{ KiB}$ are raw leaf nodes (`links: []`); larger files form a 64-way fanout Merkle tree of 64 KiB leaves (`putBlobDag`, `readBlobDag`, `statBlobDag`, `streamBlobDag`). Used by both `session.content.putBlob()` and `$publications` (`publishRelease()`).
- **`chronolog-enc-blob/v1`:** Epoch-encrypted chunked blob manifest linking 64 KiB AEAD-encrypted chunk `CasNode`s (ciphertext-safe for blind relays and unified on `session.cas`).
- **`chronolog-pkg/v1`:** Executable package Merkle-DAG (`putPackageDag`):
  - `runtime`: `'esm-quickjs' | 'wasm-pure' | 'hybrid'`
  - `files`: POSIX relative paths $\to$ `cas:sha256-...` (`chronolog-blob/v1`)
  - `exports`: subpath map (e.g. `".": "index.js"`, `"./util": "sub/util.js"`)
  - `dependencies`: package-scoped bare specifiers $\to$ `cas:sha256-...`
  - `builtins`: per-package capability allowlist (`chronolog:crypto`, `chronolog:cas`, `chronolog:sqlite`, `chronolog:wasm`)
  - `wasm?`: `{ entry, abi: 'chronolog-wasm/v1' }` for standalone pure-WASM reducers
  - `derivation?`: provenance back-link to `chronolog-drv/v1` (stored in manifest bytes only, omitted from `CasNode.links` so replay-critical sync never forces devices to pull build source trees)
- **`chronolog-tree/v1`:** Canonical sorted directory tree (used for deterministic source trees and canonical npm/JSR tarball ingestion).
- **`chronolog-drv/v1`:** Content-addressed build derivation (`profile: 'quickjs-inline' | 'wasi-cas-v1'`, `builder`, `inputs`, `args`, `limits`).

---

## 2. Scoped Execution, Deterministic Fuel & Pure WASM (`@chronolog/materializer`)

- **2-Arg Scoped QuickJS-NG Loader:** Resolves `./` and `../` relative imports strictly inside `pkg:<pkgHash>/<path>`, resolves bare imports through `pkg.dependencies` (zero diamond dependency conflicts), supports direct `cas:sha256-...` imports, and enforces **per-package capability attenuation** (a package can only import `chronolog:*` builtins declared in both `$reducers.runtime.builtins` and its own `pkg.builtins`).
- **Per-Hash Decode Cache & Historical GC Pinning:** Immutable CAS modules and parsed manifests are cached in memory per `cas:sha256-...` hash, and `TopicKernel.gcRoots()` pins every `$reducers` package activated across the active replay window so late-arriving ops and `materializeAt()` time-travel survive GC.
- **Deterministic Fuel Metering:** `GenesisLimits.maxFuel` bounds QuickJS interrupt ticks deterministically across devices (`vm:fuel_exhausted`).
- **Pure Deterministic WASM (`WasmSandbox` & `chronolog:wasm`):** Rejects non-`chronolog` host imports (zero WASI/clock/network), compiles and caches each `WebAssembly.Module` once per `cas:sha256-...` hash, and supports both standalone `runtime: 'wasm-pure'` topic reducers (`chronolog-wasm/v1` ABI) and `chronolog:wasm` `invoke()` / `invokeJson()` calls from JS reducers.
- **Content-Addressed Derivations (`evaluateDerivation` / `verifyDerivationOutput`):** `quickjs-inline` derivations execute directly inside `QuickJsSandbox` with durable `drvHash -> outputHash` memoization; `wasi-cas-v1` derivations pair deterministic CAS-backed builds with Ed25519 `chronolog-attestation/v1` receipts (`signBuildAttestation`, `signAuditAttestation`).

---

## 3. Unified Transport, Mirrors & Composition (`@chronolog/peer-session`)

- **Single-Round-Trip Subgraph Pull (`cas-want`):** Missing package roots automatically pull their full executable `CasNode.links` subgraph via `cas.collectSubgraph()`.
- **Untrusted HTTP CAS Mirrors (`casMirrors`):** Missing public CAS nodes can be fetched from read-only HTTP mirrors (`GET <mirror>/cas/sha256-<hex>`) and cryptographically verified via `putManyVerified()`.
- **Private App Packages:** On `privateLog: true`, `$*` control topics stay in `public` CAS (preserving blind-host parity) while private application packages may live in `private` CAS.
- **Verified Cross-Log Mounts (`$mounts` / `chronolog/mounts`):** `session.mountLog(name, otherSession)` pins a signed snapshot + reachable public CAS nodes of an external Chronolog log so reducers can query it deterministically via `ctx.mount(name)` and `ctx.mountQuery(name, topic, input)`.
- **Attested Governance (`$builders` / `chronolog/builders`):** `attestedReducers` supports M-of-N reproducible-build attestations, auditor approval, and mounted Registry approval (`requireMountApproval`).

---

## 4. Developer Ergonomics & Dogfooded Registry (`@chronolog/pack`)

- **`packReducers()` & `packNpmTarball()`:** Deterministically compiles TypeScript/JS + npm/JSR packages via esbuild (ESM, tree-shaken, dead dev-branch elimination), runs the static **Determinism Linter** (`lintDeterminism`), auto-detects minimal `builtins`, emits `chronolog-pkg/v1` + `chronolog-drv/v1` + `chronolog.lock.json`, and plugs directly into `createLogGenesis({ bundle })` or `session.installPackage(...)`.
- **Dogfooded Registry Chronolog (`createRegistryGenesis` + `RegistryClient`):** A standard Chronolog log running `chronolog/registry` (SQLite + FTS5 full-text search + signed build/audit attestations) for decentralized or org-private package discovery and verified installation.
