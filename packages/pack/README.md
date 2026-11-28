# `@chronolog/pack`

Deterministic reducer packer, static determinism linter, npm/JSR tarball ingester, lockfile, and registry client for Chronolog `chronolog-pkg/v1` packages.

## Exports

- **`packReducers()`:** Bundles TypeScript/JavaScript reducer entries via `esbuild` into deterministic `chronolog-pkg/v1` Merkle-DAG CAS nodes ready for `createLogGenesis()` or `session.installPackage()`.
- **Determinism linter:** Flags non-deterministic globals (`Date`, `Math.random`, `performance`) and disallowed host builtins at build time.
- **Registry & lockfile:** Package ingestion, `chronolog.lock` resolution, and client helpers for the dogfooded `chronolog/registry` Chronolog.
