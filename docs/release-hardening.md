# Qualification and release checks

All qualification targets the single owned-session composition (`@chronolog/peer-session` + `@chronolog/peer-generation`).

## Test suites

| Command | Coverage |
| --- | --- |
| `pnpm lint && pnpm typecheck` | ESLint (zero warnings) and strict TypeScript across all packages |
| `pnpm test` | Protocol, crypto, authority, replica replay, recovery, signals, WebRTC/WebSocket transports, and sessions |
| `pnpm test:publication-crash` | Real process kill at publication boundaries with reopen verification |
| `pnpm test:fuzz` | Canonical CBOR and SQL input fuzzing |
| `pnpm test:soak` | Repeated materialization, late-order replay, and reopen stress test |
| `pnpm test:native-sanitizers` | Patched C DoltLite engine under sanitizers |
| `pnpm conformance` | Cross-adapter execution digests and native/WASM equivalence |
| `pnpm docs:check` | Markdown link and anchor validation |

## Standalone packages

Build clean, provenance-verified archives from committed source:

```sh
node tools/package-peer-session.mjs
node tools/package-peer-session.mjs --sql-native --output artifacts/peer-session-sql
node tools/package-peer-session.mjs --sql-browser --output artifacts/peer-session-sql-browser
node tools/package-peer-generation-control.mjs
```

Each archive embeds `provenance.json` with exact commit SHA, tree hash, input list, and SHA-256 digests. The default session archive is SQL-free and keeps browser entries free of Node/Werift imports. `--allow-dirty` is for local debugging only and marks the archive dirty.

## Limits of local qualification

Loopback WebRTC, local Worker tests, and synthetic hosts verify protocol and lifecycle invariants, not public Internet NAT traversal, mobile browser suspension, or deployed provider costs. Record real deployment measurements separately before promotion.
