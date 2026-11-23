# Chronolog-DB Architecture & Implementation Review

**Reviewed commit:** `680b70b` (`main`)
**Verification run:** `pnpm lint` (pass), `pnpm typecheck` (pass), `pnpm docs:check` (pass), `pnpm test:fast` (63/63 pure-JS test files, 603/603 tests pass; 22 native-SQL test files excluded from `test:fast`).

## Executive Summary

Chronolog-DB is a well-tested 12-package TypeScript monorepo (~22,300 LOC non-test source, 84 test files, 443 commits), but it has undergone **major architectural drift** away from its original author-submitted temporal ordering model:

1. **Ordering model inverted**: Author-submitted temporal ordering (`authorTimestampMs`, `authorId`, `txId`) is still defined in `@chronolog/protocol` and supported by both materializers, **but is completely unused at runtime**. `packages/peer-generation` and `packages/peer-session` hardcode single-coordinator sequential ordering (`OrderReceipt.sequence`) backed by a centralized compare-and-swap `GenerationRegistry`.
2. **Finality plumbing orphaned**: Both `@chronolog/materializer` and `@chronolog/materializer-doltlite` still maintain `finalRevision`, `finalOrderLength`, `view: 'local' | 'final'`, and `publishFinal()`, yet nothing in `peer-generation` or `peer-session` ever calls `publishFinal()`. Finality is collapsed into "the active coordinator's selected generation prefix."
3. **Session & messaging runtime sprawl**: `packages/peer-session` has grown to 8,360 LOC (37% of the codebase) and mixes transport, discovery, recovery, chunked blobs, reactive views, browser `localStorage` bookkeeping, event outboxes, checkpoints, batch clients, Tendriller adapters, and LLM tool schemas into one tightly coupled package with overlapping abstractions.
4. **Concrete bugs and scaling cliffs**: Several functional bugs (checkpoint quota smaller than replica quota, hardcoded `unknownLoss: true`, spurious recovery abort in `forwardSessionEvents`) and scaling traps (O(N) full-history clone per notification in `waitForCoverage`, O(G²) authority verification, hard 4,096-record ceiling with no compaction) need resolution before scaling real workloads.

## Review Documents

- 01 — Architectural Drift & Ordering Model (document not included)
- 02 — Session State, Streaming & Messaging Architecture (document not included)
- [03 — Bugs, Shortcomings & Operational Risks](./03-bugs-shortcomings-and-risks.md)
