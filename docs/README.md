# Chronolog documentation

The public application composition is the [owned session](../packages/peer-session/README.md).
Every participant uses its operation, query, replication and recovery contracts.

- [Architecture and authority](peer-generation-v1.md): selected history,
  participant roles, control, publication, recovery and bounded retention.
- [Deterministic SQL](implementation-specs/10-deterministic-sql-transactions.md):
  programs, limits, execution identity, original authorship and atomic outcomes.
- [Row ownership](design-owner-rows.md): data authorization independent of
  sequencing and control rights.
- [Sealed values](sealed-data.md): explicit reader encryption and its limits.
- [Qualification](release-hardening.md): current test, artifact and deployment gates.
- [Browser record storage](browser-storage.md): OPFS/IndexedDB backend pinning, diagnostics, browser qualification and recovery limits.

Superseded daemon, hosted application, RPC and finality application guides have
been removed. Git history retains past implementations and their evidence. They
are not supported alternative compositions.
