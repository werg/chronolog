# Portable peer database implementation plan

## Goal

Make Chronolog a portable local SQL peer with one durable record substrate and
one synchronization path. Keep existing peer chronological finality and add
coordinated order as a second built-in history policy. The optional Tendriller
adapter consumes a generic retained record log through public artifacts.

The project is unreleased. Refactor prototype interfaces directly; do not add
backward compatibility, legacy data migration, or duplicate execution paths.

## A. Portable records and peer replication

- [x] Extract exact signed records, identity checks, canonical encoding, and feed
      continuity from native SSB connections.
- [x] Inject durable storage and crypto; share neutral connection types.
- [x] Extract pull/range synchronization and provide an in-process link.
- [x] Preserve native peer admission, tentative replay, and independent finality.
- [x] Prove forwarding preserves original authorship and record identity.

## B. Order, execution, and enrollment

- [x] Pin the two built-in policies and execution profile in group configuration.
- [x] Implement domain-bound prefix certificates, exact ordered-entry evidence,
      a durable reference log, and a head-reading authority that executes no SQL.
- [x] Use policy-selected order in node, control store, and materializer together;
      coordinated order must never be re-sorted by author timestamps.
- [x] Persist exact proposals and caller-operation mappings before send.
- [x] Deduplicate proposals across envelopes and preserve original final outcomes.
- [x] Publish actual local/final immutable SQL revisions; final waits require
      complete verified evidence and durable materialization.
- [x] Keep missing bytes/keys/engines and infrastructure failures as blocked
      progress rather than fabricated SQL rejections.
- [x] Add signed resumable reader/writer requests and exact durable approvals.
- [x] Serialize governance signing and publication; bind writes to grant identity.
- [x] Enforce ordered governance activation, revocation, predecessor continuity,
      and explicit full-history key approval.
- [x] Expose readiness through a captured final target, including authorized but
      disconnected and missing historical keys.

## C. Durable browser peer

- [x] One Worker owns OPFS record/control storage, signer, and SQL engine.
- [x] Enforce one active storage writer with browser ownership/locking.
- [x] Inject the native/WASM engine boundary and qualify deterministic SQL,
      assertions, read enforcement, replay, and publication recovery.
- [x] Verify native/browser outcome and state equivalence from the same history.
- [x] Verify reload, interrupted authoring/application, and competing-tab behavior.

A browser RPC shell or a mocked SQL engine does not establish this milestone.
Any engine conformance gap remains visible until resolved and exercised.

## D. Optional public Tendriller integration

- [x] Adapt the public retained log to shared record synchronization.
- [x] Keep certificates outside the log they certify; retain and relay certificates
      and ordered mappings in the ordinary replica record store.
- [x] Compose an on-demand authority endpoint around the public engine handler.
- [x] Keep host authentication separate from Chronolog database enrollment.
- [x] Exercise shared SQL, a contested claim, lost replies, reconnection, third
      device enrollment, and peer delivery during authority unavailability.
- [x] Check that neither core depends on the other repository's private files.
- [x] Qualify one real browser/native scenario combining public enrollment,
      collective SQL contention, durable retry, and offline third-peer replay.

## Acceptance and delivery

Native peer regression tests are a gate throughout. Add meaningful tests for
immutable final prefixes, late tentative replay, cross-envelope deduplication,
malformed entries, incomplete evidence, grant revocation/regrant, concurrent
approval, full-history readiness, real final queries, and atomic publication.

Commit and publish small coherent increments. Keep both draft PR descriptions
current with completed work, exact validation, and remaining limitations. No
deployment or merge is part of this implementation request.

Deferred scope: snapshots/compaction, dynamic validator sets, multi-issuer
governance, engine upgrades, authority rotation/failover, bearer invitations,
WebRTC discovery, and general-purpose plugin frameworks.

## Status

Portable records, both integrated native history policies, live enrollment,
actual final SQL/RPC/client interfaces, and the public Tendriller integration are
implemented and covered by executable acceptance tests. The patched WASM engine
passes native/WASM differential replay tests. Real Chromium Worker/OPFS
qualification passes all seven checks, including exclusive ownership, actual final
SQL, persistent identity, and termination after durable preparation and candidate
commit, and a private validator cutoff that cannot be reconstructed from feed
replay. The required workflow repeats these gates from a clean checkout; the PR
description records its latest result. See
[portable peers](../portable-peers.md) for the verification map.

The combined browser/native public-adapter gate also passes five checks: live
enrollment with historical keys, explicit collective ownership, one final SQL
claim winner, page-reload retry identity, and a fresh approved browser reader
replaying from another browser peer with no hub requests while the hub is offline.
