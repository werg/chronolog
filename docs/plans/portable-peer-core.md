# Portable peer database implementation plan

## Goal

Make Chronolog a portable local SQL peer with one durable record substrate and
one synchronization path. Keep existing peer chronological finality and add
coordinated order as a second built-in history policy. The optional Tendriller
adapter consumes a generic retained record log through public artifacts.

The project is unreleased. Refactor prototype interfaces directly; do not add
backward compatibility, legacy data migration, or duplicate execution paths.

## A. Portable records and peer replication

- [ ] Extract exact signed records, identity checks, canonical encoding, and feed
      continuity from native SSB connections.
- [ ] Inject durable storage and crypto; share neutral connection types.
- [ ] Extract pull/range synchronization and provide an in-process link.
- [ ] Preserve native peer admission, tentative replay, and independent finality.
- [ ] Prove forwarding preserves original authorship and record identity.

## B. Order, execution, and enrollment

- [ ] Pin the two built-in policies and execution profile in group configuration.
- [ ] Implement domain-bound prefix certificates, exact ordered-entry evidence,
      a durable reference log, and a head-reading authority that executes no SQL.
- [ ] Use policy-selected order in node, control store, and materializer together;
      coordinated order must never be re-sorted by author timestamps.
- [ ] Persist exact proposals and caller-operation mappings before send.
- [ ] Deduplicate proposals across envelopes and preserve original final outcomes.
- [ ] Publish actual local/final immutable SQL revisions; final waits require
      complete verified evidence and durable materialization.
- [ ] Keep missing bytes/keys/engines and infrastructure failures as blocked
      progress rather than fabricated SQL rejections.
- [ ] Add signed resumable reader/writer requests and exact durable approvals.
- [ ] Serialize governance signing and publication; bind writes to grant identity.
- [ ] Enforce ordered governance activation, revocation, predecessor continuity,
      and explicit full-history key approval.
- [ ] Expose readiness through a captured final target, including authorized but
      disconnected and missing historical keys.

## C. Durable browser peer

- [ ] One Worker owns OPFS record/control storage, signer, and SQL engine.
- [ ] Enforce one active storage writer with browser ownership/locking.
- [ ] Inject the native/WASM engine boundary and qualify deterministic SQL,
      assertions, read enforcement, replay, and publication recovery.
- [ ] Verify native/browser outcome and state equivalence from the same history.
- [ ] Verify reload, interrupted authoring/application, and competing-tab behavior.

A browser RPC shell or a mocked SQL engine does not establish this milestone.
Any engine conformance gap remains visible until resolved and exercised.

## D. Optional public Tendriller integration

- [ ] Adapt the public retained log to shared record synchronization.
- [ ] Keep certificates outside the log they certify; retain and relay certificates
      and ordered mappings in the ordinary replica record store.
- [ ] Compose an on-demand authority endpoint around the public engine handler.
- [ ] Keep host authentication separate from Chronolog database enrollment.
- [ ] Exercise shared SQL, a contested claim, lost replies, reconnection, third
      device enrollment, and peer delivery during authority unavailability.
- [ ] Check that neither core depends on the other repository's private files.

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

Planning scaffold. Implementation and verification are tracked above; unchecked
items are not claimed as complete.
