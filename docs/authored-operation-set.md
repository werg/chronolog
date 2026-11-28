# Authored Operation-Set Lifecycle

This guide walks through how operations flow from local authoring through replication, suffix replay, key rotation, and optional finality checkpoints.

## 1. Genesis & Chain Identity

Use `createLogGenesis()` from `@chronolog/peer-session`:
- Pins the standard audited modules (`chronolog/admission`, `chronolog/seals`, `chronolog/reducer`, `chronolog/keys`, `chronolog/publications`, `chronolog/rls`, `chronolog/sql`, etc.) and your application ES Modules into public CAS (`cas:sha256-...`).
- Configures `$reducers`, `$admission`, `$seals`, `$keys`, `$publications`, and your app topics.
- Produces canonical `genesisBytes`, deterministic `logId`, `casNodes`, and (for private chains) an initial `epoch0Key`.

## 2. Local Durable Authoring

`session.submit()` / `session.command()` signs `OperationCore` with the device's Ed25519 key and writes it to local durable storage (`BytesStore`) **before** any network I/O:
- Public control updates (`$*` topics) are stored as `SignedOperation` bytes.
- Private application updates are encrypted under the current epoch key into an `EncryptedOperationEnvelope`, and the signed plaintext is kept locally in `local-pending` so offline operations can be rewrapped if the epoch rotates before reconnect.
- Calling `submit()` / `command()` again with the same `operationId` returns the exact original durable operation without changing its timestamp or bytes.

## 3. Replication & Reconnect Rewrapping

Peers exchange facts over authenticated `ApplicationSecureChannel` connections (WebRTC or WebSocket) with the sync-v3 protocol described in [Performance](PERFORMANCE.md) (range-fingerprint reconciliation, live push, on-demand CAS pull), or transport-agnostically via `exportFacts()` / `mergeFacts()`:
- Encrypted envelopes are tracked by `encryptedEnvelopeDigest`, never by `opId` alone.
- If Peer B authored offline at epoch `0` while Peer A rotated to epoch `1`, Peer B unseals epoch `1` from `$keys` upon reconnecting, automatically re-encrypts its exact original signed bytes under epoch `1`, and syncs the new envelope digest so all peers converge with identical `opId` and `stateRoot`.

## 4. Reactive Views & Event Forwarding

Because late earlier operations can revise SQL rows, topic states, and emitted events:
- Derive UI state from coherent snapshots via `createLiveView(session, derive)` rather than appending incremental arrival events.
- For durable external side effects (webhooks, notifications, agent dispatch), use `forwardSessionEvents()`, which reconciles effective snapshots by stable event ID and emits explicit `retract` callbacks if a late operation changes a provisional outcome.

## 5. Checkpoint Bootstrap

When a finalizing policy is active in `$admission`:
- Authorized signers call `session.admission.createCheckpoint({ throughMs })`, producing an `AdmissionEvidence` record committing to `includedSetDigest`, `stateRoot`, and `historyDigest`, plus a `CheckpointBootstrapSnapshot` (`{ topics, seenOpsRoot, historyDigest, stateRoot }`).
- A new replica calls `session.admission.bootstrapFromCheckpoint(evidence, snapshot)` (which also pins a non-rewinding `PinnedFrontier`) and replays only suffix operations after `closedThroughMs`, arriving at the exact same `stateRoot` and `revision.digest` as a full replay from genesis.
