# Authored Operation-Set Lifecycle

This guide walks through how operations flow from local authoring through replication, suffix replay, key rotation, and optional finality checkpoints.

## 1. Genesis & Chain Identity

Use `createLogGenesis()` from `@chronolog/peer-session`:
- Pins the 5 standard modules (`chronolog/permissions`, `chronolog/keys`, `chronolog/finality`, `chronolog/publications`, `chronolog/rls`) and your application ES Modules into public CAS (`cas:sha256-...`).
- Configures `$reducers`, `$permissions`, `$keys`, `$finality`, `$publications`, `$signal_policy`, and your app topics.
- Produces canonical `genesisBytes`, deterministic `logId`, `casNodes`, and (for private chains) an initial `epoch0Key`.

## 2. Local Durable Authoring

`session.submit()` / `session.command()` signs `OperationCore` with the device's Ed25519 key and writes it to local durable storage (`BytesStore`) **before** any network I/O:
- Public control updates (`$*` topics) are stored as `SignedOperation` bytes.
- Private application updates are encrypted under the current epoch key into an `EncryptedOperationEnvelope`, and the signed plaintext is kept locally in `local-pending` so offline operations can be rewrapped if the epoch rotates before reconnect.
- Calling `submit()` / `command()` again with the same `operationId` returns the exact original durable operation without changing its timestamp or bytes.

## 3. Replication & Reconnect Rewrapping

Peers exchange `SessionFacts` (`publicOps`, `encryptedEnvelopes`, `casNodes`, `retentions`, `checkpoints`) over authenticated `ApplicationSecureChannel` connections (WebRTC or WebSocket) or via `exportFacts()` / `mergeFacts()`:
- Encrypted envelopes are tracked by `encryptedEnvelopeDigest`, never by `opId` alone.
- If Peer B authored offline at epoch `0` while Peer A rotated to epoch `1`, Peer B unseals epoch `1` from `$keys` upon reconnecting, automatically re-encrypts its exact original signed bytes under epoch `1`, and syncs the new envelope digest so all peers converge with identical `opId` and `stateRoot`.

## 4. Reactive Views & Event Forwarding

Because late earlier operations can revise SQL rows, topic states, and emitted events:
- Derive UI state from coherent snapshots via `createLiveView(session, derive)` rather than appending incremental arrival events.
- For durable external side effects (webhooks, notifications, agent dispatch), use `forwardSessionEvents()`, which reconciles effective snapshots by stable event ID and emits explicit `retract` callbacks if a late operation changes a provisional outcome.

## 5. Checkpoint Bootstrap

When a finalizing policy is active in `$finality`:
- Authorized finalizers call `session.finality.createCheckpoint({ throughMs })`, producing a signed `FinalityCheckpoint` committing to `includedSetDigest`, `stateRoot`, and `historyDigest`, plus a `CheckpointBootstrapSnapshot` (`{ topics, seenOpsRoot, historyDigest, stateRoot }`).
- A new replica calls `session.finality.bootstrapFromCheckpoint(checkpoint, snapshot)` and replays only suffix operations after `closedThroughMs`, arriving at the exact same `stateRoot` and `revision.digest` as a full replay from genesis.
