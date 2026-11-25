# Chronolog documentation

- [Session API reference](../packages/peer-session/README.md): definitions, devices, commands, queries, operation observations, participation, browser Workers, content, and tools.
- [Worker lifetime and conversation delivery](../packages/peer-session/README.md#separate-the-session-owner-request-worker-and-conversation-host): distinguish connectivity, request handling, retained progress and host delivery.
- [Authored operation-set contract](CRDT_CONTRACT.md): immutable signed proposals, canonical author-time order, observations, optional finality, ordinary schema and permission transactions.
- [Architecture and authority](authored-operation-set.md): execution model, observations, authority separation, finality, transports, and storage bounds.
- [Deterministic SQL](implementation-specs/10-deterministic-sql-transactions.md): change programs, limits, execution identity, and atomic outcomes.
- [Row ownership](design-owner-rows.md): SQL data ownership and collective membership.
- [Sealed values](sealed-data.md): explicit recipient encryption for private fields.
- [Browser storage](browser-storage.md): OPFS/IndexedDB selection, locking, and capability probing.
- [Qualification](release-hardening.md): test suites, packaging, and verification gates.
- [Materializer](../packages/materializer/README.md) | [Signals](../packages/signals/README.md) | [WebRTC transport](../packages/transport-webrtc/README.md)
