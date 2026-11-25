# Architecture and authority (authored operation set)

Chronolog replicates application history across browser Workers and native peers as an immutable, signed operation set. This page is the architectural overview. The normative rules are in the [authored operation-set contract](CRDT_CONTRACT.md); the session API is in the [session reference](../packages/peer-session/README.md).

## Execution model

- An author prepares a canonical transaction core, chooses one nonnegative int64 `authorTimestampMs`, signs it, encrypts it for the current epoch and durably stores it before `submit()` or `command()` returns.
- The proposal ID is the domain-separated digest of the canonical transaction core. Rewrapping, retransmission, lost acknowledgements and reconnect never mint another proposal or timestamp. Reusing an operation ID with different contents is an error.
- Every replica independently verifies each operation and unions the facts it holds. It replays the eligible set in one order: signed author timestamp, then signing public-key bytes, then proposal-ID bytes. Arrival, feed or receipt position, host clocks and participant roles cannot supply order.
- Materialization is a replaceable deterministic projection of the set. An operation that arrives with an earlier author time causes later outcomes to be re-derived, so a provisional result can change. The signed intent never does.
- A missing body, epoch key or authority predecessor is a visible pending dependency, not a deterministic rejection. Engine failures are operational errors, not transaction outcomes.
- No peer coordinates, selects or hands over ordering, and there is no generation, takeover, reapplication or compatibility API.

A browser or native device that has already been enrolled and provisioned reopens its cached identity, authority, keys and store, then authors and materializes with no host, peer, agent or finalizer reachable. A fresh browser must first enroll and receive explicit key provisioning. An empty browser cannot invent missing private keys.

## Observations of an operation

| Observation | Meaning |
| --- | --- |
| `stored` | The exact signed intent is durable on this device. |
| `materialized` | A coherent local outcome (accepted or rejected) at a particular operation-set and execution revision. It stays revisable until finalized. |
| `retained` | Signed availability evidence from named peers. Independent of execution and finality. |
| `finalized` | Inclusion and closed-time evidence verified under the configured finality policy, with required bodies, keys and replay complete. |

None of these implies another. `finalized` is not a retention promise or an exactly-once external-effect mechanism. Irreversible external effects still need an application-level journal and reconciliation policy.

## Authority separation

| Concern | Rule |
| --- | --- |
| **Authorship and reading** | Signed membership windows grant `reader` and `writer` by author time, so a late operation is judged against the membership that applied at its own time. The current epoch key is required to encrypt or read. |
| **Application data rights** | Collective membership, row ownership and DDL permissions live in the application's materialized permission catalog and change only through ordinary authored transactions. The root `GROUP_COLLECTIVE_ID` is the genesis collective; group membership and grants are authored operations. |
| **DDL rights** | Creating, altering, dropping and indexing objects is authorized per namespace and object from that catalog. It is independent of the cryptographic grants below. |
| **Administration** | `administrator` governs signed membership and metadata changes. It grants no data or DDL rights by itself. |
| **Finality** | `finalizer` eligibility and the finality policy decide who can sign admission and closed-time evidence. A finalizer has no authoring right and no ordering interface. |
| **Publication** | `publisher` signs code releases. Publication is independent of data authority and does not overwrite application permission state. |

Enrollment, host credentials and device grants authenticate who may hold keys or publish. They are not application operations and do not reorder them.

## Optional finality

The default policy is `none`, a complete local-first mode: nothing waits for a finalizer, and replayable history is kept. Two other policies are supported, each with explicit scopes:

- `signed-frontier`: one named signer closes an author-time frontier.
- `fixed-validator`: a fixed validator set with a threshold signs the same statements.

A browser, native peer or host can act as finalizer under the same proof contract. A provider may determine inclusion and close a frontier through `session.finality`; it has no comparator. A blocker at time T limits safe closure to T-1. After a frontier is sealed, a proposal first included behind it is excluded, including genuinely delayed offline work. The original intent remains inspectable. It is never silently retimestamped or resubmitted. Unavailable finality never blocks local authoring or provisional reads. Safe pruning of history needs a verified finalized prefix or checkpoint.

## Transports and roles

Direct WebRTC and relayed WebSockets carry signed facts (operations, retention and finality evidence, authority bundles) through one authenticated, encrypted `FramedPeerConnection` with reliable and disposable live lanes. Every receiver re-verifies signatures, grants and epochs. Merging the same facts again is idempotent, and transports may keep replay counters that are unrelated to application order. Direct peer links continue to work if the control host is unreachable.

A host control participant handles signed metadata and code publications. It never receives application payloads or epoch keys. Revoking a reader requires rotating the encryption epoch. Plaintext already disclosed cannot be revoked.

## Storage and bounds

Replicas retain encrypted signed history and replay it. They never accept an unverified remote database image. The session bounds operation count and serialized history through `maxOperations` and `maxHistoryBytes`. Checkpoints restore device state from verified encrypted export. `readView()` captures an immutable snapshot, so release views promptly. Content attachments are encrypted chunked objects whose access rechecks current reader grants.

## Reactive consumers

Render domain UI from coherent snapshots from `query()` or `readView()` plus separate local view and draft state. A change notification invalidates and rederives. It is not an append-only source for a second UI database. Late operations can change counts, rows, details and schema, so preserve stable-ID selection, focus and unsent drafts, and report stale-query errors honestly. The ordinary Save action depends on local durable submission, not network readiness.
