# Architecture and authority (`peer-generation-v1`)

Chronolog replicates application history across browser Workers and native peers using replaceable generation coordinators and a monotonic signed control chain.

## Execution model

- One eligible peer sequences commands for the active generation.
- Every peer independently verifies the author's signed, encrypted attempt, the coordinator's signed order receipt, and the execution manifest before materializing state.
- Local durability precedes acknowledgment. Commands require no control-service round trip once a generation is selected.
- Direct peer connections continue unaffected if the control host is unreachable. Relayed WebSocket connections depend only on byte forwarding, not control availability.
- If both coordinator and control service are unavailable, attempts stay saved locally until a valid successor is selected.

This model assumes the control service does not equivocate and the selected coordinator orders consistently; peers detect conflicting signed orders and fence the session.

## Authority separation

| Concern | Rule |
| --- | --- |
| **Authorship** | Signing device identity and `reader`/`writer` grants determine who can read and submit commands. |
| **Sequencing** | A generation delegates ordering to one eligible `coordinator`. Sequencing grants no author or SQL admin rights. |
| **Recovery** | Requesting a transition requires `recovery: true`; the candidate separately needs `coordinator: true`. |
| **Administration & publication** | `administrator` (control changes) and `publisher` (signed code releases) are independent opt-in rights. |
| **SQL ownership** | `dataRole` (`member` / `admin` / `null`) governs `APPLICATION_COLLECTIVE_ID` membership separately from control rights. |

`participantGrant(key, opts)` configures an ordinary participant; `controlParticipantGrant(key)` gives a host only `administrator` and `recovery` rights with data access disabled.

## Roles and transports

Participant roles define which records a peer may author, receive, retain, and serve. Transports (HTTP control, WebRTC, WebSocket relay) enforce role interest filters while every receiver re-verifies signatures and grants.

- **Control participant**: handles signed descriptors, monotonic control revisions, generation selection, and signed page-code publications. Never receives application payloads or epoch keys.
- **Peer connections**: direct WebRTC or relayed WebSockets feed one `FramedPeerConnection` interface with an authenticated, HPKE-keyed encrypted channel and independent reliable and disposable live lanes.

## Generations, ancestry, and recovery

A signed transition binds `transitionId`, expected generation, requester, candidate, control revision, reason, and adopted prefix. Compare-and-swap selects a single successor; exact retries return the original selection.

Each generation adopts a prefix of the currently selected history, carrying signed order headers up to the exclusion cutoff. Once a generation excludes positions beyond a cutoff, no later generation can revive them.

- Adopted attempts keep their original bytes and identities.
- Excluded work is quarantined and never silently merged or resubmitted.
- Deliberate reapplication creates a new signed attempt linked via `reapplyOf` under current controls and domain guards.

## Operation states and controls

Operations move through `saved`, `applied` (`accepted` or `rejected`), `shared` (retained on another peer), `abandoned`, or `needsReapply`. `applied()` is stable within the selected history, not globally irreversible. Irreversible external effects require an explicit application-level journal and reconciliation policy.

Controls form a monotonic signed chain that never rolls back with data recovery:

- Inherited commands replay against their historical control revision; the latest controls reapply before publishing the current view.
- Revoking a reader requires rotating the encryption epoch and key commitment. Previously disclosed plaintext cannot be revoked.
- Signed page-code publications form an independent monotonic chain that never rewinds on application data recovery.

## Storage and bounds

Recovery replays retained encrypted history—peers never accept unverified remote database images.

- **History budget**: default limit of 4,096 ordered records and 64 MiB serialized history (including abandoned records).
- **Content attachments**: encrypted 64 KiB chunks, up to 128 MiB per object and 8 attached sources. Access rechecks current reader grants on every read/serve.
- **Views**: `readView()` captures an immutable materialized snapshot; release views promptly.
