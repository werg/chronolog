# CRDT-Native Sub-Linear Group Key Rotation (`chronolog-keytree-dag/v1`)

> **Status:** Implemented (`chronolog-keytree-dag/v1` / `chronolog-keytree-subtree/v1` via `@chronolog/crypto`, `chronolog/keys:rotateTreeEpoch`, `$keys.policy.distribution: 'tree'`, and `session.rotateTreeEpoch()`).
> **Goal:** Reduce member-removal / epoch-rotation overhead from $O(N)$ HPKE lockboxes per rotation to $O(\log N)$ while preserving Chronolog's leaderless flat-CRDT convergence, blind-host verifiability, and hybrid post-quantum (`X-Wing`) security.

---

## 1. Why Flat HPKE Lockboxes Are the Right Default Today — and Where They Hit Their Limit

Chronolog v2.0 ships `chronolog/keys:hpkeEpochs`, where each epoch $e$ publishes one HPKE lockbox (`hpke-x25519-aes256gcm` or hybrid PQ `hpke-xwing-aes256gcm`) per admitted reader:

- For personal, family, team, and workspace logs ($N \le 500$ members):
  - X25519 boxes are ~96 bytes each (~48 KiB for 500 members).
  - Hybrid PQ X-Wing boxes are ~1,184 bytes each (~590 KiB for 500 members; still well under a single control op for $N \le 100$, and chunkable via CAS nodes).
- Beyond ~500 members—especially with hybrid PQ X-Wing (1,120-byte KEM ciphertexts) and frequent membership churn—flat $O(N)$ lockboxes become a bandwidth bottleneck:
  - Removing 1 member from a 5,000-member hybrid-PQ group would publish ~6 MB of ciphertext on every removal.
  - Worse, in a leaderless CRDT, two concurrent removals could produce two competing $O(N)$ rotations.

---

## 2. Why Vanilla RFC 9420 MLS / TreeKEM Does Not Drop Directly Into a Flat CRDT

Standard MLS (RFC 9420) assumes a **totally ordered Delivery Service (DS)** that linearizes `Commit` messages into a single chain of epochs $0 \to 1 \to 2 \to \dots$. If two admins concurrently commit removals while offline:

1. In MLS, one commit wins and the other is **discarded and retried** against the winner's new ratchet tree.
2. Chronolog has **no central ordering server**: every replica independently orders operations by `(authorTimestampMs, author, opId)` and must deterministically converge on the exact same `$keys` state without discarding offline edits.

Therefore, sub-linear rotation in Chronolog must be **CRDT-native**, **deterministic under replay**, and **100% blind-host verifiable** without trusting any relay or delivery service.

---

## 3. Architecture: Key-Tagged TreeKEM over Structural-Sharing CAS Merkle-DAG

`EncryptedOperationEnvelope` and `TopicKernel` are completely decoupled from how epoch keys are distributed:

- Envelopes only reference `(ring, epoch)` and authenticate against `mailboxVerifyKey`.
- `$keys` is a normal reducer topic (`chronolog/keys`) whose state is plain JSON referencing content-addressed CAS nodes.

### 3.1 Core Data Structure: Structural-Sharing Binary Ratchet Tree (`chronolog-keytree-dag/v1`)

Instead of storing an inline `boxes: { [pk]: Box }` map of size $O(N)$ in `$keys`, a tree epoch stores:

```json
{
  "epoch": 42,
  "suite": "hpke-tree-xwing-aes256gcm",
  "keyCommitment": "<sha256>",
  "mailboxVerifyKey": "<ed25519-pub>",
  "treeRef": "cas:sha256-...",
  "leafCount": 4096,
  "activeMembers": ["..."],
  "boxes": {}
}
```

The tree itself is stored as a **structural-sharing binary Merkle-DAG of public CAS nodes** (`writeKeyTreeToCas` / `readKeyTreeFromCas` in `@chronolog/crypto`):

- **Root manifest (`chronolog-keytree-dag/v1`):** Holds `suite`, `epoch`, `leafCount`, `treeRootRef`, and `copathBoxes` ($O(\log N)$ sibling boxes plus 1 self-box for the updater's own leaf so cold boot and 1-member groups recover statelessly).
- **Subtree nodes (`chronolog-keytree-subtree/v1`):** Subtrees of height $\le 2$ pack inline ($\le 7$ nodes, always $< 24\text{ KiB}$ even with 1,216-byte X-Wing keys); higher internal nodes store their own `KeyTreeNodePublic` plus `leftRef`/`rightRef` with explicit `CasNode.links`.
- **Structural sharing & P2P pull:** Updating a member's direct path from leaf $\ell$ to root writes only $\lceil \log_2 N \rceil$ small CAS nodes. Unchanged subtrees keep identical `cas:sha256-...` hashes, `missingCasDependencies()` reports missing `treeRef`/subtree hashes to `sync-v3` (`cas-want` `{ subgraph: true }`) and HTTP `casMirrors`, and `collectControlReferencedCasHashes()` keeps active tree DAGs pinned across GC.

### 3.2 Member Removal (Forward Secrecy & PCS) in $O(\log N)$

When an admin removes member at leaf $\ell$:
1. Blank leaf $\ell$ and every node along its direct path to the root.
2. Pick a fresh random `pathSeed` for the updater's own leaf.
3. Walk up the direct path, deriving each parent's `(seed, pubKey)` via `HKDF(childSeed, "chronolog/tree-parent/v1")` and HPKE-sealing each new parent seed **strictly to the copath resolution** (at most $\log_2 N$ sibling subtrees, plus 1 self-box for the updater's leaf).
4. Derive `epochKey = HKDF(rootSeed, "chronolog/tree-epoch-key/v1:" + scope + ":" + epoch)` and `mailboxVerifyKey = deriveEpochMailboxKeyPair(epochKey).publicKey`.
5. Publish the $O(\log N)$ new CAS nodes + one compact `$keys` `rotateTreeEpoch` op!

Every remaining member holds the private seed for at least one node in the copath resolution, decrypts the single box for their ancestor, verifies each derived intermediate `pubKeyHash` against the tree up to `rootSeed`, and obtains `epochKey` in $O(\log N)$ symmetric operations.

### 3.3 Chronolog-Style Undo-Do-Redo for TreeKEM: Key-Tagged TreeKEM (No Delivery Service, No Fork State Machine)

Standard MLS breaks under undo-do-redo because:
1. `epochKey(n)` is cryptographically chained from `epochKey(n-1)`'s linear transcript hash, and
2. Each commit's copath boxes assume exact tree-version parity, so if a concurrent Commit B ($t = 90$) arrives after Commit A ($t = 100$), other replicas cannot "re-encrypt" A's path secret $S_A$ to B's new public keys without knowing $S_A$.

**Key-Tagged TreeKEM** eliminates that conflict completely and makes sub-linear group rotation converge cleanly under pure Chronolog undo-do-redo:

1. **Decouple epoch roots (no linear transcript chain):**
   Each epoch derives `epochKey` from a fresh random `rootSeed` (not chained from the previous epoch's secret). A late-arriving epoch commit never invalidates decryption of another epoch, and new devices can cleanly receive only `[minEpoch..current]`.
2. **LWW-per-node public ratchet tree over CAS:**
   Each leaf `(memberPk, wrapKey / pqWrapKey)` and each internal node `(nodePubKey, updatedAtMs, opId)` merges via Last-Write-Wins under Chronolog's exact `(authorTimestampMs, author, opId)` total order. Every replica and blind host converges bit-for-bit on the same public ratchet tree via standard undo-do-redo replay.
3. **Tag every HPKE copath box by `targetPubKeyHash` (not fragile tree slot version):**
   Each copath lockbox is indexed by `H(targetNodePubKey)` rather than assuming a single linear tree version. Devices retain a small rolling window of their recent node private keys (pruned once the epoch is retired). When Commit B arrives out-of-order and updates overlapping nodes, every remaining member who held `targetNodePubKey` **still decrypts Commit A's box in $O(1)$** during undo-do-redo!
4. **Deterministic `needsRotation` healing + reconnect rewrapping:**
   If Commit B removed Carol while Alice (offline) encrypted Commit A against a tree that still included Carol (which no crypto can retroactively undo once sent), undo-do-redo replay deterministically flags `needsRotation: true` in `$keys` because the latest epoch's tree still contains a leaf for a member removed in `$admission`. The first online admin emits **one $O(\log N)$ healing commit** excluding both Carol and Dave, and offline peers automatically rewrap any pending ops under the healed epoch (preserving `opId`, `authorTimestampMs`, and signature).

> **Why this beats both vanilla MLS and DCGKA for Chronolog:**
> - Unlike vanilla MLS, it requires **no central Delivery Service** and never forks into an unrecoverable group state.
> - Unlike DCGKA, it requires **no complex pairwise causal ratchet state machine** and scales at $O(\log N)$ per removal with hybrid PQ `X-Wing` (`xwingPublicKeyFromSeed` deterministically derives internal node keys from 32-byte seeds).
> - Optional Phase 2: for ultra-high-churn groups, concurrent disjoint commits can additionally combine their root seeds deterministically in canonical `(authorTimestampMs, author, opId)` order.

### 3.4 Member Addition & Historical Backfill

- **Forward-only addition ($O(\log N)$):** Place the new member into the leftmost blank leaf (or append a new leaf), and seal the current `epochKey` (or current copath seeds) in a single box to the new member.
- **Full-history backfill:** When granting a new device access to past epochs $[0 \dots e]$, instead of sealing $e$ separate boxes, wrap a single compact **History Key Bundle** (encrypted under a fresh 32-byte key, or chained backwards via a hash ratchet if forward secrecy across old epochs is not required) in **one** HPKE box per new member!

---

## 4. Implementation Summary

All components are live in `@chronolog/crypto`, `@chronolog/materializer`, and `@chronolog/peer-session`:

1. **Structural-sharing CAS Merkle-DAG (`@chronolog/crypto`):** `buildTreeEpochUpdate()`, `openTreeEpoch()`, `writeKeyTreeToCas()`, and `readKeyTreeFromCas()` support both `hpke-tree-x25519-aes256gcm` and hybrid PQ `hpke-tree-xwing-aes256gcm` (including mixed PQ + X25519 member rosters) with explicit `CasNode.links` and updater self-recovery boxes.
2. **On-log `$keys` support (`chronolog/keys`):** `policy.distribution: 'flat' | 'tree'`, `rotateTreeEpoch`, `needsRotation` (checking `activeMembers ∪ boxes`), and `query({ member })`.
3. **Unified session API (`@chronolog/peer-session`):** `session.rotateTreeEpoch()`, `session.rotateEpoch()` / `session.removeMember()` / `session.admitMember()` respecting `policy.distribution`, `session.keysNeedsRotation()` (covering both stale members and `policy.maxOpsPerEpoch`), automatic `missingCasDependencies()` + P2P/mirror pull of `treeRef` DAGs, and blind-host `mailboxVerifyKeys` + GC parity.
