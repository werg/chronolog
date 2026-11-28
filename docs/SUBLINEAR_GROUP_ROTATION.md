# Design Brief: CRDT-Native Sub-Linear Group Key Rotation (`$keys` v2.1)

> **Status:** Planned next cryptography milestone (schema hooks already prepared in Chronolog v2.0 `$keys`).
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

## 3. Proposed Architecture: Epoch-Tree HPKE + Causal-TreeKEM over CAS (`hpke-tree-v1`)

We already prepared `$keys` in v2.0 so `EncryptedOperationEnvelope` and `TopicKernel` are completely decoupled from how epoch keys are distributed:

- Envelopes only reference `(ring, epoch)` and authenticate against `mailboxVerifyKey`.
- `$keys` is a normal reducer topic (`chronolog/keys`) whose state is plain JSON referencing content-addressed CAS nodes.

### 3.1 Core Data Structure: Content-Addressed Binary Ratchet Tree (`chronolog-keytree/v1`)

Instead of storing an inline `boxes: { [pk]: Box }` map of size $O(N)$ in `$keys`, a `hpke-tree-v1` epoch stores:

```json
{
  "epoch": 42,
  "suite": "hpke-tree-xwing-aes256gcm",
  "keyCommitment": "<sha256>",
  "mailboxVerifyKey": "<ed25519-pub>",
  "treeRoot": "cas:sha256-...",
  "leafCount": 4096
}
```

The tree itself is stored as a **Merkle-DAG of public CAS nodes** (4-ary or binary tree, immutable nodes, automatic structural sharing across epochs!):

- **Leaves** hold each active member's `(publicKey, wrapKey / pqWrapKey)` and leaf index.
- **Internal nodes** hold a deterministic node public key derived from a seed `nodeSeed` (using `xwingPublicKeyFromSeed` or X25519 scalar clamping), plus an optional `parentHash` commitment.
- **Structural sharing:** Updating a member's direct path from leaf $\ell$ to root only allocates $\lceil \log_2 N \rceil$ new CAS nodes (~12 nodes for 4,096 members = ~16 KiB even with X-Wing!). Unchanged subtrees keep their exact CAS hashes, so peers and blind hosts sync only the $O(\log N)$ delta nodes.

### 3.2 Member Removal (Forward Secrecy & PCS) in $O(\log N)$

When an admin removes member at leaf $\ell$:
1. Blank leaf $\ell$ and every node along its direct path to the root.
2. Pick a fresh random `pathSeed` for the admin's own leaf (or a fresh root secret for `epoch + 1`).
3. Walk up the direct path, deriving each parent's `(seed, pubKey)` via `HKDF(childSeed, "chronolog/tree-parent/v1")` and HPKE-sealing each new parent seed **strictly to the copath resolution** (at most $\log_2 N$ sibling subtrees!).
4. Derive `epochKey = HKDF(rootSeed, "chronolog/epoch-key/v3:" + logId + ":" + epoch)` and `mailboxVerifyKey = deriveEpochMailboxKeyPair(epochKey).publicKey`.
5. Publish the $O(\log N)$ new CAS nodes + one compact `$keys` `rotateTreeEpoch` op!

Every remaining member holds the private seed for at least one node in the copath resolution, decrypts the single box for their ancestor, hashes up to `rootSeed`, and obtains `epochKey` in $O(\log N)$ symmetric operations.

### 3.3 Handling Concurrent Leaderless Operations (The CRDT Insight)

How do we avoid MLS's "reject concurrent commit" problem when Admin A removes Carol while offline and Admin B concurrently removes Dave?

1. **Deterministic Winner + Automatic Healing (Phase 1 — Simple, Zero Key-Split):**
   - `$keys` maintains strict monotonic `epoch === currentEpoch + 1` (same invariant as `hpkeEpochs`).
   - If Admin A's removal sorts first at `(tsA, A, opA)`, it advances `currentEpoch` to `e + 1` excluding Carol.
   - Admin B's concurrent removal op at `(tsB, B, opB)` had `epoch: e + 1` — its `$admission` `removeMember(Dave)` update **still succeeds** (if split into a separate op or via `onConflict`), while the stale `$keys` rotation is rejected with `epoch_sequence_invalid`.
   - Any online admin sees `removedMembers` contains Dave after `epoch = e + 1` (via a deterministic `$keys` health query: `{ kind: 'staleMembers' }`) and automatically emits a single `O(log N)` healing rotation for `e + 2` excluding both Carol and Dave!
   - Meanwhile, `$admission.authorize()` already blocks Dave from writing immediately upon `removeMember(Dave)` materializing.

2. **Causal Multi-Epoch Merge / DCGKA (Phase 2 — Optional True Concurrent Rotations):**
   - Follow Kleppmann et al. (DCGKA / Causal-TreeKEM): allow concurrent updates to publish independent update-secret nodes keyed by `(opId)` into a DAG of tree deltas, and derive the combined epoch secret by HKDF-combining the causally maximal concurrent update secrets in canonical `(authorTimestampMs, author, opId)` order.
   - Because Chronolog already has a canonical total order over all ops, every replica computes the exact same merged tree without a central Delivery Service.

### 3.4 Member Addition & Historical Backfill

- **Forward-only addition ($O(\log N)$):** Place the new member into the leftmost blank leaf (or append a new leaf), and seal the current `epochKey` (or current copath seeds) in a single box to the new member.
- **Full-history backfill:** When granting a new device access to past epochs $[0 \dots e]$, instead of sealing $e$ separate boxes, wrap a single compact **History Key Bundle** (encrypted under a fresh 32-byte key, or chained backwards via a hash ratchet if forward secrecy across old epochs is not required) in **one** HPKE box per new member!

---

## 4. Compatibility & Preparation Already Landed in v2.0

The v2.0 crypto pass intentionally prepared all four clean seams needed for `hpke-tree-v1`:

1. **Suite agility in `$keys`:** `policy.minSuite` and per-epoch `suite` already gate acceptable key-distribution suites (`SUITE_RANK` in `chronolog/keys`), so adding `'hpke-tree-x25519-aes256gcm'` and `'hpke-tree-xwing-aes256gcm'` is an additive reducer upgrade.
2. **Envelope decoupling:** `EncryptedOperationEnvelope` uses `(epoch, ring, suite: 'hkdf-aes-256-gcm', mailboxTag)` and never cares whether `epochKey` arrived via a flat HPKE box or a Merkle ratchet tree.
3. **Blind-host parity:** Blind hosts only read `$keys` `{ kind: 'mailboxKeys' }` (for `mailboxVerifyKey` verification) and `collectControlReferencedCasHashes()` (which already walks `cas:sha256-...` refs in `$keys` and transitive `CasNode.links` for exact GC!).
4. **Deterministic PQ KEM seeds:** `generateXWingKeyPair(seed)` and `xwingPublicKeyFromSeed(seed)` in `@chronolog/crypto` already derive full 1,216-byte X-Wing public keys deterministically from a 32-byte seed — the exact primitive required for internal ratchet-tree nodes!

---

## 5. Rollout Plan (Next Milestone)

1. Add `chronolog-keytree/v1` CBOR CAS node codec + tree path derivation/resolution in `@chronolog/crypto` and `@chronolog/records`.
2. Add `hpkeTreeEpochs` (or extend `hpkeEpochs` with `rotateTreeEpoch` + `grantHistoryBundle`) in `chronolog/keys`.
3. Auto-switch or opt-in via `$keys.policy.distribution: 'flat' | 'tree'` (default `'flat'` below 64 members, `'tree'` for larger groups).
4. Add property-based fuzz tests verifying convergence under arbitrary concurrent offline joins, removals, and network partitions.
