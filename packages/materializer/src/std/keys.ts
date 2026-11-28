/**
 * Standard `chronolog/keys` reducer for the `$keys` control topic (export `hpkeEpochs`).
 *
 * - Flat epochs (`rotateEpoch`, `rotateRingEpoch`) carry one HPKE lockbox per recipient; every
 *   recipient must be a current `$admission` reader holding a wrap key of the box suite.
 * - Tree epochs (`rotateTreeEpoch`) reference a public-CAS Key-Tagged TreeKEM DAG
 *   (`chronolog-keytree-dag/v1`, canonical JSON). The reducer reads the DAG root and its leaf
 *   directory (`chronolog-keytree-leaves/v1`) through `chronolog:cas` and derives `activeMembers`
 *   and `leafCount` itself; caller-supplied claims are ignored. Every leaf member must be a reader.
 * - Lockboxes are write-once. `grantBoxes` / `grantRingBoxes` may be written by an administrator,
 *   by the member itself, or by the reader recorded as the member's `admittedBy` in `$admission`;
 *   only an administrator may `replace` an existing box.
 * - `policy.rotateOnRemove` is enforced by `chronolog/admission` (a removal must be preceded in the
 *   same operation by a rotation excluding the removed member). `policy.maxOpsPerEpoch` is stored
 *   and reported here but must be enforced by the kernel, which alone sees encrypted envelopes.
 */
export const STD_KEYS_SOURCE = `
import { get as casGet } from 'chronolog:cas';
import {
  HEX32,
  CAS_REF,
  SUITE_X25519,
  TREE_SUITE_X25519,
  isTreeSuite,
  normalizeSuite,
  suiteAtLeast,
  validateBox,
  validateBoxesMap,
  recipientHoldsSuiteKey,
  parseHexJson,
} from 'chronolog/keybox';

const RING_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const DEFAULT_POLICY = { rotateOnRemove: true, minSuite: SUITE_X25519, paddingBucketBytes: 0, hideEnvelopeAuthor: false };
const MAX_LEAF_COUNT = 1048576;

function isAdmin(ctx, author) { return ctx.can('administrator', author); }
function isReader(ctx, author) { return ctx.can('reader', author); }
function isGuardian(ctx, author) { return ctx.can('guardian', author); }

function normalizePolicy(raw) {
  const p = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const minSuite = normalizeSuite(p.minSuite, SUITE_X25519);
  if (!minSuite || isTreeSuite(minSuite)) return null;
  const paddingBucketBytes = p.paddingBucketBytes === undefined ? 0 : Number(p.paddingBucketBytes);
  if (!Number.isSafeInteger(paddingBucketBytes) || paddingBucketBytes < 0 || paddingBucketBytes > 65536) return null;
  const maxOpsPerEpoch = p.maxOpsPerEpoch === undefined || p.maxOpsPerEpoch === null ? null : Number(p.maxOpsPerEpoch);
  if (maxOpsPerEpoch !== null && (!Number.isSafeInteger(maxOpsPerEpoch) || maxOpsPerEpoch < 1)) return null;
  const distribution = p.distribution === undefined || p.distribution === 'flat' ? 'flat' : (p.distribution === 'tree' ? 'tree' : null);
  if (!distribution) return null;
  return {
    rotateOnRemove: p.rotateOnRemove !== false,
    ...(maxOpsPerEpoch !== null ? { maxOpsPerEpoch } : {}),
    minSuite,
    paddingBucketBytes,
    hideEnvelopeAuthor: p.hideEnvelopeAuthor === true,
    ...(distribution !== 'flat' ? { distribution } : {}),
  };
}

/** One roster read per operation: reader eligibility + member records (wrap keys, admittedBy). */
function rosterOf(ctx) {
  const r = ctx.query('$admission', { kind: 'roster' });
  const readers = r && Array.isArray(r.readers) ? r.readers : [];
  const open = readers.includes('*');
  const readerSet = new Set(readers);
  const members = new Map();
  for (const m of (r && Array.isArray(r.members) ? r.members : [])) {
    if (m && typeof m.publicKey === 'string') members.set(m.publicKey, m);
  }
  return {
    isReader(pk) { return open || readerSet.has(pk); },
    member(pk) { return members.get(pk) || null; },
    /** validateBoxesMap recipient callback: readers only. */
    recipient(pk) { return open || readerSet.has(pk) ? (members.get(pk) || true) : null; },
  };
}

function epochHeader(input, policy, defaultSuite) {
  if (!HEX32.test(input.keyCommitment || '')) return { ok: false, code: 'key_commitment_invalid' };
  if (input.mailboxVerifyKey !== undefined && !HEX32.test(input.mailboxVerifyKey || '')) return { ok: false, code: 'mailbox_key_invalid' };
  const suite = normalizeSuite(input.suite, defaultSuite);
  if (!suite) return { ok: false, code: 'suite_invalid' };
  if (!suiteAtLeast(suite, policy.minSuite)) return { ok: false, code: 'suite_below_minimum' };
  return { ok: true, suite };
}

function readCasJson(ref) {
  // casGet trips an uncatchable host-level MissingDependency interrupt when the node has not synced yet.
  const raw = casGet(ref);
  let node;
  try { node = JSON.parse(raw); } catch { return null; }
  return node && typeof node === 'object' ? parseHexJson(node.bytesHex) : null;
}

/**
 * Read a Key-Tagged TreeKEM DAG root + leaf directory from public CAS and derive its member set.
 * The full tree (internal nodes, copath boxes) is validated by readers in @chronolog/crypto.
 */
function readTreeMembers(treeRef, epoch, suite) {
  const root = readCasJson(treeRef);
  if (!root || typeof root !== 'object' || Array.isArray(root) || root.format !== 'chronolog-keytree-dag/v1') return { ok: false, code: 'tree_invalid' };
  if (root.epoch !== epoch || root.suite !== suite) return { ok: false, code: 'tree_header_mismatch' };
  const leafCount = root.leafCount;
  if (!Number.isSafeInteger(leafCount) || leafCount < 2 || leafCount > MAX_LEAF_COUNT || (leafCount & (leafCount - 1)) !== 0) {
    return { ok: false, code: 'tree_invalid' };
  }
  if (typeof root.treeRootRef !== 'string' || !CAS_REF.test(root.treeRootRef) || !Array.isArray(root.leafChunkRefs) || !Array.isArray(root.copathBoxes)) {
    return { ok: false, code: 'tree_invalid' };
  }
  const slots = new Set();
  const members = [];
  const seen = new Set();
  for (const ref of root.leafChunkRefs) {
    if (typeof ref !== 'string' || !CAS_REF.test(ref)) return { ok: false, code: 'tree_invalid' };
    const chunk = readCasJson(ref);
    if (!chunk || chunk.format !== 'chronolog-keytree-leaves/v1' || !Array.isArray(chunk.leaves)) return { ok: false, code: 'tree_invalid' };
    for (const entry of chunk.leaves) {
      if (!Array.isArray(entry) || entry.length !== 3) return { ok: false, code: 'tree_invalid' };
      const [slot, member, hash] = entry;
      if (!Number.isSafeInteger(slot) || slot < 0 || slot >= leafCount || slots.has(slot)) return { ok: false, code: 'tree_invalid' };
      if (typeof member !== 'string' || !HEX32.test(member) || seen.has(member) || typeof hash !== 'string' || !HEX32.test(hash)) {
        return { ok: false, code: 'tree_invalid' };
      }
      slots.add(slot);
      seen.add(member);
      members.push(member);
    }
  }
  if (members.length === 0) return { ok: false, code: 'tree_empty' };
  members.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { ok: true, leafCount, members };
}

/** Who may write grant boxes for \`member\`: an admin, the member itself, or the reader that admitted it. */
function canGrantFor(ctx, roster, author, member) {
  if (isAdmin(ctx, author)) return true;
  if (!isReader(ctx, author)) return false;
  if (author === member) return true;
  const rec = roster.member(member);
  return Boolean(rec && rec.admittedBy === author);
}

function applyGrant(epochs, input, ctx, roster, policy, tx) {
  if (!HEX32.test(input.member || '') || !input.epochBoxes || typeof input.epochBoxes !== 'object' || Array.isArray(input.epochBoxes)) {
    return { ok: false, code: 'grant_boxes_invalid' };
  }
  if (!roster.isReader(input.member)) return { ok: false, code: 'member_not_authorized' };
  if (!canGrantFor(ctx, roster, tx.author, input.member)) return { ok: false, code: 'grant_not_authorized' };
  const allowReplace = input.replace === true && isAdmin(ctx, tx.author);
  const rec = roster.member(input.member);
  const next = { ...epochs };
  for (const [epKey, rawBox] of Object.entries(input.epochBoxes)) {
    const existing = next[epKey];
    if (!existing) return { ok: false, code: 'epoch_missing' };
    if (isTreeSuite(existing.suite)) return { ok: false, code: 'tree_epoch_grant_invalid' };
    if (existing.boxes && Object.prototype.hasOwnProperty.call(existing.boxes, input.member) && !allowReplace) {
      return { ok: false, code: 'box_already_exists' };
    }
    const res = validateBox(rawBox, policy.minSuite);
    if (!res.ok) return res;
    if (!recipientHoldsSuiteKey(rec, res.suite)) return { ok: false, code: 'box_recipient_key_missing', detail: input.member };
    next[epKey] = { ...existing, boxes: { ...existing.boxes, [input.member]: res.box } };
  }
  return { ok: true, epochs: next };
}

function holdersOf(entry) {
  const out = new Set();
  if (!entry) return out;
  if (Array.isArray(entry.activeMembers)) for (const pk of entry.activeMembers) out.add(pk);
  for (const pk of Object.keys(entry.boxes || {})) out.add(pk);
  return out;
}

export const hpkeEpochs = {
  reduce(state, tx, ctx) {
    const cur = state && typeof state === 'object' ? state : { currentEpoch: -1, epochs: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const policy = normalizePolicy(cur.policy) || DEFAULT_POLICY;

    if (input.action === 'setPolicy') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      const nextPolicy = normalizePolicy({ ...policy, ...(input.policy || input) });
      if (!nextPolicy) return { ok: false, code: 'invalid_keys_policy' };
      return {
        ok: true,
        state: { ...cur, policy: nextPolicy },
        events: [{ topic: '$keys.policy_updated', payload: nextPolicy }],
      };
    }

    if (input.action === 'setRecoveryVault') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      const vault = input.vault;
      if (!vault || typeof vault.nonce !== 'string' || typeof vault.ciphertext !== 'string') {
        return { ok: false, code: 'recovery_vault_invalid' };
      }
      if (!input.guardianShares || typeof input.guardianShares !== 'object') {
        return { ok: false, code: 'guardian_shares_invalid' };
      }
      const guardianShares = {};
      for (const [pk, item] of Object.entries(input.guardianShares)) {
        if (!HEX32.test(pk) || !item || !Number.isSafeInteger(item.index) || item.index < 1 || item.index > 255) {
          return { ok: false, code: 'guardian_share_invalid' };
        }
        const res = validateBox(item.box, SUITE_X25519);
        if (!res.ok) return { ok: false, code: 'guardian_share_invalid' };
        guardianShares[pk] = { index: item.index, box: res.box };
      }
      return {
        ok: true,
        state: {
          ...cur,
          recovery: {
            vault: { nonce: vault.nonce, ciphertext: vault.ciphertext },
            guardianShares,
          },
        },
        events: [{ topic: '$keys.recovery_vault_updated', payload: { guardians: Object.keys(guardianShares).length } }],
      };
    }

    if (input.action === 'submitRecoveryShare') {
      if (!isGuardian(ctx, tx.author)) return { ok: false, code: 'guardian_required' };
      const res = validateBox(input.box, SUITE_X25519);
      if (!HEX32.test(input.member || '') || !Number.isSafeInteger(input.index) || input.index < 1 || input.index > 255 || !res.ok) {
        return { ok: false, code: 'recovery_share_invalid' };
      }
      const recoveryGrants = { ...(cur.recoveryGrants || {}) };
      const forMember = { ...(recoveryGrants[input.member] || {}) };
      forMember[tx.author] = { index: input.index, box: res.box };
      recoveryGrants[input.member] = forMember;
      return {
        ok: true,
        state: { ...cur, recoveryGrants },
        events: [{ topic: '$keys.recovery_share_submitted', payload: { member: input.member, guardian: tx.author } }],
      };
    }

    if (input.action === 'rotateRingEpoch') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      const ringName = typeof input.ring === 'string' && RING_RE.test(input.ring) ? input.ring : null;
      if (!ringName || ringName === 'default') return { ok: false, code: 'ring_name_invalid' };
      const rings = { ...(cur.rings || {}) };
      const prevRing = rings[ringName] || { currentEpoch: -1, epochs: {} };
      const epoch = input.epoch;
      if (!Number.isSafeInteger(epoch) || epoch !== prevRing.currentEpoch + 1) return { ok: false, code: 'epoch_sequence_invalid' };
      const header = epochHeader(input, policy, SUITE_X25519);
      if (!header.ok) return header;
      if (isTreeSuite(header.suite)) return { ok: false, code: 'suite_invalid' };
      const boxesRes = validateBoxesMap(input.boxes, { minSuite: policy.minSuite, recipient: rosterOf(ctx).recipient });
      if (!boxesRes.ok) return boxesRes;
      const entry = {
        epoch,
        ...(header.suite !== SUITE_X25519 ? { suite: header.suite } : {}),
        keyCommitment: input.keyCommitment,
        ...(input.mailboxVerifyKey ? { mailboxVerifyKey: input.mailboxVerifyKey } : {}),
        boxes: boxesRes.boxes,
      };
      rings[ringName] = {
        currentEpoch: epoch,
        epochs: { ...prevRing.epochs, [String(epoch)]: entry },
      };
      const topicRings = { ...(cur.topicRings || {}) };
      if (Array.isArray(input.topics)) {
        for (const t of input.topics) {
          if (typeof t === 'string' && t.length > 0 && !t.startsWith('$')) topicRings[t] = ringName;
        }
      }
      return {
        ok: true,
        state: { ...cur, rings, topicRings },
        events: [{ topic: '$keys.ring_rotated', payload: { ring: ringName, epoch, suite: header.suite } }],
      };
    }

    if (input.action === 'grantRingBoxes') {
      const ringName = typeof input.ring === 'string' && RING_RE.test(input.ring) ? input.ring : null;
      const rings = { ...(cur.rings || {}) };
      if (!ringName || !rings[ringName]) return { ok: false, code: 'ring_not_found' };
      const granted = applyGrant(rings[ringName].epochs, input, ctx, rosterOf(ctx), policy, tx);
      if (!granted.ok) return granted;
      rings[ringName] = { ...rings[ringName], epochs: granted.epochs };
      return {
        ok: true,
        state: { ...cur, rings },
        events: [{ topic: '$keys.ring_granted', payload: { ring: ringName, member: input.member } }],
      };
    }

    if (input.action === 'rotateTreeEpoch') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      const epoch = input.epoch;
      if (!Number.isSafeInteger(epoch) || epoch !== cur.currentEpoch + 1) return { ok: false, code: 'epoch_sequence_invalid' };
      const header = epochHeader(input, policy, TREE_SUITE_X25519);
      if (!header.ok) return header;
      if (!isTreeSuite(header.suite)) return { ok: false, code: 'suite_invalid' };
      if (typeof input.treeRef !== 'string' || !CAS_REF.test(input.treeRef)) return { ok: false, code: 'tree_ref_invalid' };
      const tree = readTreeMembers(input.treeRef, epoch, header.suite);
      if (!tree.ok) return tree;
      const roster = rosterOf(ctx);
      for (const pk of tree.members) {
        if (!roster.isReader(pk)) return { ok: false, code: 'tree_member_not_eligible', detail: pk };
      }
      const entry = {
        epoch,
        suite: header.suite,
        keyCommitment: input.keyCommitment,
        ...(input.mailboxVerifyKey ? { mailboxVerifyKey: input.mailboxVerifyKey } : {}),
        treeRef: input.treeRef,
        leafCount: tree.leafCount,
        activeMembers: tree.members,
        boxes: {},
      };
      return {
        ok: true,
        state: { ...cur, currentEpoch: epoch, epochs: { ...cur.epochs, [String(epoch)]: entry } },
        events: [{ topic: '$keys.tree_rotated', payload: { epoch, suite: header.suite, leafCount: tree.leafCount } }],
      };
    }

    if (input.action === 'rotateEpoch') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      const epoch = input.epoch;
      if (!Number.isSafeInteger(epoch) || epoch !== cur.currentEpoch + 1) return { ok: false, code: 'epoch_sequence_invalid' };
      const header = epochHeader(input, policy, SUITE_X25519);
      if (!header.ok) return header;
      if (isTreeSuite(header.suite)) return { ok: false, code: 'suite_invalid' };
      const boxesRes = validateBoxesMap(input.boxes, { minSuite: policy.minSuite, recipient: rosterOf(ctx).recipient });
      if (!boxesRes.ok) return boxesRes;
      const entry = {
        epoch,
        ...(header.suite !== SUITE_X25519 ? { suite: header.suite } : {}),
        keyCommitment: input.keyCommitment,
        ...(input.mailboxVerifyKey ? { mailboxVerifyKey: input.mailboxVerifyKey } : {}),
        boxes: boxesRes.boxes,
      };
      return {
        ok: true,
        state: { ...cur, currentEpoch: epoch, epochs: { ...cur.epochs, [String(epoch)]: entry } },
        events: [{ topic: '$keys.rotated', payload: { epoch, suite: header.suite } }],
      };
    }

    // Grant a newly admitted device lockboxes for one or more retained historical flat epochs.
    if (input.action === 'grantBoxes') {
      const granted = applyGrant(cur.epochs || {}, input, ctx, rosterOf(ctx), policy, tx);
      if (!granted.ok) return granted;
      return {
        ok: true,
        state: { ...cur, epochs: granted.epochs },
        events: [{ topic: '$keys.granted', payload: { member: input.member } }],
      };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input, ctx) {
    const cur = state || { currentEpoch: -1, epochs: {} };
    if (input && typeof input === 'object') {
      if (input.kind === 'policy') {
        return normalizePolicy(cur.policy) || DEFAULT_POLICY;
      }
      if (input.kind === 'needsRotation') {
        // Members still holding the latest default or ring epoch but no longer readers in $admission.
        const stale = new Set();
        const staleRings = [];
        const latest = cur.currentEpoch >= 0 && cur.epochs ? cur.epochs[String(cur.currentEpoch)] : null;
        for (const pk of holdersOf(latest)) if (!isReader(ctx, pk)) stale.add(pk);
        for (const [ringName, ring] of Object.entries(cur.rings || {})) {
          const entry = ring && ring.currentEpoch >= 0 && ring.epochs ? ring.epochs[String(ring.currentEpoch)] : null;
          let ringStale = false;
          for (const pk of holdersOf(entry)) {
            if (!isReader(ctx, pk)) { stale.add(pk); ringStale = true; }
          }
          if (ringStale) staleRings.push(ringName);
        }
        const staleMembers = Array.from(stale).sort();
        return { needsRotation: staleMembers.length > 0, staleMembers, staleRings: staleRings.sort() };
      }
      if (input.kind === 'mailboxKeys') {
        const out = { default: {} };
        for (const [ep, entry] of Object.entries(cur.epochs || {})) {
          if (entry && typeof entry.mailboxVerifyKey === 'string') out.default[ep] = entry.mailboxVerifyKey;
        }
        for (const [ringName, ring] of Object.entries(cur.rings || {})) {
          const map = {};
          for (const [ep, entry] of Object.entries((ring && ring.epochs) || {})) {
            if (entry && typeof entry.mailboxVerifyKey === 'string') map[ep] = entry.mailboxVerifyKey;
          }
          out[ringName] = map;
        }
        return out;
      }
      if (typeof input.recoveryFor === 'string') {
        const vault = cur.recovery ? cur.recovery.vault : null;
        const shares = cur.recoveryGrants && cur.recoveryGrants[input.recoveryFor] ? cur.recoveryGrants[input.recoveryFor] : {};
        return { vault, shares };
      }
      if (typeof input.guardianShareFor === 'string') {
        return cur.recovery && cur.recovery.guardianShares ? (cur.recovery.guardianShares[input.guardianShareFor] || null) : null;
      }
      if (typeof input.topicRing === 'string') {
        return cur.topicRings && cur.topicRings[input.topicRing] ? cur.topicRings[input.topicRing] : 'default';
      }
      if (typeof input.ring === 'string' && input.ring !== 'default') {
        const ring = cur.rings && cur.rings[input.ring] ? cur.rings[input.ring] : { currentEpoch: -1, epochs: {} };
        if (input.member) {
          const out = {};
          for (const [ep, entry] of Object.entries(ring.epochs || {})) {
            if (entry.boxes && entry.boxes[input.member]) {
              out[ep] = { epoch: entry.epoch, suite: entry.suite || SUITE_X25519, keyCommitment: entry.keyCommitment, box: entry.boxes[input.member] };
            }
          }
          return { ring: input.ring, currentEpoch: ring.currentEpoch, memberEpochs: out };
        }
        return ring;
      }
      if (input.member) {
        const out = {};
        for (const [ep, entry] of Object.entries(cur.epochs || {})) {
          const hasBox = Boolean(entry.boxes && entry.boxes[input.member]);
          const inTree = Array.isArray(entry.activeMembers) && entry.activeMembers.includes(input.member);
          if (hasBox || inTree) {
            out[ep] = {
              epoch: entry.epoch,
              suite: entry.suite || SUITE_X25519,
              keyCommitment: entry.keyCommitment,
              ...(hasBox ? { box: entry.boxes[input.member] } : {}),
              ...(entry.treeRef ? { treeRef: entry.treeRef } : {}),
            };
          }
        }
        return { currentEpoch: cur.currentEpoch, memberEpochs: out };
      }
    }
    return cur;
  },
};
`.trimStart()
