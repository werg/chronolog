/**
 * Standard `chronolog/vaults` reducer for Private Capability Vaults:
 * Lives in the encrypted application partition so blind hosts NEVER learn vault names,
 * project/team topology, or fine-grained ACLs.
 *
 * Each vault maintains its own symmetric capability key with forward-secret epochs
 * (`0, 1, 2...`), HPKE lockboxes (X25519 or hybrid PQ X-Wing, validated by `chronolog/keybox`),
 * write-once backfill (vault admins or the member itself), and O(1) member grants + per-vault
 * rotation on removal whose lockboxes may only address remaining members.
 */
export const STD_VAULTS_SOURCE = `
import { HEX32, SUITE_X25519, FLAT_SUITES, validateBox, validateBoxesMap, recipientHoldsSuiteKey } from 'chronolog/keybox';

const VAULT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}$/;

function getMinSuite(ctx) {
  try {
    const p = ctx.query('$keys', { kind: 'policy' });
    if (p && typeof p === 'object' && FLAT_SUITES.includes(p.minSuite)) return p.minSuite;
  } catch { /* fallback */ }
  return SUITE_X25519;
}

function sortedKeys(list) {
  return Array.from(new Set(list.filter(k => typeof k === 'string' && HEX32.test(k)))).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Log member records (wrap keys) for box recipient checks; one roster read per operation. */
function logMembers(ctx) {
  const r = ctx.query('$admission', { kind: 'roster' });
  const map = new Map();
  for (const m of (r && Array.isArray(r.members) ? r.members : [])) {
    if (m && typeof m.publicKey === 'string') map.set(m.publicKey, m);
  }
  return map;
}

/** Box recipients must be (next) vault members; known log members must hold a key of the box suite. */
function vaultRecipient(memberSet, records) {
  return pk => (memberSet.has(pk) ? (records.get(pk) || true) : null);
}

export const privateVaults = {
  reduce(state, tx, ctx) {
    if (!ctx.can('writer')) return { ok: false, code: 'writer_required' };
    const cur = state && typeof state === 'object' && state.vaults && typeof state.vaults === 'object'
      ? { vaults: { ...state.vaults } }
      : { vaults: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const minSuite = getMinSuite(ctx);

    const vaultId = typeof input.vaultId === 'string' && VAULT_ID_RE.test(input.vaultId) ? input.vaultId : null;
    if (!vaultId) return { ok: false, code: 'vault_id_invalid' };

    if (input.action === 'createVault') {
      if (cur.vaults[vaultId]) return { ok: false, code: 'vault_exists' };
      if (!HEX32.test(input.keyCommitment || '')) return { ok: false, code: 'key_commitment_invalid' };
      const admins = sortedKeys([tx.author, ...(Array.isArray(input.admins) ? input.admins : [])]);
      const members = sortedKeys([...admins, ...(Array.isArray(input.members) ? input.members : [])]);
      const boxesRes = validateBoxesMap(input.boxes, { minSuite, recipient: vaultRecipient(new Set(members), logMembers(ctx)) });
      if (!boxesRes.ok) return boxesRes;
      const boxes = boxesRes.boxes;
      cur.vaults[vaultId] = {
        vaultId,
        admins,
        members,
        currentEpoch: 0,
        epochs: {
          '0': {
            epoch: 0,
            keyCommitment: input.keyCommitment,
            boxes,
          },
        },
      };
      return {
        ok: true,
        state: cur,
        events: [{ topic: 'vaults.created', payload: { vaultId, members: members.length } }],
      };
    }

    const vault = cur.vaults[vaultId];
    if (!vault) return { ok: false, code: 'vault_not_found' };
    const isVaultAdmin = Array.isArray(vault.admins) && vault.admins.includes(tx.author);
    const isVaultMember = Array.isArray(vault.members) && vault.members.includes(tx.author);

    if (input.action === 'addMember') {
      if (!isVaultAdmin) return { ok: false, code: 'vault_admin_required' };
      if (!HEX32.test(input.member || '')) return { ok: false, code: 'invalid_member' };
      const nextMembers = sortedKeys([...vault.members, input.member]);
      const nextAdmins = input.admin === true ? sortedKeys([...vault.admins, input.member]) : vault.admins;
      const nextEpochs = { ...vault.epochs };
      if (input.epochBoxes && typeof input.epochBoxes === 'object') {
        const rec = logMembers(ctx).get(input.member) || null;
        for (const [epKey, rawBox] of Object.entries(input.epochBoxes)) {
          const existing = nextEpochs[epKey];
          if (!existing) return { ok: false, code: 'epoch_missing' };
          if (existing.boxes && Object.prototype.hasOwnProperty.call(existing.boxes, input.member)) return { ok: false, code: 'box_already_exists' };
          const vb = validateBox(rawBox, minSuite);
          if (!vb.ok) return vb;
          if (!recipientHoldsSuiteKey(rec, vb.suite)) return { ok: false, code: 'box_recipient_key_missing', detail: input.member };
          nextEpochs[epKey] = { ...existing, boxes: { ...existing.boxes, [input.member]: vb.box } };
        }
      }
      cur.vaults[vaultId] = { ...vault, admins: nextAdmins, members: nextMembers, epochs: nextEpochs };
      return {
        ok: true,
        state: cur,
        events: [{ topic: 'vaults.member_added', payload: { vaultId, member: input.member } }],
      };
    }

    // Write-once backfill. Only a vault admin or the member itself may write a member's boxes, so
    // another member cannot front-run a newcomer with undecryptable garbage.
    if (input.action === 'grantBoxes') {
      if (!HEX32.test(input.member || '') || !input.epochBoxes || typeof input.epochBoxes !== 'object') {
        return { ok: false, code: 'grant_boxes_invalid' };
      }
      if (!isVaultAdmin && !(isVaultMember && tx.author === input.member)) return { ok: false, code: 'vault_admin_required' };
      if (!vault.members.includes(input.member)) return { ok: false, code: 'member_not_in_vault' };
      const allowReplace = isVaultAdmin && input.replace === true;
      const rec = logMembers(ctx).get(input.member) || null;
      const nextEpochs = { ...vault.epochs };
      for (const [epKey, rawBox] of Object.entries(input.epochBoxes)) {
        const existing = nextEpochs[epKey];
        if (!existing) return { ok: false, code: 'epoch_missing' };
        if (existing.boxes && Object.prototype.hasOwnProperty.call(existing.boxes, input.member) && !allowReplace) {
          return { ok: false, code: 'box_already_exists' };
        }
        const vb = validateBox(rawBox, minSuite);
        if (!vb.ok) return vb;
        if (!recipientHoldsSuiteKey(rec, vb.suite)) return { ok: false, code: 'box_recipient_key_missing', detail: input.member };
        nextEpochs[epKey] = { ...existing, boxes: { ...existing.boxes, [input.member]: vb.box } };
      }
      cur.vaults[vaultId] = { ...vault, epochs: nextEpochs };
      return {
        ok: true,
        state: cur,
        events: [{ topic: 'vaults.boxes_granted', payload: { vaultId, member: input.member } }],
      };
    }

    if (input.action === 'removeMember' || input.action === 'rotateVault') {
      if (!isVaultAdmin) return { ok: false, code: 'vault_admin_required' };
      const nextEpoch = vault.currentEpoch + 1;
      if (input.epoch !== nextEpoch) return { ok: false, code: 'epoch_sequence_invalid' };
      if (!HEX32.test(input.keyCommitment || '')) return { ok: false, code: 'key_commitment_invalid' };
      let nextMembers = vault.members;
      let nextAdmins = vault.admins;
      if (input.action === 'removeMember') {
        if (!HEX32.test(input.member || '')) return { ok: false, code: 'invalid_member' };
        nextMembers = vault.members.filter(m => m !== input.member);
        nextAdmins = vault.admins.filter(a => a !== input.member);
        if (nextAdmins.length === 0) return { ok: false, code: 'last_vault_admin_required' };
      }
      // Every new-epoch lockbox must go to a remaining vault member (never to a removed or foreign key).
      const boxesRes = validateBoxesMap(input.boxes, { minSuite, recipient: vaultRecipient(new Set(nextMembers), logMembers(ctx)) });
      if (!boxesRes.ok) return boxesRes;
      const boxes = boxesRes.boxes;
      cur.vaults[vaultId] = {
        ...vault,
        admins: nextAdmins,
        members: nextMembers,
        currentEpoch: nextEpoch,
        epochs: {
          ...vault.epochs,
          [String(nextEpoch)]: {
            epoch: nextEpoch,
            keyCommitment: input.keyCommitment,
            boxes,
          },
        },
      };
      return {
        ok: true,
        state: cur,
        events: [{
          topic: input.action === 'removeMember' ? 'vaults.member_removed' : 'vaults.rotated',
          payload: { vaultId, epoch: nextEpoch, ...(input.member ? { member: input.member } : {}) },
        }],
      };
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input) {
    const vaults = state && typeof state === 'object' && state.vaults && typeof state.vaults === 'object' ? state.vaults : {};
    if (!input || typeof input !== 'object') return { vaults };
    if (input.kind === 'list') return Object.keys(vaults).sort();
    if (input.kind === 'vault' && typeof input.vaultId === 'string') return vaults[input.vaultId] || null;
    if (input.kind === 'members' && typeof input.vaultId === 'string') return vaults[input.vaultId] ? vaults[input.vaultId].members : [];
    if (input.kind === 'canAccess' && typeof input.vaultId === 'string' && typeof input.actor === 'string') {
      const v = vaults[input.vaultId];
      return Boolean(v && Array.isArray(v.members) && v.members.includes(input.actor));
    }
    if (input.kind === 'isAdmin' && typeof input.vaultId === 'string' && typeof input.actor === 'string') {
      const v = vaults[input.vaultId];
      return Boolean(v && Array.isArray(v.admins) && v.admins.includes(input.actor));
    }
    return { vaults };
  },
};

export default privateVaults;
`.trimStart()
