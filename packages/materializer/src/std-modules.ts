import { utf8 } from '@chronolog/canonical'
import { computeCasHash, type ContentAddressedStore } from '@chronolog/records'

export const STD_PERMISSIONS_SOURCE = `
import { verifyEd25519, canonicalJson } from 'chronolog:crypto';

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function sortedKeys(list) {
  return Array.from(new Set(list)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function isLegacyAdmin(perms, author) {
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.administrator === true));
}

function hasCapability(ctx, capability, actor) {
  const checked = ctx.query('$permissions', { check: capability, actor });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  if (!perms || !Array.isArray(perms.members)) return false;
  const m = perms.members.find(x => x.publicKey === actor);
  if (!m) return false;
  if (capability === 'administrator') return m.administrator === true;
  if (capability === 'publisher') return m.publisher === true || m.administrator === true;
  if (capability === 'writer') return m.writer === true || m.administrator === true;
  if (capability === 'reader') return m.reader === true;
  if (capability === 'finalizer') return m.finalizer === true;
  return true;
}

function normalizeMember(m) {
  if (!m || typeof m !== 'object' || !HEX32.test(m.publicKey || '') || (m.wrapKey !== undefined && m.wrapKey !== null && !HEX32.test(m.wrapKey))) {
    throw new Error('INVALID_MEMBER');
  }
  return {
    publicKey: m.publicKey,
    ...(m.wrapKey ? { wrapKey: m.wrapKey } : {}),
    reader: Boolean(m.reader),
    writer: Boolean(m.writer),
    administrator: Boolean(m.administrator),
    publisher: Boolean(m.publisher),
    finalizer: Boolean(m.finalizer),
  };
}

function queryMembersList(members, role) {
  if (role === 'members') return members;
  if (role === 'readers') return sortedKeys(members.filter(m => m.reader === true).map(m => m.publicKey));
  if (role === 'writers') return sortedKeys(members.filter(m => m.writer === true || m.administrator === true).map(m => m.publicKey));
  if (role === 'administrators') return sortedKeys(members.filter(m => m.administrator === true).map(m => m.publicKey));
  if (role === 'publishers') return sortedKeys(members.filter(m => m.publisher === true || m.administrator === true).map(m => m.publicKey));
  if (role === 'finalizers') return sortedKeys(members.filter(m => m.finalizer === true).map(m => m.publicKey));
  return [];
}

function checkMembersCapability(members, capability, actor) {
  const m = members.find(x => x.publicKey === actor);
  if (!m) return false;
  if (capability === 'reader') return m.reader === true;
  if (capability === 'writer') return m.writer === true || m.administrator === true;
  if (capability === 'administrator') return m.administrator === true;
  if (capability === 'publisher') return m.publisher === true || m.administrator === true;
  if (capability === 'finalizer') return m.finalizer === true;
  if (capability === 'member') return true;
  return false;
}

export const attestedMembers = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? state : { members: [], admission: null };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    if (!isLegacyAdmin(cur, tx.author)) return { ok: false, code: 'admin_required' };

    if (input.action === 'setMember') {
      if (input.attestation) {
        const att = input.attestation;
        const hostKey = cur.admission && cur.admission.hostKey;
        if (!hostKey || !HEX32.test(hostKey) || !HEX64.test(att.signature || '')) {
          return { ok: false, code: 'attestation_invalid' };
        }
        const msg = canonicalJson(['chronolog/host-attestation/v1', att.payload]);
        if (!verifyEd25519(hostKey, msg, att.signature)) {
          return { ok: false, code: 'attestation_signature_invalid' };
        }
        if (att.payload.publicKey !== input.member.publicKey) {
          return { ok: false, code: 'attestation_subject_mismatch' };
        }
      }
      const next = normalizeMember(input.member);
      const members = cur.members.filter(m => m.publicKey !== next.publicKey).concat([next]);
      members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      return { ok: true, state: { ...cur, members }, events: [{ topic: '$permissions.member', payload: { publicKey: next.publicKey } }] };
    }

    if (input.action === 'removeMember') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const members = cur.members.filter(m => m.publicKey !== input.publicKey);
      if (!members.some(m => m.administrator)) return { ok: false, code: 'last_admin_required' };
      return { ok: true, state: { ...cur, members }, events: [{ topic: '$permissions.removed', payload: { publicKey: input.publicKey } }] };
    }

    if (input.action === 'setAdmission') {
      return { ok: true, state: { ...cur, admission: input.admission ?? null } };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const cur = state && typeof state === 'object' ? state : { members: [], admission: null };
    const members = Array.isArray(cur.members) ? cur.members : [];
    if (input && typeof input === 'object') {
      if (typeof input.check === 'string' && typeof input.actor === 'string') {
        return checkMembersCapability(members, input.check, input.actor);
      }
      if (typeof input.list === 'string') {
        return queryMembersList(members, input.list);
      }
      if (input.admission === true) {
        return cur.admission ?? null;
      }
      if (input.summary === true) {
        return {
          members,
          readers: queryMembersList(members, 'readers'),
          writers: queryMembersList(members, 'writers'),
          administrators: queryMembersList(members, 'administrators'),
          publishers: queryMembersList(members, 'publishers'),
          openReaders: false,
          openWriters: false,
          admission: cur.admission ?? null,
        };
      }
      if (input.publicKey) {
        return members.find(m => m.publicKey === input.publicKey) || null;
      }
    }
    return cur;
  },
};

/**
 * Open public-write / open-read authority model:
 * Any valid Ed25519 key can write (and read when openRead !== false), while listed
 * administrators govern control topics ($reducers, $finality, $publications).
 */
export const openMembers = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object'
      ? {
          admins: Array.isArray(state.admins) ? state.admins : [],
          members: Array.isArray(state.members) ? state.members : [],
          openRead: state.openRead !== false,
          openWrite: state.openWrite !== false,
          admission: state.admission ?? null,
        }
      : { admins: [], members: [], openRead: true, openWrite: true, admission: null };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    if (!cur.admins.includes(tx.author)) return { ok: false, code: 'admin_required' };

    if (input.action === 'setAdmin') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const admins = input.enabled === false
        ? cur.admins.filter(k => k !== input.publicKey)
        : sortedKeys(cur.admins.concat([input.publicKey]));
      if (admins.length === 0) return { ok: false, code: 'last_admin_required' };
      return { ok: true, state: { ...cur, admins }, events: [{ topic: '$permissions.admin', payload: { publicKey: input.publicKey, enabled: input.enabled !== false } }] };
    }

    if (input.action === 'setOpen') {
      return {
        ok: true,
        state: {
          ...cur,
          ...(input.openRead === undefined ? {} : { openRead: Boolean(input.openRead) }),
          ...(input.openWrite === undefined ? {} : { openWrite: Boolean(input.openWrite) }),
        },
      };
    }

    if (input.action === 'setMember') {
      const next = normalizeMember(input.member);
      const members = cur.members.filter(m => m.publicKey !== next.publicKey).concat([next]);
      members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      const admins = next.administrator ? sortedKeys(cur.admins.concat([next.publicKey])) : cur.admins;
      return { ok: true, state: { ...cur, admins, members }, events: [{ topic: '$permissions.member', payload: { publicKey: next.publicKey } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const cur = state && typeof state === 'object'
      ? {
          admins: Array.isArray(state.admins) ? state.admins : [],
          members: Array.isArray(state.members) ? state.members : [],
          openRead: state.openRead !== false,
          openWrite: state.openWrite !== false,
          admission: state.admission ?? null,
        }
      : { admins: [], members: [], openRead: true, openWrite: true, admission: null };

    const adminSet = new Set(cur.admins);
    const synthesizedMap = new Map();
    for (const m of cur.members) synthesizedMap.set(m.publicKey, m);
    for (const a of cur.admins) {
      const existing = synthesizedMap.get(a);
      synthesizedMap.set(a, {
        publicKey: a,
        ...(existing && existing.wrapKey ? { wrapKey: existing.wrapKey } : {}),
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: Boolean(existing && existing.finalizer),
      });
    }
    const members = Array.from(synthesizedMap.values()).sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));

    if (input && typeof input === 'object') {
      if (typeof input.check === 'string' && typeof input.actor === 'string') {
        if (!HEX32.test(input.actor)) return false;
        if (input.check === 'administrator') return adminSet.has(input.actor);
        if (input.check === 'publisher') return adminSet.has(input.actor) || checkMembersCapability(members, 'publisher', input.actor);
        if (input.check === 'writer') return cur.openWrite || adminSet.has(input.actor) || checkMembersCapability(members, 'writer', input.actor);
        if (input.check === 'reader') return cur.openRead || adminSet.has(input.actor) || checkMembersCapability(members, 'reader', input.actor);
        if (input.check === 'member') return cur.openWrite || cur.openRead || adminSet.has(input.actor) || checkMembersCapability(members, 'member', input.actor);
        return checkMembersCapability(members, input.check, input.actor);
      }
      if (typeof input.list === 'string') {
        if (input.list === 'readers' && cur.openRead) return ['*'];
        if (input.list === 'writers' && cur.openWrite) return ['*'];
        return queryMembersList(members, input.list);
      }
      if (input.admission === true) return cur.admission;
      if (input.summary === true) {
        return {
          members,
          readers: cur.openRead ? ['*'] : queryMembersList(members, 'readers'),
          writers: cur.openWrite ? ['*'] : queryMembersList(members, 'writers'),
          administrators: sortedKeys(cur.admins),
          publishers: queryMembersList(members, 'publishers'),
          openReaders: cur.openRead,
          openWriters: cur.openWrite,
          admission: cur.admission,
        };
      }
      if (input.publicKey) {
        return members.find(m => m.publicKey === input.publicKey) || null;
      }
    }
    return cur;
  },
};

/**
 * M-of-N multisig authority model (zero host attestation, completely distinct state shape):
 * State: { threshold: number, signers: string[], members: Record<pubkey, { wrapKey?, reader, writer, publisher, finalizer }>, proposals: Record<id, ...> }
 * Signers submit proposals (action: 'propose' | 'approve'); once approvals >= threshold, the proposal executes atomically.
 */
function normalizeMultisigState(state) {
  const s = state && typeof state === 'object' ? state : {};
  const signers = sortedKeys(Array.isArray(s.signers) ? s.signers.filter(k => HEX32.test(k || '')) : []);
  const threshold = Number.isSafeInteger(s.threshold) && s.threshold >= 1 ? Math.min(s.threshold, Math.max(1, signers.length)) : 1;
  const members = s.members && typeof s.members === 'object' && !Array.isArray(s.members) ? { ...s.members } : {};
  const proposals = s.proposals && typeof s.proposals === 'object' && !Array.isArray(s.proposals) ? { ...s.proposals } : {};
  return { threshold, signers, members, proposals };
}

function multisigMemberRecords(cur) {
  const byKey = new Map();
  for (const [pk, entry] of Object.entries(cur.members)) {
    if (!HEX32.test(pk) || !entry || typeof entry !== 'object') continue;
    byKey.set(pk, {
      publicKey: pk,
      ...(entry.wrapKey ? { wrapKey: entry.wrapKey } : {}),
      reader: Boolean(entry.reader),
      writer: Boolean(entry.writer),
      administrator: cur.signers.includes(pk),
      publisher: Boolean(entry.publisher) || cur.signers.includes(pk),
      finalizer: Boolean(entry.finalizer),
    });
  }
  for (const pk of cur.signers) {
    if (!byKey.has(pk)) {
      byKey.set(pk, {
        publicKey: pk,
        reader: true,
        writer: true,
        administrator: true,
        publisher: true,
        finalizer: false,
      });
    }
  }
  return Array.from(byKey.values()).sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
}

function applyMultisigProposal(cur, prop) {
  if (prop.kind === 'setMember') {
    const m = normalizeMember(prop.member);
    const nextMembers = {
      ...cur.members,
      [m.publicKey]: {
        ...(m.wrapKey ? { wrapKey: m.wrapKey } : {}),
        reader: m.reader,
        writer: m.writer,
        publisher: m.publisher,
        finalizer: m.finalizer,
      },
    };
    const nextSigners = m.administrator ? sortedKeys(cur.signers.concat([m.publicKey])) : cur.signers;
    return { ok: true, state: { ...cur, signers: nextSigners, members: nextMembers }, event: { topic: '$permissions.member', payload: { publicKey: m.publicKey } } };
  }
  if (prop.kind === 'removeMember') {
    if (!HEX32.test(prop.publicKey || '')) return { ok: false, code: 'invalid_member' };
    const nextMembers = { ...cur.members };
    delete nextMembers[prop.publicKey];
    const nextSigners = cur.signers.filter(k => k !== prop.publicKey);
    if (nextSigners.length === 0 || nextSigners.length < cur.threshold) return { ok: false, code: 'threshold_unsatisfiable' };
    return { ok: true, state: { ...cur, signers: nextSigners, members: nextMembers }, event: { topic: '$permissions.removed', payload: { publicKey: prop.publicKey } } };
  }
  if (prop.kind === 'setThreshold') {
    const t = prop.threshold;
    if (!Number.isSafeInteger(t) || t < 1 || t > cur.signers.length) return { ok: false, code: 'invalid_threshold' };
    return { ok: true, state: { ...cur, threshold: t }, event: { topic: '$permissions.threshold', payload: { threshold: t } } };
  }
  return { ok: false, code: 'unknown_proposal_kind' };
}

export const multisigMembers = {
  reduce(state, tx) {
    const cur = normalizeMultisigState(state);
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    if (!cur.signers.includes(tx.author)) return { ok: false, code: 'signer_required' };

    if (input.action === 'propose') {
      const id = typeof input.proposalId === 'string' && input.proposalId.length > 0 ? input.proposalId : tx.opId;
      if (cur.proposals[id]) return { ok: false, code: 'proposal_exists' };
      const prop = {
        kind: input.kind,
        ...(input.member !== undefined ? { member: input.member } : {}),
        ...(input.publicKey !== undefined ? { publicKey: input.publicKey } : {}),
        ...(input.threshold !== undefined ? { threshold: input.threshold } : {}),
        approvals: [tx.author],
      };
      if (prop.approvals.length >= cur.threshold) {
        const applied = applyMultisigProposal(cur, prop);
        if (!applied.ok) return applied;
        return { ok: true, state: applied.state, events: [applied.event] };
      }
      const nextProposals = { ...cur.proposals, [id]: prop };
      return {
        ok: true,
        state: { ...cur, proposals: nextProposals },
        events: [{ topic: '$permissions.proposed', payload: { proposalId: id, approvals: 1, threshold: cur.threshold } }],
      };
    }

    if (input.action === 'approve') {
      const id = input.proposalId;
      const existing = typeof id === 'string' ? cur.proposals[id] : null;
      if (!existing) return { ok: false, code: 'proposal_not_found' };
      const approvals = sortedKeys((existing.approvals || []).concat([tx.author]));
      const updated = { ...existing, approvals };
      if (approvals.length >= cur.threshold) {
        const nextProposals = { ...cur.proposals };
        delete nextProposals[id];
        const applied = applyMultisigProposal({ ...cur, proposals: nextProposals }, updated);
        if (!applied.ok) return applied;
        return { ok: true, state: applied.state, events: [applied.event] };
      }
      return {
        ok: true,
        state: { ...cur, proposals: { ...cur.proposals, [id]: updated } },
        events: [{ topic: '$permissions.approved', payload: { proposalId: id, approvals: approvals.length, threshold: cur.threshold } }],
      };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const cur = normalizeMultisigState(state);
    const members = multisigMemberRecords(cur);
    if (input && typeof input === 'object') {
      if (typeof input.check === 'string' && typeof input.actor === 'string') {
        return checkMembersCapability(members, input.check, input.actor);
      }
      if (typeof input.list === 'string') {
        return queryMembersList(members, input.list);
      }
      if (input.admission === true) return null;
      if (input.summary === true) {
        return {
          members,
          readers: queryMembersList(members, 'readers'),
          writers: queryMembersList(members, 'writers'),
          administrators: queryMembersList(members, 'administrators'),
          publishers: queryMembersList(members, 'publishers'),
          openReaders: false,
          openWriters: false,
          admission: null,
        };
      }
      if (input.publicKey) {
        return members.find(m => m.publicKey === input.publicKey) || null;
      }
    }
    return cur;
  },
};

export const adminOnlyReducers = {
  reduce(state, tx, ctx) {
    if (!hasCapability(ctx, 'administrator', tx.author)) return { ok: false, code: 'admin_required' };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const next = {
      runtime: state.runtime,
      imports: { ...(state.imports || {}) },
      topics: { ...(state.topics || {}) },
    };
    if (input.imports && typeof input.imports === 'object') {
      for (const [k, v] of Object.entries(input.imports)) {
        if (v === null) delete next.imports[k];
        else next.imports[k] = v;
      }
    }
    if (input.topics && typeof input.topics === 'object') {
      for (const [k, v] of Object.entries(input.topics)) {
        if (v === null) delete next.topics[k];
        else next.topics[k] = v;
      }
    }
    return { ok: true, state: next, events: [{ topic: '$reducers.updated', payload: { author: tx.author } }] };
  },
};

export const defaultSignalPolicy = {
  reduce(state, tx, ctx) {
    if (!hasCapability(ctx, 'administrator', tx.author)) return { ok: false, code: 'admin_required' };
    if (!tx.payload || !Array.isArray(tx.payload.rules)) return { ok: false, code: 'invalid_signal_policy' };
    return { ok: true, state: { rules: tx.payload.rules } };
  },
  query(state, _input, ctx) {
    if (state && Array.isArray(state.rules)) return state;
    const queried = ctx.query('$permissions', { list: 'readers' });
    if (Array.isArray(queried)) {
      return {
        rules: [{ topicPattern: '*', allowedAuthors: queried, maxTtlMs: 30000, allowRelay: true }],
      };
    }
    const perms = ctx.topic('$permissions') || { members: [] };
    const readers = Array.isArray(perms.members) ? perms.members.filter(m => m.reader).map(m => m.publicKey) : [];
    return {
      rules: [{ topicPattern: '*', allowedAuthors: readers, maxTtlMs: 30000, allowRelay: true }],
    };
  },
};
`.trimStart()

export const STD_KEYS_SOURCE = `
const HEX32 = /^[0-9a-f]{64}$/;

function isAdmin(ctx, author) {
  const checked = ctx.query('$permissions', { check: 'administrator', actor: author });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.administrator === true));
}

export const hpkeEpochs = {
  reduce(state, tx, ctx) {
    if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
    const cur = state && typeof state === 'object' ? state : { currentEpoch: -1, epochs: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };

    if (input.action === 'rotateEpoch') {
      const epoch = input.epoch;
      if (!Number.isSafeInteger(epoch) || epoch !== cur.currentEpoch + 1) return { ok: false, code: 'epoch_sequence_invalid' };
      if (!HEX32.test(input.keyCommitment || '')) return { ok: false, code: 'key_commitment_invalid' };
      if (!input.boxes || typeof input.boxes !== 'object') return { ok: false, code: 'boxes_invalid' };
      const boxes = {};
      for (const [pk, box] of Object.entries(input.boxes)) {
        if (!HEX32.test(pk) || !box || typeof box.encapsulatedKey !== 'string' || typeof box.ciphertext !== 'string') {
          return { ok: false, code: 'box_invalid' };
        }
        boxes[pk] = { encapsulatedKey: box.encapsulatedKey, ciphertext: box.ciphertext };
      }
      const nextEpochs = { ...cur.epochs, [String(epoch)]: { epoch, keyCommitment: input.keyCommitment, boxes } };
      return {
        ok: true,
        state: { currentEpoch: epoch, epochs: nextEpochs },
        events: [{ topic: '$keys.rotated', payload: { epoch } }],
      };
    }

    // Grant a newly admitted fresh device lockboxes for one or more retained historical epochs (0..N or checkpointEpoch..N).
    if (input.action === 'grantBoxes') {
      if (!HEX32.test(input.member || '') || !input.epochBoxes || typeof input.epochBoxes !== 'object') {
        return { ok: false, code: 'grant_boxes_invalid' };
      }
      const nextEpochs = { ...cur.epochs };
      for (const [epKey, box] of Object.entries(input.epochBoxes)) {
        const existing = nextEpochs[epKey];
        if (!existing) return { ok: false, code: 'epoch_missing' };
        if (!box || typeof box.encapsulatedKey !== 'string' || typeof box.ciphertext !== 'string') {
          return { ok: false, code: 'box_invalid' };
        }
        nextEpochs[epKey] = {
          ...existing,
          boxes: { ...existing.boxes, [input.member]: { encapsulatedKey: box.encapsulatedKey, ciphertext: box.ciphertext } },
        };
      }
      return {
        ok: true,
        state: { currentEpoch: cur.currentEpoch, epochs: nextEpochs },
        events: [{ topic: '$keys.granted', payload: { member: input.member } }],
      };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const cur = state || { currentEpoch: -1, epochs: {} };
    if (input && input.member) {
      const out = {};
      for (const [ep, entry] of Object.entries(cur.epochs || {})) {
        if (entry.boxes && entry.boxes[input.member]) {
          out[ep] = { epoch: entry.epoch, keyCommitment: entry.keyCommitment, box: entry.boxes[input.member] };
        }
      }
      return { currentEpoch: cur.currentEpoch, memberEpochs: out };
    }
    return cur;
  },
};
`.trimStart()

export const STD_FINALITY_SOURCE = `
function isAdmin(ctx, author) {
  const checked = ctx.query('$permissions', { check: 'administrator', actor: author });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.administrator === true));
}

function validPolicy(policy) {
  if (!policy || typeof policy !== 'object') return false;
  if (policy.kind === 'none') return true;
  if (policy.kind === 'signed-frontier') return typeof policy.signer === 'string' && /^[0-9a-f]{64}$/.test(policy.signer);
  if (policy.kind === 'fixed-validator') {
    return Array.isArray(policy.validators) && policy.validators.length > 0 &&
      policy.validators.every(v => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)) &&
      Number.isSafeInteger(policy.threshold) && policy.threshold >= 1 && policy.threshold <= policy.validators.length;
  }
  if (policy.kind === 'blockchain-anchor') {
    return typeof policy.chain === 'string' && policy.chain.length > 0 && typeof policy.anchorId === 'string' && policy.anchorId.length > 0;
  }
  return false;
}

export const scheduledFinality = {
  reduce(state, tx, ctx) {
    if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
    const cur = state && Array.isArray(state.schedule) ? state : { schedule: [{ effectiveAfterMs: -1, policy: { kind: 'none' } }] };
    const input = tx.payload;
    if (!input || input.action !== 'schedulePolicy' || !validPolicy(input.policy)) return { ok: false, code: 'invalid_finality_policy' };
    const effectiveAfterMs = input.effectiveAfterMs;
    const last = cur.schedule[cur.schedule.length - 1];
    if (!Number.isSafeInteger(effectiveAfterMs) || effectiveAfterMs <= last.effectiveAfterMs) {
      return { ok: false, code: 'finality_activation_not_monotonic' };
    }
    if (effectiveAfterMs < tx.authorTimestampMs) {
      return { ok: false, code: 'finality_activation_in_past' };
    }
    const nextSchedule = cur.schedule.concat([{ effectiveAfterMs, policy: input.policy }]);
    return {
      ok: true,
      state: { schedule: nextSchedule },
      events: [{ topic: '$finality.scheduled', payload: { effectiveAfterMs, kind: input.policy.kind } }],
    };
  },
  query(state) {
    return state || { schedule: [{ effectiveAfterMs: -1, policy: { kind: 'none' } }] };
  },
};
`.trimStart()

export const STD_PUBLICATIONS_SOURCE = `
const HEX32 = /^[0-9a-f]{64}$/;

function isPublisher(ctx, author) {
  const checked = ctx.query('$permissions', { check: 'publisher', actor: author });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && (m.publisher === true || m.administrator === true)));
}

export const signedReleases = {
  reduce(state, tx, ctx) {
    if (!isPublisher(ctx, tx.author)) return { ok: false, code: 'publisher_required' };
    const cur = state && typeof state === 'object' ? state : { revision: 0, current: null, history: [] };
    const input = tx.payload;
    if (!input || input.action !== 'publish' || typeof input.entry !== 'string' || !Array.isArray(input.files) || input.files.length === 0) {
      return { ok: false, code: 'invalid_publication' };
    }
    if (input.expectedRevision !== undefined && input.expectedRevision !== cur.revision) {
      return { ok: false, code: 'publication_revision_conflict' };
    }
    const files = [];
    for (const f of input.files) {
      if (!f || typeof f.path !== 'string' || !HEX32.test(f.hash || '') || !Number.isSafeInteger(f.size) || f.size < 0 || typeof f.type !== 'string') {
        return { ok: false, code: 'invalid_publication_file' };
      }
      files.push({ path: f.path, hash: f.hash, size: f.size, type: f.type });
    }
    if (!files.some(f => f.path === input.entry)) return { ok: false, code: 'publication_entry_missing' };
    const revision = cur.revision + 1;
    const release = { revision, opId: tx.opId, author: tx.author, timestampMs: tx.authorTimestampMs, entry: input.entry, files };
    const history = (cur.history || []).concat([{ revision, opId: tx.opId, author: tx.author, entry: input.entry }]).slice(-32);
    return {
      ok: true,
      state: { revision, current: release, history },
      events: [{ topic: '$publications.published', payload: { revision, opId: tx.opId } }],
    };
  },
  query(state) {
    return state || { revision: 0, current: null, history: [] };
  },
};
`.trimStart()

export const STD_RLS_SOURCE = `
function quoteIdent(name) {
  if (typeof name !== 'string' || !/^[A-Za-z][A-Za-z0-9_]*$/.test(name) || name.startsWith('_rls_') || name.startsWith('sqlite_')) {
    throw new Error('RLS_INVALID_IDENTIFIER:' + String(name));
  }
  return '"' + name + '"';
}

/**
 * Install Postgres-style write RLS triggers on tables inside a chronolog:sqlite database.
 * Each predicate is validated via db.validateExpr() (SQLite mode:'readonly', zero trailing tokens)
 * before wrapping in a BEFORE INSERT/UPDATE/DELETE trigger with RAISE(ABORT, ...).
 */
export function applyRls(db, policies) {
  if (!policies || typeof policies !== 'object') throw new Error('RLS_POLICIES_INVALID');
  const ops = [
    ['insert', 'INSERT'],
    ['update', 'UPDATE'],
    ['delete', 'DELETE'],
  ];
  for (const [table, rule] of Object.entries(policies)) {
    const qTable = quoteIdent(table);
    for (const [key, sqlOp] of ops) {
      const trigName = '_rls_' + table + '_' + key;
      db.exec('DROP TRIGGER IF EXISTS ' + '"' + trigName + '"', [], { mode: 'admin' });
      const expr = rule && rule[key];
      if (expr === undefined || expr === null) continue;
      if (typeof expr !== 'string' || expr.trim().length === 0) throw new Error('RLS_EXPR_INVALID');
      // Validate pure single read-only SQL expression using SQLite's own parser in mode:'readonly'
      db.validateExpr(table, sqlOp, expr);
      const triggerSql =
        'CREATE TRIGGER "' + trigName + '" BEFORE ' + sqlOp + ' ON ' + qTable +
        " BEGIN SELECT CASE WHEN NOT (" + expr + ") THEN RAISE(ABORT, 'rls_denied:" + table + ":" + key + "') END; END";
      db.exec(triggerSql, [], { mode: 'admin' });
    }
  }
}

export function ensureTableOwners(db) {
  db.exec(
    'CREATE TABLE IF NOT EXISTS _rls_table_owners (name TEXT PRIMARY KEY NOT NULL, owner TEXT NOT NULL)',
    [],
    { mode: 'admin' },
  );
}

export function getOwnedTables(db, owner) {
  ensureTableOwners(db);
  const res = db.query('SELECT name FROM _rls_table_owners WHERE owner = ? ORDER BY name', [owner]);
  return res.rows.map(r => r[0]);
}

export function recordTableOwners(db, createdTables, droppedTables, owner) {
  ensureTableOwners(db);
  for (const name of createdTables || []) {
    db.exec('INSERT OR REPLACE INTO _rls_table_owners (name, owner) VALUES (?, ?)', [name, owner], { mode: 'admin' });
  }
  for (const name of droppedTables || []) {
    db.exec('DELETE FROM _rls_table_owners WHERE name = ?', [name], { mode: 'admin' });
  }
}
`.trimStart()

export const STD_SQL_SOURCE = `
import { openDb } from 'chronolog:sqlite';
import { applyRls, getOwnedTables, recordTableOwners } from 'chronolog/rls';

function hasCapability(ctx, capability, actor) {
  const checked = ctx.query('$permissions', { check: capability, actor });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  if (!perms || !Array.isArray(perms.members)) return false;
  const m = perms.members.find(x => x.publicKey === actor);
  if (!m) return false;
  if (capability === 'administrator') return m.administrator === true;
  if (capability === 'writer') return m.writer === true || m.administrator === true;
  if (capability === 'reader') return m.reader === true;
  return false;
}

function normalizeSqlState(state, config) {
  const cfg = config && typeof config === 'object' ? config : {};
  const s = state && typeof state === 'object' ? state : {};
  return {
    dbRoot: typeof s.dbRoot === 'string' ? s.dbRoot : null,
    schemaVersion: Number.isSafeInteger(s.schemaVersion) ? s.schemaVersion : 0,
    policies: s.policies && typeof s.policies === 'object' && !Array.isArray(s.policies) ? { ...s.policies } : {},
    allowUserDdl: s.allowUserDdl !== undefined ? Boolean(s.allowUserDdl) : cfg.allowUserDdl !== false,
  };
}

function normalizeStatement(stmt) {
  if (typeof stmt === 'string') return { sql: stmt, params: [] };
  if (stmt && typeof stmt === 'object' && typeof stmt.sql === 'string') {
    return { sql: stmt.sql, params: Array.isArray(stmt.params) ? stmt.params : [] };
  }
  return null;
}

function checkPreconditions(db, preconditions) {
  if (!Array.isArray(preconditions)) return { ok: true };
  for (let i = 0; i < preconditions.length; i++) {
    const pre = preconditions[i];
    if (!pre || typeof pre !== 'object' || typeof pre.sql !== 'string') {
      return { ok: false, code: 'sql:invalid_precondition', detail: 'Precondition ' + i + ' missing sql' };
    }
    const failCode = typeof pre.code === 'string' && pre.code.length > 0 ? pre.code : 'sql:precondition_failed';
    let res;
    try {
      res = db.query(pre.sql, Array.isArray(pre.params) ? pre.params : []);
    } catch (err) {
      return { ok: false, code: failCode, detail: String(err && err.message ? err.message : err) };
    }
    const exp = pre.expect;
    if (exp === undefined || exp === null) {
      const ok = res.rows.length > 0 && Boolean(res.rows[0][0]);
      if (!ok) return { ok: false, code: failCode, detail: 'Precondition ' + i + ' evaluated falsy' };
      continue;
    }
    if (typeof exp !== 'object') {
      return { ok: false, code: 'sql:invalid_precondition', detail: 'Precondition ' + i + ' expect must be an object' };
    }
    if (exp.rowCount !== undefined && res.rows.length !== exp.rowCount) {
      return { ok: false, code: failCode, detail: 'Expected rowCount ' + exp.rowCount + ', got ' + res.rows.length };
    }
    if (exp.minRows !== undefined && res.rows.length < exp.minRows) {
      return { ok: false, code: failCode, detail: 'Expected minRows ' + exp.minRows + ', got ' + res.rows.length };
    }
    if (exp.maxRows !== undefined && res.rows.length > exp.maxRows) {
      return { ok: false, code: failCode, detail: 'Expected maxRows ' + exp.maxRows + ', got ' + res.rows.length };
    }
    if (exp.firstValue !== undefined) {
      const actual = res.rows.length > 0 ? res.rows[0][0] : undefined;
      if (JSON.stringify(actual) !== JSON.stringify(exp.firstValue)) {
        return { ok: false, code: failCode, detail: 'Expected firstValue ' + JSON.stringify(exp.firstValue) + ', got ' + JSON.stringify(actual) };
      }
    }
    if (exp.equals !== undefined) {
      if (JSON.stringify(res.rows) !== JSON.stringify(exp.equals)) {
        return { ok: false, code: failCode, detail: 'Precondition ' + i + ' rows mismatch' };
      }
    }
  }
  return { ok: true };
}

function extractSqlErrorCode(err) {
  const msg = String(err && err.message ? err.message : err);
  const rls = /rls_denied:[A-Za-z0-9_]+:(?:insert|update|delete)/.exec(msg);
  if (rls) return rls[0];
  if (/not authorized|AUTHORIZER/i.test(msg)) return 'sql:not_authorized';
  if (/UNIQUE constraint|PRIMARY KEY/i.test(msg)) return 'sql:constraint_unique';
  if (/FOREIGN KEY constraint/i.test(msg)) return 'sql:constraint_fk';
  if (/CHECK constraint/i.test(msg)) return 'sql:constraint_check';
  if (/NOT NULL constraint/i.test(msg)) return 'sql:constraint_not_null';
  return 'sql:error';
}

function normalizeEvents(events) {
  if (!Array.isArray(events)) return [];
  const out = [];
  for (const ev of events) {
    if (ev && typeof ev === 'object' && typeof ev.topic === 'string' && ev.topic.length > 0) {
      out.push({ topic: ev.topic, payload: ev.payload === undefined ? null : ev.payload });
    }
  }
  return out;
}

function rowsToObjects(res) {
  return res.rows.map(row => {
    const obj = {};
    for (let i = 0; i < res.columns.length; i++) obj[res.columns[i]] = row[i];
    return obj;
  });
}

/**
 * First-class deterministic Merkle-paged SQLite topic reducer.
 * - Declarative SQL transactions with atomic preconditions and automatic rollback on failure
 * - Postgres-style write RLS policies (chronolog/rls) + host-bound actor()/op_id()/op_time()
 * - Admin DDL (mode:'admin') and non-admin user-owned dynamic table DDL (mode:'user')
 * - Multiple topics in one chain can each bind chronolog/sql for independent hash-addressed databases
 */
export const sqlDatabase = {
  reduce(state, tx, ctx) {
    const cur = normalizeSqlState(state, ctx.config);
    const input = tx.payload;
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return { ok: false, code: 'invalid_input' };
    }

    const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
    const allowPublicWrite = cfg.allowPublicWrite === true;
    const isAdmin = hasCapability(ctx, 'administrator', tx.author);
    const isWriter = allowPublicWrite || isAdmin || hasCapability(ctx, 'writer', tx.author);
    const action = typeof input.action === 'string' ? input.action : 'exec';

    if (action === 'setConfig') {
      if (!isAdmin) return { ok: false, code: 'admin_required' };
      const next = {
        ...cur,
        ...(input.allowUserDdl === undefined ? {} : { allowUserDdl: Boolean(input.allowUserDdl) }),
      };
      return { ok: true, state: next, events: normalizeEvents(input.events) };
    }

    if (action === 'setRls' || action === 'setPolicies') {
      if (!isAdmin) return { ok: false, code: 'admin_required' };
      if (!input.policies || typeof input.policies !== 'object' || Array.isArray(input.policies)) {
        return { ok: false, code: 'rls:invalid_policies' };
      }
      const db = openDb(cur.dbRoot);
      try {
        applyRls(db, input.policies);
        const dbRoot = db.commit();
        const nextPolicies = { ...cur.policies, ...input.policies };
        return {
          ok: true,
          state: { ...cur, dbRoot, policies: nextPolicies },
          events: normalizeEvents(input.events).concat([{ topic: 'sql.rls_updated', payload: { tables: Object.keys(input.policies) } }]),
        };
      } catch (err) {
        return { ok: false, code: extractSqlErrorCode(err), detail: String(err && err.message ? err.message : err) };
      } finally {
        db.close();
      }
    }

    if (action === 'migrate') {
      if (!isAdmin) return { ok: false, code: 'admin_required' };
      const statements = Array.isArray(input.statements) ? input.statements : [];
      const db = openDb(cur.dbRoot);
      try {
        const preCheck = checkPreconditions(db, input.preconditions);
        if (!preCheck.ok) return preCheck;
        for (const rawStmt of statements) {
          const stmt = normalizeStatement(rawStmt);
          if (!stmt) return { ok: false, code: 'sql:invalid_statement' };
          db.exec(stmt.sql, stmt.params, { mode: 'admin' });
        }
        let nextPolicies = cur.policies;
        if (input.policies && typeof input.policies === 'object' && !Array.isArray(input.policies)) {
          applyRls(db, input.policies);
          nextPolicies = { ...cur.policies, ...input.policies };
        }
        const dbRoot = db.commit();
        const schemaVersion = Number.isSafeInteger(input.schemaVersion) ? input.schemaVersion : cur.schemaVersion + 1;
        const allowUserDdl = input.allowUserDdl === undefined ? cur.allowUserDdl : Boolean(input.allowUserDdl);
        return {
          ok: true,
          state: { ...cur, dbRoot, schemaVersion, policies: nextPolicies, allowUserDdl },
          events: normalizeEvents(input.events).concat([{ topic: 'sql.migrated', payload: { schemaVersion } }]),
        };
      } catch (err) {
        return { ok: false, code: extractSqlErrorCode(err), detail: String(err && err.message ? err.message : err) };
      } finally {
        db.close();
      }
    }

    if (action === 'exec') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      const mode = input.mode === 'admin' ? 'admin' : 'user';
      if (mode === 'admin' && !isAdmin) return { ok: false, code: 'admin_required' };
      const statements = Array.isArray(input.statements)
        ? input.statements
        : typeof input.sql === 'string'
          ? [{ sql: input.sql, params: Array.isArray(input.params) ? input.params : [] }]
          : null;
      if (!statements || (statements.length === 0 && !Array.isArray(input.preconditions))) {
        return { ok: false, code: 'sql:statements_required' };
      }

      const db = openDb(cur.dbRoot);
      try {
        const preCheck = checkPreconditions(db, input.preconditions);
        if (!preCheck.ok) return preCheck;

        let owned = mode === 'user' && cur.allowUserDdl ? getOwnedTables(db, tx.author) : null;
        for (const rawStmt of statements) {
          const stmt = normalizeStatement(rawStmt);
          if (!stmt) return { ok: false, code: 'sql:invalid_statement' };
          const execOpts = mode === 'admin'
            ? { mode: 'admin' }
            : cur.allowUserDdl
              ? {
                  mode: 'user',
                  ddl: {
                    createTable: true,
                    alterTable: owned,
                    dropTable: owned,
                    indexOn: owned,
                    createView: true,
                    dropView: owned,
                  },
                }
              : { mode: 'user' };
          const res = db.exec(stmt.sql, stmt.params, execOpts);
          if (mode === 'user' && cur.allowUserDdl && (res.createdTables.length > 0 || res.droppedTables.length > 0)) {
            recordTableOwners(db, res.createdTables, res.droppedTables, tx.author);
            owned = getOwnedTables(db, tx.author);
          }
        }

        const dbRoot = db.commit();
        return {
          ok: true,
          state: { ...cur, dbRoot },
          events: normalizeEvents(input.events),
        };
      } catch (err) {
        return { ok: false, code: extractSqlErrorCode(err), detail: String(err && err.message ? err.message : err) };
      } finally {
        db.close();
      }
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input, ctx) {
    const cur = normalizeSqlState(state, ctx.config);
    if (input === null || input === undefined) {
      return {
        dbRoot: cur.dbRoot,
        schemaVersion: cur.schemaVersion,
        policies: cur.policies,
        allowUserDdl: cur.allowUserDdl,
      };
    }
    const kind = typeof input === 'object' ? (input.query || input.kind) : null;
    if (typeof input === 'object' && typeof input.sql === 'string') {
      const db = openDb(cur.dbRoot);
      try {
        const res = db.query(input.sql, Array.isArray(input.params) ? input.params : []);
        return input.format === 'objects'
          ? { columns: res.columns, rows: rowsToObjects(res) }
          : res;
      } finally {
        db.close();
      }
    }
    if (kind === 'tables') {
      const db = openDb(cur.dbRoot);
      try {
        const res = db.query("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_rls_%' ORDER BY name", []);
        return { dbRoot: cur.dbRoot, tables: res.rows.map(r => ({ name: r[0], type: r[1] })) };
      } finally {
        db.close();
      }
    }
    if (kind === 'schema') {
      const db = openDb(cur.dbRoot);
      try {
        const res = db.query("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name", []);
        return {
          dbRoot: cur.dbRoot,
          schemaVersion: cur.schemaVersion,
          policies: cur.policies,
          allowUserDdl: cur.allowUserDdl,
          objects: res.rows.map(r => ({ type: r[0], name: r[1], table: r[2], sql: r[3] })),
        };
      } finally {
        db.close();
      }
    }
    return {
      dbRoot: cur.dbRoot,
      schemaVersion: cur.schemaVersion,
      policies: cur.policies,
      allowUserDdl: cur.allowUserDdl,
    };
  },

  describe() {
    const scalarParam = {
      anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }],
    };
    const statementSchema = {
      anyOf: [
        { type: 'string' },
        {
          type: 'object',
          properties: {
            sql: { type: 'string' },
            params: { type: 'array', items: scalarParam },
          },
          required: ['sql'],
        },
      ],
    };
    return {
      commands: [
        {
          name: 'exec',
          description: 'Execute a deterministic SQL transaction with optional atomic preconditions under write RLS.',
          input: {
            type: 'object',
            properties: {
              mode: { type: 'string', enum: ['user', 'admin'] },
              preconditions: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    sql: { type: 'string' },
                    params: { type: 'array', items: scalarParam },
                    code: { type: 'string' },
                  },
                  required: ['sql'],
                },
              },
              statements: { type: 'array', items: statementSchema },
              events: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: { topic: { type: 'string' } },
                  required: ['topic'],
                },
              },
            },
          },
        },
        {
          name: 'migrate',
          description: 'Run administrator DDL migrations and optionally install write RLS policies atomically.',
          input: {
            type: 'object',
            properties: {
              statements: { type: 'array', items: statementSchema },
              schemaVersion: { type: 'integer' },
              allowUserDdl: { type: 'boolean' },
            },
          },
        },
        {
          name: 'setRls',
          description: 'Install or update Postgres-style write RLS policies (administrator only).',
          input: {
            type: 'object',
            properties: {
              policies: { type: 'object', properties: {} },
            },
            required: ['policies'],
          },
        },
        {
          name: 'setConfig',
          description: 'Update SQL topic configuration such as allowUserDdl (administrator only).',
          input: {
            type: 'object',
            properties: {
              allowUserDdl: { type: 'boolean' },
            },
          },
        },
      ],
      queries: [
        {
          name: 'sql',
          description: 'Execute a read-only SQL query against the deterministic SQLite-CAS state.',
          input: {
            type: 'object',
            properties: {
              sql: { type: 'string' },
              params: { type: 'array', items: scalarParam },
              format: { type: 'string', enum: ['rows', 'objects'] },
            },
            required: ['sql'],
          },
        },
        {
          name: 'tables',
          description: 'List user tables and views in this SQLite-CAS database.',
          input: { type: 'object', properties: {} },
        },
        {
          name: 'schema',
          description: 'Inspect schema objects, dbRoot, and active write RLS policies.',
          input: { type: 'object', properties: {} },
        },
      ],
    };
  },
};

export default sqlDatabase;
`.trimStart()

export const STANDARD_MODULE_SOURCES: Readonly<Record<string, string>> = Object.freeze({
  'chronolog/permissions': STD_PERMISSIONS_SOURCE,
  'chronolog/keys': STD_KEYS_SOURCE,
  'chronolog/finality': STD_FINALITY_SOURCE,
  'chronolog/publications': STD_PUBLICATIONS_SOURCE,
  'chronolog/rls': STD_RLS_SOURCE,
  'chronolog/sql': STD_SQL_SOURCE,
})

export const STANDARD_MODULE_IMPORTS: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(
    Object.entries(STANDARD_MODULE_SOURCES).map(([spec, src]) => [spec, `cas:sha256-${computeCasHash(utf8(src))}`]),
  ),
)

/** Seed all standard audited ES modules into CAS (public partition) and return their pinned import map entries. */
export async function seedStandardModules(cas: ContentAddressedStore): Promise<Record<string, string>> {
  const imports: Record<string, string> = {}
  for (const [spec, src] of Object.entries(STANDARD_MODULE_SOURCES)) {
    const hash = await cas.put(utf8(src), [], 'public')
    imports[spec] = `cas:sha256-${hash}`
  }
  return imports
}
