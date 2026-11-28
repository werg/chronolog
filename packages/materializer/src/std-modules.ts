import { utf8 } from '@chronolog/canonical'
import {
  computeCasHash,
  putPackageDag,
  type ChronologBuiltinName,
  type ContentAddressedStore,
} from '@chronolog/records'
import { STD_CRDT_SOURCE } from './std/crdt.js'
import { STD_TEXT_SOURCE } from './std/text.js'
import { STD_LEDGER_SOURCE } from './std/ledger.js'
import { STD_WORKFLOW_SOURCE } from './std/workflow.js'
import { STD_FS_SOURCE } from './std/fs.js'
import { STD_MOUNTS_SOURCE } from './std/mounts.js'
import { STD_BUILDERS_SOURCE } from './std/builders.js'
import { STD_REGISTRY_SOURCE } from './std/registry.js'

export {
  STD_CRDT_SOURCE,
  STD_TEXT_SOURCE,
  STD_LEDGER_SOURCE,
  STD_WORKFLOW_SOURCE,
  STD_FS_SOURCE,
  STD_MOUNTS_SOURCE,
  STD_BUILDERS_SOURCE,
  STD_REGISTRY_SOURCE,
}

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
  const scopes = Array.isArray(m.scopes)
    ? sortedKeys(m.scopes.filter(s => typeof s === 'string' && s.length > 0 && s.length <= 128))
    : undefined;
  const expiresAtMs = m.expiresAtMs !== undefined && m.expiresAtMs !== null && Number.isSafeInteger(m.expiresAtMs)
    ? m.expiresAtMs
    : undefined;
  return {
    publicKey: m.publicKey,
    ...(m.wrapKey ? { wrapKey: m.wrapKey } : {}),
    ...(typeof m.label === 'string' && m.label.length > 0 ? { label: m.label } : {}),
    ...(typeof m.subject === 'string' && m.subject.length > 0 ? { subject: m.subject } : {}),
    ...(scopes && scopes.length > 0 ? { scopes } : {}),
    ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
    reader: Boolean(m.reader),
    writer: Boolean(m.writer),
    administrator: Boolean(m.administrator),
    publisher: Boolean(m.publisher),
    finalizer: Boolean(m.finalizer),
  };
}

function isMemberExpired(member, atMs) {
  if (!member || member.expiresAtMs === undefined || member.expiresAtMs === null) return false;
  if (!Number.isSafeInteger(atMs) || atMs <= 0) return false;
  return atMs > member.expiresAtMs;
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

function checkMembersCapability(members, capability, actor, options) {
  const m = members.find(x => x.publicKey === actor);
  if (!m) return false;
  const atMs = options && Number.isSafeInteger(options.atMs) ? options.atMs : 0;
  if (isMemberExpired(m, atMs)) return false;
  if (capability === 'scope') {
    if (m.administrator === true) return true;
    const scope = options && typeof options.scope === 'string' ? options.scope : '';
    if (!scope) return false;
    if (!Array.isArray(m.scopes)) return false;
    return m.scopes.includes('*') || m.scopes.includes(scope);
  }
  if (capability === 'reader') return m.reader === true;
  if (capability === 'writer') return m.writer === true || m.administrator === true;
  if (capability === 'administrator') return m.administrator === true;
  if (capability === 'publisher') return m.publisher === true || m.administrator === true;
  if (capability === 'finalizer') return m.finalizer === true;
  if (capability === 'member') return true;
  return false;
}

function isLegacyReader(perms, author) {
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.reader === true));
}

function attestedMatchesPolicy(cur, attPayload, member) {
  const adm = cur.admission;
  if (!adm || adm.mode === 'strict') return false;
  if (Array.isArray(adm.removed) && adm.removed.includes(member.publicKey)) return false;
  if (cur.members.some(m => m.publicKey === member.publicKey)) return false;
  const accounts = Array.isArray(adm.accounts) ? adm.accounts : [];
  const email = typeof attPayload.email === 'string' ? attPayload.email.toLowerCase() : null;
  const accountOk = accounts.includes(attPayload.accountId) || (email !== null && accounts.includes('email:' + email));
  if (accountOk) {
    if (attPayload.subject === 'agent') {
      return member.administrator !== true && member.finalizer !== true;
    }
    const grant = adm.grant || { reader: true, writer: true, administrator: true };
    return Boolean(member.reader) === Boolean(grant.reader) &&
      Boolean(member.writer) === Boolean(grant.writer) &&
      Boolean(member.administrator) === Boolean(grant.administrator);
  }
  if (attPayload.inviteId && Array.isArray(adm.invites)) {
    const inv = adm.invites.find(i => i.inviteId === attPayload.inviteId && !i.revoked);
    if (!inv) return false;
    if (inv.binding && inv.binding.kind === 'email' && email !== inv.binding.email) return false;
    const expected = inv.role === 'admin'
      ? { reader: true, writer: true, administrator: true }
      : inv.role === 'reader'
        ? { reader: true, writer: false, administrator: false }
        : { reader: true, writer: true, administrator: false };
    return Boolean(member.reader) === expected.reader &&
      Boolean(member.writer) === expected.writer &&
      Boolean(member.administrator) === expected.administrator;
  }
  return false;
}

export const attestedMembers = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? state : { members: [], admission: null };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const authorIsAdmin = isLegacyAdmin(cur, tx.author);

    if (input.action === 'setMember') {
      if (!authorIsAdmin) {
        if (!isLegacyReader(cur, tx.author) || !input.attestation) {
          return { ok: false, code: 'admin_required' };
        }
      }
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
        if (!authorIsAdmin && !attestedMatchesPolicy(cur, att.payload, input.member)) {
          return { ok: false, code: 'admin_required' };
        }
      }
      const next = normalizeMember(input.member);
      const members = cur.members.filter(m => m.publicKey !== next.publicKey).concat([next]);
      members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      let admission = cur.admission;
      if (authorIsAdmin && admission && Array.isArray(admission.removed) && admission.removed.includes(next.publicKey)) {
        admission = { ...admission, removed: admission.removed.filter(k => k !== next.publicKey) };
      }
      return { ok: true, state: { ...cur, members, admission }, events: [{ topic: '$permissions.member', payload: { publicKey: next.publicKey } }] };
    }

    if (input.action === 'requestRecovery') {
      const guardians = cur.guardians;
      if (!guardians || !Array.isArray(guardians.members) || guardians.members.length === 0) {
        return { ok: false, code: 'guardians_not_configured' };
      }
      if (!HEX32.test(input.newPublicKey || '') || !HEX32.test(input.newWrapKey || '')) {
        return { ok: false, code: 'invalid_recovery_key' };
      }
      if (tx.author !== input.newPublicKey && !authorIsAdmin) {
        return { ok: false, code: 'recovery_author_mismatch' };
      }
      const requestId = typeof input.requestId === 'string' && input.requestId.length > 0 ? input.requestId : tx.opId;
      const requests = { ...(cur.recoveryRequests || {}) };
      requests[requestId] = {
        requestId,
        newPublicKey: input.newPublicKey,
        newWrapKey: input.newWrapKey,
        label: typeof input.label === 'string' ? input.label.slice(0, 80) : 'Recovered device',
        verificationCode: typeof input.verificationCode === 'string' ? input.verificationCode.slice(0, 32) : '',
        approvals: [],
        status: 'pending',
        createdAtMs: Number(tx.authorTimestampMs || 0),
      };
      return {
        ok: true,
        state: { ...cur, recoveryRequests: requests },
        events: [{ topic: '$permissions.recovery_requested', payload: { requestId, newPublicKey: input.newPublicKey } }],
      };
    }

    if (input.action === 'approveRecovery') {
      const guardians = cur.guardians;
      if (!guardians || !Array.isArray(guardians.members) || !guardians.members.some(g => g.publicKey === tx.author)) {
        return { ok: false, code: 'guardian_required' };
      }
      const requests = { ...(cur.recoveryRequests || {}) };
      const req = requests[input.requestId];
      if (!req || req.status !== 'pending') return { ok: false, code: 'recovery_request_not_found' };
      const approvals = sortedKeys((req.approvals || []).concat([tx.author]));
      const completed = approvals.length >= guardians.threshold;
      requests[input.requestId] = { ...req, approvals, status: completed ? 'completed' : 'pending' };
      let members = cur.members;
      if (completed) {
        const promoted = normalizeMember({
          publicKey: req.newPublicKey,
          wrapKey: req.newWrapKey,
          label: req.label,
          reader: true,
          writer: true,
          administrator: true,
          publisher: true,
          finalizer: false,
        });
        members = cur.members.filter(m => m.publicKey !== promoted.publicKey).concat([promoted]);
        members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      }
      return {
        ok: true,
        state: { ...cur, members, recoveryRequests: requests },
        events: [{ topic: completed ? '$permissions.recovery_completed' : '$permissions.recovery_approved', payload: { requestId: input.requestId, guardian: tx.author, approvals: approvals.length, threshold: guardians.threshold } }],
      };
    }

    if (!authorIsAdmin) return { ok: false, code: 'admin_required' };

    if (input.action === 'setGuardians') {
      if (input.guardians === null) {
        return { ok: true, state: { ...cur, guardians: null }, events: [{ topic: '$permissions.guardians_cleared', payload: {} }] };
      }
      const g = input.guardians;
      if (!g || typeof g !== 'object' || !Array.isArray(g.members) || g.members.length === 0) {
        return { ok: false, code: 'invalid_guardians' };
      }
      const cleaned = [];
      const seen = new Set();
      for (const item of g.members) {
        if (!item || !HEX32.test(item.publicKey || '') || !HEX32.test(item.wrapKey || '') || seen.has(item.publicKey)) {
          return { ok: false, code: 'invalid_guardian' };
        }
        seen.add(item.publicKey);
        cleaned.push({
          publicKey: item.publicKey,
          wrapKey: item.wrapKey,
          ...(typeof item.label === 'string' && item.label.length > 0 ? { label: item.label.slice(0, 80) } : {}),
        });
      }
      cleaned.sort((a, b) => (a.publicKey < b.publicKey ? -1 : 1));
      const threshold = Number(g.threshold);
      if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > cleaned.length) {
        return { ok: false, code: 'invalid_guardian_threshold' };
      }
      return {
        ok: true,
        state: { ...cur, guardians: { threshold, members: cleaned } },
        events: [{ topic: '$permissions.guardians_updated', payload: { threshold, count: cleaned.length } }],
      };
    }

    if (input.action === 'removeMember') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const members = cur.members.filter(m => m.publicKey !== input.publicKey);
      if (!members.some(m => m.administrator)) return { ok: false, code: 'last_admin_required' };
      let admission = cur.admission;
      if (admission && typeof admission === 'object') {
        const prevRemoved = Array.isArray(admission.removed) ? admission.removed : [];
        const removed = sortedKeys(prevRemoved.concat([input.publicKey])).slice(-512);
        admission = { ...admission, removed };
      }
      return { ok: true, state: { ...cur, members, admission }, events: [{ topic: '$permissions.removed', payload: { publicKey: input.publicKey } }] };
    }

    if (input.action === 'createInvite') {
      const inv = input.invite;
      if (!inv || typeof inv !== 'object' || typeof inv.inviteId !== 'string' || inv.inviteId.length < 1 || inv.inviteId.length > 128) {
        return { ok: false, code: 'invalid_invite' };
      }
      const admission = cur.admission && typeof cur.admission === 'object' ? cur.admission : { mode: 'attested' };
      const invites = (Array.isArray(admission.invites) ? admission.invites : []).filter(i => i.inviteId !== inv.inviteId).concat([{ ...inv, revoked: false }]).slice(-128);
      return { ok: true, state: { ...cur, admission: { ...admission, invites } }, events: [{ topic: '$permissions.invite_created', payload: { inviteId: inv.inviteId } }] };
    }

    if (input.action === 'revokeInvite') {
      if (typeof input.inviteId !== 'string' || !input.inviteId) return { ok: false, code: 'invalid_invite' };
      const admission = cur.admission && typeof cur.admission === 'object' ? cur.admission : null;
      if (!admission || !Array.isArray(admission.invites)) return { ok: false, code: 'invite_not_found' };
      let found = false;
      const invites = admission.invites.map(i => {
        if (i.inviteId !== input.inviteId) return i;
        found = true;
        return { ...i, revoked: true };
      });
      if (!found) return { ok: false, code: 'invite_not_found' };
      return { ok: true, state: { ...cur, admission: { ...admission, invites } }, events: [{ topic: '$permissions.invite_revoked', payload: { inviteId: input.inviteId } }] };
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
        if (input.check === 'guardian') {
          return Boolean(cur.guardians && Array.isArray(cur.guardians.members) && cur.guardians.members.some(g => g.publicKey === input.actor));
        }
        return checkMembersCapability(members, input.check, input.actor, input);
      }
      if (typeof input.list === 'string') {
        if (input.list === 'guardians') return cur.guardians && Array.isArray(cur.guardians.members) ? cur.guardians.members.map(g => g.publicKey) : [];
        return queryMembersList(members, input.list);
      }
      if (input.guardians === true) {
        return { guardians: cur.guardians ?? null, recoveryRequests: cur.recoveryRequests ?? {} };
      }
      if (input.admission === true) {
        return cur.admission ?? null;
      }
      if (input.summary === true) {
        return {
          mode: 'attested',
          members,
          readers: queryMembersList(members, 'readers'),
          writers: queryMembersList(members, 'writers'),
          administrators: queryMembersList(members, 'administrators'),
          publishers: queryMembersList(members, 'publishers'),
          openReaders: false,
          openWriters: false,
          blockedAuthors: [],
          admission: cur.admission ?? null,
          guardians: cur.guardians ?? null,
          recoveryRequests: cur.recoveryRequests ?? {},
          multisig: null,
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
          blockedAuthors: Array.isArray(state.blockedAuthors) ? state.blockedAuthors : [],
          vouchedAuthors: Array.isArray(state.vouchedAuthors) ? state.vouchedAuthors : [],
          antiSpam: state.antiSpam && typeof state.antiSpam === 'object' ? state.antiSpam : null,
          admission: state.admission ?? null,
        }
      : { admins: [], members: [], openRead: true, openWrite: true, blockedAuthors: [], vouchedAuthors: [], antiSpam: null, admission: null };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };

    if (input.action === 'vouchAuthor') {
      const canVouch = cur.admins.includes(tx.author) || cur.vouchedAuthors.includes(tx.author);
      if (!canVouch) return { ok: false, code: 'vouch_permission_required' };
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      if (cur.blockedAuthors.includes(input.publicKey)) return { ok: false, code: 'author_blocked' };
      const vouchedAuthors = sortedKeys(cur.vouchedAuthors.concat([input.publicKey])).slice(-4096);
      return { ok: true, state: { ...cur, vouchedAuthors }, events: [{ topic: '$permissions.author_vouched', payload: { publicKey: input.publicKey, by: tx.author } }] };
    }

    if (!cur.admins.includes(tx.author)) return { ok: false, code: 'admin_required' };

    if (input.action === 'setAntiSpam') {
      if (input.antiSpam === null) {
        return { ok: true, state: { ...cur, antiSpam: null } };
      }
      const cfg = input.antiSpam;
      if (!cfg || typeof cfg !== 'object') return { ok: false, code: 'invalid_antispam' };
      const next = {
        requireVouch: Boolean(cfg.requireVouch),
        ...(Number.isSafeInteger(cfg.maxOpsPerWindow) && cfg.maxOpsPerWindow > 0 ? { maxOpsPerWindow: cfg.maxOpsPerWindow } : {}),
        ...(Number.isSafeInteger(cfg.windowMs) && cfg.windowMs > 0 ? { windowMs: cfg.windowMs } : {}),
      };
      return { ok: true, state: { ...cur, antiSpam: next }, events: [{ topic: '$permissions.antispam_updated', payload: next }] };
    }

    if (input.action === 'setAdmin') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const admins = input.enabled === false
        ? cur.admins.filter(k => k !== input.publicKey)
        : sortedKeys(cur.admins.concat([input.publicKey]));
      if (admins.length === 0) return { ok: false, code: 'last_admin_required' };
      const blockedAuthors = input.enabled === false
        ? cur.blockedAuthors
        : cur.blockedAuthors.filter(k => k !== input.publicKey);
      return { ok: true, state: { ...cur, admins, blockedAuthors }, events: [{ topic: '$permissions.admin', payload: { publicKey: input.publicKey, enabled: input.enabled !== false } }] };
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

    if (input.action === 'blockAuthor') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      if (cur.admins.includes(input.publicKey)) return { ok: false, code: 'cannot_block_admin' };
      const blockedAuthors = sortedKeys(cur.blockedAuthors.concat([input.publicKey])).slice(-2048);
      return {
        ok: true,
        state: { ...cur, blockedAuthors },
        events: [{ topic: '$permissions.author_blocked', payload: { publicKey: input.publicKey, ...(typeof input.reason === 'string' && input.reason ? { reason: input.reason.slice(0, 160) } : {}) } }],
      };
    }

    if (input.action === 'unblockAuthor') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const blockedAuthors = cur.blockedAuthors.filter(k => k !== input.publicKey);
      return {
        ok: true,
        state: { ...cur, blockedAuthors },
        events: [{ topic: '$permissions.author_unblocked', payload: { publicKey: input.publicKey } }],
      };
    }

    if (input.action === 'setMember') {
      const next = normalizeMember(input.member);
      const members = cur.members.filter(m => m.publicKey !== next.publicKey).concat([next]);
      members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      const admins = next.administrator ? sortedKeys(cur.admins.concat([next.publicKey])) : cur.admins;
      const blockedAuthors = next.administrator ? cur.blockedAuthors.filter(k => k !== next.publicKey) : cur.blockedAuthors;
      return { ok: true, state: { ...cur, admins, members, blockedAuthors }, events: [{ topic: '$permissions.member', payload: { publicKey: next.publicKey } }] };
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
          blockedAuthors: Array.isArray(state.blockedAuthors) ? sortedKeys(state.blockedAuthors.filter(k => HEX32.test(k || ''))) : [],
          vouchedAuthors: Array.isArray(state.vouchedAuthors) ? sortedKeys(state.vouchedAuthors.filter(k => HEX32.test(k || ''))) : [],
          antiSpam: state.antiSpam && typeof state.antiSpam === 'object' ? state.antiSpam : null,
          admission: state.admission ?? null,
        }
      : { admins: [], members: [], openRead: true, openWrite: true, blockedAuthors: [], vouchedAuthors: [], antiSpam: null, admission: null };

    const adminSet = new Set(cur.admins);
    const blockedSet = new Set(cur.blockedAuthors);
    const vouchedSet = new Set(cur.vouchedAuthors);
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
        if (input.check === 'blocked') return blockedSet.has(input.actor);
        if (input.check === 'administrator') return adminSet.has(input.actor);
        if (input.check === 'publisher') return adminSet.has(input.actor) || checkMembersCapability(members, 'publisher', input.actor);
        if (input.check === 'writer') {
          if (blockedSet.has(input.actor)) return false;
          if (adminSet.has(input.actor)) return true;
          if (checkMembersCapability(members, 'writer', input.actor, input)) return true;
          if (!cur.openWrite) return false;
          if (cur.antiSpam && cur.antiSpam.requireVouch === true) {
            return vouchedSet.has(input.actor);
          }
          return true;
        }
        if (input.check === 'reader') return cur.openRead || adminSet.has(input.actor) || checkMembersCapability(members, 'reader', input.actor, input);
        if (input.check === 'member') return cur.openWrite || cur.openRead || adminSet.has(input.actor) || checkMembersCapability(members, 'member', input.actor, input);
        return checkMembersCapability(members, input.check, input.actor, input);
      }
      if (typeof input.list === 'string') {
        if (input.list === 'blockedAuthors') return cur.blockedAuthors;
        if (input.list === 'readers' && cur.openRead) return ['*'];
        if (input.list === 'writers' && cur.openWrite) return ['*'];
        return queryMembersList(members, input.list);
      }
      if (input.admission === true) return cur.admission;
      if (input.summary === true) {
        return {
          mode: 'open',
          members,
          readers: cur.openRead ? ['*'] : queryMembersList(members, 'readers'),
          writers: cur.openWrite ? ['*'] : queryMembersList(members, 'writers'),
          administrators: sortedKeys(cur.admins),
          publishers: queryMembersList(members, 'publishers'),
          openReaders: cur.openRead,
          openWriters: cur.openWrite,
          blockedAuthors: cur.blockedAuthors,
          admission: cur.admission,
          multisig: null,
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
    const nextSigners = m.administrator
      ? sortedKeys(cur.signers.concat([m.publicKey]))
      : cur.signers.filter(k => k !== m.publicKey);
    if (nextSigners.length === 0 || nextSigners.length < cur.threshold) {
      return { ok: false, code: 'threshold_unsatisfiable' };
    }
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

    if (input.action === 'cancel') {
      const id = input.proposalId;
      if (typeof id !== 'string' || !cur.proposals[id]) return { ok: false, code: 'proposal_not_found' };
      const nextProposals = { ...cur.proposals };
      delete nextProposals[id];
      return {
        ok: true,
        state: { ...cur, proposals: nextProposals },
        events: [{ topic: '$permissions.cancelled', payload: { proposalId: id } }],
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
          mode: 'multisig',
          members,
          readers: queryMembersList(members, 'readers'),
          writers: queryMembersList(members, 'writers'),
          administrators: queryMembersList(members, 'administrators'),
          publishers: queryMembersList(members, 'publishers'),
          openReaders: false,
          openWriters: false,
          blockedAuthors: [],
          admission: null,
          multisig: {
            threshold: cur.threshold,
            signers: cur.signers,
            proposals: cur.proposals,
          },
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

function isReader(ctx, author) {
  const checked = ctx.query('$permissions', { check: 'reader', actor: author });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.reader === true));
}

function isGuardian(ctx, author) {
  const checked = ctx.query('$permissions', { check: 'guardian', actor: author });
  return checked === true;
}

const RING_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export const hpkeEpochs = {
  reduce(state, tx, ctx) {
    const cur = state && typeof state === 'object' ? state : { currentEpoch: -1, epochs: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };

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
        if (!HEX32.test(pk) || !item || !Number.isSafeInteger(item.index) || item.index < 1 || item.index > 255 || !item.box || typeof item.box.encapsulatedKey !== 'string' || typeof item.box.ciphertext !== 'string') {
          return { ok: false, code: 'guardian_share_invalid' };
        }
        guardianShares[pk] = { index: item.index, box: { encapsulatedKey: item.box.encapsulatedKey, ciphertext: item.box.ciphertext } };
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
      if (!HEX32.test(input.member || '') || !Number.isSafeInteger(input.index) || input.index < 1 || input.index > 255 || !input.box || typeof input.box.encapsulatedKey !== 'string' || typeof input.box.ciphertext !== 'string') {
        return { ok: false, code: 'recovery_share_invalid' };
      }
      const recoveryGrants = { ...(cur.recoveryGrants || {}) };
      const forMember = { ...(recoveryGrants[input.member] || {}) };
      forMember[tx.author] = {
        index: input.index,
        box: { encapsulatedKey: input.box.encapsulatedKey, ciphertext: input.box.ciphertext },
      };
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
      if (!HEX32.test(input.keyCommitment || '')) return { ok: false, code: 'key_commitment_invalid' };
      if (!input.boxes || typeof input.boxes !== 'object') return { ok: false, code: 'boxes_invalid' };
      const boxes = {};
      for (const [pk, box] of Object.entries(input.boxes)) {
        if (!HEX32.test(pk) || !box || typeof box.encapsulatedKey !== 'string' || typeof box.ciphertext !== 'string') {
          return { ok: false, code: 'box_invalid' };
        }
        boxes[pk] = { encapsulatedKey: box.encapsulatedKey, ciphertext: box.ciphertext };
      }
      rings[ringName] = {
        currentEpoch: epoch,
        epochs: { ...prevRing.epochs, [String(epoch)]: { epoch, keyCommitment: input.keyCommitment, boxes } },
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
        events: [{ topic: '$keys.ring_rotated', payload: { ring: ringName, epoch } }],
      };
    }

    if (input.action === 'grantRingBoxes') {
      if (!isAdmin(ctx, tx.author) && !isReader(ctx, tx.author)) return { ok: false, code: 'reader_required' };
      const ringName = typeof input.ring === 'string' && RING_RE.test(input.ring) ? input.ring : null;
      const rings = { ...(cur.rings || {}) };
      if (!ringName || !rings[ringName]) return { ok: false, code: 'ring_not_found' };
      if (!HEX32.test(input.member || '') || !input.epochBoxes || typeof input.epochBoxes !== 'object') {
        return { ok: false, code: 'grant_boxes_invalid' };
      }
      const nextEpochs = { ...rings[ringName].epochs };
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
      rings[ringName] = { ...rings[ringName], epochs: nextEpochs };
      return {
        ok: true,
        state: { ...cur, rings },
        events: [{ topic: '$keys.ring_granted', payload: { ring: ringName, member: input.member } }],
      };
    }

    if (input.action === 'rotateEpoch') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
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
        state: { ...cur, currentEpoch: epoch, epochs: nextEpochs },
        events: [{ topic: '$keys.rotated', payload: { epoch } }],
      };
    }

    // Grant a newly admitted fresh device lockboxes for one or more retained historical epochs (0..N or checkpointEpoch..N).
    // Any existing reader holding the epoch keys may seal lockboxes for an already-authorized reader in $permissions.
    if (input.action === 'grantBoxes') {
      if (!isAdmin(ctx, tx.author) && !isReader(ctx, tx.author)) return { ok: false, code: 'reader_required' };
      if (!HEX32.test(input.member || '') || !input.epochBoxes || typeof input.epochBoxes !== 'object') {
        return { ok: false, code: 'grant_boxes_invalid' };
      }
      if (!isAdmin(ctx, tx.author) && !isReader(ctx, input.member)) {
        return { ok: false, code: 'member_not_authorized' };
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
        state: { ...cur, currentEpoch: cur.currentEpoch, epochs: nextEpochs },
        events: [{ topic: '$keys.granted', payload: { member: input.member } }],
      };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const cur = state || { currentEpoch: -1, epochs: {} };
    if (input && typeof input === 'object') {
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
              out[ep] = { epoch: entry.epoch, keyCommitment: entry.keyCommitment, box: entry.boxes[input.member] };
            }
          }
          return { ring: input.ring, currentEpoch: ring.currentEpoch, memberEpochs: out };
        }
        return ring;
      }
      if (input.member) {
        const out = {};
        for (const [ep, entry] of Object.entries(cur.epochs || {})) {
          if (entry.boxes && entry.boxes[input.member]) {
            out[ep] = { epoch: entry.epoch, keyCommitment: entry.keyCommitment, box: entry.boxes[input.member] };
          }
        }
        return { currentEpoch: cur.currentEpoch, memberEpochs: out };
      }
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

function validPublicationPath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 512 || path.startsWith('/')) return false;
  for (let i = 0; i < path.length; i++) {
    const code = path.charCodeAt(i);
    if (code < 0x20 || code === 0x7f || code === 0x5c) return false;
  }
  const parts = path.split('/');
  return !parts.some(p => p.length === 0 || p === '.' || p === '..');
}

export const signedReleases = {
  reduce(state, tx, ctx) {
    if (!isPublisher(ctx, tx.author)) return { ok: false, code: 'publisher_required' };
    const cur = state && typeof state === 'object' ? state : { revision: 0, current: null, history: [] };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_publication' };

    if (input.action === 'rollback') {
      const hist = Array.isArray(cur.history) ? cur.history : [];
      const target = input.opId !== undefined
        ? hist.find(r => r.opId === input.opId)
        : Number.isSafeInteger(input.revision)
          ? hist.find(r => r.revision === input.revision)
          : null;
      if (!target || !Array.isArray(target.files)) return { ok: false, code: 'publication_not_found' };
      const revision = cur.revision + 1;
      const release = {
        revision,
        opId: tx.opId,
        author: tx.author,
        timestampMs: tx.authorTimestampMs,
        entry: target.entry,
        files: target.files,
        rollbackOf: target.revision,
      };
      const history = hist.concat([release]).slice(-128);
      return {
        ok: true,
        state: { revision, current: release, history },
        events: [{ topic: '$publications.published', payload: { revision, opId: tx.opId, rollbackOf: target.revision } }],
      };
    }

    if (input.action !== 'publish' || typeof input.entry !== 'string' || !Array.isArray(input.files) || input.files.length === 0) {
      return { ok: false, code: 'invalid_publication' };
    }
    if (input.expectedRevision !== undefined && input.expectedRevision !== cur.revision) {
      return { ok: false, code: 'publication_revision_conflict' };
    }
    const files = [];
    const seenPaths = new Set();
    for (const f of input.files) {
      if (!f || !validPublicationPath(f.path) || seenPaths.has(f.path) || !HEX32.test(f.hash || '') || !Number.isSafeInteger(f.size) || f.size < 0 || typeof f.type !== 'string' || f.type.length === 0) {
        return { ok: false, code: 'invalid_publication_file' };
      }
      seenPaths.add(f.path);
      files.push({ path: f.path, hash: f.hash, size: f.size, type: f.type });
    }
    if (!files.some(f => f.path === input.entry)) return { ok: false, code: 'publication_entry_missing' };
    const revision = cur.revision + 1;
    const release = { revision, opId: tx.opId, author: tx.author, timestampMs: tx.authorTimestampMs, entry: input.entry, files };
    const history = (Array.isArray(cur.history) ? cur.history : []).concat([release]).slice(-128);
    return {
      ok: true,
      state: { revision, current: release, history },
      events: [{ topic: '$publications.published', payload: { revision, opId: tx.opId } }],
    };
  },
  query(state, input) {
    const cur = state && typeof state === 'object' ? state : { revision: 0, current: null, history: [] };
    if (input && typeof input === 'object') {
      const hist = Array.isArray(cur.history) ? cur.history : [];
      if (typeof input.opId === 'string') {
        if (cur.current && cur.current.opId === input.opId) return cur.current;
        return hist.find(r => r.opId === input.opId) || null;
      }
      if (Number.isSafeInteger(input.revision)) {
        if (cur.current && cur.current.revision === input.revision) return cur.current;
        return hist.find(r => r.revision === input.revision) || null;
      }
      if (input.history === true) return hist;
    }
    return cur;
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

/**
 * Install automatic row-version stamping triggers on tables that have '_last_op_id TEXT'
 * (and optional '_updated_at INTEGER') columns. Powers 1-line 'based_on_row' optimistic concurrency.
 */
export function stampRowOp(db, tables, options = {}) {
  const list = Array.isArray(tables) ? tables : [tables];
  const withUpdatedAt = options && options.updatedAt === true;
  for (const table of list) {
    const qTable = quoteIdent(table);
    const insName = '_rls_stamp_' + table + '_ins';
    const updName = '_rls_stamp_' + table + '_upd';
    db.exec('DROP TRIGGER IF EXISTS "' + insName + '"', [], { mode: 'admin' });
    db.exec('DROP TRIGGER IF EXISTS "' + updName + '"', [], { mode: 'admin' });
    const setClause = withUpdatedAt
      ? '_last_op_id = op_id(), _updated_at = op_time()'
      : '_last_op_id = op_id()';
    db.exec(
      'CREATE TRIGGER "' + insName + '" AFTER INSERT ON ' + qTable +
      ' WHEN NEW._last_op_id IS NOT op_id() BEGIN UPDATE ' + qTable +
      ' SET ' + setClause + ' WHERE rowid = NEW.rowid; END',
      [],
      { mode: 'admin' },
    );
    db.exec(
      'CREATE TRIGGER "' + updName + '" AFTER UPDATE ON ' + qTable +
      ' WHEN NEW._last_op_id IS NOT op_id() BEGIN UPDATE ' + qTable +
      ' SET ' + setClause + ' WHERE rowid = NEW.rowid; END',
      [],
      { mode: 'admin' },
    );
  }
}

export function ensureConflictsTable(db) {
  db.exec(
    'CREATE TABLE IF NOT EXISTS _chronolog_conflicts (' +
    'op_id TEXT PRIMARY KEY NOT NULL, ' +
    'author TEXT NOT NULL, ' +
    'author_time INTEGER NOT NULL, ' +
    'code TEXT NOT NULL, ' +
    'detail TEXT, ' +
    'payload_json TEXT NOT NULL, ' +
    'resolved INTEGER NOT NULL DEFAULT 0, ' +
    'resolution TEXT' +
    ')',
    [],
    { mode: 'admin' },
  );
}

export function recordConflict(db, tx, failure) {
  ensureConflictsTable(db);
  db.exec(
    'INSERT OR REPLACE INTO _chronolog_conflicts (op_id, author, author_time, code, detail, payload_json, resolved, resolution) VALUES (?, ?, ?, ?, ?, ?, 0, NULL)',
    [
      String(tx.opId),
      String(tx.author),
      Number(tx.authorTimestampMs || 0),
      String((failure && failure.code) || 'assumption:failed'),
      failure && failure.detail ? String(failure.detail) : null,
      JSON.stringify(tx.payload === undefined ? null : tx.payload),
    ],
    { mode: 'admin' },
  );
}

export function ensureAuditTable(db) {
  db.exec(
    'CREATE TABLE IF NOT EXISTS _chronolog_audit (' +
    'seq INTEGER PRIMARY KEY AUTOINCREMENT, ' +
    'table_name TEXT NOT NULL, ' +
    'row_rowid INTEGER NOT NULL, ' +
    'action TEXT NOT NULL, ' +
    'actor TEXT NOT NULL, ' +
    'op_id TEXT NOT NULL, ' +
    'op_time INTEGER NOT NULL, ' +
    'before_json TEXT, ' +
    'after_json TEXT' +
    ')',
    [],
    { mode: 'admin' },
  );
}

/**
 * Install deterministic AFTER INSERT/UPDATE/DELETE audit triggers on tables, recording
 * actor(), op_id(), op_time(), and JSON row snapshots into _chronolog_audit.
 */
export function enableAuditLog(db, tables) {
  ensureAuditTable(db);
  const list = Array.isArray(tables) ? tables : [tables];
  for (const table of list) {
    const qTable = quoteIdent(table);
    const info = db.query('SELECT * FROM ' + qTable + ' LIMIT 0', []);
    const cols = Array.isArray(info.columns) ? info.columns : [];
    const quoteCol = c => {
      if (typeof c !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(c)) {
        throw new Error('RLS_INVALID_COLUMN:' + String(c));
      }
      return '"' + c + '"';
    };
    const buildJsonObj = prefix => {
      if (cols.length === 0) return "'{}'";
      const pairs = cols.map(c => "'" + String(c).replace(/'/g, "''") + "', " + prefix + '.' + quoteCol(c));
      return 'json_object(' + pairs.join(', ') + ')';
    };
    const insTrig = '_rls_audit_' + table + '_ins';
    const updTrig = '_rls_audit_' + table + '_upd';
    const delTrig = '_rls_audit_' + table + '_del';
    db.exec('DROP TRIGGER IF EXISTS "' + insTrig + '"', [], { mode: 'admin' });
    db.exec('DROP TRIGGER IF EXISTS "' + updTrig + '"', [], { mode: 'admin' });
    db.exec('DROP TRIGGER IF EXISTS "' + delTrig + '"', [], { mode: 'admin' });
    db.exec(
      'CREATE TRIGGER "' + insTrig + '" AFTER INSERT ON ' + qTable +
      " BEGIN INSERT INTO _chronolog_audit (table_name, row_rowid, action, actor, op_id, op_time, before_json, after_json) VALUES ('" +
      table + "', NEW.rowid, 'insert', actor(), op_id(), op_time(), NULL, " + buildJsonObj('NEW') + '); END',
      [],
      { mode: 'admin' },
    );
    db.exec(
      'CREATE TRIGGER "' + updTrig + '" AFTER UPDATE ON ' + qTable +
      " BEGIN INSERT INTO _chronolog_audit (table_name, row_rowid, action, actor, op_id, op_time, before_json, after_json) VALUES ('" +
      table + "', NEW.rowid, 'update', actor(), op_id(), op_time(), " + buildJsonObj('OLD') + ', ' + buildJsonObj('NEW') + '); END',
      [],
      { mode: 'admin' },
    );
    db.exec(
      'CREATE TRIGGER "' + delTrig + '" AFTER DELETE ON ' + qTable +
      " BEGIN INSERT INTO _chronolog_audit (table_name, row_rowid, action, actor, op_id, op_time, before_json, after_json) VALUES ('" +
      table + "', OLD.rowid, 'delete', actor(), op_id(), op_time(), " + buildJsonObj('OLD') + ', NULL); END',
      [],
      { mode: 'admin' },
    );
  }
}

export function queryAuditHistory(db, options = {}) {
  const hasTable = db.query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_chronolog_audit'", []);
  if (hasTable.rows.length === 0) return [];
  const limit = Number.isSafeInteger(options.limit) && options.limit > 0 ? Math.min(options.limit, 500) : 100;
  const where = [];
  const params = [];
  if (typeof options.table === 'string' && options.table.length > 0) {
    where.push('table_name = ?');
    params.push(options.table);
  }
  if (typeof options.opId === 'string' && options.opId.length > 0) {
    where.push('op_id = ?');
    params.push(options.opId);
  }
  const whereSql = where.length > 0 ? ' WHERE ' + where.join(' AND ') : '';
  params.push(limit);
  const res = db.query(
    'SELECT seq, table_name, row_rowid, action, actor, op_id, op_time, before_json, after_json FROM _chronolog_audit' +
    whereSql + ' ORDER BY seq DESC LIMIT ?',
    params,
  );
  return res.rows.map(r => ({
    seq: r[0],
    table: r[1],
    rowid: r[2],
    action: r[3],
    actor: r[4],
    opId: r[5],
    opTimeMs: r[6],
    before: r[7] ? JSON.parse(String(r[7])) : null,
    after: r[8] ? JSON.parse(String(r[8])) : null,
  }));
}
`.trimStart()

export const STD_SQL_SOURCE = `
import { openDb } from 'chronolog:sqlite';
import { applyRls, enableAuditLog, ensureConflictsTable, getOwnedTables, queryAuditHistory, recordConflict, recordTableOwners, stampRowOp } from 'chronolog/rls';

function extractTouchedTables(sql) {
  const out = [];
  const re = /(?:INSERT\\s+(?:OR\\s+\\w+\\s+)?INTO|UPDATE\\s+(?:OR\\s+\\w+\\s+)?|DELETE\\s+FROM|CREATE\\s+(?:VIRTUAL\\s+)?TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?|ALTER\\s+TABLE|DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?)\\s+["']?([A-Za-z_][A-Za-z0-9_]*)["']?/gi;
  let m;
  while ((m = re.exec(String(sql))) !== null) {
    if (m[1] && !out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

function hasCapability(ctx, capability, actor, extra) {
  const queryInput = extra ? { check: capability, actor, ...extra } : { check: capability, actor };
  const checked = ctx.query('$permissions', queryInput);
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

function quoteSqlIdent(name) {
  if (typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error('SQL_INVALID_IDENTIFIER:' + String(name));
  }
  return '"' + name + '"';
}

function buildWhereClause(whereObj) {
  if (!whereObj || typeof whereObj !== 'object' || Array.isArray(whereObj)) {
    throw new Error('PRECONDITION_WHERE_INVALID');
  }
  const keys = Object.keys(whereObj).sort();
  if (keys.length === 0) throw new Error('PRECONDITION_WHERE_EMPTY');
  const clauses = [];
  const params = [];
  for (const k of keys) {
    const val = whereObj[k];
    if (val === null) {
      clauses.push(quoteSqlIdent(k) + ' IS NULL');
    } else {
      clauses.push(quoteSqlIdent(k) + ' = ?');
      params.push(val);
    }
  }
  return { clause: clauses.join(' AND '), params };
}

function checkPreconditions(db, preconditions) {
  if (!Array.isArray(preconditions)) return { ok: true };
  for (let i = 0; i < preconditions.length; i++) {
    const pre = preconditions[i];
    if (!pre || typeof pre !== 'object') {
      return { ok: false, code: 'sql:invalid_precondition', detail: 'Precondition ' + i + ' invalid' };
    }
    const failCode = typeof pre.code === 'string' && pre.code.length > 0 ? pre.code : 'sql:precondition_failed';

    if (pre.kind === 'based_on_row') {
      try {
        const qTable = quoteSqlIdent(pre.table);
        const { clause, params } = buildWhereClause(pre.where);
        const res = db.query('SELECT _last_op_id FROM ' + qTable + ' WHERE ' + clause, params);
        if (pre.lastOpId === null) {
          if (res.rows.length > 0) {
            return { ok: false, code: failCode === 'sql:precondition_failed' ? 'sql:row_already_exists' : failCode, detail: 'Expected row to not exist in ' + pre.table };
          }
          continue;
        }
        if (res.rows.length !== 1) {
          return { ok: false, code: failCode === 'sql:precondition_failed' ? 'sql:row_missing' : failCode, detail: 'Expected 1 row in ' + pre.table + ', got ' + res.rows.length };
        }
        if (res.rows[0][0] !== pre.lastOpId) {
          return { ok: false, code: failCode === 'sql:precondition_failed' ? 'sql:row_modified' : failCode, detail: 'Row in ' + pre.table + ' modified (expected op ' + pre.lastOpId + ', got ' + String(res.rows[0][0]) + ')' };
        }
        continue;
      } catch (err) {
        return { ok: false, code: failCode, detail: String(err && err.message ? err.message : err) };
      }
    }

    if (pre.kind === 'row_matches') {
      try {
        const qTable = quoteSqlIdent(pre.table);
        const { clause, params } = buildWhereClause(pre.where);
        const expectObj = pre.expect && typeof pre.expect === 'object' && !Array.isArray(pre.expect) ? pre.expect : null;
        if (!expectObj) return { ok: false, code: 'sql:invalid_precondition', detail: 'row_matches requires expect object' };
        const cols = Object.keys(expectObj).sort();
        if (cols.length === 0) return { ok: false, code: 'sql:invalid_precondition', detail: 'row_matches expect empty' };
        const sel = cols.map(quoteSqlIdent).join(', ');
        const res = db.query('SELECT ' + sel + ' FROM ' + qTable + ' WHERE ' + clause, params);
        if (res.rows.length !== 1) {
          return { ok: false, code: failCode, detail: 'Expected 1 matching row in ' + pre.table + ', got ' + res.rows.length };
        }
        for (let c = 0; c < cols.length; c++) {
          const actual = res.rows[0][c];
          const expected = expectObj[cols[c]];
          if (JSON.stringify(actual) !== JSON.stringify(expected)) {
            return { ok: false, code: failCode, detail: 'Column ' + cols[c] + ' expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual) };
          }
        }
        continue;
      } catch (err) {
        return { ok: false, code: failCode, detail: String(err && err.message ? err.message : err) };
      }
    }

    if (typeof pre.sql !== 'string') {
      return { ok: false, code: 'sql:invalid_precondition', detail: 'Precondition ' + i + ' missing sql' };
    }
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
    if (exp.exists !== undefined) {
      const hasRows = res.rows.length > 0;
      if (hasRows !== Boolean(exp.exists)) {
        return { ok: false, code: failCode, detail: 'Expected exists=' + Boolean(exp.exists) + ', got ' + hasRows };
      }
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

function mergeRlsPolicies(existing, incoming) {
  const next = { ...existing };
  const toApply = {};
  for (const [table, rule] of Object.entries(incoming)) {
    if (rule === null) {
      delete next[table];
      toApply[table] = { insert: null, update: null, delete: null };
      continue;
    }
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new Error('RLS_POLICIES_INVALID');
    }
    const merged = { ...(existing[table] || {}), ...rule };
    const clean = {};
    for (const op of ['insert', 'update', 'delete']) {
      if (merged[op] !== undefined && merged[op] !== null) clean[op] = merged[op];
    }
    if (Object.keys(clean).length === 0) delete next[table];
    else next[table] = clean;
    toApply[table] = {
      insert: merged.insert ?? null,
      update: merged.update ?? null,
      delete: merged.delete ?? null,
    };
  }
  return { nextPolicies: next, toApply };
}

/**
 * First-class deterministic Merkle-paged SQLite topic reducer.
 * - Declarative SQL transactions with atomic preconditions, postconditions, and automatic rollback on failure
 * - Postgres-style write RLS policies (chronolog/rls) + host-bound actor()/op_id()/op_time()
 * - Admin DDL (mode:'admin') and non-admin user-owned dynamic table & view DDL (mode:'user')
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
    const atMs = Number(tx.authorTimestampMs || 0);
    const isAdmin = hasCapability(ctx, 'administrator', tx.author, { atMs });
    const isWriter = allowPublicWrite || isAdmin || hasCapability(ctx, 'writer', tx.author, { atMs });
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
        const { nextPolicies, toApply } = mergeRlsPolicies(cur.policies, input.policies);
        applyRls(db, toApply);
        const dbRoot = db.commit();
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
        if (!preCheck.ok) {
          if (input.onPreconditionFailed === 'record_conflict') {
            recordConflict(db, tx, preCheck);
            const dbRoot = db.commit();
            return {
              ok: true,
              state: { ...cur, dbRoot },
              events: [{ topic: 'sql.conflict_recorded', payload: { opId: tx.opId, code: preCheck.code, detail: preCheck.detail || null } }],
            };
          }
          return preCheck;
        }
        for (const rawStmt of statements) {
          const stmt = normalizeStatement(rawStmt);
          if (!stmt) return { ok: false, code: 'sql:invalid_statement' };
          db.exec(stmt.sql, stmt.params, { mode: 'admin' });
        }
        let nextPolicies = cur.policies;
        if (input.policies && typeof input.policies === 'object' && !Array.isArray(input.policies)) {
          const merged = mergeRlsPolicies(cur.policies, input.policies);
          applyRls(db, merged.toApply);
          nextPolicies = merged.nextPolicies;
        }
        if (Array.isArray(input.stampTables) && input.stampTables.length > 0) {
          stampRowOp(db, input.stampTables, { updatedAt: input.stampUpdatedAt === true });
        }
        if (Array.isArray(input.auditTables) && input.auditTables.length > 0) {
          enableAuditLog(db, input.auditTables);
        }
        const postCheck = checkPreconditions(db, input.postconditions);
        if (!postCheck.ok) return postCheck;
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
      if (!isAdmin && typeof input.requiredScope === 'string' && input.requiredScope.length > 0) {
        if (!hasCapability(ctx, 'scope', tx.author, { scope: input.requiredScope, atMs })) {
          return { ok: false, code: 'scope_required', detail: input.requiredScope };
        }
      }
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
        if (!preCheck.ok) {
          if (input.onPreconditionFailed === 'record_conflict') {
            recordConflict(db, tx, preCheck);
            const dbRoot = db.commit();
            return {
              ok: true,
              state: { ...cur, dbRoot },
              events: [{ topic: 'sql.conflict_recorded', payload: { opId: tx.opId, code: preCheck.code, detail: preCheck.detail || null } }],
            };
          }
          return preCheck;
        }

        let owned = mode === 'user' && cur.allowUserDdl ? getOwnedTables(db, tx.author) : null;
        const touchedSet = new Set();
        for (const rawStmt of statements) {
          const stmt = normalizeStatement(rawStmt);
          if (!stmt) return { ok: false, code: 'sql:invalid_statement' };
          for (const tbl of extractTouchedTables(stmt.sql)) touchedSet.add(tbl);
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
          const created = (res.createdTables || []).concat(res.createdViews || []);
          const dropped = (res.droppedTables || []).concat(res.droppedViews || []);
          for (const tbl of created) touchedSet.add(tbl);
          for (const tbl of dropped) touchedSet.add(tbl);
          if (mode === 'user' && cur.allowUserDdl && (created.length > 0 || dropped.length > 0)) {
            recordTableOwners(db, created, dropped, tx.author);
            owned = getOwnedTables(db, tx.author);
          }
        }

        const postCheck = checkPreconditions(db, input.postconditions);
        if (!postCheck.ok) return postCheck;

        const dbRoot = db.commit();
        const touchedTables = Array.from(touchedSet).sort();
        const baseEvents = normalizeEvents(input.events);
        const events = touchedTables.length > 0
          ? baseEvents.concat([{ topic: 'sql.tables_changed', payload: { tables: touchedTables, dbRoot } }])
          : baseEvents;
        return {
          ok: true,
          state: { ...cur, dbRoot },
          events,
        };
      } catch (err) {
        return { ok: false, code: extractSqlErrorCode(err), detail: String(err && err.message ? err.message : err) };
      } finally {
        db.close();
      }
    }

    if (action === 'resolveConflict') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      if (typeof input.opId !== 'string' || input.opId.length === 0) return { ok: false, code: 'sql:invalid_conflict_id' };
      const db = openDb(cur.dbRoot);
      try {
        ensureConflictsTable(db);
        const existing = db.query('SELECT author FROM _chronolog_conflicts WHERE op_id = ?', [input.opId]);
        if (existing.rows.length === 0) return { ok: false, code: 'sql:conflict_not_found' };
        if (!isAdmin && existing.rows[0][0] !== tx.author) return { ok: false, code: 'conflict_owner_or_admin_required' };
        db.exec(
          'UPDATE _chronolog_conflicts SET resolved = 1, resolution = ? WHERE op_id = ?',
          [typeof input.resolution === 'string' ? input.resolution : 'resolved', input.opId],
          { mode: 'admin' },
        );
        const dbRoot = db.commit();
        return {
          ok: true,
          state: { ...cur, dbRoot },
          events: normalizeEvents(input.events).concat([{ topic: 'sql.conflict_resolved', payload: { opId: input.opId } }]),
        };
      } catch (err) {
        return { ok: false, code: extractSqlErrorCode(err), detail: String(err && err.message ? err.message : err) };
      } finally {
        db.close();
      }
    }

    return { ok: false, code: 'unknown_action' };
  },

  onConflict(state, tx, ctx, failure) {
    const cur = normalizeSqlState(state, ctx.config);
    const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
    const allowPublicWrite = cfg.allowPublicWrite === true;
    const isAdmin = hasCapability(ctx, 'administrator', tx.author);
    const isWriter = allowPublicWrite || isAdmin || hasCapability(ctx, 'writer', tx.author);
    if (!isWriter) return { ok: false, code: 'writer_required' };
    const db = openDb(cur.dbRoot);
    try {
      recordConflict(db, tx, failure);
      const dbRoot = db.commit();
      return {
        ok: true,
        state: { ...cur, dbRoot },
        events: [{ topic: 'sql.conflict_recorded', payload: { opId: tx.opId, code: (failure && failure.code) || 'assumption:failed', detail: (failure && failure.detail) || null } }],
      };
    } catch (err) {
      return { ok: false, code: extractSqlErrorCode(err), detail: String(err && err.message ? err.message : err) };
    } finally {
      db.close();
    }
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
    const kind = typeof input === 'object' ? (input.query || input.kind || input.action) : null;
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
    if (kind === 'audit') {
      const db = openDb(cur.dbRoot);
      try {
        return { dbRoot: cur.dbRoot, audit: queryAuditHistory(db, input || {}) };
      } finally {
        db.close();
      }
    }
    if (kind === 'conflicts') {
      const db = openDb(cur.dbRoot);
      try {
        const hasTable = db.query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_chronolog_conflicts'", []);
        if (hasTable.rows.length === 0) return { dbRoot: cur.dbRoot, conflicts: [] };
        const unresolvedOnly = input && input.unresolvedOnly !== false;
        const sql = unresolvedOnly
          ? 'SELECT op_id, author, author_time, code, detail, payload_json, resolved, resolution FROM _chronolog_conflicts WHERE resolved = 0 ORDER BY author_time DESC'
          : 'SELECT op_id, author, author_time, code, detail, payload_json, resolved, resolution FROM _chronolog_conflicts ORDER BY author_time DESC';
        const res = db.query(sql, []);
        return {
          dbRoot: cur.dbRoot,
          conflicts: res.rows.map(r => ({
            opId: r[0],
            author: r[1],
            authorTimeMs: r[2],
            code: r[3],
            detail: r[4],
            payload: JSON.parse(String(r[5] || 'null')),
            resolved: Boolean(r[6]),
            resolution: r[7],
          })),
        };
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
        const objects = res.rows.map(r => ({ type: r[0], name: r[1], table: r[2], sql: r[3] }));
        const owners = {};
        const hasOwners = objects.some(o => o.type === 'table' && o.name === '_rls_table_owners');
        if (hasOwners) {
          const ownRes = db.query('SELECT name, owner FROM _rls_table_owners ORDER BY name', []);
          for (const row of ownRes.rows) owners[String(row[0])] = String(row[1]);
        }
        const tables = [];
        for (const obj of objects) {
          if ((obj.type !== 'table' && obj.type !== 'view') || String(obj.name).startsWith('_rls_')) continue;
          const quoted = '"' + String(obj.name).replace(/"/g, '""') + '"';
          let columns = [];
          try {
            const info = db.query('SELECT * FROM ' + quoted + ' LIMIT 0', []);
            columns = Array.isArray(info.columns) ? info.columns.slice() : [];
          } catch {}
          tables.push({
            name: obj.name,
            type: obj.type,
            owner: Object.prototype.hasOwnProperty.call(owners, obj.name) ? owners[obj.name] : null,
            columns,
            rls: Object.prototype.hasOwnProperty.call(cur.policies, obj.name) ? cur.policies[obj.name] : null,
          });
        }
        return {
          dbRoot: cur.dbRoot,
          schemaVersion: cur.schemaVersion,
          policies: cur.policies,
          allowUserDdl: cur.allowUserDdl,
          userOwnedObjects: owners,
          tables,
          objects,
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
              postconditions: {
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

export const STD_SQLITE_HELPERS_SOURCE = `
import { openDb } from 'chronolog:sqlite';
import { applyRls } from 'chronolog/rls';

export function rowsToObjects(res) {
  return (res.rows || []).map(row => {
    const obj = {};
    for (let i = 0; i < res.columns.length; i++) obj[res.columns[i]] = row[i];
    return obj;
  });
}

/**
 * Open a deterministic chronolog:sqlite database, invoke fn(db), auto-close in finally,
 * and optionally commit when mutate === true.
 */
export function withDb(dbRoot, fn, options) {
  const db = openDb(dbRoot ?? null);
  try {
    const value = fn(db);
    if (options && options.commit === true) {
      return { value, dbRoot: db.commit() };
    }
    return value;
  } finally {
    db.close();
  }
}

/**
 * Build a concise, self-describing chronolog:sqlite ES Module reducer with automatic
 * schema/tables/read-only SQL query introspection, permission checks, and write RLS.
 */
export function defineSqlReducer(spec) {
  const commands = (spec && spec.commands) || {};
  const queries = (spec && spec.queries) || {};
  const setup = typeof (spec && spec.setup) === 'function' ? spec.setup : null;
  const policies = (spec && spec.policies) || null;
  const allowPublicWrite = Boolean(spec && spec.allowPublicWrite);

  function checkCap(ctx, cap, actor) {
    const checked = ctx.query('$permissions', { check: cap, actor });
    if (typeof checked === 'boolean') return checked;
    const perms = ctx.topic('$permissions');
    if (!perms || !Array.isArray(perms.members)) return false;
    const m = perms.members.find(x => x.publicKey === actor);
    if (!m) return false;
    if (cap === 'administrator') return m.administrator === true;
    if (cap === 'writer') return m.writer === true || m.administrator === true;
    return m.reader === true;
  }

  return {
    reduce(state, tx, ctx) {
      const cur = state && typeof state === 'object' ? state : { dbRoot: null, initialized: false };
      const input = tx.payload;
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return { ok: false, code: 'invalid_input' };
      }
      const action = typeof input.action === 'string' ? input.action : null;
      const handler = action && Object.prototype.hasOwnProperty.call(commands, action) ? commands[action] : null;
      if (!handler) return { ok: false, code: 'unknown_action' };
      const reqAdmin = Boolean(handler.adminOnly);
      if (reqAdmin) {
        if (!checkCap(ctx, 'administrator', tx.author)) return { ok: false, code: 'admin_required' };
      } else if (!allowPublicWrite && !checkCap(ctx, 'writer', tx.author)) {
        return { ok: false, code: 'writer_required' };
      }
      const db = openDb(cur.dbRoot ?? null);
      try {
        if (!cur.initialized) {
          if (setup) setup(db);
          if (policies) applyRls(db, policies);
        }
        const run = typeof handler === 'function' ? handler : handler.run;
        const out = run(db, input, tx, ctx);
        if (out && out.ok === false) return out;
        const dbRoot = db.commit();
        return {
          ok: true,
          state: { ...cur, dbRoot, initialized: true },
          ...(out && Array.isArray(out.events) ? { events: out.events } : {}),
        };
      } catch (err) {
        const msg = String(err && err.message ? err.message : err);
        const rls = /rls_denied:[A-Za-z0-9_]+:(?:insert|update|delete)/.exec(msg);
        return { ok: false, code: rls ? rls[0] : 'sql:error', detail: msg };
      } finally {
        db.close();
      }
    },
    query(state, input, ctx) {
      const cur = state && typeof state === 'object' ? state : { dbRoot: null, initialized: false };
      const qObj = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
      const qName = typeof qObj.query === 'string' ? qObj.query : (typeof qObj.kind === 'string' ? qObj.kind : null);
      if (qName && Object.prototype.hasOwnProperty.call(queries, qName)) {
        const qHandler = queries[qName];
        const run = typeof qHandler === 'function' ? qHandler : qHandler.run;
        return withDb(cur.dbRoot, db => run(db, qObj, ctx));
      }
      if (typeof qObj.sql === 'string') {
        return withDb(cur.dbRoot, db => {
          const res = db.query(qObj.sql, Array.isArray(qObj.params) ? qObj.params : []);
          return qObj.format === 'objects' ? { columns: res.columns, rows: rowsToObjects(res) } : res;
        });
      }
      if (qName === 'tables') {
        return withDb(cur.dbRoot, db => {
          const res = db.query("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_rls_%' ORDER BY name", []);
          return { dbRoot: cur.dbRoot, tables: res.rows.map(r => ({ name: r[0], type: r[1] })) };
        });
      }
      if (qName === 'schema') {
        return withDb(cur.dbRoot, db => {
          const res = db.query("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name", []);
          const objects = res.rows.map(r => ({ type: r[0], name: r[1], table: r[2], sql: r[3] }));
          const tables = [];
          for (const obj of objects) {
            if ((obj.type !== 'table' && obj.type !== 'view') || String(obj.name).startsWith('_rls_')) continue;
            let columns = [];
            try {
              const info = db.query('SELECT * FROM "' + String(obj.name).replace(/"/g, '""') + '" LIMIT 0', []);
              columns = Array.isArray(info.columns) ? info.columns.slice() : [];
            } catch {}
            tables.push({ name: obj.name, type: obj.type, owner: null, columns, rls: policies && policies[obj.name] ? policies[obj.name] : null });
          }
          return { dbRoot: cur.dbRoot, schemaVersion: 1, policies: policies || {}, allowUserDdl: false, userOwnedObjects: {}, tables, objects };
        });
      }
      return { dbRoot: cur.dbRoot, initialized: Boolean(cur.initialized) };
    },
    describe() {
      return {
        commands: Object.entries(commands).map(([name, entry]) => ({
          name,
          description: (entry && entry.description) || '',
          input: (entry && entry.input) || { type: 'object', properties: {} },
        })),
        queries: [
          ...Object.entries(queries).map(([name, entry]) => ({
            name,
            description: (entry && entry.description) || '',
            input: (entry && entry.input) || { type: 'object', properties: {} },
          })),
          { name: 'schema', description: 'Inspect SQLite-CAS schema tables and RLS policies.', input: { type: 'object', properties: {} } },
          { name: 'tables', description: 'List user tables and views.', input: { type: 'object', properties: {} } },
        ],
      };
    },
  };
}
`.trimStart()

export const STANDARD_MODULE_SOURCES: Readonly<Record<string, string>> = Object.freeze({
  'chronolog/permissions': STD_PERMISSIONS_SOURCE,
  'chronolog/keys': STD_KEYS_SOURCE,
  'chronolog/finality': STD_FINALITY_SOURCE,
  'chronolog/publications': STD_PUBLICATIONS_SOURCE,
  'chronolog/rls': STD_RLS_SOURCE,
  'chronolog/sql': STD_SQL_SOURCE,
  'chronolog/sqlite-helpers': STD_SQLITE_HELPERS_SOURCE,
  'chronolog/crdt': STD_CRDT_SOURCE,
  'chronolog/text': STD_TEXT_SOURCE,
  'chronolog/ledger': STD_LEDGER_SOURCE,
  'chronolog/workflow': STD_WORKFLOW_SOURCE,
  'chronolog/fs': STD_FS_SOURCE,
  'chronolog/mounts': STD_MOUNTS_SOURCE,
  'chronolog/builders': STD_BUILDERS_SOURCE,
  'chronolog/registry': STD_REGISTRY_SOURCE,
})

export const STANDARD_MODULE_BUILTINS: Readonly<Record<string, readonly ChronologBuiltinName[]>> = Object.freeze({
  'chronolog/permissions': ['chronolog:crypto'],
  'chronolog/keys': ['chronolog:crypto'],
  'chronolog/finality': ['chronolog:crypto'],
  'chronolog/publications': ['chronolog:crypto'],
  'chronolog/rls': [],
  'chronolog/sql': ['chronolog:sqlite'],
  'chronolog/sqlite-helpers': ['chronolog:sqlite'],
  'chronolog/crdt': [],
  'chronolog/text': [],
  'chronolog/ledger': [],
  'chronolog/workflow': [],
  'chronolog/fs': ['chronolog:cas'],
  'chronolog/mounts': ['chronolog:crypto'],
  'chronolog/builders': ['chronolog:crypto'],
  'chronolog/registry': ['chronolog:sqlite', 'chronolog:crypto'],
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

/** Seed all standard audited modules as capability-attenuated chronolog-pkg/v1 DAG packages in public CAS. */
export async function seedStandardPackages(cas: ContentAddressedStore): Promise<Record<string, string>> {
  const imports: Record<string, string> = {}
  for (const [spec, src] of Object.entries(STANDARD_MODULE_SOURCES)) {
    const pkg = await putPackageDag(cas, {
      name: spec,
      version: '1.0.0',
      runtime: 'esm-quickjs',
      files: { 'index.js': src },
      exports: { '.': 'index.js' },
      builtins: STANDARD_MODULE_BUILTINS[spec] ?? [],
    }, 'public')
    imports[spec] = pkg.ref
  }
  return imports
}
