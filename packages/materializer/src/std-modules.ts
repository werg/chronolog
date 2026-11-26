import { utf8 } from '@chronolog/canonical'
import { computeCasHash, type ContentAddressedStore } from '@chronolog/records'

export const STD_PERMISSIONS_SOURCE = `
import { verifyEd25519, canonicalJson } from 'chronolog:crypto';

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function isAdmin(perms, author) {
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.administrator === true));
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

export const attestedMembers = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? state : { members: [], admission: null };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    if (!isAdmin(cur, tx.author)) return { ok: false, code: 'admin_required' };

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
    const cur = state || { members: [] };
    if (input && input.publicKey) {
      return cur.members.find(m => m.publicKey === input.publicKey) || null;
    }
    return cur;
  },
};

export const adminOnlyReducers = {
  reduce(state, tx, ctx) {
    const perms = ctx.topic('$permissions');
    if (!isAdmin(perms, tx.author)) return { ok: false, code: 'admin_required' };
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
    const perms = ctx.topic('$permissions');
    if (!isAdmin(perms, tx.author)) return { ok: false, code: 'admin_required' };
    if (!tx.payload || !Array.isArray(tx.payload.rules)) return { ok: false, code: 'invalid_signal_policy' };
    return { ok: true, state: { rules: tx.payload.rules } };
  },
  query(state, _input, ctx) {
    if (state && Array.isArray(state.rules)) return state;
    const perms = ctx.topic('$permissions') || { members: [] };
    const readers = perms.members.filter(m => m.reader).map(m => m.publicKey);
    return {
      rules: [{ topicPattern: '*', allowedAuthors: readers, maxTtlMs: 30000, allowRelay: true }],
    };
  },
};
`.trimStart()

export const STD_KEYS_SOURCE = `
const HEX32 = /^[0-9a-f]{64}$/;

function isAdmin(perms, author) {
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && m.administrator === true));
}

export const hpkeEpochs = {
  reduce(state, tx, ctx) {
    const perms = ctx.topic('$permissions');
    if (!isAdmin(perms, tx.author)) return { ok: false, code: 'admin_required' };
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
function isAdmin(perms, author) {
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
    const perms = ctx.topic('$permissions');
    if (!isAdmin(perms, tx.author)) return { ok: false, code: 'admin_required' };
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

function isPublisher(perms, author) {
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === author && (m.publisher === true || m.administrator === true)));
}

export const signedReleases = {
  reduce(state, tx, ctx) {
    const perms = ctx.topic('$permissions');
    if (!isPublisher(perms, tx.author)) return { ok: false, code: 'publisher_required' };
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

export const STANDARD_MODULE_SOURCES: Readonly<Record<string, string>> = Object.freeze({
  'chronolog/permissions': STD_PERMISSIONS_SOURCE,
  'chronolog/keys': STD_KEYS_SOURCE,
  'chronolog/finality': STD_FINALITY_SOURCE,
  'chronolog/publications': STD_PUBLICATIONS_SOURCE,
  'chronolog/rls': STD_RLS_SOURCE,
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
