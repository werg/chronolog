/**
 * Unified `chronolog/admission` standard module:
 * Replaces separate `$permissions`, `$finality`, `$signal_policy`, and hardcoded finality kinds
 * with ONE state-defined `$admission` topic combining:
 * - `reduce(state, tx, ctx)`: membership/roles/invites/guardians/multisig/open-mode,
 *   time-scoped history admission rules (`open`, `signed-frontier`, `threshold-quorum`,
 *   `member-quorum`, `optimistic-challenge`, `merkle-anchor`, `pinned-checkpoint`, custom `module`),
 *   signal/relay rules, and per-topic access declarations.
 * - `authorize(state, tx, ctx)`: kernel-enforced fail-closed global authorization gate
 *   (local topic reducers can only monotonically tighten, never weaken).
 * - `admit(state, { logId, ops, evidence, pinnedFrontier }, ctx)`: pure read-only history
 *   admission over candidate operations and external evidence (checkpoints, quorum seals,
 *   fraud proofs, Merkle/L1 anchors, surgical descent checkpoints).
 * - `query(state, input, ctx)`: universal `{ kind: 'can' | 'roster' | 'signals' | 'schedule' }` API.
 */
export const STD_ADMISSION_SOURCE = `
import { verifyEd25519, canonicalJson, sha256 } from 'chronolog:crypto';

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function sortedKeys(list) {
  return Array.from(new Set(list)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
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
    if (!scope || !Array.isArray(m.scopes)) return false;
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

function normalizeSchedule(raw) {
  if (!Array.isArray(raw) || raw.length === 0) {
    return [{ effectiveAfterMs: -1, policy: { kind: 'open' } }];
  }
  return raw;
}

function validHistoryPolicy(policy) {
  if (!policy || typeof policy !== 'object') return false;
  if (policy.kind === 'open') return true;
  if (policy.kind === 'signed-frontier') return typeof policy.signer === 'string' && HEX32.test(policy.signer);
  if (policy.kind === 'threshold-quorum') {
    const threshold = Number(policy.threshold);
    if (!Number.isFinite(threshold) || threshold < 1) return false;
    if (Array.isArray(policy.validators)) {
      return policy.validators.length > 0 && policy.validators.every(v => typeof v === 'string' && HEX32.test(v)) && threshold <= policy.validators.length;
    }
    if (policy.validators && typeof policy.validators === 'object') {
      const entries = Object.entries(policy.validators);
      return entries.length > 0 && entries.every(([k, w]) => HEX32.test(k) && typeof w === 'number' && Number.isFinite(w) && w > 0);
    }
    return false;
  }
  if (policy.kind === 'member-quorum') {
    const role = policy.role || 'administrator';
    return (role === 'administrator' || role === 'finalizer' || role === 'member') &&
      Number.isSafeInteger(policy.threshold) && policy.threshold >= 1;
  }
  if (policy.kind === 'optimistic-challenge') {
    return Array.isArray(policy.proposers) && policy.proposers.length > 0 &&
      policy.proposers.every(v => typeof v === 'string' && HEX32.test(v)) &&
      Number.isFinite(Number(policy.challengeWindowMs)) && Number(policy.challengeWindowMs) >= 0;
  }
  if (policy.kind === 'merkle-anchor') {
    const hasSigners = Array.isArray(policy.anchorSigners) && policy.anchorSigners.every(v => typeof v === 'string' && HEX32.test(v));
    const hasRoots = Array.isArray(policy.trustedRoots) && policy.trustedRoots.every(v => typeof v === 'string' && HEX32.test(v));
    return hasSigners || hasRoots;
  }
  if (policy.kind === 'pinned-checkpoint') {
    return Number.isSafeInteger(policy.closedThroughMs) &&
      typeof policy.stateRoot === 'string' && HEX32.test(policy.stateRoot) &&
      typeof policy.historyDigest === 'string' && HEX32.test(policy.historyDigest) &&
      Array.isArray(policy.includedOpIds);
  }
  return false;
}

function scopeIdForEntry(logId, entry) {
  return sha256(canonicalJson(['chronolog/admission-scope/v1', logId, entry.effectiveAfterMs, entry.policy]));
}

function canonicalCheckpointMessage(payload) {
  return canonicalJson(['chronolog/admission-checkpoint/v1', payload]);
}

function verifyCheckpointSig(entry, payload) {
  if (!entry || typeof entry !== 'object') return false;
  if (typeof entry.signer !== 'string' || !HEX32.test(entry.signer)) return false;
  if (typeof entry.signature !== 'string' || !HEX64.test(entry.signature)) return false;
  return verifyEd25519(entry.signer, canonicalCheckpointMessage(payload), entry.signature);
}

function verifyEvidenceForRule(rule, ev, members) {
  const payload = ev && ev.payload;
  const data = ev && ev.data && typeof ev.data === 'object' ? ev.data : {};
  if (!payload || typeof payload !== 'object') return { ok: false, signers: [] };

  if (rule.kind === 'signed-frontier') {
    const sigs = Array.isArray(data.signatures) ? data.signatures : (data.signer ? [data] : []);
    for (const s of sigs) {
      if (s && s.signer === rule.signer && verifyCheckpointSig(s, payload)) {
        return { ok: true, signers: [rule.signer] };
      }
    }
    return { ok: false, signers: [] };
  }

  if (rule.kind === 'threshold-quorum') {
    const weights = {};
    if (Array.isArray(rule.validators)) {
      for (const v of rule.validators) weights[v] = 1;
    } else if (rule.validators && typeof rule.validators === 'object') {
      for (const [k, w] of Object.entries(rule.validators)) weights[k] = Number(w);
    }
    const sigs = Array.isArray(data.signatures) ? data.signatures : [];
    const seen = new Set();
    let total = 0;
    for (const s of sigs) {
      if (!s || typeof s.signer !== 'string' || !Object.prototype.hasOwnProperty.call(weights, s.signer) || seen.has(s.signer)) continue;
      if (verifyCheckpointSig(s, payload)) {
        seen.add(s.signer);
        total += weights[s.signer];
      }
    }
    return { ok: total >= Number(rule.threshold || 1), signers: Array.from(seen) };
  }

  if (rule.kind === 'member-quorum') {
    const role = rule.role || 'administrator';
    const eligible = new Set(
      role === 'member'
        ? members.map(m => m.publicKey)
        : queryMembersList(members, role === 'administrator' ? 'administrators' : 'finalizers'),
    );
    const sigs = Array.isArray(data.signatures) ? data.signatures : [];
    const seen = new Set();
    for (const s of sigs) {
      if (!s || typeof s.signer !== 'string' || !eligible.has(s.signer) || seen.has(s.signer)) continue;
      if (verifyCheckpointSig(s, payload)) seen.add(s.signer);
    }
    return { ok: seen.size >= Number(rule.threshold || 1), signers: Array.from(seen) };
  }

  if (rule.kind === 'optimistic-challenge') {
    const proposers = Array.isArray(rule.proposers) ? rule.proposers : [];
    const challengers = Array.isArray(rule.challengers) ? rule.challengers : proposers;
    const windowMs = Number(rule.challengeWindowMs || 0);
    const closedMs = Number(payload.closedThroughMs || 0);
    const observedMs = Number(data.observedAtMs || 0);
    if (!Number.isFinite(observedMs) || observedMs < closedMs + windowMs) return { ok: false, signers: [] };
    const proposal = data.proposal;
    if (!proposal || !proposers.includes(proposal.signer) || !verifyCheckpointSig(proposal, payload)) {
      return { ok: false, signers: [] };
    }
    const challenges = Array.isArray(data.challenges) ? data.challenges : [];
    for (const ch of challenges) {
      if (!ch || !challengers.includes(ch.signer) || !HEX64.test(ch.signature || '')) continue;
      const chMsg = canonicalJson(['chronolog/admission-challenge/v1', {
        logId: payload.logId,
        scopeId: payload.scopeId || null,
        closedThroughMs: payload.closedThroughMs,
        reason: ch.reason || 'fraud',
      }]);
      if (verifyEd25519(ch.signer, chMsg, ch.signature)) {
        return { ok: false, signers: [] };
      }
    }
    return { ok: true, signers: [proposal.signer] };
  }

  if (rule.kind === 'merkle-anchor') {
    const root = data.root;
    const proof = Array.isArray(data.proof) ? data.proof : null;
    if (typeof root !== 'string' || !HEX32.test(root) || !proof || proof.length > 64) return { ok: false, signers: [] };
    let cur = sha256(canonicalCheckpointMessage(payload));
    for (const step of proof) {
      if (!step || typeof step.sibling !== 'string' || !HEX32.test(step.sibling)) return { ok: false, signers: [] };
      cur = step.position === 'left' ? sha256(step.sibling + cur) : sha256(cur + step.sibling);
    }
    if (cur !== root) return { ok: false, signers: [] };
    const trustedRoots = Array.isArray(rule.trustedRoots) ? rule.trustedRoots : [];
    if (trustedRoots.includes(root)) return { ok: true, signers: [] };
    const signers = Array.isArray(rule.anchorSigners) ? rule.anchorSigners : [];
    const anchorSig = data.anchorSignature;
    if (anchorSig && signers.includes(anchorSig.signer) && HEX64.test(anchorSig.signature || '')) {
      const msg = canonicalJson(['chronolog/merkle-anchor/v1', root]);
      if (verifyEd25519(anchorSig.signer, msg, anchorSig.signature)) {
        return { ok: true, signers: [anchorSig.signer] };
      }
    }
    return { ok: false, signers: [] };
  }

  return { ok: false, signers: [] };
}

/**
 * Evaluate time-scoped history admission + pinned checkpoint descent + equivocation detection.
 */
function evaluateHistoryAdmission(schedule, members, input) {
  const logId = String((input && input.logId) || '');
  const ops = Array.isArray(input && input.ops) ? input.ops : [];
  const evidence = Array.isArray(input && input.evidence) ? input.evidence : [];
  const pinnedFrontier = input && input.pinnedFrontier ? input.pinnedFrontier : null;

  const entries = normalizeSchedule(schedule).map((entry, index) => ({
    index,
    entry,
    scopeId: scopeIdForEntry(logId, entry),
  }));
  const byScope = new Map(entries.map(e => [e.scopeId, e]));

  const includedSet = new Set();
  const verifiedIndices = [];
  const verifiedRecords = [];
  const closedByScopeIndex = new Map();
  let highestClosed = null;
  let latestCheckpointIndex = null;

  // Apply any pinned-checkpoint entries baked into the schedule (surgical descent)
  for (const item of entries) {
    if (item.entry.policy && item.entry.policy.kind === 'pinned-checkpoint') {
      const p = item.entry.policy;
      for (const id of p.includedOpIds || []) includedSet.add(id);
      const c = Number(p.closedThroughMs);
      closedByScopeIndex.set(item.index, c);
      if (highestClosed === null || c > highestClosed) highestClosed = c;
    }
  }

  // Sort evidence chronologically by checkpoint closedThroughMs while keeping original indices
  const indexed = evidence
    .map((ev, origIdx) => ({ ev, origIdx, closedMs: ev && ev.payload && typeof ev.payload === 'object' ? Number(ev.payload.closedThroughMs) : NaN }))
    .filter(x => x.ev && x.ev.payload && typeof x.ev.payload === 'object' && x.ev.payload.logId === logId && Number.isSafeInteger(x.closedMs))
    .sort((a, b) => a.closedMs - b.closedMs || a.origIdx - b.origIdx);

  for (const item of indexed) {
    const ev = item.ev;
    const p = ev.payload;
    let scope = typeof p.scopeId === 'string' ? byScope.get(p.scopeId) : undefined;
    if (!scope) {
      // If scopeId omitted, match the latest active schedule entry <= closedThroughMs
      for (const cand of entries) {
        if (cand.entry.effectiveAfterMs <= item.closedMs) scope = cand;
      }
    }
    if (!scope || !scope.entry.policy || scope.entry.policy.kind === 'open') continue;
    if (item.closedMs < scope.entry.effectiveAfterMs) continue;

    // Enforce monotonic P_{i-1} -> P_i handoff
    if (scope.index > 0) {
      const prev = entries[scope.index - 1];
      if (prev && prev.entry.policy && prev.entry.policy.kind !== 'open') {
        const prevClosed = closedByScopeIndex.get(prev.index);
        if (prevClosed === undefined || prevClosed < scope.entry.effectiveAfterMs) continue;
      }
    }

    const res = verifyEvidenceForRule(scope.entry.policy, ev, members);
    if (!res.ok) continue;

    if (Array.isArray(p.inclusions)) {
      for (const inc of p.inclusions) {
        if (inc && typeof inc.opId === 'string') includedSet.add(inc.opId);
      }
    }
    const prevClosed = closedByScopeIndex.get(scope.index);
    if (prevClosed === undefined || item.closedMs > prevClosed) closedByScopeIndex.set(scope.index, item.closedMs);
    if (highestClosed === null || item.closedMs > highestClosed) {
      highestClosed = item.closedMs;
      latestCheckpointIndex = item.origIdx;
    }
    verifiedIndices.push(item.origIdx);
    verifiedRecords.push({ ev, scopeId: scope.scopeId, signers: res.signers, closedMs: item.closedMs });
  }

  // Honor locally pinned frontier (descent anchor)
  if (pinnedFrontier && Number.isSafeInteger(pinnedFrontier.closedThroughMs)) {
    for (const id of pinnedFrontier.includedOpIds || []) includedSet.add(id);
    if (highestClosed === null || pinnedFrontier.closedThroughMs > highestClosed) {
      highestClosed = pinnedFrontier.closedThroughMs;
    }
  }

  // Exclude any op <= highestClosed that is not in includedSet
  const excludedOpIds = [];
  if (highestClosed !== null) {
    for (const op of ops) {
      if (op && Number(op.authorTimestampMs) <= highestClosed && !includedSet.has(op.opId)) {
        excludedOpIds.push(op.opId);
      }
    }
  }

  // Equivocation detection across verified checkpoints by the same signer within a scope
  const equivocations = [];
  const bySignerScope = new Map();
  for (const rec of verifiedRecords) {
    for (const signer of rec.signers) {
      const key = signer + ':' + rec.scopeId;
      let list = bySignerScope.get(key);
      if (!list) { list = []; bySignerScope.set(key, list); }
      list.push(rec);
    }
  }
  for (const [key, list] of bySignerScope) {
    const sep = key.indexOf(':');
    const signer = key.slice(0, sep);
    const scopeId = key.slice(sep + 1);
    for (let i = 0; i < list.length; i++) {
      const a = list[i].ev.payload;
      const aOps = new Set((a.inclusions || []).map(x => x.opId));
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j].ev.payload;
        if (a.closedThroughMs === b.closedThroughMs) {
          if (a.includedSetDigest !== b.includedSetDigest || a.stateRoot !== b.stateRoot || a.historyDigest !== b.historyDigest) {
            equivocations.push({ signer, scopeId, reason: 'conflicting_checkpoint_at_frontier' });
          }
        } else {
          const bOps = new Set((b.inclusions || []).map(x => x.opId));
          for (const opId of aOps) {
            if (!bOps.has(opId)) {
              equivocations.push({ signer, scopeId, reason: 'dropped_prior_inclusion', detail: opId });
              break;
            }
          }
        }
      }
    }
  }

  return {
    closedThroughMs: highestClosed,
    includedOpIds: Array.from(includedSet),
    excludedOpIds,
    verifiedEvidenceIndices: verifiedIndices,
    latestCheckpointIndex,
    equivocations,
  };
}

function applyCommonAdminControlActions(cur, input, tx) {
  if (input.action === 'schedulePolicy') {
    if (!validHistoryPolicy(input.policy)) return { ok: false, code: 'invalid_admission_policy' };
    const schedule = normalizeSchedule(cur.schedule);
    const effectiveAfterMs = input.effectiveAfterMs;
    const last = schedule[schedule.length - 1];
    if (!Number.isSafeInteger(effectiveAfterMs) || effectiveAfterMs <= last.effectiveAfterMs) {
      return { ok: false, code: 'admission_activation_not_monotonic' };
    }
    if (effectiveAfterMs < tx.authorTimestampMs) {
      return { ok: false, code: 'admission_activation_in_past' };
    }
    const nextSchedule = schedule.concat([{ effectiveAfterMs, policy: input.policy }]);
    return {
      ok: true,
      state: { ...cur, schedule: nextSchedule },
      events: [{ topic: '$admission.policy_scheduled', payload: { effectiveAfterMs, kind: input.policy.kind } }],
    };
  }

  if (input.action === 'pinCheckpoint') {
    const policy = {
      kind: 'pinned-checkpoint',
      closedThroughMs: input.closedThroughMs,
      stateRoot: input.stateRoot,
      historyDigest: input.historyDigest,
      includedOpIds: Array.isArray(input.includedOpIds) ? sortedKeys(input.includedOpIds) : [],
    };
    if (!validHistoryPolicy(policy)) return { ok: false, code: 'invalid_checkpoint_pin' };
    const schedule = normalizeSchedule(cur.schedule);
    const last = schedule[schedule.length - 1];
    const effectiveAfterMs = Math.max(Number(input.closedThroughMs), last.effectiveAfterMs + 1);
    const nextSchedule = schedule.concat([{ effectiveAfterMs, policy }]);
    return {
      ok: true,
      state: { ...cur, schedule: nextSchedule },
      events: [{ topic: '$admission.checkpoint_pinned', payload: { closedThroughMs: policy.closedThroughMs, stateRoot: policy.stateRoot } }],
    };
  }

  if (input.action === 'setSignalPolicy') {
    if (!Array.isArray(input.rules)) return { ok: false, code: 'invalid_signal_policy' };
    return {
      ok: true,
      state: { ...cur, signals: { rules: input.rules } },
      events: [{ topic: '$admission.signals_updated', payload: { count: input.rules.length } }],
    };
  }

  if (input.action === 'setTopicAccess') {
    if (typeof input.topic !== 'string' || input.topic.length === 0 || input.topic.startsWith('$')) {
      return { ok: false, code: 'invalid_topic_access' };
    }
    const topicAccess = { ...(cur.topicAccess || {}) };
    if (input.rule === null) {
      delete topicAccess[input.topic];
    } else if (input.rule && typeof input.rule === 'object') {
      topicAccess[input.topic] = {
        ...(input.rule.allowPublicWrite === undefined ? {} : { allowPublicWrite: Boolean(input.rule.allowPublicWrite) }),
        ...(typeof input.rule.requiredCapability === 'string' ? { requiredCapability: input.rule.requiredCapability } : {}),
        ...(typeof input.rule.requiredScope === 'string' ? { requiredScope: input.rule.requiredScope } : {}),
      };
    } else {
      return { ok: false, code: 'invalid_topic_access' };
    }
    return {
      ok: true,
      state: { ...cur, topicAccess },
      events: [{ topic: '$admission.topic_access_updated', payload: { topic: input.topic } }],
    };
  }

  return null;
}

function defaultAuthorizeOp(canFn, state, tx) {
  const actor = tx.author;
  const atMs = Number(tx.authorTimestampMs || 0);
  const updates = Array.isArray(tx.updates) ? tx.updates : [];
  if (updates.length === 0) return { ok: false, code: 'invalid_input' };
  const topicAccess = (state && state.topicAccess && typeof state.topicAccess === 'object') ? state.topicAccess : {};

  for (const u of updates) {
    const topic = u.topic;
    if (topic === '$admission') continue;
    if (topic === '$keys') {
      if (!canFn('administrator', actor, { atMs }) && !canFn('reader', actor, { atMs }) && !canFn('guardian', actor, { atMs })) {
        return { ok: false, code: 'keys_access_denied' };
      }
      continue;
    }
    if (topic === '$publications') {
      if (!canFn('publisher', actor, { atMs }) && !canFn('administrator', actor, { atMs })) {
        return { ok: false, code: 'publisher_required' };
      }
      continue;
    }
    if (topic === '$seals') {
      if (!canFn('administrator', actor, { atMs })) {
        return { ok: false, code: 'admin_required' };
      }
      continue;
    }
    if (topic === '$reducers' || topic === '$mounts' || topic === '$builders') {
      if (!canFn('writer', actor, { atMs }) && !canFn('administrator', actor, { atMs })) {
        return { ok: false, code: 'admin_required' };
      }
      continue;
    }
    const rule = topicAccess[topic];
    if (rule && rule.allowPublicWrite === true) {
      if (canFn('blocked', actor, { atMs })) return { ok: false, code: 'author_blocked' };
      continue;
    }
    if (rule && typeof rule.requiredCapability === 'string') {
      if (!canFn(rule.requiredCapability, actor, { atMs })) {
        return { ok: false, code: rule.requiredCapability + '_required' };
      }
    } else if (!canFn('writer', actor, { atMs }) && !canFn('administrator', actor, { atMs })) {
      return { ok: false, code: 'writer_required' };
    }
    if (rule && typeof rule.requiredScope === 'string') {
      if (!canFn('scope', actor, { atMs, scope: rule.requiredScope })) {
        return { ok: false, code: 'scope_required', detail: rule.requiredScope };
      }
    }
  }
  return { ok: true };
}

function resolveSignals(state, readers) {
  if (state && state.signals && Array.isArray(state.signals.rules)) {
    return { rules: state.signals.rules };
  }
  return {
    rules: [{ topicPattern: '*', allowedAuthors: readers, maxTtlMs: 30000, allowRelay: true }],
  };
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

export const attestedAdmission = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? state : { members: [], admission: null };
    const membersList = Array.isArray(cur.members) ? cur.members : [];
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const atMs = Number(tx.authorTimestampMs || 0);
    const authorIsAdmin = checkMembersCapability(membersList, 'administrator', tx.author, { atMs });
    const authorIsReader = checkMembersCapability(membersList, 'reader', tx.author, { atMs });

    if (input.action === 'setMember') {
      if (!authorIsAdmin) {
        if (!authorIsReader || !input.attestation) return { ok: false, code: 'admin_required' };
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
      const members = membersList.filter(m => m.publicKey !== next.publicKey).concat([next]);
      members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      let admission = cur.admission;
      if (authorIsAdmin && admission && Array.isArray(admission.removed) && admission.removed.includes(next.publicKey)) {
        admission = { ...admission, removed: admission.removed.filter(k => k !== next.publicKey) };
      }
      return { ok: true, state: { ...cur, members, admission }, events: [{ topic: '$admission.member', payload: { publicKey: next.publicKey } }] };
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
        createdAtMs: atMs,
      };
      return {
        ok: true,
        state: { ...cur, recoveryRequests: requests },
        events: [{ topic: '$admission.recovery_requested', payload: { requestId, newPublicKey: input.newPublicKey } }],
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
      let members = membersList;
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
        members = membersList.filter(m => m.publicKey !== promoted.publicKey).concat([promoted]);
        members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      }
      return {
        ok: true,
        state: { ...cur, members, recoveryRequests: requests },
        events: [{ topic: completed ? '$admission.recovery_completed' : '$admission.recovery_approved', payload: { requestId: input.requestId, guardian: tx.author, approvals: approvals.length, threshold: guardians.threshold } }],
      };
    }

    if (!authorIsAdmin) return { ok: false, code: 'admin_required' };

    const common = applyCommonAdminControlActions(cur, input, tx);
    if (common !== null) return common;

    if (input.action === 'setGuardians') {
      if (input.guardians === null) {
        return { ok: true, state: { ...cur, guardians: null }, events: [{ topic: '$admission.guardians_cleared', payload: {} }] };
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
        events: [{ topic: '$admission.guardians_updated', payload: { threshold, count: cleaned.length } }],
      };
    }

    if (input.action === 'removeMember') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const members = membersList.filter(m => m.publicKey !== input.publicKey);
      if (!members.some(m => m.administrator)) return { ok: false, code: 'last_admin_required' };
      let admission = cur.admission;
      if (admission && typeof admission === 'object') {
        const prevRemoved = Array.isArray(admission.removed) ? admission.removed : [];
        const removed = sortedKeys(prevRemoved.concat([input.publicKey])).slice(-512);
        admission = { ...admission, removed };
      }
      return { ok: true, state: { ...cur, members, admission }, events: [{ topic: '$admission.removed', payload: { publicKey: input.publicKey } }] };
    }

    if (input.action === 'createInvite') {
      const inv = input.invite;
      if (!inv || typeof inv !== 'object' || typeof inv.inviteId !== 'string' || inv.inviteId.length < 1 || inv.inviteId.length > 128) {
        return { ok: false, code: 'invalid_invite' };
      }
      const admission = cur.admission && typeof cur.admission === 'object' ? cur.admission : { mode: 'attested' };
      const invites = (Array.isArray(admission.invites) ? admission.invites : []).filter(i => i.inviteId !== inv.inviteId).concat([{ ...inv, revoked: false }]).slice(-128);
      return { ok: true, state: { ...cur, admission: { ...admission, invites } }, events: [{ topic: '$admission.invite_created', payload: { inviteId: inv.inviteId } }] };
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
      return { ok: true, state: { ...cur, admission: { ...admission, invites } }, events: [{ topic: '$admission.invite_revoked', payload: { inviteId: input.inviteId } }] };
    }

    if (input.action === 'setAdmission') {
      return { ok: true, state: { ...cur, admission: input.admission ?? null } };
    }

    return { ok: false, code: 'unknown_action' };
  },

  authorize(state, tx) {
    const cur = state && typeof state === 'object' ? state : { members: [] };
    const members = Array.isArray(cur.members) ? cur.members : [];
    const canFn = (capability, actor, opts) => {
      if (capability === 'guardian') {
        return Boolean(cur.guardians && Array.isArray(cur.guardians.members) && cur.guardians.members.some(g => g.publicKey === actor));
      }
      return checkMembersCapability(members, capability, actor, opts);
    };
    return defaultAuthorizeOp(canFn, cur, tx);
  },

  admit(state, input) {
    const cur = state && typeof state === 'object' ? state : {};
    const members = Array.isArray(cur.members) ? cur.members : [];
    return evaluateHistoryAdmission(cur.schedule, members, input);
  },

  query(state, input) {
    const cur = state && typeof state === 'object' ? state : { members: [], admission: null };
    const members = Array.isArray(cur.members) ? cur.members : [];
    if (input && typeof input === 'object') {
      if (input.kind === 'can') {
        if (input.capability === 'guardian') {
          return Boolean(cur.guardians && Array.isArray(cur.guardians.members) && cur.guardians.members.some(g => g.publicKey === input.actor));
        }
        return checkMembersCapability(members, input.capability, input.actor, input);
      }
      if (input.kind === 'roster') {
        if (typeof input.role === 'string') {
          if (input.role === 'guardians') return cur.guardians && Array.isArray(cur.guardians.members) ? cur.guardians.members.map(g => g.publicKey) : [];
          return queryMembersList(members, input.role);
        }
        return {
          mode: 'attested',
          members,
          readers: queryMembersList(members, 'readers'),
          writers: queryMembersList(members, 'writers'),
          administrators: queryMembersList(members, 'administrators'),
          publishers: queryMembersList(members, 'publishers'),
          finalizers: queryMembersList(members, 'finalizers'),
          openReaders: false,
          openWriters: false,
          blockedAuthors: [],
          removedMembers: cur.admission && Array.isArray(cur.admission.removed) ? cur.admission.removed : [],
          admission: cur.admission ?? null,
          guardians: cur.guardians ?? null,
          recoveryRequests: cur.recoveryRequests ?? {},
          multisig: null,
        };
      }
      if (input.kind === 'signals') {
        return resolveSignals(cur, queryMembersList(members, 'readers'));
      }
      if (input.kind === 'schedule') {
        return normalizeSchedule(cur.schedule);
      }
      if (input.kind === 'guardians') {
        return { guardians: cur.guardians ?? null, recoveryRequests: cur.recoveryRequests ?? {} };
      }
      if (input.publicKey) {
        return members.find(m => m.publicKey === input.publicKey) || null;
      }
    }
    return cur;
  },
};

export const openAdmission = {
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
          schedule: state.schedule,
          signals: state.signals,
          topicAccess: state.topicAccess,
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
      return { ok: true, state: { ...cur, vouchedAuthors }, events: [{ topic: '$admission.author_vouched', payload: { publicKey: input.publicKey, by: tx.author } }] };
    }

    if (!cur.admins.includes(tx.author)) return { ok: false, code: 'admin_required' };

    const common = applyCommonAdminControlActions(cur, input, tx);
    if (common !== null) return common;

    if (input.action === 'setAntiSpam') {
      if (input.antiSpam === null) return { ok: true, state: { ...cur, antiSpam: null } };
      const cfg = input.antiSpam;
      if (!cfg || typeof cfg !== 'object') return { ok: false, code: 'invalid_antispam' };
      const next = {
        requireVouch: Boolean(cfg.requireVouch),
        ...(Number.isSafeInteger(cfg.maxOpsPerWindow) && cfg.maxOpsPerWindow > 0 ? { maxOpsPerWindow: cfg.maxOpsPerWindow } : {}),
        ...(Number.isSafeInteger(cfg.windowMs) && cfg.windowMs > 0 ? { windowMs: cfg.windowMs } : {}),
      };
      return { ok: true, state: { ...cur, antiSpam: next }, events: [{ topic: '$admission.antispam_updated', payload: next }] };
    }

    if (input.action === 'setAdmin') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const admins = input.enabled === false ? cur.admins.filter(k => k !== input.publicKey) : sortedKeys(cur.admins.concat([input.publicKey]));
      if (admins.length === 0) return { ok: false, code: 'last_admin_required' };
      const blockedAuthors = input.enabled === false ? cur.blockedAuthors : cur.blockedAuthors.filter(k => k !== input.publicKey);
      return { ok: true, state: { ...cur, admins, blockedAuthors }, events: [{ topic: '$admission.admin', payload: { publicKey: input.publicKey, enabled: input.enabled !== false } }] };
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
        events: [{ topic: '$admission.author_blocked', payload: { publicKey: input.publicKey, ...(typeof input.reason === 'string' && input.reason ? { reason: input.reason.slice(0, 160) } : {}) } }],
      };
    }

    if (input.action === 'unblockAuthor') {
      if (!HEX32.test(input.publicKey || '')) return { ok: false, code: 'invalid_member' };
      const blockedAuthors = cur.blockedAuthors.filter(k => k !== input.publicKey);
      return { ok: true, state: { ...cur, blockedAuthors }, events: [{ topic: '$admission.author_unblocked', payload: { publicKey: input.publicKey } }] };
    }

    if (input.action === 'setMember') {
      const next = normalizeMember(input.member);
      const members = cur.members.filter(m => m.publicKey !== next.publicKey).concat([next]);
      members.sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
      const admins = next.administrator ? sortedKeys(cur.admins.concat([next.publicKey])) : cur.admins;
      const blockedAuthors = next.administrator ? cur.blockedAuthors.filter(k => k !== next.publicKey) : cur.blockedAuthors;
      return { ok: true, state: { ...cur, admins, members, blockedAuthors }, events: [{ topic: '$admission.member', payload: { publicKey: next.publicKey } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },

  authorize(state, tx) {
    const canFn = (capability, actor, opts) => openAdmission.query(state, { kind: 'can', capability, actor, ...(opts || {}) }) === true;
    return defaultAuthorizeOp(canFn, state, tx);
  },

  admit(state, input) {
    const roster = openAdmission.query(state, { kind: 'roster' });
    return evaluateHistoryAdmission(state && state.schedule, roster.members, input);
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
          schedule: state.schedule,
          signals: state.signals,
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
      if (input.kind === 'can') {
        if (!HEX32.test(input.actor || '')) return false;
        if (input.capability === 'blocked') return blockedSet.has(input.actor);
        if (input.capability === 'administrator') return adminSet.has(input.actor);
        if (input.capability === 'publisher') return adminSet.has(input.actor) || checkMembersCapability(members, 'publisher', input.actor, input);
        if (input.capability === 'writer') {
          if (blockedSet.has(input.actor)) return false;
          if (adminSet.has(input.actor)) return true;
          if (checkMembersCapability(members, 'writer', input.actor, input)) return true;
          if (!cur.openWrite) return false;
          if (cur.antiSpam && cur.antiSpam.requireVouch === true) return vouchedSet.has(input.actor);
          return true;
        }
        if (input.capability === 'reader') return cur.openRead || adminSet.has(input.actor) || checkMembersCapability(members, 'reader', input.actor, input);
        if (input.capability === 'member') return cur.openWrite || cur.openRead || adminSet.has(input.actor) || checkMembersCapability(members, 'member', input.actor, input);
        return checkMembersCapability(members, input.capability, input.actor, input);
      }
      if (input.kind === 'roster') {
        if (typeof input.role === 'string') {
          if (input.role === 'blockedAuthors') return cur.blockedAuthors;
          if (input.role === 'readers' && cur.openRead) return ['*'];
          if (input.role === 'writers' && cur.openWrite) return ['*'];
          return queryMembersList(members, input.role);
        }
        return {
          mode: 'open',
          members,
          readers: cur.openRead ? ['*'] : queryMembersList(members, 'readers'),
          writers: cur.openWrite ? ['*'] : queryMembersList(members, 'writers'),
          administrators: sortedKeys(cur.admins),
          publishers: queryMembersList(members, 'publishers'),
          finalizers: queryMembersList(members, 'finalizers'),
          openReaders: cur.openRead,
          openWriters: cur.openWrite,
          blockedAuthors: cur.blockedAuthors,
          removedMembers: [],
          admission: cur.admission,
          guardians: null,
          recoveryRequests: {},
          multisig: null,
        };
      }
      if (input.kind === 'signals') {
        return resolveSignals(cur, cur.openRead ? ['*'] : queryMembersList(members, 'readers'));
      }
      if (input.kind === 'schedule') {
        return normalizeSchedule(cur.schedule);
      }
      if (input.publicKey) {
        return members.find(m => m.publicKey === input.publicKey) || null;
      }
    }
    return cur;
  },
};

function normalizeMultisigState(state) {
  const s = state && typeof state === 'object' ? state : {};
  const signers = sortedKeys(Array.isArray(s.signers) ? s.signers.filter(k => HEX32.test(k || '')) : []);
  const threshold = Number.isSafeInteger(s.threshold) && s.threshold >= 1 ? Math.min(s.threshold, Math.max(1, signers.length)) : 1;
  const members = s.members && typeof s.members === 'object' && !Array.isArray(s.members) ? { ...s.members } : {};
  const proposals = s.proposals && typeof s.proposals === 'object' && !Array.isArray(s.proposals) ? { ...s.proposals } : {};
  return {
    threshold,
    signers,
    members,
    proposals,
    ...(s.schedule === undefined ? {} : { schedule: s.schedule }),
    ...(s.signals === undefined ? {} : { signals: s.signals }),
    ...(s.topicAccess === undefined ? {} : { topicAccess: s.topicAccess }),
  };
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
      byKey.set(pk, { publicKey: pk, reader: true, writer: true, administrator: true, publisher: true, finalizer: false });
    }
  }
  return Array.from(byKey.values()).sort((a, b) => (a.publicKey < b.publicKey ? -1 : a.publicKey > b.publicKey ? 1 : 0));
}

function applyMultisigProposal(cur, prop, tx) {
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
    if (nextSigners.length === 0 || nextSigners.length < cur.threshold) return { ok: false, code: 'threshold_unsatisfiable' };
    return { ok: true, state: { ...cur, signers: nextSigners, members: nextMembers }, event: { topic: '$admission.member', payload: { publicKey: m.publicKey } } };
  }
  if (prop.kind === 'removeMember') {
    if (!HEX32.test(prop.publicKey || '')) return { ok: false, code: 'invalid_member' };
    const nextMembers = { ...cur.members };
    delete nextMembers[prop.publicKey];
    const nextSigners = cur.signers.filter(k => k !== prop.publicKey);
    if (nextSigners.length === 0 || nextSigners.length < cur.threshold) return { ok: false, code: 'threshold_unsatisfiable' };
    return { ok: true, state: { ...cur, signers: nextSigners, members: nextMembers }, event: { topic: '$admission.removed', payload: { publicKey: prop.publicKey } } };
  }
  if (prop.kind === 'setThreshold') {
    const t = prop.threshold;
    if (!Number.isSafeInteger(t) || t < 1 || t > cur.signers.length) return { ok: false, code: 'invalid_threshold' };
    return { ok: true, state: { ...cur, threshold: t }, event: { topic: '$admission.threshold', payload: { threshold: t } } };
  }
  if (prop.kind === 'schedulePolicy') {
    const res = applyCommonAdminControlActions(cur, { action: 'schedulePolicy', effectiveAfterMs: prop.effectiveAfterMs, policy: prop.policy }, tx);
    if (!res || !res.ok) return res || { ok: false, code: 'invalid_admission_policy' };
    return { ok: true, state: res.state, event: res.events[0] };
  }
  return { ok: false, code: 'unknown_proposal_kind' };
}

export const multisigAdmission = {
  reduce(state, tx) {
    const cur = normalizeMultisigState(state);
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    if (!cur.signers.includes(tx.author)) return { ok: false, code: 'signer_required' };

    if (input.action === 'propose') {
      const id = typeof input.id === 'string' && input.id.length > 0 ? input.id : tx.opId;
      if (cur.proposals[id]) return { ok: false, code: 'proposal_exists' };
      const prop = {
        kind: input.kind,
        ...(input.member !== undefined ? { member: input.member } : {}),
        ...(input.publicKey !== undefined ? { publicKey: input.publicKey } : {}),
        ...(input.threshold !== undefined ? { threshold: input.threshold } : {}),
        ...(input.effectiveAfterMs !== undefined ? { effectiveAfterMs: input.effectiveAfterMs } : {}),
        ...(input.policy !== undefined ? { policy: input.policy } : {}),
        approvals: [tx.author],
      };
      if (prop.approvals.length >= cur.threshold) {
        const applied = applyMultisigProposal(cur, prop, tx);
        if (!applied.ok) return applied;
        return { ok: true, state: applied.state, events: [applied.event] };
      }
      return {
        ok: true,
        state: { ...cur, proposals: { ...cur.proposals, [id]: prop } },
        events: [{ topic: '$admission.proposed', payload: { id, approvals: 1, threshold: cur.threshold } }],
      };
    }

    if (input.action === 'approve') {
      const id = input.id;
      const existing = typeof id === 'string' ? cur.proposals[id] : null;
      if (!existing) return { ok: false, code: 'proposal_not_found' };
      const approvals = sortedKeys((existing.approvals || []).concat([tx.author]));
      const updated = { ...existing, approvals };
      if (approvals.length >= cur.threshold) {
        const nextProposals = { ...cur.proposals };
        delete nextProposals[id];
        const applied = applyMultisigProposal({ ...cur, proposals: nextProposals }, updated, tx);
        if (!applied.ok) return applied;
        return { ok: true, state: applied.state, events: [applied.event] };
      }
      return {
        ok: true,
        state: { ...cur, proposals: { ...cur.proposals, [id]: updated } },
        events: [{ topic: '$admission.approved', payload: { id, approvals: approvals.length, threshold: cur.threshold } }],
      };
    }

    if (input.action === 'cancel') {
      const id = input.id;
      if (typeof id !== 'string' || !cur.proposals[id]) return { ok: false, code: 'proposal_not_found' };
      const nextProposals = { ...cur.proposals };
      delete nextProposals[id];
      return { ok: true, state: { ...cur, proposals: nextProposals }, events: [{ topic: '$admission.cancelled', payload: { id } }] };
    }

    if (cur.threshold === 1) {
      const common = applyCommonAdminControlActions(cur, input, tx);
      if (common !== null) return common;
    }

    return { ok: false, code: 'unknown_action' };
  },

  authorize(state, tx) {
    const cur = normalizeMultisigState(state);
    const members = multisigMemberRecords(cur);
    const canFn = (capability, actor, opts) => checkMembersCapability(members, capability, actor, opts);
    return defaultAuthorizeOp(canFn, cur, tx);
  },

  admit(state, input) {
    const cur = normalizeMultisigState(state);
    return evaluateHistoryAdmission(cur.schedule, multisigMemberRecords(cur), input);
  },

  query(state, input) {
    const cur = normalizeMultisigState(state);
    const members = multisigMemberRecords(cur);
    if (input && typeof input === 'object') {
      if (input.kind === 'can') {
        return checkMembersCapability(members, input.capability, input.actor, input);
      }
      if (input.kind === 'roster') {
        if (typeof input.role === 'string') return queryMembersList(members, input.role);
        return {
          mode: 'multisig',
          members,
          readers: queryMembersList(members, 'readers'),
          writers: queryMembersList(members, 'writers'),
          administrators: queryMembersList(members, 'administrators'),
          publishers: queryMembersList(members, 'publishers'),
          finalizers: queryMembersList(members, 'finalizers'),
          openReaders: false,
          openWriters: false,
          blockedAuthors: [],
          removedMembers: [],
          admission: null,
          guardians: null,
          recoveryRequests: {},
          multisig: { threshold: cur.threshold, signers: cur.signers, proposals: cur.proposals },
        };
      }
      if (input.kind === 'signals') {
        return resolveSignals(cur, queryMembersList(members, 'readers'));
      }
      if (input.kind === 'schedule') {
        return normalizeSchedule(cur.schedule);
      }
      if (input.publicKey) {
        return members.find(m => m.publicKey === input.publicKey) || null;
      }
    }
    return cur;
  },
};

/**
 * Composable admission factory: build custom data-driven or callback-driven $admission modules
 * by overriding any subset of { base, reduce, authorize, verify, admit, query }.
 */
export function createAdmission(options = {}) {
  const base = options.base || attestedAdmission;
  const mod = {
    reduce(state, tx, ctx) {
      return typeof options.reduce === 'function' ? options.reduce(state, tx, ctx, base) : base.reduce(state, tx, ctx);
    },
    authorize(state, tx, ctx) {
      const baseRes = base.authorize(state, tx, ctx);
      if (!baseRes || baseRes.ok === false) return baseRes;
      if (typeof options.authorize === 'function') {
        const extra = options.authorize(state, tx, ctx);
        if (extra === false) return { ok: false, code: 'admission_denied' };
        if (extra && typeof extra === 'object' && extra.ok === false) return extra;
      }
      return { ok: true };
    },
    admit(state, input, ctx) {
      return typeof options.admit === 'function' ? options.admit(state, input, ctx, base) : base.admit(state, input, ctx);
    },
    query(state, input, ctx) {
      return typeof options.query === 'function' ? options.query(state, input, ctx, base) : base.query(state, input, ctx);
    },
  };
  if (typeof options.verify === 'function') {
    mod.verify = function verify(before, after, tx, ctx) {
      return options.verify(before, after, tx, ctx, base);
    };
  }
  return mod;
}

export const adminOnlyReducers = {
  reduce(state, tx, ctx) {
    if (!ctx.can('administrator')) return { ok: false, code: 'admin_required' };
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

export default attestedAdmission;
`.trimStart()
