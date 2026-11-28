/**
 * Extended audited standard library modules seeded into CAS as `chronolog/*`:
 * - `chronolog/finality-predicates`: programmable state-defined finality / admission predicates
 * - `chronolog/guards`: composable pre/post condition helpers + OCC/causal-chain guards
 * - `chronolog/quotas`: deterministic per-author rate limits and quotas driven by tx.authorTimestampMs
 * - `chronolog/queue`: deterministic job queue with time-based leases and dead-letter handling
 * - `chronolog/votes`: weighted voting, quorum polls, ranked/approval tallies, timelocked close
 * - `chronolog/schema`: deterministic JSON schema validator and versioned state migrations
 * - `chronolog/audit`: hash-chained tamper-evident audit trail reducer
 */

export const STD_FINALITY_PREDICATES_SOURCE = `
import { canonicalJson, sha256, verifyEd25519 } from 'chronolog:crypto';

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function canonicalCheckpointMessage(payload) {
  return canonicalJson(['chronolog/finality-predicate/v1', payload]);
}

function verifySigEntry(entry, payload) {
  if (!entry || typeof entry !== 'object') return false;
  if (typeof entry.signer !== 'string' || !HEX32.test(entry.signer)) return false;
  if (typeof entry.signature !== 'string' || !HEX64.test(entry.signature)) return false;
  return verifyEd25519(entry.signer, canonicalCheckpointMessage(payload), entry.signature);
}

/** Single-signer programmable finality predicate (config: { signer: 64-hex }). */
export const signedFrontierPredicate = {
  query(state, input, ctx) {
    const cfg = (input && input.policy && input.policy.config) || ctx.config || {};
    const cp = input && input.checkpoint;
    if (!cp || !cp.payload || !cp.attestation || typeof cfg.signer !== 'string' || !HEX32.test(cfg.signer)) {
      return { admitted: false, reason: 'invalid_input' };
    }
    const data = cp.attestation.kind === 'evidence' ? cp.attestation.data : cp.attestation;
    const sigs = Array.isArray(data && data.signatures) ? data.signatures : (data && data.signer ? [data] : []);
    for (const s of sigs) {
      if (s && s.signer === cfg.signer && verifySigEntry(s, cp.payload)) {
        return { admitted: true, signer: cfg.signer };
      }
    }
    return { admitted: false, reason: 'signature_missing_or_invalid' };
  },
};

/**
 * Weighted or M-of-N validator quorum predicate.
 * config: { validators: string[] | Record<string, number>, threshold: number }
 */
export const thresholdQuorumPredicate = {
  query(state, input, ctx) {
    const cfg = (input && input.policy && input.policy.config) || ctx.config || {};
    const cp = input && input.checkpoint;
    if (!cp || !cp.payload || !cp.attestation) return { admitted: false, reason: 'invalid_input' };
    const threshold = Number(cfg.threshold || 1);
    if (!Number.isFinite(threshold) || threshold < 1) return { admitted: false, reason: 'invalid_threshold' };

    const weights = {};
    if (Array.isArray(cfg.validators)) {
      for (const v of cfg.validators) if (typeof v === 'string' && HEX32.test(v)) weights[v] = 1;
    } else if (cfg.validators && typeof cfg.validators === 'object') {
      for (const [k, w] of Object.entries(cfg.validators)) {
        if (HEX32.test(k) && typeof w === 'number' && Number.isFinite(w) && w > 0) weights[k] = w;
      }
    }

    const data = cp.attestation.kind === 'evidence' ? cp.attestation.data : cp.attestation;
    const sigs = Array.isArray(data && data.signatures) ? data.signatures : [];
    const seen = new Set();
    let total = 0;
    for (const s of sigs) {
      if (!s || typeof s.signer !== 'string' || !Object.prototype.hasOwnProperty.call(weights, s.signer)) continue;
      if (seen.has(s.signer)) continue;
      if (verifySigEntry(s, cp.payload)) {
        seen.add(s.signer);
        total += weights[s.signer];
      }
    }
    return { admitted: total >= threshold, weight: total, threshold };
  },
};

/**
 * Optimistic challenge-window predicate:
 * Admits a signed checkpoint once an attested observation timestamp >= closedThroughMs + challengeWindowMs,
 * UNLESS a valid signed fraud/challenge counter-proof is present in attestation.data.challenges.
 * config: { proposers: string[], challengers?: string[], challengeWindowMs: number }
 */
export const optimisticChallengePredicate = {
  query(state, input, ctx) {
    const cfg = (input && input.policy && input.policy.config) || ctx.config || {};
    const cp = input && input.checkpoint;
    if (!cp || !cp.payload || !cp.attestation || cp.attestation.kind !== 'evidence') {
      return { admitted: false, reason: 'evidence_required' };
    }
    const data = cp.attestation.data || {};
    const proposers = Array.isArray(cfg.proposers) ? cfg.proposers : [];
    const challengers = Array.isArray(cfg.challengers) ? cfg.challengers : proposers;
    const windowMs = Number(cfg.challengeWindowMs || 0);
    const closedMs = Number(cp.payload.closedThroughMs || 0);
    const observedMs = Number(data.observedAtMs || 0);
    if (!Number.isFinite(observedMs) || observedMs < closedMs + windowMs) {
      return { admitted: false, reason: 'challenge_window_open' };
    }
    const proposal = data.proposal;
    if (!proposal || !proposers.includes(proposal.signer) || !verifySigEntry(proposal, cp.payload)) {
      return { admitted: false, reason: 'invalid_proposal_signature' };
    }
    const challenges = Array.isArray(data.challenges) ? data.challenges : [];
    for (const ch of challenges) {
      if (!ch || !challengers.includes(ch.signer) || typeof ch.signature !== 'string' || !HEX64.test(ch.signature)) continue;
      const challengeMsg = canonicalJson(['chronolog/finality-challenge/v1', cp.payload.logId, cp.payload.policyScopeId, cp.payload.closedThroughMs, ch.reason || 'fraud']);
      if (verifyEd25519(ch.signer, challengeMsg, ch.signature)) {
        return { admitted: false, challenged: true, challenger: ch.signer, reason: ch.reason || 'fraud' };
      }
    }
    return { admitted: true, proposer: proposal.signer };
  },
};

/**
 * External Merkle-anchor predicate:
 * Verifies a SHA-256 Merkle inclusion proof tying sha256(canonicalJson(checkpoint.payload))
 * into a root signed by a trusted anchor oracle (or pinned in config.trustedRoots).
 * config: { anchorSigners?: string[], trustedRoots?: string[] }
 */
export const merkleAnchorPredicate = {
  query(state, input, ctx) {
    const cfg = (input && input.policy && input.policy.config) || ctx.config || {};
    const cp = input && input.checkpoint;
    if (!cp || !cp.payload || !cp.attestation || cp.attestation.kind !== 'evidence') {
      return { admitted: false, reason: 'evidence_required' };
    }
    const data = cp.attestation.data || {};
    const root = data.root;
    const proof = Array.isArray(data.proof) ? data.proof : null;
    if (typeof root !== 'string' || !HEX32.test(root) || !proof || proof.length > 64) {
      return { admitted: false, reason: 'invalid_merkle_proof' };
    }
    let cur = sha256(canonicalCheckpointMessage(cp.payload));
    for (const step of proof) {
      if (!step || typeof step.sibling !== 'string' || !HEX32.test(step.sibling)) {
        return { admitted: false, reason: 'invalid_merkle_step' };
      }
      cur = step.position === 'left'
        ? sha256(step.sibling + cur)
        : sha256(cur + step.sibling);
    }
    if (cur !== root) return { admitted: false, reason: 'merkle_root_mismatch' };
    const trustedRoots = Array.isArray(cfg.trustedRoots) ? cfg.trustedRoots : [];
    if (trustedRoots.includes(root)) return { admitted: true, root };
    const signers = Array.isArray(cfg.anchorSigners) ? cfg.anchorSigners : [];
    const anchorSig = data.anchorSignature;
    if (anchorSig && signers.includes(anchorSig.signer) && HEX64.test(anchorSig.signature || '')) {
      const msg = canonicalJson(['chronolog/merkle-anchor/v1', root]);
      if (verifyEd25519(anchorSig.signer, msg, anchorSig.signature)) {
        return { admitted: true, root, anchorSigner: anchorSig.signer };
      }
    }
    return { admitted: false, reason: 'untrusted_anchor_root' };
  },
};

export default thresholdQuorumPredicate;
`.trimStart()

export const STD_GUARDS_SOURCE = `
/**
 * Composable pre/post condition standard library for JS & SQL reducers.
 */

export function requireAuthorChain(ctx, tx, expectedLastOpId) {
  const actual = typeof ctx.authorLastOpId === 'function' ? ctx.authorLastOpId(tx.author) : null;
  if (actual !== expectedLastOpId) {
    return {
      ok: false,
      code: 'guard:author_history_mismatch',
      detail: 'Author ' + tx.author + ' expected last op ' + String(expectedLastOpId) + ', got ' + String(actual),
    };
  }
  return { ok: true };
}

export function requireOpsAccepted(ctx, opIds) {
  if (!Array.isArray(opIds)) return { ok: true };
  for (const id of opIds) {
    const st = typeof ctx.opOutcome === 'function' ? ctx.opOutcome(id) : null;
    if (st === null) return { ok: false, code: 'guard:missing_op', detail: 'Required op ' + id + ' not present' };
    if (st !== 'accepted') return { ok: false, code: 'guard:op_rejected', detail: 'Required op ' + id + ' was rejected' };
  }
  return { ok: true };
}

export function requireTopicVersion(ctx, topic, expectedLastOpId) {
  const actual = typeof ctx.topicLastOpId === 'function' ? ctx.topicLastOpId(topic) : null;
  if (actual !== expectedLastOpId) {
    return {
      ok: false,
      code: 'guard:topic_modified',
      detail: 'Topic ' + topic + ' expected last op ' + String(expectedLastOpId) + ', got ' + String(actual),
    };
  }
  return { ok: true };
}

export function checkPostInvariant(predicate, nextState, tx, ctx, code = 'guard:postcondition_failed', detail = 'Postcondition failed') {
  const res = predicate(nextState, tx, ctx);
  if (res === true) return { ok: true };
  if (res && typeof res === 'object' && res.ok === true) return { ok: true };
  if (res && typeof res === 'object' && res.ok === false) {
    return { ok: false, code: res.code || code, detail: res.detail || detail };
  }
  return { ok: false, code, detail };
}

/**
 * Higher-order reducer wrapper enforcing declarative pre/post conditions around any reducer.
 */
export function guardReducer(reducer, options = {}) {
  const preList = Array.isArray(options.pre) ? options.pre : (options.pre ? [options.pre] : []);
  const postList = Array.isArray(options.post) ? options.post : (options.post ? [options.post] : []);
  return {
    ...reducer,
    reduce(state, tx, ctx) {
      for (const check of preList) {
        const res = check(state, tx, ctx);
        if (res && res.ok === false) return res;
        if (res === false) return { ok: false, code: 'guard:precondition_failed' };
      }
      const out = reducer.reduce(state, tx, ctx);
      if (!out || out.ok !== true) return out;
      for (const check of postList) {
        const res = check(out.state, tx, ctx, state);
        if (res && res.ok === false) return res;
        if (res === false) return { ok: false, code: 'guard:postcondition_failed' };
      }
      return out;
    },
  };
}

/** SQL precondition/postcondition builders compatible with chronolog/sql. */
export function sqlBasedOnRow(table, where, lastOpId, code) {
  return { kind: 'based_on_row', table, where, lastOpId, ...(code ? { code } : {}) };
}

export function sqlRowMatches(table, where, expect, code) {
  return { kind: 'row_matches', table, where, expect, ...(code ? { code } : {}) };
}

export function sqlRequireAuthorLastOp(expectedLastOpId, author, code = 'sql:author_history_mismatch') {
  if (expectedLastOpId === null) {
    return {
      sql: author ? 'SELECT chronolog_author_last_op(?) IS NULL' : 'SELECT chronolog_author_last_op() IS NULL',
      params: author ? [author] : [],
      expect: { firstValue: 1 },
      code,
    };
  }
  return {
    sql: author ? 'SELECT chronolog_author_last_op(?)' : 'SELECT chronolog_author_last_op()',
    params: author ? [author] : [],
    expect: { firstValue: expectedLastOpId },
    code,
  };
}

export function sqlPostInvariant(sql, params = [], expect = { firstValue: 1 }, code = 'sql:postcondition_failed') {
  return { sql, params, expect, code };
}

export default {
  requireAuthorChain,
  requireOpsAccepted,
  requireTopicVersion,
  checkPostInvariant,
  guardReducer,
  sqlBasedOnRow,
  sqlRowMatches,
  sqlRequireAuthorLastOp,
  sqlPostInvariant,
};
`.trimStart()

export const STD_QUOTAS_SOURCE = `
/**
 * Deterministic per-author token-bucket rate limiter & quota tracker driven purely by tx.authorTimestampMs.
 * Usable both as a standalone topic reducer AND as a helper inside custom reducers.
 */

export function consumeTokenBucket(buckets, actor, nowMs, { capacity = 60, refillPerSec = 1, cost = 1 } = {}) {
  const cur = (buckets && buckets[actor]) || { tokens: capacity, lastMs: nowMs };
  const elapsedSec = Math.max(0, (nowMs - cur.lastMs) / 1000);
  const replenished = Math.min(capacity, cur.tokens + elapsedSec * refillPerSec);
  if (replenished < cost) {
    return {
      ok: false,
      code: 'quota:rate_limited',
      retryAfterMs: Math.ceil(((cost - replenished) / Math.max(refillPerSec, 0.0001)) * 1000),
      remaining: replenished,
    };
  }
  const nextTokens = replenished - cost;
  return {
    ok: true,
    remaining: nextTokens,
    buckets: { ...(buckets || {}), [actor]: { tokens: nextTokens, lastMs: nowMs } },
  };
}

export const tokenBucketQuotas = {
  reduce(state, tx, ctx) {
    const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
    const cur = state && typeof state === 'object' ? state : { buckets: {}, usage: {} };
    const input = tx.payload || {};
    const action = input.action || 'consume';
    const nowMs = Number(tx.authorTimestampMs || 0);
    if (action === 'consume') {
      const cost = Number(input.cost === undefined ? 1 : input.cost);
      if (!Number.isFinite(cost) || cost <= 0) return { ok: false, code: 'quota:invalid_cost' };
      const res = consumeTokenBucket(cur.buckets, tx.author, nowMs, {
        capacity: Number(cfg.capacity || 60),
        refillPerSec: Number(cfg.refillPerSec || 1),
        cost,
      });
      if (!res.ok) return { ok: false, code: res.code, detail: 'Retry after ' + res.retryAfterMs + 'ms' };
      const prevUsage = Number((cur.usage && cur.usage[tx.author]) || 0);
      return {
        ok: true,
        state: { buckets: res.buckets, usage: { ...(cur.usage || {}), [tx.author]: prevUsage + cost } },
        events: [{ topic: 'quota.consumed', payload: { actor: tx.author, cost, remaining: res.remaining } }],
      };
    }
    return { ok: false, code: 'quota:unknown_action' };
  },
  query(state, input) {
    const cur = state && typeof state === 'object' ? state : { buckets: {}, usage: {} };
    if (input && typeof input.actor === 'string') {
      return {
        bucket: (cur.buckets && cur.buckets[input.actor]) || null,
        usage: Number((cur.usage && cur.usage[input.actor]) || 0),
      };
    }
    return cur;
  },
};

export default tokenBucketQuotas;
`.trimStart()

export const STD_QUEUE_SOURCE = `
/**
 * Deterministic CRDT job queue with time-based leases (tx.authorTimestampMs),
 * idempotent claims, retries, and dead-letter queue — ideal for multi-agent workspaces.
 */

export const jobQueue = {
  reduce(state, tx, ctx) {
    const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
    const defaultLeaseMs = Number(cfg.defaultLeaseMs || 30_000);
    const defaultMaxAttempts = Number(cfg.maxAttempts || 3);
    const cur = state && typeof state === 'object' ? state : { jobs: {} };
    const jobs = { ...(cur.jobs || {}) };
    const input = tx.payload || {};
    const nowMs = Number(tx.authorTimestampMs || 0);
    const action = input.action;

    if (action === 'enqueue') {
      const id = String(input.id || tx.operationId || tx.opId);
      if (jobs[id]) return { ok: false, code: 'queue:job_exists' };
      jobs[id] = {
        id,
        kind: String(input.kind || 'default'),
        payload: input.payload === undefined ? null : input.payload,
        status: 'pending',
        attempts: 0,
        maxAttempts: Number(input.maxAttempts || defaultMaxAttempts),
        createdAtMs: nowMs,
        createdBy: tx.author,
        claimedBy: null,
        leaseUntilMs: null,
        result: null,
        lastError: null,
      };
      return { ok: true, state: { jobs }, events: [{ topic: 'queue.enqueued', payload: { id, kind: jobs[id].kind } }] };
    }

    if (action === 'claim') {
      const id = String(input.id || '');
      const job = jobs[id];
      if (!job) return { ok: false, code: 'queue:not_found' };
      const leaseExpired = job.status === 'claimed' && job.leaseUntilMs !== null && nowMs >= job.leaseUntilMs;
      if (job.status !== 'pending' && !leaseExpired) return { ok: false, code: 'queue:already_claimed' };
      const nextAttempts = job.attempts + 1;
      if (nextAttempts > job.maxAttempts) {
        jobs[id] = { ...job, status: 'dead', claimedBy: null, leaseUntilMs: null, lastError: 'max_attempts_exceeded' };
        return { ok: true, state: { jobs }, events: [{ topic: 'queue.dead_letter', payload: { id } }] };
      }
      const leaseMs = Number(input.leaseMs || defaultLeaseMs);
      jobs[id] = { ...job, status: 'claimed', attempts: nextAttempts, claimedBy: tx.author, leaseUntilMs: nowMs + leaseMs };
      return { ok: true, state: { jobs }, events: [{ topic: 'queue.claimed', payload: { id, worker: tx.author, leaseUntilMs: nowMs + leaseMs } }] };
    }

    if (action === 'complete') {
      const id = String(input.id || '');
      const job = jobs[id];
      if (!job) return { ok: false, code: 'queue:not_found' };
      if (job.status !== 'claimed' || job.claimedBy !== tx.author) return { ok: false, code: 'queue:not_lease_holder' };
      jobs[id] = { ...job, status: 'completed', leaseUntilMs: null, completedAtMs: nowMs, result: input.result === undefined ? null : input.result };
      return { ok: true, state: { jobs }, events: [{ topic: 'queue.completed', payload: { id, worker: tx.author } }] };
    }

    if (action === 'fail') {
      const id = String(input.id || '');
      const job = jobs[id];
      if (!job) return { ok: false, code: 'queue:not_found' };
      if (job.status !== 'claimed' || job.claimedBy !== tx.author) return { ok: false, code: 'queue:not_lease_holder' };
      const dead = job.attempts >= job.maxAttempts;
      jobs[id] = {
        ...job,
        status: dead ? 'dead' : 'pending',
        claimedBy: null,
        leaseUntilMs: null,
        lastError: typeof input.error === 'string' ? input.error : 'failed',
      };
      return { ok: true, state: { jobs }, events: [{ topic: dead ? 'queue.dead_letter' : 'queue.requeued', payload: { id } }] };
    }

    return { ok: false, code: 'queue:unknown_action' };
  },
  query(state, input) {
    const jobs = (state && state.jobs) || {};
    const list = Object.values(jobs);
    if (!input || typeof input !== 'object') return list;
    if (typeof input.id === 'string') return jobs[input.id] || null;
    const nowMs = typeof input.nowMs === 'number' ? input.nowMs : null;
    return list.filter(j => {
      if (input.kind && j.kind !== input.kind) return false;
      if (input.status === 'claimable') {
        return j.status === 'pending' || (j.status === 'claimed' && nowMs !== null && j.leaseUntilMs !== null && nowMs >= j.leaseUntilMs);
      }
      if (input.status && j.status !== input.status) return false;
      return true;
    });
  },
};

export default jobQueue;
`.trimStart()

export const STD_VOTES_SOURCE = `
/**
 * Deterministic weighted voting, quorum polls, and timelocked decision reducer.
 */

export const weightedVotes = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? state : { polls: {} };
    const polls = { ...(cur.polls || {}) };
    const input = tx.payload || {};
    const nowMs = Number(tx.authorTimestampMs || 0);
    const action = input.action;

    if (action === 'create') {
      const id = String(input.id || tx.operationId || tx.opId);
      if (polls[id]) return { ok: false, code: 'votes:poll_exists' };
      const options = Array.isArray(input.options) ? input.options.map(String) : [];
      if (options.length < 2) return { ok: false, code: 'votes:options_required' };
      polls[id] = {
        id,
        title: String(input.title || id),
        options,
        quorum: Number(input.quorum || 1),
        weights: input.weights && typeof input.weights === 'object' ? input.weights : null,
        closesAtMs: typeof input.closesAtMs === 'number' ? input.closesAtMs : null,
        status: 'open',
        createdBy: tx.author,
        createdAtMs: nowMs,
        ballots: {},
      };
      return { ok: true, state: { polls }, events: [{ topic: 'votes.created', payload: { id } }] };
    }

    if (action === 'cast') {
      const id = String(input.id || '');
      const poll = polls[id];
      if (!poll) return { ok: false, code: 'votes:not_found' };
      if (poll.status !== 'open') return { ok: false, code: 'votes:closed' };
      if (poll.closesAtMs !== null && nowMs > poll.closesAtMs) return { ok: false, code: 'votes:deadline_passed' };
      const choice = String(input.choice || '');
      if (!poll.options.includes(choice)) return { ok: false, code: 'votes:invalid_option' };
      const weight = poll.weights ? Number(poll.weights[tx.author] || 0) : 1;
      if (weight <= 0) return { ok: false, code: 'votes:not_eligible' };
      polls[id] = { ...poll, ballots: { ...poll.ballots, [tx.author]: { choice, weight, atMs: nowMs } } };
      return { ok: true, state: { polls }, events: [{ topic: 'votes.cast', payload: { id, voter: tx.author, choice, weight } }] };
    }

    if (action === 'close') {
      const id = String(input.id || '');
      const poll = polls[id];
      if (!poll) return { ok: false, code: 'votes:not_found' };
      if (poll.status !== 'open') return { ok: false, code: 'votes:already_closed' };
      if (poll.createdBy !== tx.author && (poll.closesAtMs === null || nowMs < poll.closesAtMs)) {
        return { ok: false, code: 'votes:cannot_close_yet' };
      }
      polls[id] = { ...poll, status: 'closed', closedAtMs: nowMs };
      return { ok: true, state: { polls }, events: [{ topic: 'votes.closed', payload: { id } }] };
    }

    return { ok: false, code: 'votes:unknown_action' };
  },
  query(state, input) {
    const polls = (state && state.polls) || {};
    const tally = poll => {
      const counts = Object.fromEntries(poll.options.map(o => [o, 0]));
      let totalWeight = 0;
      for (const b of Object.values(poll.ballots || {})) {
        counts[b.choice] = (counts[b.choice] || 0) + b.weight;
        totalWeight += b.weight;
      }
      let winner = null;
      let best = -1;
      let tied = false;
      for (const [opt, score] of Object.entries(counts)) {
        if (score > best) { best = score; winner = opt; tied = false; }
        else if (score === best) { tied = true; }
      }
      return { ...poll, counts, totalWeight, quorumMet: totalWeight >= poll.quorum, winner: totalWeight >= poll.quorum && !tied ? winner : null };
    };
    if (input && typeof input.id === 'string') {
      const poll = polls[input.id];
      return poll ? tally(poll) : null;
    }
    return Object.values(polls).map(tally);
  },
};

export default weightedVotes;
`.trimStart()

export const STD_SCHEMA_SOURCE = `
/**
 * Lightweight deterministic JSON schema validator and state migration helper for JS reducers.
 */

export function validate(schema, value, path = '$') {
  if (!schema || typeof schema !== 'object') return { ok: true };
  if (schema.enum && !schema.enum.some(v => JSON.stringify(v) === JSON.stringify(value))) {
    return { ok: false, code: 'schema:enum', detail: path + ' must be one of enum values' };
  }
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    const matched = types.some(t => t === actual || (t === 'integer' && typeof value === 'number' && Number.isInteger(value)));
    if (!matched) return { ok: false, code: 'schema:type', detail: path + ' expected ' + types.join('|') + ', got ' + actual };
  }
  if (typeof value === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) return { ok: false, code: 'schema:min_length', detail: path + ' too short' };
    if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) return { ok: false, code: 'schema:max_length', detail: path + ' too long' };
  }
  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) return { ok: false, code: 'schema:minimum', detail: path + ' below minimum' };
    if (typeof schema.maximum === 'number' && value > schema.maximum) return { ok: false, code: 'schema:maximum', detail: path + ' above maximum' };
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) return { ok: false, code: 'schema:min_items', detail: path + ' too few items' };
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) return { ok: false, code: 'schema:max_items', detail: path + ' too many items' };
    if (schema.items) {
      for (let i = 0; i < value.length; i++) {
        const res = validate(schema.items, value[i], path + '[' + i + ']');
        if (!res.ok) return res;
      }
    }
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if (Array.isArray(schema.required)) {
      for (const req of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(value, req) || value[req] === undefined) {
          return { ok: false, code: 'schema:required', detail: path + '.' + req + ' is required' };
        }
      }
    }
    if (schema.properties && typeof schema.properties === 'object') {
      for (const [k, propSchema] of Object.entries(schema.properties)) {
        if (Object.prototype.hasOwnProperty.call(value, k)) {
          const res = validate(propSchema, value[k], path + '.' + k);
          if (!res.ok) return res;
        }
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const k of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(schema.properties, k)) {
          return { ok: false, code: 'schema:additional_property', detail: path + '.' + k + ' is not allowed' };
        }
      }
    }
  }
  return { ok: true };
}

export function migrateState(state, migrations, targetVersion) {
  let cur = state && typeof state === 'object' ? state : { schemaVersion: 0 };
  let v = Number(cur.schemaVersion || 0);
  while (v < targetVersion) {
    const fn = migrations[v + 1];
    if (typeof fn !== 'function') throw new Error('SCHEMA_MIGRATION_MISSING:' + (v + 1));
    cur = { ...fn(cur), schemaVersion: v + 1 };
    v += 1;
  }
  return cur;
}

export default { validate, migrateState };
`.trimStart()

export const STD_AUDIT_SOURCE = `
import { canonicalJson, sha256 } from 'chronolog:crypto';

const GENESIS_CHAIN_HASH = '0'.repeat(64);

/**
 * Deterministic hash-chained tamper-evident audit log reducer.
 */
export const auditLog = {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? state : { head: GENESIS_CHAIN_HASH, entries: [] };
    const input = tx.payload || {};
    if (input.action && input.action !== 'append') return { ok: false, code: 'audit:unknown_action' };
    const entryCore = {
      seq: cur.entries.length,
      prevHash: cur.head,
      opId: tx.opId,
      actor: tx.author,
      atMs: Number(tx.authorTimestampMs || 0),
      category: String(input.category || 'general'),
      subject: input.subject === undefined ? null : input.subject,
      detail: input.detail === undefined ? null : input.detail,
    };
    const hash = sha256(canonicalJson(entryCore));
    const entry = { ...entryCore, hash };
    return {
      ok: true,
      state: { head: hash, entries: cur.entries.concat([entry]) },
      events: [{ topic: 'audit.appended', payload: { seq: entry.seq, category: entry.category, hash } }],
    };
  },
  query(state, input) {
    const cur = state && typeof state === 'object' ? state : { head: GENESIS_CHAIN_HASH, entries: [] };
    if (input && input.verify === true) {
      let prev = GENESIS_CHAIN_HASH;
      for (const e of cur.entries) {
        const { hash, ...core } = e;
        if (core.prevHash !== prev || sha256(canonicalJson(core)) !== hash) {
          return { valid: false, brokenAt: e.seq };
        }
        prev = hash;
      }
      return { valid: prev === cur.head, count: cur.entries.length, head: cur.head };
    }
    let list = cur.entries;
    if (input && typeof input.actor === 'string') list = list.filter(e => e.actor === input.actor);
    if (input && typeof input.category === 'string') list = list.filter(e => e.category === input.category);
    if (input && typeof input.sinceMs === 'number') list = list.filter(e => e.atMs >= input.sinceMs);
    return { head: cur.head, count: list.length, entries: list };
  },
};

export default auditLog;
`.trimStart()
