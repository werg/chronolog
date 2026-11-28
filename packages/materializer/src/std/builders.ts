export const STD_BUILDERS_SOURCE = `
import { verifyEd25519, canonicalJson } from 'chronolog:crypto';

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;
const CAS_REF = /^cas:sha256-[0-9a-f]{64}$/;

function isAdmin(ctx, actor) {
  const checked = ctx.query('$permissions', { check: 'administrator', actor });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === actor && m.administrator === true));
}

function uniqueSortedHex(list) {
  return Array.from(new Set((Array.isArray(list) ? list : []).filter(k => typeof k === 'string' && HEX32.test(k)))).sort();
}

function verifyAttestation(att) {
  if (!att || typeof att !== 'object') return false;
  if (!att.payload || typeof att.payload !== 'object') return false;
  if (att.payload.format !== 'chronolog-attestation/v1') return false;
  if (typeof att.signer !== 'string' || !HEX32.test(att.signer)) return false;
  if (typeof att.signature !== 'string' || !HEX64.test(att.signature)) return false;
  const msg = 'chronolog/attestation/v1:' + canonicalJson(att.payload);
  return verifyEd25519(att.signer, msg, att.signature);
}

export const attestedBuilders = {
  reduce(state, tx, ctx) {
    if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
    const cur = state && typeof state === 'object'
      ? {
          builders: uniqueSortedHex(state.builders),
          auditors: uniqueSortedHex(state.auditors),
          threshold: typeof state.threshold === 'number' && state.threshold >= 1 ? Math.floor(state.threshold) : 1,
          requireAudit: Boolean(state.requireAudit),
          requireMountApproval: typeof state.requireMountApproval === 'string' ? state.requireMountApproval : null,
        }
      : { builders: [], auditors: [], threshold: 1, requireAudit: false, requireMountApproval: null };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_builders_input' };
    const next = { ...cur };
    if (Array.isArray(input.builders)) next.builders = uniqueSortedHex(input.builders);
    if (Array.isArray(input.auditors)) next.auditors = uniqueSortedHex(input.auditors);
    if (typeof input.threshold === 'number' && Number.isInteger(input.threshold) && input.threshold >= 1) {
      next.threshold = input.threshold;
    }
    if (typeof input.requireAudit === 'boolean') next.requireAudit = input.requireAudit;
    if (input.requireMountApproval === null || typeof input.requireMountApproval === 'string') {
      next.requireMountApproval = input.requireMountApproval;
    }
    return { ok: true, state: next, events: [{ topic: '$builders.updated', payload: { threshold: next.threshold } }] };
  },
  query(state) {
    return state || { builders: [], auditors: [], threshold: 1, requireAudit: false, requireMountApproval: null };
  },
};

/**
 * Governed $reducers policy that accepts upgrades either from an administrator
 * OR via M-of-N verified chronolog-attestation/v1 build/audit receipts from $builders
 * (and optional verification against a mounted Registry Chronolog via ctx.mountQuery).
 */
export const attestedReducers = {
  reduce(state, tx, ctx) {
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const admin = isAdmin(ctx, tx.author);
    const buildersCfg = ctx.topic('$builders');
    const builders = buildersCfg && Array.isArray(buildersCfg.builders) ? buildersCfg.builders : [];
    const auditors = buildersCfg && Array.isArray(buildersCfg.auditors) ? buildersCfg.auditors : [];
    const threshold = buildersCfg && typeof buildersCfg.threshold === 'number' && buildersCfg.threshold >= 1
      ? buildersCfg.threshold
      : 1;
    const requireAudit = Boolean(buildersCfg && buildersCfg.requireAudit);
    const requireMount = buildersCfg && typeof buildersCfg.requireMountApproval === 'string'
      ? buildersCfg.requireMountApproval
      : null;

    const newRefs = [];
    if (input.imports && typeof input.imports === 'object') {
      for (const [, v] of Object.entries(input.imports)) {
        if (typeof v === 'string' && CAS_REF.test(v)) newRefs.push(v);
      }
    }

    // If a mounted Registry approval policy is configured, verify every added/updated ref exists in the mount!
    if (requireMount && newRefs.length > 0) {
      for (const ref of newRefs) {
        const found = ctx.mountQuery(requireMount, 'packages', { query: 'resolveByHash', pkgRef: ref });
        if (!found || found.revoked) {
          return { ok: false, code: 'mount_approval_required', detail: 'Package not approved in mount ' + requireMount + ': ' + ref };
        }
      }
    }

    if (!admin) {
      if (builders.length === 0 || newRefs.length === 0) {
        return { ok: false, code: 'admin_or_attestation_required' };
      }
      const attestations = Array.isArray(input.attestations) ? input.attestations : [];
      for (const ref of newRefs) {
        const buildSigners = new Set();
        const auditSigners = new Set();
        for (const att of attestations) {
          if (!verifyAttestation(att)) continue;
          if (att.payload.kind === 'build' && att.payload.outputRef === ref && builders.includes(att.signer)) {
            buildSigners.add(att.signer);
          }
          if (att.payload.kind === 'audit' && att.payload.pkgRef === ref && att.payload.verdict === 'approved' && auditors.includes(att.signer)) {
            auditSigners.add(att.signer);
          }
        }
        if (buildSigners.size < threshold) {
          return { ok: false, code: 'build_attestation_threshold_unmet', detail: 'Need ' + threshold + ' builder attestations for ' + ref };
        }
        if (requireAudit && auditSigners.size < 1) {
          return { ok: false, code: 'audit_attestation_required', detail: 'Need approved auditor attestation for ' + ref };
        }
      }
    }

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
    return {
      ok: true,
      state: next,
      events: [{ topic: '$reducers.updated', payload: { author: tx.author, attested: !admin } }],
    };
  },
};
`.trimStart()
