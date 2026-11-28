export const STD_MOUNTS_SOURCE = `
import { verifyEd25519, canonicalJson } from 'chronolog:crypto';

const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function isAdmin(ctx, actor) {
  const checked = ctx.query('$permissions', { check: 'administrator', actor });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  return Boolean(perms && Array.isArray(perms.members) && perms.members.some(m => m.publicKey === actor && m.administrator === true));
}

export const verifiedMounts = {
  reduce(state, tx, ctx) {
    const cur = state && typeof state === 'object' && state.mounts && typeof state.mounts === 'object'
      ? { mounts: { ...state.mounts } }
      : { mounts: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_mount_input' };
    const action = input.action || 'update';
    const name = typeof input.name === 'string' ? input.name.trim() : '';
    if (!name || name.length > 128) return { ok: false, code: 'invalid_mount_name' };

    if (action === 'remove') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      delete cur.mounts[name];
      return { ok: true, state: cur, events: [{ topic: '$mounts.removed', payload: { name } }] };
    }

    if (action === 'configure') {
      if (!isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_required' };
      if (typeof input.logId !== 'string' || !HEX32.test(input.logId)) return { ok: false, code: 'invalid_log_id' };
      const signers = Array.isArray(input.trustedSigners)
        ? Array.from(new Set(input.trustedSigners.filter(k => typeof k === 'string' && HEX32.test(k)))).sort()
        : [];
      const prev = cur.mounts[name] || null;
      cur.mounts[name] = {
        logId: input.logId,
        stateRoot: prev ? prev.stateRoot : null,
        topics: prev ? prev.topics : {},
        casRoots: prev ? prev.casRoots : [],
        trustedSigners: signers,
        attestedBy: prev ? prev.attestedBy : null,
        updatedAtMs: tx.authorTimestampMs,
      };
      return { ok: true, state: cur, events: [{ topic: '$mounts.configured', payload: { name, logId: input.logId } }] };
    }

    if (action === 'update') {
      const prev = cur.mounts[name] || null;
      const logId = typeof input.logId === 'string' ? input.logId : (prev ? prev.logId : '');
      const stateRoot = typeof input.stateRoot === 'string' ? input.stateRoot : '';
      const topics = input.topics && typeof input.topics === 'object' && !Array.isArray(input.topics) ? input.topics : null;
      if (!HEX32.test(logId) || !HEX32.test(stateRoot) || !topics) {
        return { ok: false, code: 'invalid_mount_snapshot' };
      }
      if (prev && prev.logId !== logId) return { ok: false, code: 'mount_log_id_mismatch' };
      const trustedSigners = Array.isArray(input.trustedSigners) && isAdmin(ctx, tx.author)
        ? Array.from(new Set(input.trustedSigners.filter(k => typeof k === 'string' && HEX32.test(k)))).sort()
        : (prev && Array.isArray(prev.trustedSigners) ? prev.trustedSigners : []);

      let attestedBy = null;
      if (typeof input.signer === 'string' && typeof input.signature === 'string') {
        if (!HEX32.test(input.signer) || !HEX64.test(input.signature)) {
          return { ok: false, code: 'invalid_mount_signature' };
        }
        if (trustedSigners.length > 0 && !trustedSigners.includes(input.signer)) {
          return { ok: false, code: 'untrusted_mount_signer' };
        }
        const msg = 'chronolog/mount/v1:' + canonicalJson({ logId, stateRoot, topics });
        if (!verifyEd25519(input.signer, msg, input.signature)) {
          return { ok: false, code: 'mount_signature_failed' };
        }
        attestedBy = input.signer;
      } else if (!isAdmin(ctx, tx.author)) {
        return { ok: false, code: 'mount_authorization_required' };
      }

      const casRoots = Array.isArray(input.casRoots)
        ? Array.from(new Set(input.casRoots.filter(h => typeof h === 'string' && (HEX32.test(h) || /^cas:sha256-[0-9a-f]{64}$/.test(h))))).sort()
        : [];
      cur.mounts[name] = {
        logId,
        stateRoot,
        topics,
        casRoots,
        trustedSigners,
        attestedBy,
        updatedAtMs: tx.authorTimestampMs,
      };
      return {
        ok: true,
        state: cur,
        events: [{ topic: '$mounts.updated', payload: { name, logId, stateRoot, attestedBy } }],
      };
    }

    return { ok: false, code: 'unknown_mount_action' };
  },
  query(state, input) {
    const mounts = state && typeof state === 'object' && state.mounts && typeof state.mounts === 'object' ? state.mounts : {};
    if (input && typeof input === 'object' && typeof input.name === 'string') {
      return Object.prototype.hasOwnProperty.call(mounts, input.name) ? mounts[input.name] : null;
    }
    return { mounts };
  },
};
`.trimStart()
