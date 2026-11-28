export const STD_REGISTRY_SOURCE = `
import { openDb } from 'chronolog:sqlite';
import { verifyEd25519, canonicalJson, sha256 } from 'chronolog:crypto';

const CAS_REF = /^cas:sha256-[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{128}$/;

function isWriter(ctx, actor) {
  return ctx.can('writer', actor);
}

function isAdmin(ctx, actor) {
  return ctx.can('administrator', actor);
}

function ensureSchema(db) {
  db.exec(\`
    CREATE TABLE IF NOT EXISTS packages (
      name TEXT PRIMARY KEY,
      description TEXT NOT NULL DEFAULT '',
      latest_version TEXT NOT NULL,
      publisher TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS versions (
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      pkg_ref TEXT NOT NULL,
      drv_ref TEXT,
      runtime TEXT NOT NULL,
      builtins_json TEXT NOT NULL DEFAULT '[]',
      describe_json TEXT,
      publisher TEXT NOT NULL,
      published_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (name, version)
    );
    CREATE INDEX IF NOT EXISTS idx_versions_pkg_ref ON versions(pkg_ref);
    CREATE TABLE IF NOT EXISTS attestations (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      target_ref TEXT NOT NULL,
      drv_ref TEXT,
      verdict TEXT,
      runtime TEXT,
      signer TEXT NOT NULL,
      signature TEXT NOT NULL,
      notes TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attestations_target ON attestations(target_ref);
    CREATE VIRTUAL TABLE IF NOT EXISTS packages_fts USING fts5(name, description);
  \`, [], { mode: 'admin' });
}

function withDb(dbRoot, fn) {
  const db = openDb(dbRoot || null);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

export const packageRegistry = {
  reduce(state, tx, ctx) {
    if (!isWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_registry_input' };
    const curRoot = state && typeof state === 'object' && typeof state.dbRoot === 'string' ? state.dbRoot : null;

    return withDb(curRoot, db => {
      ensureSchema(db);
      const action = input.action;

      if (action === 'publish') {
        const name = typeof input.name === 'string' ? input.name.trim() : '';
        const version = typeof input.version === 'string' ? input.version.trim() : '';
        const pkgRef = typeof input.pkgRef === 'string' ? input.pkgRef : '';
        const drvRef = typeof input.drvRef === 'string' && CAS_REF.test(input.drvRef) ? input.drvRef : null;
        const runtime = typeof input.runtime === 'string' ? input.runtime : 'esm-quickjs';
        const description = typeof input.description === 'string' ? input.description : '';
        const builtins = Array.isArray(input.builtins) ? input.builtins.filter(b => typeof b === 'string').sort() : [];
        const describeJson = input.describeSchema !== undefined ? JSON.stringify(input.describeSchema) : null;
        if (!name || name.length > 256 || !version || version.length > 128 || !CAS_REF.test(pkgRef)) {
          return { ok: false, code: 'invalid_package_release' };
        }
        const existingPkg = db.query('SELECT publisher FROM packages WHERE name = ?', [name]);
        if (existingPkg.rows.length > 0 && existingPkg.rows[0][0] !== tx.author && !isAdmin(ctx, tx.author)) {
          return { ok: false, code: 'package_owner_mismatch' };
        }
        const existingVer = db.query('SELECT pkg_ref FROM versions WHERE name = ? AND version = ?', [name, version]);
        if (existingVer.rows.length > 0) {
          return { ok: false, code: 'version_already_exists' };
        }
        db.exec(
          'INSERT INTO versions(name, version, pkg_ref, drv_ref, runtime, builtins_json, describe_json, publisher, published_at, revoked) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0)',
          [name, version, pkgRef, drvRef, runtime, JSON.stringify(builtins), describeJson, tx.author, tx.authorTimestampMs],
          { mode: 'admin' },
        );
        db.exec(
          'INSERT INTO packages(name, description, latest_version, publisher, updated_at) VALUES(?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET description = excluded.description, latest_version = excluded.latest_version, updated_at = excluded.updated_at',
          [name, description, version, tx.author, tx.authorTimestampMs],
          { mode: 'admin' },
        );
        db.exec('DELETE FROM packages_fts WHERE name = ?', [name], { mode: 'admin' });
        db.exec('INSERT INTO packages_fts(name, description) VALUES(?, ?)', [name, description], { mode: 'admin' });
        const dbRoot = db.commit();
        return {
          ok: true,
          state: { dbRoot },
          events: [{ topic: 'registry.published', payload: { name, version, pkgRef, drvRef } }],
        };
      }

      if (action === 'attest') {
        const att = input.attestation;
        if (!att || typeof att !== 'object' || !att.payload || typeof att.payload !== 'object') {
          return { ok: false, code: 'invalid_attestation' };
        }
        if (att.payload.format !== 'chronolog-attestation/v1') return { ok: false, code: 'invalid_attestation_format' };
        if (typeof att.signer !== 'string' || !HEX32.test(att.signer) || typeof att.signature !== 'string' || !HEX64.test(att.signature)) {
          return { ok: false, code: 'invalid_attestation_signature' };
        }
        const msg = 'chronolog/attestation/v1:' + canonicalJson(att.payload);
        if (!verifyEd25519(att.signer, msg, att.signature)) {
          return { ok: false, code: 'attestation_signature_failed' };
        }
        const kind = att.payload.kind;
        let targetRef = '';
        let drvRef = null;
        let verdict = null;
        let runtime = null;
        let notes = null;
        if (kind === 'build') {
          targetRef = typeof att.payload.outputRef === 'string' ? att.payload.outputRef : '';
          drvRef = typeof att.payload.drvRef === 'string' ? att.payload.drvRef : null;
          runtime = typeof att.payload.runtime === 'string' ? att.payload.runtime : null;
        } else if (kind === 'audit') {
          targetRef = typeof att.payload.pkgRef === 'string' ? att.payload.pkgRef : '';
          verdict = typeof att.payload.verdict === 'string' ? att.payload.verdict : null;
          notes = typeof att.payload.notes === 'string' ? att.payload.notes : null;
        } else {
          return { ok: false, code: 'unknown_attestation_kind' };
        }
        if (!CAS_REF.test(targetRef)) return { ok: false, code: 'invalid_attestation_target' };
        const id = sha256(att.signer + ':' + msg);
        db.exec(
          'INSERT OR IGNORE INTO attestations(id, kind, target_ref, drv_ref, verdict, runtime, signer, signature, notes, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [id, kind, targetRef, drvRef, verdict, runtime, att.signer, att.signature, notes, tx.authorTimestampMs],
          { mode: 'admin' },
        );
        const dbRoot = db.commit();
        return {
          ok: true,
          state: { dbRoot },
          events: [{ topic: 'registry.attested', payload: { kind, targetRef, signer: att.signer } }],
        };
      }

      if (action === 'revoke') {
        const name = typeof input.name === 'string' ? input.name.trim() : '';
        const version = typeof input.version === 'string' ? input.version.trim() : '';
        const existing = db.query('SELECT publisher FROM versions WHERE name = ? AND version = ?', [name, version]);
        if (existing.rows.length === 0) return { ok: false, code: 'version_not_found' };
        if (existing.rows[0][0] !== tx.author && !isAdmin(ctx, tx.author)) return { ok: false, code: 'admin_or_owner_required' };
        db.exec('UPDATE versions SET revoked = 1 WHERE name = ? AND version = ?', [name, version], { mode: 'admin' });
        const dbRoot = db.commit();
        return { ok: true, state: { dbRoot }, events: [{ topic: 'registry.revoked', payload: { name, version } }] };
      }

      return { ok: false, code: 'unknown_registry_action' };
    });
  },
  query(state, input) {
    const curRoot = state && typeof state === 'object' && typeof state.dbRoot === 'string' ? state.dbRoot : null;
    if (!curRoot) return input && input.query === 'resolve' ? null : [];
    const req = input && typeof input === 'object' ? input : { query: 'list' };

    return withDb(curRoot, db => {
      const q = req.query || 'list';
      if (q === 'search') {
        const term = typeof req.q === 'string' ? req.q.trim() : '';
        const limit = typeof req.limit === 'number' && req.limit > 0 ? Math.min(100, Math.floor(req.limit)) : 25;
        if (!term) {
          const all = db.query('SELECT name, description, latest_version, publisher, updated_at FROM packages ORDER BY name LIMIT ?', [limit]);
          return all.rows.map(r => ({ name: r[0], description: r[1], latestVersion: r[2], publisher: r[3], updatedAt: r[4] }));
        }
        let rows = [];
        try {
          const fts = db.query(
            'SELECT p.name, p.description, p.latest_version, p.publisher, p.updated_at FROM packages_fts f JOIN packages p ON p.name = f.name WHERE packages_fts MATCH ? LIMIT ?',
            [term, limit],
          );
          rows = fts.rows;
        } catch {
          const like = '%' + term + '%';
          rows = db.query(
            'SELECT name, description, latest_version, publisher, updated_at FROM packages WHERE name LIKE ? OR description LIKE ? ORDER BY name LIMIT ?',
            [like, like, limit],
          ).rows;
        }
        return rows.map(r => ({ name: r[0], description: r[1], latestVersion: r[2], publisher: r[3], updatedAt: r[4] }));
      }

      if (q === 'resolve') {
        const name = typeof req.name === 'string' ? req.name : '';
        const version = typeof req.version === 'string' && req.version.length > 0 ? req.version : null;
        const sql = version
          ? 'SELECT name, version, pkg_ref, drv_ref, runtime, builtins_json, describe_json, publisher, published_at, revoked FROM versions WHERE name = ? AND version = ? LIMIT 1'
          : 'SELECT v.name, v.version, v.pkg_ref, v.drv_ref, v.runtime, v.builtins_json, v.describe_json, v.publisher, v.published_at, v.revoked FROM packages p JOIN versions v ON v.name = p.name AND v.version = p.latest_version WHERE p.name = ? LIMIT 1';
        const res = db.query(sql, version ? [name, version] : [name]);
        if (res.rows.length === 0) return null;
        const r = res.rows[0];
        const att = db.query('SELECT kind, verdict, signer, signature, drv_ref, runtime, notes FROM attestations WHERE target_ref = ? ORDER BY created_at ASC', [r[2]]);
        return {
          name: r[0],
          version: r[1],
          pkgRef: r[2],
          drvRef: r[3],
          runtime: r[4],
          builtins: JSON.parse(r[5]),
          describeSchema: r[6] ? JSON.parse(r[6]) : null,
          publisher: r[7],
          publishedAt: r[8],
          revoked: Boolean(r[9]),
          attestations: att.rows.map(a => ({ kind: a[0], verdict: a[1], signer: a[2], signature: a[3], drvRef: a[4], runtime: a[5], notes: a[6] })),
        };
      }

      if (q === 'resolveByHash') {
        const pkgRef = typeof req.pkgRef === 'string' ? req.pkgRef : '';
        const res = db.query(
          'SELECT name, version, pkg_ref, drv_ref, runtime, builtins_json, publisher, published_at, revoked FROM versions WHERE pkg_ref = ? LIMIT 1',
          [pkgRef],
        );
        if (res.rows.length === 0) return null;
        const r = res.rows[0];
        const att = db.query('SELECT kind, verdict, signer FROM attestations WHERE target_ref = ?', [pkgRef]);
        return {
          name: r[0],
          version: r[1],
          pkgRef: r[2],
          drvRef: r[3],
          runtime: r[4],
          builtins: JSON.parse(r[5]),
          publisher: r[6],
          publishedAt: r[7],
          revoked: Boolean(r[8]),
          buildAttestations: att.rows.filter(a => a[0] === 'build').length,
          approvedAudits: att.rows.filter(a => a[0] === 'audit' && a[1] === 'approved').length,
        };
      }

      if (q === 'attestations') {
        const targetRef = typeof req.targetRef === 'string' ? req.targetRef : '';
        const res = db.query('SELECT id, kind, target_ref, drv_ref, verdict, runtime, signer, signature, notes, created_at FROM attestations WHERE target_ref = ? ORDER BY created_at ASC', [targetRef]);
        return res.rows.map(a => ({ id: a[0], kind: a[1], targetRef: a[2], drvRef: a[3], verdict: a[4], runtime: a[5], signer: a[6], signature: a[7], notes: a[8], createdAt: a[9] }));
      }

      const limit = typeof req.limit === 'number' && req.limit > 0 ? Math.min(200, Math.floor(req.limit)) : 50;
      const all = db.query('SELECT name, description, latest_version, publisher, updated_at FROM packages ORDER BY name LIMIT ?', [limit]);
      return all.rows.map(r => ({ name: r[0], description: r[1], latestVersion: r[2], publisher: r[3], updatedAt: r[4] }));
    });
  },
  describe() {
    return {
      commands: [
        { name: 'publish', description: 'Publish a content-addressed package release (pkgRef + optional drvRef).' },
        { name: 'attest', description: 'Record a signed Ed25519 reproducible-build or security audit attestation.' },
        { name: 'revoke', description: 'Revoke a published package version.' },
      ],
      queries: [
        { name: 'search', description: 'Full-text search packages via SQLite FTS5.' },
        { name: 'resolve', description: 'Resolve package name/version to its CAS root and attestations.' },
        { name: 'resolveByHash', description: 'Look up package provenance and attestations by cas:sha256-... root.' },
        { name: 'attestations', description: 'List verified attestations for a package CAS root.' },
        { name: 'list', description: 'List published packages.' },
      ],
    };
  },
};
`.trimStart()
