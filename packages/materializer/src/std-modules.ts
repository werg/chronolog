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
import { STD_ADMISSION_SOURCE } from './std/admission.js'
import { STD_SEALS_SOURCE } from './std/seals.js'
import { STD_REDUCER_SOURCE } from './std/reducer.js'
import { STD_VAULTS_SOURCE } from './std/vaults.js'
import { STD_KEYBOX_SOURCE } from './std/keybox.js'
import { STD_KEYS_SOURCE } from './std/keys.js'
import {
  STD_GUARDS_SOURCE,
  STD_QUOTAS_SOURCE,
  STD_QUEUE_SOURCE,
  STD_VOTES_SOURCE,
  STD_SCHEMA_SOURCE,
  STD_AUDIT_SOURCE,
} from './std-stdlib-extra.js'

export {
  STD_CRDT_SOURCE,
  STD_TEXT_SOURCE,
  STD_LEDGER_SOURCE,
  STD_WORKFLOW_SOURCE,
  STD_FS_SOURCE,
  STD_MOUNTS_SOURCE,
  STD_BUILDERS_SOURCE,
  STD_REGISTRY_SOURCE,
  STD_ADMISSION_SOURCE,
  STD_SEALS_SOURCE,
  STD_REDUCER_SOURCE,
  STD_VAULTS_SOURCE,
  STD_KEYBOX_SOURCE,
  STD_KEYS_SOURCE,
  STD_GUARDS_SOURCE,
  STD_QUOTAS_SOURCE,
  STD_QUEUE_SOURCE,
  STD_VOTES_SOURCE,
  STD_SCHEMA_SOURCE,
  STD_AUDIT_SOURCE,
}

export const STD_PUBLICATIONS_SOURCE = `
const HEX32 = /^[0-9a-f]{64}$/;

function isPublisher(ctx, author) {
  return ctx.can('publisher', author);
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
        ...(typeof target.treeRoot === 'string' ? { treeRoot: target.treeRoot } : {}),
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
    if (input.treeRoot !== undefined && (typeof input.treeRoot !== 'string' || !/^cas:sha256-[0-9a-f]{64}$/.test(input.treeRoot))) {
      return { ok: false, code: 'invalid_publication_tree_root' };
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
    const release = {
      revision,
      opId: tx.opId,
      author: tx.author,
      timestampMs: tx.authorTimestampMs,
      entry: input.entry,
      files,
      ...(typeof input.treeRoot === 'string' ? { treeRoot: input.treeRoot } : {}),
    };
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
    db.exec(
      'UPDATE ' + qTable + ' SET ' + setClause + ' WHERE _last_op_id IS NULL',
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

function quoteColIdent(name) {
  if (typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error('RLS_INVALID_COLUMN:' + String(name));
  }
  return '"' + name + '"';
}

/**
 * Build a deterministic SQLite write-RLS expression verifying that a column holds a valid
 * \`chronolog-sealed/v1\` box (\`session.sealFor\`) whose recipient keys are non-empty and
 * strictly a subset of \`allowedSubquerySql\` (e.g. \`"SELECT public_key FROM team_members WHERE team_id = NEW.team_id"\`).
 */
export function sealRecipientsPolicy(column, allowedSubquerySql, options = {}) {
  const col = 'NEW.' + quoteColIdent(column);
  if (typeof allowedSubquerySql !== 'string' || !allowedSubquerySql.trim()) {
    throw new Error('RLS_ALLOWED_SUBQUERY_REQUIRED');
  }
  const allowNull = options && options.allowNull === true;
  const check =
    '(json_valid(' + col + ') = 1' +
    " AND json_extract(" + col + ", '$.format') = 'chronolog-sealed/v1'" +
    " AND json_type(" + col + ", '$.nonce') = 'text'" +
    " AND json_type(" + col + ", '$.ciphertext') = 'text'" +
    " AND json_type(" + col + ", '$.boxes') = 'object'" +
    " AND (SELECT COUNT(*) FROM json_each(" + col + ", '$.boxes')) > 0" +
    " AND NOT EXISTS (SELECT 1 FROM json_each(" + col + ", '$.boxes') WHERE key NOT IN (" + allowedSubquerySql + ')))';
  return allowNull ? '(' + col + ' IS NULL OR ' + check + ')' : check;
}

/**
 * Build a deterministic SQLite write-RLS expression verifying that:
 * 1. \`NEW.<column>\` is a valid \`chronolog-vault-box/v1\` payload bound to \`NEW.<vaultIdColumn>\`, AND
 * 2. \`actor()\` is an authorized member of that private vault in \`vaultsTopic\` (default \`'vaults'\`).
 */
export function vaultBoxPolicy(column, vaultIdColumn, vaultsTopic = 'vaults', options = {}) {
  const col = 'NEW.' + quoteColIdent(column);
  const vCol = 'NEW.' + quoteColIdent(vaultIdColumn);
  if (typeof vaultsTopic !== 'string' || !/^[A-Za-z0-9_.:/-]{1,64}$/.test(vaultsTopic)) {
    throw new Error('RLS_INVALID_VAULTS_TOPIC');
  }
  const safeTopic = "'" + vaultsTopic.replace(/'/g, "''") + "'";
  const allowNull = options && options.allowNull === true;
  const check =
    '(json_valid(' + col + ') = 1' +
    " AND json_extract(" + col + ", '$.format') = 'chronolog-vault-box/v1'" +
    " AND json_extract(" + col + ", '$.vaultId') = " + vCol +
    " AND json_type(" + col + ", '$.epoch') = 'integer'" +
    " AND json_type(" + col + ", '$.nonce') = 'text'" +
    " AND json_type(" + col + ", '$.ciphertext') = 'text'" +
    " AND chronolog_topic_query(" + safeTopic + ", json_object('kind', 'canAccess', 'vaultId', " + vCol + ", 'actor', actor())) = 'true')";
  return allowNull ? '(' + col + ' IS NULL OR ' + check + ')' : check;
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
  return ctx.can(capability, actor, extra);
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
    return ctx.can(cap, actor);
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
  'chronolog/admission': STD_ADMISSION_SOURCE,
  'chronolog/reducer': STD_REDUCER_SOURCE,
  'chronolog/keys': STD_KEYS_SOURCE,
  'chronolog/keybox': STD_KEYBOX_SOURCE,
  'chronolog/vaults': STD_VAULTS_SOURCE,
  'chronolog/publications': STD_PUBLICATIONS_SOURCE,
  'chronolog/seals': STD_SEALS_SOURCE,
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
  'chronolog/guards': STD_GUARDS_SOURCE,
  'chronolog/quotas': STD_QUOTAS_SOURCE,
  'chronolog/queue': STD_QUEUE_SOURCE,
  'chronolog/votes': STD_VOTES_SOURCE,
  'chronolog/schema': STD_SCHEMA_SOURCE,
  'chronolog/audit': STD_AUDIT_SOURCE,
})

export const STANDARD_MODULE_BUILTINS: Readonly<Record<string, readonly ChronologBuiltinName[]>> = Object.freeze({
  'chronolog/admission': ['chronolog:crypto'],
  'chronolog/seals': [],
  'chronolog/reducer': [],
  'chronolog/keys': ['chronolog:cas'],
  'chronolog/keybox': [],
  'chronolog/vaults': [],
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
  'chronolog/guards': [],
  'chronolog/quotas': [],
  'chronolog/queue': [],
  'chronolog/votes': [],
  'chronolog/schema': [],
  'chronolog/audit': ['chronolog:crypto'],
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
