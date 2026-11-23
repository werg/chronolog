// Kept as JavaScript source so the same worker runs from TypeScript sources,
// compiled JS and the self-contained distribution bundle without a TS loader.
export const nativeWorkerSource = String.raw`
(async () => {
const { parentPort, workerData } = await import('node:worker_threads')
const { createRequire } = await import('node:module')
const require = createRequire(workerData.sqliteModule)
const { mkdirSync } = require('node:fs')
const { dirname } = require('node:path')
const Database = require(workerData.sqliteModule)
let db, used = 0, restoring = false, restoredBytes = 0
const quota = workerData.options.quotaBytes ?? 256 * 1024 * 1024
const maxValue = workerData.options.maxValueBytes ?? 128 * 1024 * 1024
function error(message) { throw new Error(message) }
function validate(key, value) {
  if (typeof key !== 'string' || key.length === 0 || key.length > 4096 || [...key].some(c => c.charCodeAt(0) < 32)) error('BYTES_STORE_KEY_INVALID')
  if (value !== undefined && (!(value instanceof Uint8Array) || value.length > maxValue)) error('BYTES_STORE_VALUE_TOO_LARGE')
}
function reply(id, value, cause) {
  parentPort.postMessage({ id, value, used, ...(cause ? { error: { message: cause.message, code: cause.code } } : {}) })
}
try {
  if (workerData.path !== ':memory:') mkdirSync(dirname(workerData.path), { recursive: true })
  db = new Database(workerData.path, { timeout: 0 })
  db.exec('PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS stored_bytes (key TEXT PRIMARY KEY, value BLOB NOT NULL); COMMIT')
  used = db.prepare('SELECT coalesce(sum(length(value)), 0) AS bytes FROM stored_bytes').get().bytes
} catch (cause) {
  try { db?.close() } catch {}
  if (/locked|busy/i.test(cause.message)) cause = new Error('BYTES_STORE_IN_USE', { cause })
  reply(0, undefined, cause)
  parentPort.close()
  return
}
const get = db.prepare('SELECT value FROM stored_bytes WHERE key = ?')
const size = db.prepare('SELECT length(value) AS bytes FROM stored_bytes WHERE key = ?')
const put = db.prepare('INSERT INTO stored_bytes (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
const insert = db.prepare('INSERT INTO stored_bytes (key,value) VALUES (?,?)')
const count = db.prepare('SELECT count(*) AS count FROM stored_bytes')
const page = db.prepare('SELECT key,value FROM stored_bytes WHERE key > ? ORDER BY key')
reply(0)
parentPort.on('message', ({ id, method, args }) => {
  try {
    let value
    if (method === 'getMany') {
      if (!Array.isArray(args.keys) || args.keys.length > 128) error('BYTES_STORE_BATCH_LIMIT')
      value = args.keys.map(key => { validate(key); return get.get(key)?.value ?? null })
    } else if (method === 'get') { validate(args.key); value = get.get(args.key)?.value ?? null }
    else if (method === 'put') {
      validate(args.key, args.value)
      const next = used - (size.get(args.key)?.bytes ?? 0) + args.value.length
      if (next > quota) error('BYTES_STORE_QUOTA_EXCEEDED')
      put.run(args.key, args.value); used = next
    } else if (method === 'page') {
      value = []; let bytes = 0
      for (const row of page.iterate(args.after)) {
        value.push(row); bytes += row.value.length
        if (value.length >= 64 || bytes >= 1024 * 1024) break
      }
    } else if (method === 'restoreBegin') {
      if (restoring) error('BYTES_STORE_RESTORE_IN_PROGRESS')
      db.exec('BEGIN IMMEDIATE')
      if (count.get().count !== 0) { db.exec('ROLLBACK'); value = false }
      else { restoring = true; restoredBytes = 0; value = true }
    } else if (method === 'restorePut') {
      if (!restoring) error('BYTES_STORE_RESTORE_NOT_STARTED')
      validate(args.key, args.value)
      if (restoredBytes + args.value.length > quota) error('BYTES_STORE_QUOTA_EXCEEDED')
      try { insert.run(args.key, args.value) } catch (cause) {
        if (cause.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') error('BYTES_STORE_DUPLICATE_KEY')
        throw cause
      }
      restoredBytes += args.value.length
    } else if (method === 'restoreCommit') {
      if (!restoring) error('BYTES_STORE_RESTORE_NOT_STARTED')
      db.exec('COMMIT'); restoring = false; used = restoredBytes
    } else if (method === 'restoreAbort') {
      if (restoring) { db.exec('ROLLBACK'); restoring = false }
    } else if (method === 'checkpoint') db.exec('PRAGMA wal_checkpoint(TRUNCATE)')
    else if (method === 'close') {
      if (restoring) { db.exec('ROLLBACK'); restoring = false }
      db.close()
    } else error('BYTES_STORE_METHOD_INVALID')
    reply(id, value)
    if (method === 'close') parentPort.close()
  } catch (cause) { reply(id, undefined, cause) }
})
})()
`
