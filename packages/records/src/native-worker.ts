// Kept as JavaScript source so the same worker runs from TypeScript sources,
// compiled JS and the self-contained distribution bundle without a TS loader.
// One pool worker serves every NativeBytesStore in the process. Each store is a
// separate SQLite file addressed by its numeric handle.
export const nativeWorkerSource = String.raw`
(async () => {
const { parentPort } = await import('node:worker_threads')
const { mkdirSync } = await import('node:fs')
const { dirname } = await import('node:path')
const { DatabaseSync } = await import('node:sqlite')
const stores = new Map()
function error(message) { throw new Error(message) }
function validate(store, key, value) {
  if (typeof key !== 'string' || key.length === 0 || key.length > 4096 || [...key].some(c => c.charCodeAt(0) < 32)) error('BYTES_STORE_KEY_INVALID')
  if (value !== undefined && (!(value instanceof Uint8Array) || value.length > store.maxValue)) error('BYTES_STORE_VALUE_TOO_LARGE')
}
function reply(id, store, value, cause) {
  parentPort.postMessage({ id, value, used: store?.used ?? 0, ...(cause ? { error: { message: cause.message, code: cause.code } } : {}) })
}
function open(handle, { path, options }) {
  if (stores.has(handle)) error('BYTES_STORE_HANDLE_IN_USE')
  let db
  try {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
    db = new DatabaseSync(path)
    db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS stored_bytes (key TEXT PRIMARY KEY, value BLOB NOT NULL); COMMIT')
  } catch (cause) {
    try { db?.close() } catch {}
    if (/locked|busy/i.test(cause.message)) throw Object.assign(new Error('BYTES_STORE_IN_USE', { cause }), { code: 'BYTES_STORE_IN_USE' })
    throw cause
  }
  const store = {
    db, restoring: false, restoredBytes: 0,
    quota: options.quotaBytes ?? 256 * 1024 * 1024,
    maxValue: options.maxValueBytes ?? 128 * 1024 * 1024,
    used: Number(db.prepare('SELECT coalesce(sum(length(value)), 0) AS bytes FROM stored_bytes').get().bytes),
    get: db.prepare('SELECT value FROM stored_bytes WHERE key = ?'),
    size: db.prepare('SELECT length(value) AS bytes FROM stored_bytes WHERE key = ?'),
    put: db.prepare('INSERT INTO stored_bytes (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
    insert: db.prepare('INSERT INTO stored_bytes (key,value) VALUES (?,?)'),
    remove: db.prepare('DELETE FROM stored_bytes WHERE key = ?'),
    count: db.prepare('SELECT count(*) AS count FROM stored_bytes'),
    page: db.prepare('SELECT key,value FROM stored_bytes WHERE key > ? ORDER BY key LIMIT 1024'),
  }
  stores.set(handle, store)
  return store
}
function run(store, method, args) {
  const db = store.db
  if (method === 'getMany') {
    if (!Array.isArray(args.keys) || args.keys.length > 128) error('BYTES_STORE_BATCH_LIMIT')
    return args.keys.map(key => { validate(store, key); return store.get.get(key)?.value ?? null })
  }
  if (method === 'get') { validate(store, args.key); return store.get.get(args.key)?.value ?? null }
  if (method === 'put') {
    validate(store, args.key, args.value)
    const next = store.used - Number(store.size.get(args.key)?.bytes ?? 0) + args.value.length
    if (next > store.quota) error('BYTES_STORE_QUOTA_EXCEEDED')
    store.put.run(args.key, args.value); store.used = next
    return undefined
  }
  if (method === 'putMany') {
    if (!Array.isArray(args.entries) || args.entries.length > 128) error('BYTES_STORE_BATCH_LIMIT')
    const staged = new Map()
    for (const entry of args.entries) { validate(store, entry.key, entry.value); staged.set(entry.key, entry.value) }
    let next = store.used
    for (const [k, v] of staged) next = next - Number(store.size.get(k)?.bytes ?? 0) + v.length
    if (next > store.quota) error('BYTES_STORE_QUOTA_EXCEEDED')
    db.exec('BEGIN IMMEDIATE')
    try {
      for (const [k, v] of staged) store.put.run(k, v)
      db.exec('COMMIT')
      store.used = next
    } catch (cause) { try { db.exec('ROLLBACK') } catch {} throw cause }
    return undefined
  }
  if (method === 'delete') {
    validate(store, args.key)
    const prior = Number(store.size.get(args.key)?.bytes ?? 0)
    store.remove.run(args.key); store.used -= prior
    return undefined
  }
  if (method === 'page') {
    const value = []; let bytes = 0
    // Large pages: one worker round trip per ~1024 entries / 4 MiB instead of per 64 entries.
    for (const row of store.page.iterate(args.after)) {
      value.push({ key: row.key, value: row.value }); bytes += row.value.length
      if (value.length >= 1024 || bytes >= 4 * 1024 * 1024) break
    }
    return value
  }
  if (method === 'restoreBegin') {
    if (store.restoring) error('BYTES_STORE_RESTORE_IN_PROGRESS')
    db.exec('BEGIN IMMEDIATE')
    if (Number(store.count.get().count) !== 0) { db.exec('ROLLBACK'); return false }
    store.restoring = true; store.restoredBytes = 0
    return true
  }
  if (method === 'restorePut') {
    if (!store.restoring) error('BYTES_STORE_RESTORE_NOT_STARTED')
    validate(store, args.key, args.value)
    if (store.restoredBytes + args.value.length > store.quota) error('BYTES_STORE_QUOTA_EXCEEDED')
    try { store.insert.run(args.key, args.value) } catch (cause) {
      if (cause.errcode === 1555 || cause.code === 'SQLITE_CONSTRAINT_PRIMARYKEY' || /UNIQUE constraint failed|PRIMARY KEY/i.test(cause.message)) error('BYTES_STORE_DUPLICATE_KEY')
      throw cause
    }
    store.restoredBytes += args.value.length
    return undefined
  }
  if (method === 'restoreCommit') {
    if (!store.restoring) error('BYTES_STORE_RESTORE_NOT_STARTED')
    db.exec('COMMIT'); store.restoring = false; store.used = store.restoredBytes
    return undefined
  }
  if (method === 'restoreAbort') {
    if (store.restoring) { db.exec('ROLLBACK'); store.restoring = false }
    return undefined
  }
  if (method === 'checkpoint') { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); return undefined }
  error('BYTES_STORE_METHOD_INVALID')
}
parentPort.on('message', ({ id, handle, method, args }) => {
  let store
  try {
    if (method === 'open') { store = open(handle, args); reply(id, store); return }
    store = stores.get(handle)
    if (store === undefined) error('BYTES_STORE_CLOSED')
    if (method === 'close') {
      stores.delete(handle)
      if (store.restoring) { try { store.db.exec('ROLLBACK') } catch {} store.restoring = false }
      store.db.close()
      reply(id, store)
      return
    }
    reply(id, store, run(store, method, args))
  } catch (cause) { reply(id, store, undefined, cause) }
})
parentPort.postMessage({ id: 0, used: 0 })
})()
`
