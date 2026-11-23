export interface SqliteBytesStoreOptions {
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}

export function sqliteByteLimits(options: SqliteBytesStoreOptions) {
  const quotaBytes = options.quotaBytes ?? 256 * 1024 * 1024
  const maxValueBytes = options.maxValueBytes ?? 128 * 1024 * 1024
  for (const value of [quotaBytes, maxValueBytes]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error('BYTES_STORE_QUOTA_INVALID')
  }
  return { quotaBytes, maxValueBytes }
}

export function validateSqliteByteKey(key: string): void {
  if (key.length === 0 || key.length > 2048 || [...key].some((character) => character.charCodeAt(0) < 32)) {
    throw new Error('BYTES_STORE_KEY_INVALID')
  }
}
