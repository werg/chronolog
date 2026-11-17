/** The column that stores a row's internal principal id; use `ownerKeySql` to read its public key. */
export const OWNER_COLUMN = 'chronolog_owner'

/**
 * SQL expression for a row owner's 32-byte key:
 * `SELECT n.*, ${ownerKeySql('n')} AS owner FROM notes AS n`, or
 * `WHERE ${ownerKeySql('n')} = ?` with a key bound as bytes.
 * The optional alias is a SQL identifier supplied by the application definition.
 */
export function ownerKeySql(alias?: string): string {
  const column = alias === undefined ? OWNER_COLUMN : `${alias}.${OWNER_COLUMN}`
  return `(SELECT key FROM chronolog_principals WHERE id = ${column})`
}

/**
 * SQL expression for the internal owner id of the 32-byte key bound to `?`:
 * `INSERT INTO notes (id, body, chronolog_owner) VALUES (?, ?, ${OWNER_FOR_KEY_SQL})`.
 * For shared application rows, bind `APPLICATION_COLLECTIVE_ID` as bytes.
 */
export const OWNER_FOR_KEY_SQL = '(SELECT id FROM chronolog_principals WHERE key = ?)'
