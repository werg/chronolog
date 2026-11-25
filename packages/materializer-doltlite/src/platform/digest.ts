import { createSha256, utf8 } from '@chronolog/canonical'

import { SQL_PROFILE_VERSION } from '../sql-profile.js'
import { SYSTEM_LOG_SQL } from '../system-log.js'

import { PLATFORM_TABLES_SQL, PLATFORM_VIEWS_SQL } from './schema.js'
import { platformTriggers, type TableShape } from './tables.js'

/**
 * Version of the platform-operation semantics in ./session.ts. Bump it with
 * any change to what an operation checks or writes: the platform code decides
 * replicated state, so replicas must run the same version.
 */
export const PLATFORM_CODE_VERSION = 'chronolog-platform-ops-v11-authored-replay-ddl-acl-v1'

/** A fixed table that exercises the trigger generator (composite key, odd names, a cap column). */
const REFERENCE_TABLE: TableShape = {
  name: 'Reference "table"',
  columns: [
    { name: 'id', type: 'INTEGER', notNull: true, defaultValue: null, primaryKey: 1, hidden: 0 },
    { name: "o'k", type: 'TEXT', notNull: true, defaultValue: null, primaryKey: 2, hidden: 0 },
    { name: 'body', type: 'TEXT', notNull: false, defaultValue: null, primaryKey: 0, hidden: 0 },
    { name: 'generated', type: 'TEXT', notNull: false, defaultValue: null, primaryKey: 0, hidden: 3 },
    { name: 'chronolog_owner', type: 'INTEGER', notNull: true, defaultValue: 'chronolog_actor_id()', primaryKey: 0, hidden: 0 },
  ],
  primaryKey: ['id', "o'k"],
  foreignKeys: [],
}

/** SHA-256 over SQL/operation semantics, replicated schemas, and generated views and triggers. */
export function computePlatformDigest(): Uint8Array {
  const hash = createSha256()
  hash.update('chronolog-platform-digest-v2\n')
  hash.update(`${PLATFORM_CODE_VERSION}\n`)
  hash.update(`${SQL_PROFILE_VERSION}\n`)
  for (const sql of [SYSTEM_LOG_SQL, ...PLATFORM_TABLES_SQL, ...PLATFORM_VIEWS_SQL, ...platformTriggers(REFERENCE_TABLE).map((trigger) => trigger.sql)]) {
    hash.update(`${utf8(sql).length}\n${sql}\n`)
  }
  return Uint8Array.from(hash.digest())
}

export const PLATFORM_DIGEST: Uint8Array = computePlatformDigest()
