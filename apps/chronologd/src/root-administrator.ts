import { access, readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { decodeSignedGenesis } from '@chronolog/capabilities'
import { readMaterializedRootAdministrator } from '@chronolog/materializer-doltlite'

import { fromBase64 } from './config.js'
import { readStaticRootAdministrator } from './static-membership.js'

/**
 * The group's genesis root administrator, needed to open the materialized
 * database: from the database itself when it exists, otherwise from the
 * group's genesis (governance.json) or the static membership file.
 */
export async function resolveRootAdministrator(dataDirectory: string, environment: NodeJS.ProcessEnv = process.env): Promise<Uint8Array> {
  const databasePath = join(dataDirectory, 'application.db')
  if (await exists(databasePath)) return readMaterializedRootAdministrator(databasePath)
  const governancePath = join(dataDirectory, 'governance.json')
  if (await exists(governancePath)) {
    const document = JSON.parse(await readFile(governancePath, 'utf8')) as { readonly signedGenesis?: unknown }
    if (typeof document.signedGenesis !== 'string') throw new Error('ROOT_ADMINISTRATOR_GENESIS_INVALID')
    return decodeSignedGenesis(fromBase64(document.signedGenesis)).manifest.rootAdminPublicKey
  }
  if (environment.CHRONOLOG_STATIC_MEMBERSHIP_FILE !== undefined) {
    return readStaticRootAdministrator(resolve(environment.CHRONOLOG_STATIC_MEMBERSHIP_FILE))
  }
  throw new Error('ROOT_ADMINISTRATOR_UNKNOWN')
}

async function exists(path: string): Promise<boolean> {
  try { await access(path); return true } catch { return false }
}
