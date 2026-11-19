import { createCelldSqlEngine, type CelldSqlStorage } from '@chronolog/materializer-doltlite/celld'
import type { ExecutionLimits } from '@chronolog/protocol'

import type { ApplicationDefinition } from './definition.js'
import { openSqlApplication, type OpenSqlApplicationOptions } from './sql.js'

export { createCelldSqlEngine, type CelldSqlStorage }
export { CelldPrivateBytesStore, type CelldPrivateBytesStorage } from '@chronolog/records/celld'
export { prepareSqlApplication } from './sql.js'

export type OpenCelldSqlApplicationOptions<D extends ApplicationDefinition = ApplicationDefinition> =
  Omit<OpenSqlApplicationOptions<D>, 'createEngine' | 'databasePath'> & {
    /** Store for the replicated SQL image. Keep private session records in separate storage. */
    readonly sqlStorage: CelldSqlStorage
    readonly sqlLimits?: Partial<ExecutionLimits>
  }

/** Open a signed current Chronolog application on the calling object's Dolt store. */
export function openCelldSqlApplication<const D extends ApplicationDefinition>(options: OpenCelldSqlApplicationOptions<D>) {
  const { sqlStorage, sqlLimits, ...application } = options
  const engineOptions = sqlLimits === undefined ? {} : { limits: { ...sqlLimits } }
  return openSqlApplication({
    ...application, databasePath: 'celld:application',
    createEngine: () => createCelldSqlEngine(sqlStorage, engineOptions),
  })
}

export { celldGroupData, type CelldGroupQueryResult } from './celld-group-data.js'
export { encodeChangeProgram, decodeChangeProgram, type ChangeProgram } from '@chronolog/protocol'
export { CelldGroupControl, type CelldGroupInvitation, type CelldGroupNode, type CelldGroupRole } from './celld-group-control.js'
