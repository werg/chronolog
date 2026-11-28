import { parseCasRef } from '@chronolog/records'
import { STANDARD_MODULE_IMPORTS } from '@chronolog/materializer/std-modules'

let hashes: ReadonlySet<string> | undefined

/**
 * CAS hashes of the audited standard modules. Every replica and host seeds these itself, so they
 * are never shipped between peers, exported in snapshots or deltas, or garbage collected.
 */
export function standardModuleHashes(): ReadonlySet<string> {
  return hashes ??= new Set(Object.values(STANDARD_MODULE_IMPORTS).map(ref => parseCasRef(ref)))
}
