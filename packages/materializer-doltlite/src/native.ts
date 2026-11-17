import { openDatabase } from './driver.js'
import { DeterministicMaterializer as PortableMaterializer } from './materializer.js'
import type { AppliedMaterializerOptions, MaterializerOptions } from './types.js'
import type { DoltLiteAppliedMaterializerRuntimeBackend } from './runtime-adapter.js'

export { MaterializerInputError } from './materializer.js'
export type DeterministicMaterializer = PortableMaterializer

/** Native convenience entry point. The portable reducer owns no native imports. */
export const DeterministicMaterializer = {
  open(options: MaterializerOptions): Promise<PortableMaterializer> {
    return PortableMaterializer.open({ ...options, openDatabase: options.openDatabase ?? openDatabase })
  },
}

/** Native applied replay has no final view, prefix state, or finality operations. */
export const AppliedMaterializer = {
  open(options: AppliedMaterializerOptions): Promise<DoltLiteAppliedMaterializerRuntimeBackend> {
    return PortableMaterializer.openApplied({ ...options, openDatabase: options.openDatabase ?? openDatabase })
  },
}
