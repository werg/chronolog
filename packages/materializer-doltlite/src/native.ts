import { openDatabase } from './driver.js'
import { DeterministicMaterializer as PortableMaterializer } from './materializer.js'
import type { MaterializerOptions } from './types.js'

export { MaterializerInputError } from './materializer.js'
export type DeterministicMaterializer = PortableMaterializer

/** Native convenience entry point. The portable reducer owns no native imports. */
export const DeterministicMaterializer = {
  open(options: MaterializerOptions): Promise<PortableMaterializer> {
    return PortableMaterializer.open({ ...options, openDatabase: options.openDatabase ?? openDatabase })
  },
}
