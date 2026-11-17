import type { ChronologMaterializationRuntime } from '@chronolog/materializer'

/** A chronological node cannot turn generation recovery into immutable finality. */
export function assertChronologicalMaterialization(runtime: ChronologMaterializationRuntime): void {
  if (runtime.historyProfile !== undefined && runtime.historyProfile !== 'chronological') {
    throw new Error('NODE_MATERIALIZATION_PROFILE_MISMATCH')
  }
}
