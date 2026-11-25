import type { MaterializerOptions } from '@chronolog/materializer-doltlite/browser'
import type { ChronologMaterializationRuntime } from '@chronolog/materializer'
/** DDL and grants are ordinary signed submissions after this empty trusted platform bootstrap. */
export async function createSqlMaterializationRuntime(options: MaterializerOptions): Promise<ChronologMaterializationRuntime> {
  const { DeterministicMaterializer, createDoltLiteMaterializationRuntime } = await import('@chronolog/materializer-doltlite/browser')
  return createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open(options))
}
export type { MaterializerOptions, SqlEngine } from '@chronolog/materializer-doltlite/browser'
