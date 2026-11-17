// Compile against the packed public engine declarations without importing its
// cloudflare:workers runtime into a Node test process.
import type engine from '@tendriller/engine'

import { authorizeThroughRecordLog, withTendrillerFinality } from './finality-service.js'
import type { FinalityHttp, TendrillerFinalityOptions } from './finality-service.js'

type WorkerRequest = Parameters<typeof engine.fetch>[0]
type WorkerResponse = Awaited<ReturnType<typeof engine.fetch>>
type WorkerContext = Parameters<typeof engine.fetch>[2]

export async function typedEngineConsumer(
  handler: typeof engine,
  http: FinalityHttp<WorkerRequest, WorkerResponse>,
  options: TendrillerFinalityOptions<unknown, WorkerContext, WorkerRequest, WorkerResponse>,
): Promise<typeof engine> {
  if (options.descriptor.history.kind !== 'coordinated') throw new Error('SIGNED_INCLUSION_REQUIRED')
  return withTendrillerFinality(handler, {
    ...options, http,
    authorize: authorizeThroughRecordLog(handler, {
      base: 'https://tendril.example/api/t/fixed', historyId: options.descriptor.history.historyId, http,
    }),
  })
}
