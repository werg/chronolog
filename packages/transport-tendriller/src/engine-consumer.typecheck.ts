// Compile against the packed public engine declarations without importing its
// cloudflare:workers runtime into a Node test process.
import type engine from '@tendriller/engine'

import { authorizeThroughRecordLog, withTendrillerAuthority } from './authority.js'
import type { AuthorityHttp, TendrillerAuthorityOptions } from './authority.js'

type WorkerRequest = Parameters<typeof engine.fetch>[0]
type WorkerResponse = Awaited<ReturnType<typeof engine.fetch>>
type WorkerContext = Parameters<typeof engine.fetch>[2]

export function typedEngineConsumer(
  handler: typeof engine,
  http: AuthorityHttp<WorkerRequest, WorkerResponse>,
  options: TendrillerAuthorityOptions<unknown, WorkerContext, WorkerRequest, WorkerResponse>,
): typeof engine {
  return withTendrillerAuthority(handler, {
    ...options, http,
    authorize: authorizeThroughRecordLog(handler, {
      base: 'https://tendril.example/api/t/fixed', historyId: options.configuration.historyId, http,
    }),
  })
}
