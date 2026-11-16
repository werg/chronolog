import type { MaterializedLocalSqlResult } from '@chronolog/materializer'
import type { TransactionOutcome } from '@chronolog/rpc'

/** Public bootstrap material only; every joining Worker creates its own keys. */
export interface BrowserBridgeBootstrap {
  readonly hubUrl: string
  readonly token: string
  readonly genesis: string
  readonly groupRoute: string
  readonly executionManifest: string
  readonly rootIdentity: string
}

export interface BrowserBridgeIdentity {
  readonly identity: string
  readonly groupId: string
  readonly transportAuthor: string
}

export interface BrowserBridgeSnapshot {
  readonly identity: string
  readonly hash: string
  readonly finalOrderLength: number
  readonly finalThrough: number
  readonly rows: MaterializedLocalSqlResult['rows']
  readonly outcomes: readonly TransactionOutcome[]
}
