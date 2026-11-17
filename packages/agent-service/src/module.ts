import type { ChronologNode, DurableOperationStore } from '@chronolog/node-core'
import type { Signals } from '@chronolog/signals'

import type { NativeFinalityService } from './finality-service.js'
import type { EffectHandler } from './effect-worker.js'
import type { FinalEventPublisher } from './event-source.js'
import type { GovernedPeerService } from './governed-peer.js'
import type { ResidentTask } from './service.js'
import type { TimerOccurrencePublisher } from './timers.js'

export interface AgentApplication {
  readonly effects?: readonly { readonly handler: EffectHandler; readonly resultTopic: string }[]
  readonly timers?: readonly { readonly id: string; readonly configurationTopic: string; readonly publisher: TimerOccurrencePublisher }[]
  readonly tasks?: readonly ResidentTask[]
}

export interface AgentApplicationContext {
  readonly node: ChronologNode
  readonly store: DurableOperationStore
  readonly finality: NativeFinalityService | null
  /** Live messages with explicit FIFO/latest delivery; receiving requires no writer grant. */
  readonly signals: Signals
  readonly publisher: FinalEventPublisher
  readonly sourceId: string
  readonly connectPeer: GovernedPeerService['connectPeer']
}

/** The daemon loads this trusted local export; provider code remains outside the core. */
export interface AgentApplicationModule {
  createAgent(context: AgentApplicationContext): AgentApplication | Promise<AgentApplication>
}
