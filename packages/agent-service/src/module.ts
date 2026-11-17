import type { ChronologNode, DurableOperationStore } from '@chronolog/node-core'

import type { NativeFinalityService } from './finality-service.js'
import type { EffectHandler } from './effect-worker.js'
import type { FinalEventPublisher } from './event-source.js'
import type { FramedPeerConnection } from './framing.js'
import type { ResidentTask } from './service.js'
import type { SignalChannel } from '@chronolog/signals'
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
  readonly publisher: FinalEventPublisher
  readonly sourceId: string
  readonly signals: SignalChannel
  connectPeer(options: { readonly connection: FramedPeerConnection; readonly grantId?: Uint8Array }): Promise<{
    readonly completion: Promise<void>
    close(): Promise<void>
  }>
}

/** The daemon loads this trusted local export; provider code remains outside the core. */
export interface AgentApplicationModule {
  createAgent(context: AgentApplicationContext): AgentApplication | Promise<AgentApplication>
}
