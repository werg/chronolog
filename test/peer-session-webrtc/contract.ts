import {
  defineApplication, defineCommand, defineQuery, emit, program,
  type ApplicationReadView, type AuthorityBundle, type PeerRevision, type ApplicationEvent, type SessionStatus,
} from '@chronolog/peer-session'
import type { EphemeralSignal } from '@chronolog/signals'

export const definition = defineApplication({ id: 'peer-session-rtc', version: '1', commands: {
  say: defineCommand({ description: 'Post one message', input: { type: 'string', minLength: 1, maxLength: 2048 },
    prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Read the current applied messages', input: { type: 'null' },
    read: (view: ApplicationReadView) => view.readEvents() }),
} })

/** Explicit fixture enrollment; this is not a hosted key-delivery protocol. */
export interface Bootstrap { readonly authority: AuthorityBundle; readonly epoch: number; readonly epochKey: string }
export interface BrowserState {
  readonly deviceId: string
  readonly storageId: string
  readonly workerOwnsSession: boolean
  readonly revision: PeerRevision
  readonly events: readonly ApplicationEvent[]
  readonly signals: readonly EphemeralSignal[]
  readonly status: SessionStatus
}
