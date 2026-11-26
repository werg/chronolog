import {
  defineApplication, defineCommand, defineQuery,
  type ApplicationReadView, type MaterializedRevision, type ApplicationEvent, type SessionStatus, type SessionCasNode,
} from '@chronolog/peer-session'
import type { EphemeralSignal } from '@chronolog/signals'

export const RTC_MESSAGES_REDUCER = `
export default {
  reduce(state, tx) {
    const items = Array.isArray(state) ? state : [];
    const text = typeof tx.payload === 'string' ? tx.payload : (tx.payload && tx.payload.text);
    return { ok: true, state: items.concat([{ opId: tx.opId, text }]), events: [{ topic: 'message', payload: { text } }] };
  },
};
`.trimStart()

export const definition = defineApplication({
  id: 'peer-session-rtc',
  version: '2',
  commands: {
    say: defineCommand({
      description: 'Post one message',
      input: { type: 'string', minLength: 1, maxLength: 2048 },
      prepare: text => [{ topic: 'messages', input: { text } }],
    }),
  },
  queries: {
    messages: defineQuery({
      description: 'Read the current materialized messages',
      input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents(),
    }),
  },
})

export interface Bootstrap {
  readonly chainId: string
  readonly genesisBytes: Uint8Array
  readonly casNodes: readonly SessionCasNode[]
  readonly epoch: number
  readonly epochKey: string
}

export interface BrowserState {
  readonly publicKey: string
  readonly storageId: string
  readonly workerOwnsSession: boolean
  readonly revision: MaterializedRevision
  readonly events: readonly ApplicationEvent[]
  readonly signals: readonly EphemeralSignal[]
  readonly status: SessionStatus
}
