import type { PeerReplica } from '@chronolog/peer-generation'
import type { SignalChannel } from '@chronolog/signals'
import type { ApplicationSession } from './session.js'

export const sessionInternals = new WeakMap<ApplicationSession, { readonly replica: PeerReplica; readonly signals: SignalChannel }>()
