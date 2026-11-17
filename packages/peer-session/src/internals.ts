import type { PeerReplica, PeerStore } from '@chronolog/peer-generation'
import type { SignalChannel } from '@chronolog/signals'
import type { ApplicationSession } from './session.js'
import type { ApplicationContent } from './content.js'

export const sessionInternals = new WeakMap<ApplicationSession, { readonly replica: PeerReplica; readonly signals: SignalChannel; readonly store: PeerStore; readonly content: ApplicationContent }>()
