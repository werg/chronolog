import { expectTypeOf, it } from 'vitest'
import type { PeerGenerationApplicationBackend } from '@tendriller/core/application'
import type { PeersClient } from '@tendriller/core/peers'
import type { ApplicationBootstrapHost, QueryParameter, QueryRows } from '@chronolog/peer-session'
import type { ApplicationPeerHost } from '@chronolog/peer-session/webrtc'
import type { createPeerGenerationApplicationBackend, PeerApplicationProgram } from './peer-application.js'

it('composes the actual packed Tendriller contracts with owned session and bootstrap ports', () => {
  expectTypeOf<ReturnType<typeof createPeerGenerationApplicationBackend>>()
    .toMatchTypeOf<PeerGenerationApplicationBackend<PeerApplicationProgram, QueryRows, QueryParameter>>()
  expectTypeOf<PeersClient>().toMatchTypeOf<ApplicationBootstrapHost>()
  expectTypeOf<PeersClient>().toMatchTypeOf<ApplicationPeerHost>()
})
