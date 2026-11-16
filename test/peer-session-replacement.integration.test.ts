import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { framePeerStream, openAuthenticatedPeerLink } from '@chronolog/agent-service'
import { MemoryOperationStore, loadOrCreateEnrollmentIdentity } from '@chronolog/node-core'
import { bytesToBase64Url, equalBytes } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { createNativeBrowserFixture, type NativeBrowserFixture } from '../tools/browser-event-fixture.js'

describe('authenticated session replacement', () => {
  it.each(['native-close', 'remote-close'] as const)('keeps the replacement native link after the old session ends through %s', async (ending) => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-session-replacement-'))
    const identity = await loadOrCreateEnrollmentIdentity(new MemoryOperationStore(), 'browser')
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(new MemoryOperationStore(), webFeedCrypto),
      crypto: webFeedCrypto, signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
    let native: NativeBrowserFixture | undefined
    const nativeSessions: Awaited<ReturnType<NativeBrowserFixture['agent']['context']['connectPeer']>>[] = []
    const remoteSessions: Awaited<ReturnType<typeof openAuthenticatedPeerLink>>[] = []
    try {
      native = await createNativeBrowserFixture({ directory, browsers: [{ identity: bytesToBase64Url(identity.signing.publicKeyBytes),
        readerKey: bytesToBase64Url(identity.reader.publicKeyBytes), transportAuthor: transport.identity }] })
      const grant = [...native.governed.activeSnapshot.capabilities.values()].find(value => value.grant.role === 'reader' &&
        equalBytes(value.grant.signingPublicKey, identity.signing.publicKeyBytes))!
      for (let index = 0; index < 2; index++) {
        const toNative = new TransformStream<Uint8Array, Uint8Array>(), toRemote = new TransformStream<Uint8Array, Uint8Array>()
        const [local, remote] = await Promise.all([
          native.agent.context.connectPeer({ connection: framePeerStream({ readable: toNative.readable, writable: toRemote.writable }) }),
          openAuthenticatedPeerLink({ connection: framePeerStream({ readable: toRemote.readable, writable: toNative.writable }),
            local: transport.asLink(), identity: identity.signing, groupId: native.node.groupId, grantId: grant.id,
            authorizePeer: peer => equalBytes(peer.authorId, native!.identity.signing.publicKeyBytes) }),
        ])
        nativeSessions.push(local); remoteSessions.push(remote)
      }
      expect((await native.transport.status()).peers).toContain(transport.identity)
      if (ending === 'native-close') await nativeSessions[0]!.close()
      else {
        await remoteSessions[0]!.close()
        await nativeSessions[0]!.completion.catch(() => undefined)
      }
      // The old close and its completion handler may both detach. Neither owns
      // the newer authenticated connection for this same durable identity.
      await nativeSessions[0]!.close()
      expect((await native.transport.status()).peers).toContain(transport.identity)
      await native.transport.catchUp()
      await expect(remoteSessions[1]!.link.read(native.transport.identity, 0n, 1)).resolves.toBeInstanceOf(Array)
      await nativeSessions[1]!.close()
      expect((await native.transport.status()).peers).not.toContain(transport.identity)
    } finally {
      await Promise.allSettled([...nativeSessions, ...remoteSessions].map(session => session.close()))
      await native?.close(); await transport.close()
      await rm(directory, { recursive: true, force: true })
    }
  })
})
