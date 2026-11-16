import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore } from '@chronolog/agent-service'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { isCapabilityActive } from '@chronolog/capabilities'
import { loadOrCreateEnrollmentIdentity } from '@chronolog/node-core'
import { bytesToBase64Url, bytesToHex, equalBytes } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { openWebRtcConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import { createPeersClient } from '@tendriller/core/peers'
import { expect, it } from 'vitest'
import { WebSocket } from 'ws'

import { createNativeBrowserFixture } from '../browser-event-fixture.js'
import { createPeerRouteFixture } from './peer-route-fixture.js'

it('introduces through the packaged host then replicates signed records over RTC with its listener stopped', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-host-rtc-'))
  const readerStore = new NativeAgentStore(join(directory, 'reader.sqlite'))
  const identity = await loadOrCreateEnrollmentIdentity(readerStore, 'rtc-reader')
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(readerStore, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
  let native: Awaited<ReturnType<typeof createNativeBrowserFixture>> | undefined
  let routes: Awaited<ReturnType<typeof createPeerRouteFixture>> | undefined
  let rtc: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined
  let authenticated: Awaited<ReturnType<typeof openAuthenticatedPeerLink>> | undefined
  let detach: (() => void) | undefined
  try {
    const engine = join(directory, 'engine')
    await mkdir(engine)
    execFileSync('tar', ['-xzf', new URL('../../test/artifacts/tendriller-engine-8e92ced5.tgz', import.meta.url).pathname,
      '-C', engine, '--strip-components=1'])
    native = await createNativeBrowserFixture({ directory: join(directory, 'native'), browsers: [{
      identity: bytesToBase64Url(identity.signing.publicKeyBytes), readerKey: bytesToBase64Url(identity.reader.publicKeyBytes), transportAuthor: transport.identity,
    }] })
    routes = await createPeerRouteFixture({ directory: join(directory, 'host'), engine, native })
    const peers = createPeersClient({ base: `${routes.hostBase}_tendril`,
      request: async () => { throw new Error('UNEXPECTED_HOST_HTTP_REQUEST') },
      socket: (url, protocols) => new WebSocket(url, [...protocols], { rejectUnauthorized: false }),
    })
    const rendezvous = peers.rendezvous(crypto.randomUUID(), 'reader')
    const { role } = await rendezvous.ready
    rtc = await openWebRtcConnection({ role, signaling: rendezvous, configuration: { iceServers: [] },
      createPeerConnection: configuration => createNativePeerConnection(configuration,
        { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false }) })
    const membership = native.governed.activeSnapshot
    const reader = [...membership.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
      equalBytes(capability.grant.signingPublicKey, identity.signing.publicKeyBytes))!
    authenticated = await openAuthenticatedPeerLink({ connection: rtc, local: transport.asLink(), identity: identity.signing,
      groupId: membership.groupId, grantId: reader.id, authorizePeer: ({ authorId, grantId }) => {
        const current = native!.governed.activeSnapshot, capability = current.capabilities.get(bytesToHex(grantId))
        return capability !== undefined && capability.grant.role === 'reader' && isCapabilityActive(capability, current.revision) &&
          equalBytes(capability.grant.signingPublicKey, authorId) && equalBytes(authorId, native!.identity.signing.publicKeyBytes)
      } })
    detach = transport.connect(authenticated.link)
    await expect.poll(() => routes!.snapshot().sessions[0]?.authenticatedMs).toEqual(expect.any(Number))
    await expect.poll(() => routes!.snapshot().signaling.activeSockets).toBe(0)
    expect(rendezvous.stats).toMatchObject({ sentDescriptions: 1, receivedDescriptions: 1, closed: true })
    expect(routes.snapshot().sessions[0]?.nativeSignaling).toMatchObject({ sentDescriptions: 1, receivedDescriptions: 1, closed: true })
    await routes.disableRendezvous()
    const signalingBefore = routes.snapshot().signaling, before = rtc.stats.receivedBytes
    const operation = await native.client.events.publish('conversation', { text: 'Final event after the introduction host stopped' }, { operationId: 'host-stopped' })
    try { expect((await operation.final({ signal: AbortSignal.timeout(15_000) })).outcome.type).toBe('accepted') }
    finally { operation.dispose() }
    const retained = await native.transport.history()
    expect(retained.length).toBeGreaterThan(0)
    await transport.catchUp()
    for (const record of retained) {
      const { receivedAtMs: _nativeReceiptTime, ...original } = record
      const { receivedAtMs: _readerReceiptTime, ...received } = (await transport.get(record.id))!
      expect(received).toEqual(original)
    }
    expect(rtc.stats.receivedBytes).toBeGreaterThan(before)
    expect(routes.snapshot().signaling).toEqual(signalingBefore)
    expect(routes.snapshot().unexpectedHostRequests).toBe(0)
    expect(routes.snapshot().failures).toEqual([])
    native.assertHealthy()
  } catch (error) {
    process.stderr.write(`Host/RTC fixture diagnostics: ${JSON.stringify(routes?.snapshot())}\n`)
    throw error
  } finally {
    detach?.()
    await authenticated?.close(); await rtc?.close(); await routes?.close()
    await native?.close(); await transport.close(); readerStore.close()
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)
