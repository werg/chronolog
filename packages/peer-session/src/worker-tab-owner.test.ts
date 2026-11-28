import { afterEach, expect, it } from 'vitest'
import { serveTabWorkerOwner, type TabWorkerScope } from './worker-tab-owner.js'
import { TAB_OWNER_PROTOCOL } from './browser-tab-owner.js'
import { FACTS_SOURCE_STORE } from './session-types.js'
import type { ApplicationSession, FactsDelta } from './session.js'

const cleanups: Array<() => unknown> = []
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup() })

function fakeScope(): TabWorkerScope & { readonly posted: unknown[]; deliver(data: unknown): void } {
  const listeners = new Set<(event: Event) => void>(), posted: unknown[] = []
  return {
    posted,
    postMessage: message => { posted.push(message) },
    addEventListener: (_type, listener) => { listeners.add(listener) },
    removeEventListener: (_type, listener) => { listeners.delete(listener) },
    deliver: data => { for (const listener of listeners) listener({ data, ports: [] } as unknown as Event) },
  }
}

function fakeSession() {
  const factListeners = new Set<(delta: FactsDelta) => void>(), lifetime = new AbortController()
  const syncs: Array<() => void> = []
  let syncCalls = 0
  const session = {
    applicationId: 'app',
    signal: lifetime.signal,
    onFacts: (listener: (delta: FactsDelta) => void) => { factListeners.add(listener); return () => factListeners.delete(listener) },
    syncFromStore: () => { syncCalls++; return new Promise<boolean>(resolve => { syncs.push(() => resolve(true)) }) },
    close: async () => { lifetime.abort() },
  }
  return {
    session: session as unknown as ApplicationSession,
    emit: (delta: FactsDelta) => { for (const listener of factListeners) listener(delta) },
    finishSync: () => syncs.shift()?.(),
    get syncCalls() { return syncCalls },
  }
}

const tick = () => new Promise(resolve => setTimeout(resolve, 20))

async function boot(profileId: string) {
  const scope = fakeScope(), fake = fakeSession()
  const handle = serveTabWorkerOwner({ scope, profileId, openSession: async () => ({ session: fake.session }) })
  cleanups.push(() => handle.close())
  scope.deliver({ protocol: TAB_OWNER_PROTOCOL, type: 'boot', id: 'b', profileId })
  await tick()
  expect(scope.posted.at(-1)).toMatchObject({ type: 'ready', id: 'b' })
  const sibling = new BroadcastChannel(`chronolog:sync:${profileId}`), heard: unknown[] = []
  sibling.addEventListener('message', event => { heard.push(event.data) })
  cleanups.push(() => sibling.close())
  return { scope, fake, handle, sibling, heard }
}

it('announces local facts written while a store sync is running, but not facts ingested from the store', async () => {
  const { fake, sibling, heard } = await boot('b2-origin')
  sibling.postMessage({ type: 'facts-updated', sender: 'other' })
  await tick()
  expect(fake.syncCalls).toBe(1)
  // A local write lands while the sync is still in flight: siblings must hear about it.
  fake.emit({ items: [{ scope: 'public', id: 'local-1' }] })
  await tick()
  expect(heard).toHaveLength(1)
  // The sync's own delta is tagged as store-sourced and is not echoed back.
  fake.emit({ items: [{ scope: 'public', id: 'from-store', source: FACTS_SOURCE_STORE }] })
  fake.finishSync()
  await tick()
  expect(heard).toHaveLength(1)
  // Network deliveries are announced (siblings read them from the shared store).
  fake.emit({ items: [{ scope: 'private', id: 'net', source: 'link-1' }] })
  await tick()
  expect(heard).toHaveLength(2)
})

it('coalesces overlapping sibling notices into one running and one queued store sync', async () => {
  const { fake, sibling, handle } = await boot('b2-coalesce')
  for (let i = 0; i < 5; i++) sibling.postMessage({ type: 'facts-updated', sender: 'other' })
  await tick()
  expect(fake.syncCalls).toBe(1)
  fake.finishSync(); await tick()
  expect(fake.syncCalls).toBe(2)
  fake.finishSync(); await tick()
  expect(fake.syncCalls).toBe(2)
  handle.wake(); await tick()
  expect(fake.syncCalls).toBe(3)
  fake.finishSync()
})

it('answers identity requests through createIdentity without opening a session and passes service context to openSession', async () => {
  const scope = fakeScope(), fake = fakeSession()
  let opened: Record<string, unknown> | undefined, servicesClosed = false
  const handle = serveTabWorkerOwner({
    scope,
    profileId: 'p',
    services: () => ({ context: { openDirectConnection: 'rtc' }, close: () => { servicesClosed = true } }),
    createIdentity: async () => 'a'.repeat(64),
    openSession: async ctx => { opened = ctx; return { session: fake.session } },
  })
  scope.deliver({ protocol: TAB_OWNER_PROTOCOL, type: 'identity', id: 'i', profileId: 'p' })
  await tick()
  expect(scope.posted.at(-1)).toMatchObject({ type: 'identity', id: 'i', publicKey: 'a'.repeat(64) })
  expect(opened).toBeUndefined()
  scope.deliver({ protocol: TAB_OWNER_PROTOCOL, type: 'boot', id: 'b', profileId: 'p' })
  await tick()
  expect(opened).toMatchObject({ openDirectConnection: 'rtc', initialNetworkActive: true })
  await handle.close()
  expect(servicesClosed).toBe(true)
})
