import { createSigningIdentity, type FinalityPolicyV2, type SigningIdentity } from '@chronolog/authority'
import { MemoryBytesStore } from '@chronolog/records'
import { defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice } from './device.js'
import { createLogGenesis } from './genesis.js'
import { createApplicationSession } from './runtime.js'
import type { ApplicationReadView } from './session-types.js'
import { createWrapKeyPair, importWrapPrivateKey } from './wrap-keys.js'

const MESSAGES_REDUCER_SOURCE = `
export default {
  reduce(state, tx) {
    const items = Array.isArray(state) ? state : [];
    const text = typeof tx.payload === 'string' ? tx.payload : (tx.payload && tx.payload.text);
    return {
      ok: true,
      state: items.concat([{ opId: tx.opId, author: tx.author, text }]),
      events: [{ topic: 'message', payload: text }],
    };
  },
  query(state) {
    return Array.isArray(state) ? state : [];
  },
  describe() {
    return {
      commands: [{ name: 'say', description: 'Emit a message', input: { type: 'string' } }],
      queries: [{ name: 'messages', description: 'Read emitted messages', input: { type: 'null' } }],
    };
  },
};
`.trimStart()

export const fixtureDefinition = defineApplication({
  id: 'chronolog-fixture',
  version: '2',
  commands: {
    say: defineCommand({
      description: 'Emit a message',
      input: { type: 'string' },
      prepare: text => [{ topic: 'messages', input: text }],
    }),
  },
  queries: {
    messages: defineQuery({
      description: 'Read emitted messages',
      input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents({ topics: ['message'] }),
    }),
  },
})

export async function sessionFixture(options: {
  readonly count?: number
  readonly identities?: readonly SigningIdentity[]
  readonly finalityPolicy?: FinalityPolicyV2
  readonly privateLog?: boolean
} = {}) {
  const identities = options.identities ?? await Promise.all(Array.from({ length: options.count ?? 2 }, () => createSigningIdentity()))
  const wrapPairs = await Promise.all(identities.map(async () => {
    const pair = await createWrapKeyPair()
    return { publicKey: pair.publicKey, privateKey: await importWrapPrivateKey(pair.privateKey) }
  }))
  const epochKey = crypto.getRandomValues(new Uint8Array(32))
  const members = identities.map((id, i) => ({
    publicKey: id.publicKey,
    wrapKey: wrapPairs[i]!.publicKey,
    reader: true,
    writer: true,
    administrator: i === 0,
    publisher: i === 0,
    finalizer: i === 0,
  }))
  const created = await createLogGenesis({
    creator: members[0]!,
    members: members.slice(1),
    privateLog: options.privateLog ?? true,
    imports: { 'app/messages': MESSAGES_REDUCER_SOURCE },
    topics: { messages: { module: 'app/messages', initialState: [] } },
    epoch0Key: epochKey,
    ...(options.finalityPolicy === undefined ? {} : {
      finalitySchedule: [{ effectiveAfterMs: -1n, policy: options.finalityPolicy }],
    }),
  })
  const stores = identities.map(() => new MemoryBytesStore())

  return {
    applicationId: created.logId,
    logId: created.logId,
    genesis: created.genesis,
    genesisBytes: created.genesisBytes,
    casNodes: created.casNodes,
    identities,
    wrapPairs,
    epochKey,
    stores,
    async open(index: number) {
      const store = stores[index]!
      const device = await openApplicationDevice({
        store,
        create: true,
        managedSigner: identities[index]!,
        managedWrapKey: wrapPairs[index]!,
      })
      return createApplicationSession({
        device,
        genesis: created.genesisBytes,
        casNodes: created.casNodes,
        epochKeys: new Map([[0, epochKey]]),
        definition: fixtureDefinition,
      })
    },
  }
}
