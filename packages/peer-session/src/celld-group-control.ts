import {
  bytesDigest, createGenerationRegistry, decodePeerValue, encodePeerValue, participantGrant, peerDigest, signApplicationDescriptor,
  signControlRevision, signTransitionRequest, verifyApplicationSchema, verifyAuthorityBundle,
  type AuthorityBundle, type PeerGrant, type PeerIdentity, type SignedApplicationDescriptor, type SignedApplicationSchema,
  type SignedControlRevision,
} from '@chronolog/peer-generation/control'
import { bytesToHex, decodeChangeProgram, encodeChangeProgram, hexToBytes } from '@chronolog/protocol'
import { CelldPrivateBytesStore, type CelldPrivateBytesStorage } from '@chronolog/records/celld'
import { openApplicationDevice, type ApplicationDevice } from './device.js'
import { defineApplication } from './definition.js'
import { acceptCelldApplicationInvitation, signCelldApplicationInvitation, type CelldApplicationInvitation } from './celld-invitation.js'
import type { CelldPeerEndpoint } from './celld-peer.js'
import { createCelldSqlEngine, type CelldSqlStorage } from '@chronolog/materializer-doltlite/celld'
import { openSqlApplication, prepareSqlApplication } from './sql.js'
import type { ApplicationSession } from './session.js'

export type CelldGroupRole = 'reader' | 'writer' | 'publisher' | 'administrator'
export interface CelldGroupNode {
  readonly publicKey: string
  readonly endpoint: CelldPeerEndpoint
}
export interface CelldGroupInvitation {
  readonly invitation: CelldApplicationInvitation
  readonly schema: SignedApplicationSchema
}
type GroupStorage = CelldPrivateBytesStorage & CelldSqlStorage
interface CreatorRecord {
  readonly kind: 'creator'
  readonly descriptor: SignedApplicationDescriptor
  readonly control: SignedControlRevision
  readonly schema: SignedApplicationSchema
  readonly epochKey: string
  readonly creator: string
}
interface JoinedRecord {
  readonly kind: 'joined'
  readonly schema: SignedApplicationSchema
  readonly authority: AuthorityBundle
  readonly creator: CelldGroupNode
}
type GroupRecord = CreatorRecord | JoinedRecord
interface Admission {
  readonly inviter: string
  readonly member: string
  readonly role: CelldGroupRole
  readonly node: CelldGroupNode
}
const profile = 'peer-generation-v1', policy = 'eligible-members-v1'
const groupDefinition = (applicationId: string, schema: string) =>
  defineApplication({ id: applicationId, version: '1', schema: decodeChangeProgram(hexToBytes(schema)), commands: {}, queries: {} })

function nodeGrant(publicKey: string, administrator: boolean): PeerGrant {
  return { ...participantGrant(publicKey, { administrator, dataRole: null, relay: true }), writer: false }
}
function memberGrant(publicKey: string, role: CelldGroupRole): PeerGrant {
  const administrator = role === 'administrator'
  return { ...participantGrant(publicKey, { administrator, publisher: role === 'publisher', dataRole: administrator ? 'admin' : 'member' }),
    writer: role !== 'reader', coordinator: false, recovery: false }
}

/** One store and one materializer per group. Only an authenticated workspace host calls these methods. */
export class CelldGroupControl {
  readonly #store: CelldPrivateBytesStore
  #session: Promise<ApplicationSession> | undefined
  #registry: ReturnType<typeof createGenerationRegistry> | undefined
  #control = Promise.resolve<unknown>(null)

  constructor(private readonly options: {
    readonly applicationId: string
    readonly storage: GroupStorage
    readonly signer: PeerIdentity
    readonly endpoint: CelldPeerEndpoint
  }) {
    this.#store = new CelldPrivateBytesStore(options.storage, { namespace: 'group' })
  }

  async #record(): Promise<GroupRecord | null> {
    const bytes = await this.#store.get('installed')
    return bytes === null ? null : decodePeerValue<GroupRecord>(bytes)
  }

  #ordered<T>(run: () => Promise<T>): Promise<T> {
    const flight = this.#control.then(run)
    this.#control = flight.catch(() => undefined)
    return flight
  }

  async #device(): Promise<ApplicationDevice> {
    const store = new CelldPrivateBytesStore(this.options.storage, { namespace: 'node' })
    try {
      return await openApplicationDevice({ store, create: true, managedSigner: this.options.signer, close: () => store.close() })
    } catch (error) { store.close(); throw error }
  }

  #controlRegistry(record: CreatorRecord) {
    return this.#registry ??= createGenerationRegistry({ store: this.#store, descriptor: record.descriptor,
      controls: [record.control], signer: this.options.signer }).catch(error => { this.#registry = undefined; throw error })
  }

  create(input: { readonly name: string; readonly schema: string }, creator: PeerIdentity): Promise<void> {
    const request = { ...input }, account = { ...creator }
    return this.#ordered(async () => {
      const { applicationId, signer, storage } = this.options
      if (!/^[0-9a-f]{64}$/u.test(applicationId) || request.name.trim() !== request.name || request.name.length < 1 || request.name.length > 128 ||
        account.publicKey === signer.publicKey) throw new Error('CELLD_GROUP_CREATE_INVALID')
      let record = await this.#record()
      if (record === null) {
        const definition = groupDefinition(applicationId, request.schema)
        if (bytesToHex(encodeChangeProgram(definition.schema!)) !== request.schema) throw new Error('CELLD_GROUP_SCHEMA_INVALID')
        const epochKey = crypto.getRandomValues(new Uint8Array(32))
        const prepared = await prepareSqlApplication({ applicationId, definition, schemaAdministrator: account, engine: createCelldSqlEngine(storage) })
        const descriptor = await signApplicationDescriptor({ applicationId, historyId: request.name, profile, policy, controlPublicKey: signer.publicKey, ...prepared.binding }, signer)
        const control = await signControlRevision({ applicationId, profile, policy, revision: 0, previous: null, epoch: 0,
          keyDigest: await bytesDigest(epochKey), recoveryFloor: null,
          grants: [nodeGrant(signer.publicKey, true), memberGrant(account.publicKey, 'administrator')],
        }, signer)
        record = { kind: 'creator', creator: account.publicKey, descriptor, control, schema: prepared.schema, epochKey: bytesToHex(epochKey) }
        await this.#store.initialize([{ key: 'installed', value: encodePeerValue(record) }])
      }
      if (record.kind !== 'creator' || record.creator !== account.publicKey ||
        record.descriptor.payload.historyId !== request.name || record.schema.payload.program !== request.schema) throw new Error('CELLD_GROUP_CREATE_CONFLICT')
      const registry = await this.#controlRegistry(record)
      if ((await registry.read()).generations.length === 0) {
        await registry.select(await signTransitionRequest({ applicationId, profile, policy, transitionId: 'create',
          expectedGeneration: null, coordinator: signer.publicKey, requester: signer.publicKey, controlRevision: 0, reason: 'create', base: null,
        }, signer))
      }
    })
  }

  join(input: CelldGroupInvitation, account: string): Promise<void> {
    const { invitation, schema } = structuredClone(input)
    return this.#ordered(async () => {
      const { applicationId } = this.options
      const current = await this.#record()
      if (current?.kind === 'joined' && (current.creator.publicKey !== invitation.payload.inviterPublicKey ||
        current.creator.endpoint.nodeId !== invitation.payload.endpoint.nodeId)) throw new Error('CELLD_GROUP_ROUTE_CONFLICT')
      const authority = await verifyAuthorityBundle(invitation.payload.authority)
      if (authority.descriptor.applicationId !== applicationId || authority.grant(account)?.reader !== true) throw new Error('CELLD_GROUP_MEMBER_FORBIDDEN')
      await verifyApplicationSchema(schema, authority.descriptor)
      const device = await this.#device()
      try {
        const admitted = await acceptCelldApplicationInvitation(device, invitation)
        const creator = { publicKey: admitted.peer.identity, endpoint: admitted.endpoint }
        if (current !== null) {
          const session = await this.session()
          await session.adopt(admitted.authority)
          if (session.memberGrant(account)?.reader !== true) throw new Error('CELLD_GROUP_MEMBER_FORBIDDEN')
          return
        }
        const record: JoinedRecord = { kind: 'joined', schema, authority: admitted.authority, creator }
        await this.#store.initialize([{ key: 'installed', value: encodePeerValue(record) }])
      } finally { await device.close() }
    })
  }

  session(): Promise<ApplicationSession> {
    return this.#session ??= (async () => {
      const record = await this.#record()
      if (record === null) throw new Error('CELLD_GROUP_NOT_FOUND')
      const authority = record.kind === 'creator' ? await (await this.#controlRegistry(record)).read() : record.authority
      if (authority.generations.length === 0) throw new Error('CELLD_GROUP_NOT_READY')
      const device = await this.#device()
      try {
        return await openSqlApplication({ device, authority, schema: record.schema, databasePath: 'celld:application',
          definition: groupDefinition(this.options.applicationId, record.schema.payload.program),
          createEngine: () => createCelldSqlEngine(this.options.storage),
          ...(record.kind === 'creator' ? { epochKeys: new Map([[0, hexToBytes(record.epochKey)]]) } : {}),
        })
      } catch (error) { await device.close(); throw error }
    })().catch(error => { this.#session = undefined; throw error })
  }

  invite(operationId: string, input: Admission): Promise<CelldGroupInvitation> {
    const request = structuredClone(input)
    return this.#ordered(async () => {
      const record = await this.#record()
      if (record?.kind !== 'creator') throw new Error('CELLD_GROUP_CONTROL_NOT_LOCAL')
      const { applicationId, signer } = this.options
      if (!/^[a-zA-Z0-9_.-]{1,120}$/u.test(operationId) || request.member === request.node.publicKey ||
        request.member === signer.publicKey ||
        !/^[0-9a-f]{64}$/u.test(request.node.endpoint.nodeId) ||
        (request.node.publicKey === signer.publicKey) !== (request.node.endpoint.nodeId === this.options.endpoint.nodeId) ||
        !['reader', 'writer', 'publisher', 'administrator'].includes(request.role)) throw new Error('CELLD_GROUP_INVITE_INVALID')
      const registry = await this.#controlRegistry(record)
      let authority = await registry.read()
      const current = await verifyAuthorityBundle(authority)
      if (current.grant(request.inviter)?.administrator !== true || request.inviter === signer.publicKey) throw new Error('CELLD_GROUP_ADMINISTRATOR_REQUIRED')
      const key = `invite/${operationId}`, encoded = encodePeerValue(request)
      const saved = await this.#store.get(key)
      if (saved !== null && bytesToHex(saved) !== bytesToHex(encoded)) throw new Error('CELLD_GROUP_INVITE_CONFLICT')
      const peerKey = `peer/${request.node.endpoint.nodeId}`
      const knownPeer = await this.#store.get(peerKey), existingNode = current.grant(request.node.publicKey)
      const localNode = request.node.publicKey === signer.publicKey
      if (knownPeer !== null && decodePeerValue<CelldGroupNode>(knownPeer).publicKey !== request.node.publicKey) throw new Error('CELLD_GROUP_ROUTE_CONFLICT')
      const transitionId = `invite/${operationId}`
      let selected = authority.generations.find(generation => generation.payload.transition.payload.transitionId === transitionId)
      const session = await this.session()
      if (selected === undefined) {
        if (current.grant(request.member) !== null) throw new Error('CELLD_GROUP_MEMBER_EXISTS')
        if (existingNode !== null && (!existingNode.relay || knownPeer === null && !localNode)) throw new Error('CELLD_GROUP_ROUTE_CONFLICT')
        const prior = current.control
        const control = await signControlRevision({ ...prior.payload, revision: prior.payload.revision + 1, previous: await peerDigest(prior),
          grants: [...prior.payload.grants, memberGrant(request.member, request.role), ...(existingNode === null ? [nodeGrant(request.node.publicKey, false)] : [])],
        }, signer)
        const transition = await signTransitionRequest({ applicationId, profile, policy, transitionId,
          expectedGeneration: current.current!.id, coordinator: signer.publicKey, requester: signer.publicKey,
          controlRevision: control.payload.revision, reason: 'control-change', base: await session.recoveryPoint(),
        }, signer)
        await this.#store.initialize([{ key, value: encoded }])
        selected = await registry.select(transition, { control })
        authority = await registry.read()
      }
      if (!localNode) await this.#store.put(peerKey, encodePeerValue(request.node))
      await session.adopt(authority)
      const issuedAuthority = { descriptor: authority.descriptor, controls: authority.controls.slice(0, selected.payload.controlRevision + 1),
        generations: authority.generations.slice(0, selected.payload.number + 1) }
      return { schema: record.schema, invitation: await signCelldApplicationInvitation({
        authority: issuedAuthority, memberPublicKey: request.node.publicKey, inviter: signer, endpoint: this.options.endpoint,
      }) }
    })
  }

  async peer(nodeId: string): Promise<CelldGroupNode | null> {
    const record = await this.#record()
    if (record?.kind === 'joined') return record.creator.endpoint.nodeId === nodeId ? record.creator : null
    const bytes = await this.#store.get(`peer/${nodeId}`)
    return bytes === null ? null : decodePeerValue<CelldGroupNode>(bytes)
  }
}
