import { peerDigest, type PeerIdentity } from '@chronolog/peer-generation/control'
import { decodeChangeProgram, hexToBytes, isEmitStep } from '@chronolog/protocol'
import type { CelldPrivateBytesStorage } from '@chronolog/records/celld'
import type { CelldSqlStorage } from '@chronolog/materializer-doltlite/celld'
import { importCelldSigningIdentity } from './celld.js'
import { CelldGroupControl, type CelldGroupInvitation, type CelldGroupNode, type CelldGroupRole } from './celld-group-control.js'
import { celldGroupData } from './celld-group-data.js'
import { serveCelldDoltPublication, type AuthorizeDoltPublication } from './celld-dolt-carrier.js'
import { createCelldPeerTransport, type CelldPeerBinding, type CelldPeerEndpoint, type CelldPeerStream } from './celld-peer.js'
import { celldGroupSocketStream, readCelldGroupAddress, writeCelldGroupAddress, type CelldGroupSocket } from './celld-group-stream.js'
import type { ApplicationPeerLink } from './network.js'
import type { ApplicationSession } from './session.js'
import type { CommandOptions, QueryParameter } from './session-types.js'
import type { PeerRevision } from '@chronolog/peer-generation'
import {
  signCelldWorkspacePublication, verifyCelldWorkspacePublication,
  type CelldWorkspacePublication, type SignedCelldWorkspacePublication,
} from './celld-workspace-publication.js'

export const CHRONOLOG_WORKSPACE_OBJECT = 'chronolog'
export const CELLD_WORKSPACE_HISTORY_ALPN = 'vibestudio/gad/1'
const internal = 'x-chronolog-node-token'
const remote = 'x-chronolog-remote-node'
const key = /^[a-f0-9]{64}$/u

type Socket = CelldGroupSocket & { accept(): void }
type Principal = { publicKey: string; pkcs8Hex: string }
type GroupInput =
  | { action: 'identity'; publicKey: string; localEndpoint?: CelldPeerEndpoint }
  | { action: 'list'; publicKey: string }
  | { action: 'create'; principal: Principal; operationId: string; name: string; schema: string }
  | { action: 'join'; group: string; publicKey: string; offer: CelldGroupInvitation }
  | { action: 'invite'; publicKey: string; group: string; operationId: string; member: string; role: CelldGroupRole; node: CelldGroupNode; localEndpoint?: CelldPeerEndpoint }
  | { action: 'describe'; publicKey: string; group: string }
  | { action: 'bind-history'; publicKey: string; group: string }
  | { action: 'review'; program: string }
  | { action: 'transact'; principal: Principal; group: string; operationId: string; program: string; basedOn?: PeerRevision }
  | { action: 'sign-publication'; principal: Principal; group: string; transition: CelldWorkspacePublication }
  | { action: 'verify-publication'; group: string; sourceNodeId: string; previousHead: string; proposedHead: string; proof: SignedCelldWorkspacePublication }
  | { action: 'outcome'; publicKey: string; group: string; txId: string }
  | { action: 'query' | 'subscribe'; publicKey: string; group: string; sql: string; bindings?: QueryParameter[]; revision?: PeerRevision }
interface DirectoryStorage {
  get<T>(key: string): Promise<T | undefined>
  put(key: string, value: unknown): Promise<void>
  list<T>(options: { prefix: string }): Promise<Map<string, T>>
}
interface Namespace {
  getByName(name: string): { fetch(request: Request): Promise<Response & { webSocket?: Socket }> }
}
interface WorkspaceEnvironment {
  readonly WORKSPACE_ID: string
  readonly CHRONOLOG_PUBLIC_KEY: string
  readonly CHRONOLOG_SIGNING_KEY: string
  readonly CHRONOLOG_ROOT_TOKEN: string
  readonly CHRONOLOG_GROUP_TOKEN: string
  readonly CHRONOLOG_ADDRS?: readonly string[]
  readonly CHRONOLOG_P2P: CelldPeerBinding & { readonly nodeId: string }
  readonly CHRONOLOG_GROUPS: Namespace
  readonly GATEWAY_URL?: string
}

interface WorkerAdapter {
  readonly DurableObject: new (state: never, env: never) => object
  readonly socketPair: () => readonly [Socket, Socket]
  readonly encode: (data: unknown) => string
  readonly decode: (data: string) => unknown
  /** Only the trusted host program can commit staged history or expose its content. */
  readonly publication?: (env: { gatewayUrl: string; token: string }) => AuthorizeDoltPublication
}

function readProgram(value: string) {
  if (typeof value !== 'string' || !/^(?:[a-f0-9]{2})+$/u.test(value) || value.length > 529_000) throw new Error('CELLD_GROUP_PROGRAM_INVALID')
  return decodeChangeProgram(hexToBytes(value))
}
async function principal(value: Principal) {
  return importCelldSigningIdentity(value.publicKey, value.pkcs8Hex)
}

interface WorkspaceRuntimeClasses {
  readonly ChronologWorkspaceDO: new (state: { storage: DirectoryStorage }, env: WorkspaceEnvironment) => {
    fetch(request: Request): Promise<Response>
    onp2pstream(stream: CelldPeerStream): void
  }
  readonly ChronologGroupDO: new (state: { id: { name?: string }; storage: CelldPrivateBytesStorage & CelldSqlStorage },
    env: WorkspaceEnvironment) => { fetch(request: Request): Promise<Response> }
}

/** Share one private node directory and Iroh listener among independently stored groups. */
export function createCelldWorkspaceClasses({ DurableObject, socketPair, encode, decode, publication }: WorkerAdapter): WorkspaceRuntimeClasses {
  const reply = (value: unknown) => new Response(encode(value), {
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  })
  const denied = () => new Response('Forbidden', { status: 403 })
  const failure = (error: unknown) => {
    const code = error instanceof Error && /^[A-Z0-9_]{1,120}$/u.test(error.message) ? error.message : 'CELLD_GROUP_REQUEST_FAILED'
    return new Response(code, { status: 409 })
  }
  const nodeEndpoint = (env: WorkspaceEnvironment, hint?: CelldPeerEndpoint): CelldPeerEndpoint => {
    const nodeId = env.CHRONOLOG_P2P.nodeId
    if (hint !== undefined) {
      if (hint.nodeId !== nodeId) throw new Error('CELLD_GROUP_ENDPOINT_MISMATCH')
      return hint
    }
    return { nodeId, ...(env.CHRONOLOG_ADDRS === undefined ? {} : { addrs: env.CHRONOLOG_ADDRS }) }
  }
  const nodeIdentity = (env: WorkspaceEnvironment): Promise<PeerIdentity> =>
    importCelldSigningIdentity(env.CHRONOLOG_PUBLIC_KEY, env.CHRONOLOG_SIGNING_KEY)
  const authorized = (token: string, request: Request) =>
    typeof token === 'string' && token.length > 0 && request.headers.get(internal) === token
  const submit = (env: WorkspaceEnvironment, group: string, input: GroupInput) =>
    env.CHRONOLOG_GROUPS.getByName(group).fetch(new Request('http://chronolog/group', {
      method: 'POST', headers: { [internal]: env.CHRONOLOG_ROOT_TOKEN, 'content-type': 'application/json' },
      body: encode(input),
    }))

  class ChronologWorkspaceDO extends DurableObject {
    #binding: Promise<void> = Promise.resolve()

    constructor(private readonly state: { storage: DirectoryStorage }, private readonly env: WorkspaceEnvironment) {
      super(state as never, env as never)
    }

    onp2pstream(raw: CelldPeerStream): void {
      if (raw.alpn === CELLD_WORKSPACE_HISTORY_ALPN) {
        if (publication === undefined || this.env.GATEWAY_URL === undefined) {
          void raw.close().catch(() => undefined)
          return
        }
        const receive = publication({ gatewayUrl: this.env.GATEWAY_URL, token: this.env.CHRONOLOG_ROOT_TOKEN })
        void serveCelldDoltPublication(raw, async input => {
          const group = await this.state.storage.get<string>('shared-history')
          if (group === undefined || group !== input.proof.payload.applicationId) throw new Error('CELLD_WORKSPACE_HISTORY_GROUP_MISMATCH')
          const { previousHead, proposedHead } = input.proof.payload
          const verified = await submit(this.env, group, { action: 'verify-publication', group, sourceNodeId: input.peer,
            previousHead, proposedHead, proof: input.proof,
          })
          if (!verified.ok) throw new Error(await verified.text())
          await verified.arrayBuffer()
          return receive(input)
        }).catch(() => raw.close().catch(() => undefined))
        return
      }
      void (async () => {
        const { group, stream } = await readCelldGroupAddress(raw)
        if (!await this.state.storage.get(`group:${group}`)) throw new Error('CELLD_GROUP_NOT_FOUND')
        const forwarded = await this.env.CHRONOLOG_GROUPS.getByName(group).fetch(new Request('http://chronolog/carrier', {
          headers: { 'upgrade': 'websocket', [internal]: this.env.CHRONOLOG_ROOT_TOKEN, [remote]: stream.remoteNodeId },
        }))
        const socket = forwarded.webSocket
        if (socket === undefined) throw new Error('CELLD_GROUP_STREAM_DENIED')
        const hop = celldGroupSocketStream(socket, stream.remoteNodeId)
        socket.accept()
        try { await Promise.all([stream.readable.pipeTo(hop.writable), hop.readable.pipeTo(stream.writable)]) }
        finally { await Promise.allSettled([hop.close(), stream.close()]) }
      })().catch(() => raw.close().catch(() => undefined))
    }

    async fetch(request: Request): Promise<Response> {
      if (!authorized(this.env.CHRONOLOG_ROOT_TOKEN, request) || request.method !== 'POST') return denied()
      try {
        const input = decode(await request.text()) as GroupInput
        switch (input.action) {
          case 'identity':
            return reply({ publicKey: input.publicKey, node: { publicKey: this.env.CHRONOLOG_PUBLIC_KEY, endpoint: nodeEndpoint(this.env, input.localEndpoint) } })
          case 'review': {
            const steps = readProgram(input.program).steps.map(step =>
              encode(isEmitStep(step) ? { event: step.topic, payload: step.payload } : step))
            return reply(steps)
          }
          case 'list': {
            const installed = await this.state.storage.list<boolean>({ prefix: 'group:' }), visible: unknown[] = []
            for (const name of installed.keys()) {
              const group = name.slice('group:'.length)
              const result = await submit(this.env, group, { action: 'describe', group, publicKey: input.publicKey })
              if (!result.ok) return result
              const row = decode(await result.text())
              if (row !== null) visible.push(row)
            }
            return reply(visible)
          }
          case 'bind-history': {
            if (publication === undefined) return denied()
            if (!key.test(input.group) || !await this.state.storage.get(`group:${input.group}`)) throw new Error('CELLD_GROUP_NOT_FOUND')
            const allowed = await submit(this.env, input.group, input)
            if (!allowed.ok) return allowed
            await allowed.arrayBuffer()
            const binding = this.#binding.then(async () => {
              const existing = await this.state.storage.get<string>('shared-history')
              if (existing !== undefined && existing !== input.group) throw new Error('CELLD_WORKSPACE_HISTORY_ALREADY_SHARED')
              if (existing === undefined) await this.state.storage.put('shared-history', input.group)
            })
            this.#binding = binding.catch(() => undefined)
            await binding
            return reply({ group: input.group })
          }
          case 'create': {
            const group = await peerDigest(['chronolog/workspace/group/v1', this.env.WORKSPACE_ID, input.principal.publicKey, input.operationId])
            return await this.#install(group, input)
          }
          case 'join':
            if (input.group !== input.offer.invitation.payload.authority.descriptor.payload.applicationId) throw new Error('CELLD_GROUP_INVITATION_MISMATCH')
            return await this.#install(input.group, input)
          default: {
            if (!key.test(input.group) || !await this.state.storage.get(`group:${input.group}`)) throw new Error('CELLD_GROUP_NOT_FOUND')
            return await submit(this.env, input.group, input)
          }
        }
      } catch (error) { return failure(error) }
    }

    async #install(group: string, input: Extract<GroupInput, { action: 'create' | 'join' }>): Promise<Response> {
      if (!key.test(group)) throw new Error('CELLD_GROUP_ADDRESS_INVALID')
      const installed = await submit(this.env, group, input)
      if (!installed.ok) return installed
      await installed.arrayBuffer()
      await this.state.storage.put(`group:${group}`, true)
      return reply({ group })
    }
  }

  class ChronologGroupDO extends DurableObject {
    #control: Promise<CelldGroupControl> | undefined
    #links = new Map<string, ApplicationPeerLink>()
    #dial: Promise<void> | undefined

    constructor(private readonly state: { id: { name?: string }; storage: CelldPrivateBytesStorage & CelldSqlStorage },
      private readonly env: WorkspaceEnvironment) {
      super(state as never, env as never)
    }

    #group() {
      return this.#control ??= nodeIdentity(this.env).then(signer => {
        const applicationId = this.state.id.name
        if (applicationId === undefined || !key.test(applicationId)) throw new Error('CELLD_GROUP_ADDRESS_INVALID')
        return new CelldGroupControl({ applicationId, storage: this.state.storage, signer, endpoint: nodeEndpoint(this.env) })
      })
    }

    async #attach(peer: CelldGroupNode, group: CelldGroupControl, incoming?: CelldPeerStream): Promise<void> {
      const session = await group.session()
      const transport = createCelldPeerTransport({
        binding: { connect: async (nodeId, options) => {
          const stream = await this.env.CHRONOLOG_P2P.connect(nodeId, options)
          try { await writeCelldGroupAddress(stream, session.applicationId); return stream }
          catch (error) { await stream.close().catch(() => undefined); throw error }
        } },
        resolveEndpoint: async () => peer.endpoint,
        takeInvitation: async () => {
          if (incoming === undefined) throw new Error('CELLD_GROUP_STREAM_MISSING')
          return incoming
        },
      })
      const connection = await transport.open({ peer: { identity: peer.publicKey, route: peer.endpoint.nodeId },
        ...(incoming === undefined ? {} : { invitation: peer.endpoint.nodeId }) }, { signal: session.signal })
      try {
        const link = await session.connectPeer({ connection, peerIdentity: peer.publicKey })
        this.#links.set(peer.publicKey, link)
        void link.completion.catch(() => undefined).finally(() => {
          if (this.#links.get(peer.publicKey) === link) this.#links.delete(peer.publicKey)
        })
      } catch (error) { await connection.close(); throw error }
    }

    async #ensureLink(group: CelldGroupControl, origin: CelldGroupNode): Promise<void> {
      if (this.#links.has(origin.publicKey)) return
      return this.#dial ??= this.#attach(origin, group).finally(() => { this.#dial = undefined })
    }

    async #synchronizeOrigin(group: CelldGroupControl, origin: CelldGroupNode): Promise<void> {
      await this.#ensureLink(group, origin)
      const link = this.#links.get(origin.publicKey)
      if (link === undefined) throw new Error('CELLD_GROUP_COORDINATOR_UNAVAILABLE')
      await link.synchronize()
    }

    async #prepareData(group: CelldGroupControl, session: ApplicationSession): Promise<void> {
      const origin = await group.origin()
      if (origin === null) return
      const missing = await session.keys.missing()
      if (session.revision === null || missing.length !== 0) {
        await this.#synchronizeOrigin(group, origin)
        await session.keys.ensure()
      } else {
        // A previously synchronized workspace may read retained data and save
        // new signed attempts while the selected coordinator is offline.
        void this.#ensureLink(group, origin).catch(() => undefined)
      }
    }

    async fetch(request: Request): Promise<Response> {
      if (!authorized(this.env.CHRONOLOG_GROUP_TOKEN, request)) return denied()
      try {
        const group = await this.#group()
        if (new URL(request.url).pathname === '/carrier') {
          const nodeId = request.headers.get(remote)
          const peer = nodeId && key.test(nodeId) ? await group.peer(nodeId) : null
          if (peer === null) return denied()
          const [client, server] = socketPair()
          const stream = celldGroupSocketStream(server, peer.endpoint.nodeId)
          server.accept()
          void this.#attach(peer, group, stream).catch(() => stream.close())
          return new Response(null, { status: 101, webSocket: client } as ResponseInit)
        }
        if (request.method !== 'POST') return denied()
        const input = decode(await request.text()) as GroupInput
        if (input.action === 'create') {
          await group.create({ name: input.name, schema: input.schema }, await principal(input.principal))
          return reply(true)
        }
        if (input.action === 'join') {
          await group.join(input.offer, input.publicKey)
          return reply(true)
        }
        if (input.action === 'invite') return reply(await group.invite(input.operationId, {
          inviter: input.publicKey, member: input.member, role: input.role, node: input.node,
        }, nodeEndpoint(this.env, input.localEndpoint)))
        const session = await group.session()
        if (input.action === 'describe') {
          const grant = session.memberGrant(input.publicKey)
          return reply(grant?.reader === true ? {
            group: session.applicationId, name: session.historyId, writer: grant.writer, publisher: grant.publisher, administrator: grant.administrator,
          } : null)
        }
        if (input.action === 'bind-history') {
          const origin = await group.origin()
          if (origin !== null) await this.#synchronizeOrigin(group, origin)
          return session.memberGrant(input.publicKey)?.administrator === true ? reply(true) : denied()
        }
        if (input.action === 'sign-publication' || input.action === 'verify-publication') {
          const origin = await group.origin()
          if (origin !== null) await this.#synchronizeOrigin(group, origin)
          const authority = session.authority
          if (input.action === 'sign-publication') {
            const publisher = await principal(input.principal)
            if (input.transition.sourceNodeId !== this.env.CHRONOLOG_P2P.nodeId)
              throw new Error('CELLD_WORKSPACE_PUBLICATION_TRANSITION_MISMATCH')
            if (!session.memberGrant(publisher.publicKey)?.publisher) return denied()
            const proof = await signCelldWorkspacePublication({ authority, transition: input.transition, publisher })
            if (session.authority.generations.at(-1)?.id !== proof.payload.generation)
              throw new Error('CELLD_WORKSPACE_PUBLICATION_AUTHORITY_CHANGED')
            return reply(proof)
          }
          const publisher = await verifyCelldWorkspacePublication({ authority,
            transition: { sourceNodeId: input.sourceNodeId, destinationNodeId: this.env.CHRONOLOG_P2P.nodeId, workspaceId: this.env.WORKSPACE_ID,
              previousHead: input.previousHead, proposedHead: input.proposedHead },
            publication: input.proof,
          })
          if (session.authority.generations.at(-1)?.id !== input.proof.payload.generation)
            throw new Error('CELLD_WORKSPACE_PUBLICATION_AUTHORITY_CHANGED')
          return reply({ publisher })
        }
        const data = celldGroupData(session)
        if (input.action === 'transact') {
          if (!session.memberGrant(input.principal.publicKey)?.writer) return denied()
          await this.#prepareData(group, session)
          const options: CommandOptions = { operationId: input.operationId, ...(input.basedOn === undefined ? {} : { basedOn: input.basedOn }) }
          return reply(await data.transact(await principal(input.principal), readProgram(input.program), options))
        }
        if (input.action === 'outcome' || input.action === 'query' || input.action === 'subscribe') {
          if (!session.memberGrant(input.publicKey)?.reader) return denied()
          await this.#prepareData(group, session)
          if (input.action === 'outcome') {
            const result = await data.outcome(input.publicKey, input.txId)
            if (result === null) return reply(null)
            if (result.status === 'saved') return reply({ status: 'pending' })
            if (result.status !== 'applied') return reply({ status: 'abandoned' })
            return reply(result.outcome === 'accepted' ? { status: 'accepted' } : {
              status: 'rejected', code: result.rejectionCode, statementIndex: result.failingStatementIndex ?? null,
            })
          }
          if (input.action === 'query') return reply(await data.query(input.publicKey, input))
          const abort = new AbortController()
          const subscription = data.subscribe(input.publicKey, input, { signal: AbortSignal.any([abort.signal, request.signal]) })[Symbol.asyncIterator]()
          const encoder = new TextEncoder()
          return new Response(new ReadableStream<Uint8Array>({
            async pull(controller) {
              const next = await subscription.next()
              if (next.done) controller.close()
              else controller.enqueue(encoder.encode(encode(next.value) + '\n'))
            },
            async cancel() { abort.abort(); await subscription.return?.() },
          }, { highWaterMark: 0 }), { headers: { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' } })
        }
        return denied()
      } catch (error) { return failure(error) }
    }
  }
  return { ChronologWorkspaceDO, ChronologGroupDO }
}
