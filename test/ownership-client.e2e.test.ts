// The app-facing ownership API (ChronologClient.ownership, ownershipQueries,
// ownerKeySql, TransactionRejectedError) against two real nodes in one group.
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  ChronologClient,
  OWNER_FOR_KEY_SQL,
  TransactionRejectedError,
  ownerKeySql,
  ownershipQueries,
  type OwnershipQuery,
  type TransactionHandle,
} from '@chronolog/client'
import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import { equalBytes, generateEd25519KeyPair, type Ed25519KeyPair } from '@chronolog/protocol'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('ownership client API', () => {
  it('shares rows, runs teams and transfers ownership between two nodes', async () => {
    const { alice, bob } = await twoNodes()
    const aliceKey = await alice.identity()
    const bobKey = await bob.identity()
    expect(aliceKey).toHaveLength(32)
    expect(equalBytes(aliceKey, bobKey)).toBe(false)

    // Alice (the root administrator) creates a table; rows are owned by their signer.
    const created = await alice.transaction([
      'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT \'open\') STRICT',
      "INSERT INTO notes (id, body) VALUES (1, 'alice note')",
    ])
    await created.accepted()
    await seenBy(bob, created)
    expect(await rows(bob, `SELECT id FROM notes AS n WHERE ${ownerKeySql('n')} = ?`, [aliceKey])).toEqual([[1n]])

    // Bob may not change it: a typed rejection says which table and operation.
    const theft = await bob.transaction(["UPDATE notes SET body = 'bob was here' WHERE id = 1"])
    const error = await theft.accepted().catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(TransactionRejectedError)
    expect((error as TransactionRejectedError).reason).toEqual({ kind: 'policy', table: 'notes', operation: 'update' })
    expect((error as TransactionRejectedError).stepIndex).toBe(0)

    // Alice shares the status column of row 1 with Bob.
    const share = await alice.ownership.share({ table: 'notes', with: bobKey, operations: ['update'], row: [1n], columns: ['status'] })
    await share.handle.accepted()
    await seenBy(bob, share.handle)
    const received = await list(bob, ownershipQueries.grantsReceived(bobKey))
    expect(received).toEqual([{
      grantId: share.id, table: 'notes', grantor: aliceKey, grantee: bobKey, rowKey: '1', operations: ['update'], columns: ['status'],
    }])
    expect(await list(alice, ownershipQueries.grantsGiven(aliceKey))).toEqual(received)
    await (await bob.transaction(["UPDATE notes SET status = 'done' WHERE id = 1"])).accepted()
    const outsideCaps = await bob.transaction(["UPDATE notes SET body = 'no' WHERE id = 1"])
    await expect(outsideCaps.accepted()).rejects.toMatchObject({ code: 'policy:notes:update' })

    // The grantee may renounce the grant.
    await (await bob.ownership.revoke(share.id)).handle.accepted()
    expect(await list(bob, ownershipQueries.grantsReceived(bobKey))).toEqual([])

    // A team: Alice creates it and invites Bob, who sees the invitation and accepts.
    const team = await alice.ownership.createTeam({ invite: [bobKey] })
    await team.handle.accepted()
    await seenBy(bob, team.handle)
    expect((await list(bob, ownershipQueries.invitations(bobKey))).map((entry) => entry.teamId)).toEqual([team.id])
    await (await bob.ownership.acceptInvitation(team.id)).handle.accepted()
    expect(await list(bob, ownershipQueries.teams(bobKey))).toEqual([
      { teamId: team.id, role: 'member', governance: { insert: 'member', update: 'member', delete: 'admin' } },
    ])
    expect((await list(bob, ownershipQueries.members(team.id))).map((member) => [member.role, member.state]).sort())
      .toEqual([['admin', 'active'], ['member', 'active']])

    // Bob writes a row owned by the team; Alice, a team member, may update it.
    const teamRow = await bob.transaction([{ sql: `INSERT INTO notes (id, body, chronolog_owner) VALUES (2, 'team note', ${OWNER_FOR_KEY_SQL})`, params: [team.id] }])
    await teamRow.accepted()
    await seenBy(alice, teamRow)
    expect(await rows(alice, `SELECT ${ownerKeySql()} FROM notes WHERE id = 2`)).toEqual([[team.id]])
    await (await alice.transaction(["UPDATE notes SET status = 'reviewed' WHERE id = 2"])).accepted()
    // Governance: deleting team rows needs a team admin.
    const memberDelete = await bob.transaction(['DELETE FROM notes WHERE id = 2'])
    await expect(memberDelete.accepted()).rejects.toMatchObject({ reason: { kind: 'policy', operation: 'delete' } })

    // A transfer: Alice offers row 1 to Bob, who sees the offer and accepts it.
    const offer = await alice.ownership.offerRow({ table: 'notes', row: [1n], to: bobKey })
    await offer.handle.accepted()
    await seenBy(bob, offer.handle)
    expect(await list(bob, ownershipQueries.incomingOffers(bobKey))).toEqual([
      { offerId: offer.id, table: 'notes', rowKey: '1', from: aliceKey, to: bobKey, carry: false },
    ])
    expect((await list(alice, ownershipQueries.outgoingOffers(aliceKey))).map((entry) => entry.offerId)).toEqual([offer.id])
    await (await bob.ownership.acceptOffer(offer.id)).handle.accepted()
    expect(await rows(bob, `SELECT ${ownerKeySql()} FROM notes WHERE id = 1`)).toEqual([[bobKey]])
    expect(await list(bob, ownershipQueries.incomingOffers(bobKey))).toEqual([])
    // A second acceptance is refused with a platform reason.
    const again = await bob.ownership.acceptOffer(offer.id)
    await expect(again.handle.accepted()).rejects.toMatchObject({ reason: { kind: 'platform', reason: 'offer_closed' } })

    // Alice is the schema administrator; Bob is not.
    expect(await list(alice, ownershipQueries.schemaAdmin(aliceKey))).toEqual([true])
    expect(await list(bob, ownershipQueries.schemaAdmin(bobKey))).toEqual([false])
  }, 60_000)
})

async function list<T>(client: ChronologClient, query: OwnershipQuery<T>): Promise<readonly T[]> {
  return query.decode((await client.query(query.sql, query.parameters)).result)
}

async function rows(client: ChronologClient, sql: string, parameters: readonly (Uint8Array | bigint)[] = []) {
  return (await client.query(sql, parameters)).result.rows
}

/** Waits until `client`'s node has settled a transaction submitted elsewhere. */
async function seenBy(client: ChronologClient, handle: TransactionHandle): Promise<void> {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    const outcome = await client.getTransactionOutcome(handle.transactionId).catch(() => undefined)
    if (outcome !== undefined && outcome.outcome.type !== 'pending') return
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  throw new Error('transaction did not reach the other node')
}

async function twoNodes(): Promise<{ readonly alice: ChronologClient; readonly bob: ChronologClient }> {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-ownership-'))
  const [aliceKeys, bobKeys] = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const capability = Uint8Array.of(7)
  const groupId = bytes32(1)
  const network = new MemoryTransportNetwork()
  const membership: MembershipResolver = {
    canWrite: ({ writerId }) => equalBytes(writerId, aliceKeys.publicKeyBytes) || equalBytes(writerId, bobKeys.publicKeyBytes),
    canValidate: ({ validatorId, validatorCapability }) =>
      equalBytes(validatorId, aliceKeys.publicKeyBytes) && equalBytes(validatorCapability, capability),
    threshold: () => 1,
    canUseTransportAuthor: ({ signingId, transportAuthor }) =>
      (equalBytes(signingId, aliceKeys.publicKeyBytes) && transportAuthor === 'alice') ||
      (equalBytes(signingId, bobKeys.publicKeyBytes) && transportAuthor === 'bob'),
  }
  const start = async (name: string, identity: Ed25519KeyPair, validator: boolean): Promise<ChronologClient> => {
    const materializer = await DeterministicMaterializer.open({
      path: join(directory, `${name}.db`),
      executionManifest: createDoltLiteExecutionManifest(),
      rootAdministrator: aliceKeys.publicKeyBytes,
    })
    const node = new ChronologNode({
      groupId,
      membershipRevision: bytes32(2),
      validationPolicy: bytes32(3),
      identity,
      transport: network.createNode(name),
      materialization: createDoltLiteMaterializationRuntime(materializer),
      membership,
      ...(validator ? { validator: { capabilityId: capability, cutoffLagMs: Number.MAX_SAFE_INTEGER } } : {}),
    })
    await node.start()
    const client = new ChronologClient({
      groupId: Buffer.from(groupId).toString('base64url'),
      transport: new InProcessRpcTransport(new NodeRpcService({ node })),
    })
    cleanup.push(async () => { await client.close(); await node.close() })
    return client
  }
  cleanup.push(async () => { await rm(directory, { recursive: true, force: true, maxRetries: 5 }) })
  const alice = await start('alice', aliceKeys, true)
  const bob = await start('bob', bobKeys, false)
  network.connectAll()
  return { alice, bob }
}

function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
