// App-facing ownership and sealed-data APIs against two real nodes in one group.
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  ChronologClient,
  OWNER_FOR_KEY_SQL,
  parseRejectionCode,
  ownerKeySql,
  ownershipQueries,
  type OwnershipQuery,
  type TransactionHandle,
} from '@chronolog/client'
import { generateX25519KeyPair } from '@chronolog/crypto'
import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import { encodeRowKey, encodeSealedEnvelope, equalBytes, generateEd25519KeyPair, utf8, type Ed25519KeyPair } from '@chronolog/protocol'
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
    await expectLocalAcceptance(created)
    await seenBy(bob, created)
    expect(await rows(bob, `SELECT id FROM notes AS n WHERE ${ownerKeySql('n')} = ?`, [aliceKey])).toEqual([[1n]])

    // This fixture inspects provisional materialization; final acceptance has
    // separate real-finality coverage. The code still identifies the denied rule.
    const theft = await bob.transaction(["UPDATE notes SET body = 'bob was here' WHERE id = 1"])
    const rejection = await expectLocalRejection(theft, 'policy:notes:update')
    expect(parseRejectionCode(rejection.code)).toEqual({ kind: 'policy', table: 'notes', operation: 'update' })
    expect(rejection.statementIndex).toBe(0)

    // Alice shares the status column of row 1 with Bob.
    const share = await alice.ownership.share({ table: 'notes', with: bobKey, operations: ['update'], row: [1n], columns: ['status'] })
    await expectLocalAcceptance(share.handle)
    await seenBy(bob, share.handle)
    const received = await list(bob, ownershipQueries.grantsReceived(bobKey))
    expect(received).toEqual([{
      grantId: share.id, table: 'notes', grantor: aliceKey, grantee: bobKey, rowKey: encodeRowKey([1n]), operations: ['update'], columns: ['status'],
    }])
    expect(await list(alice, ownershipQueries.grantsGiven(aliceKey))).toEqual(received)
    await expectLocalAcceptance(await bob.transaction(["UPDATE notes SET status = 'done' WHERE id = 1"]))
    const outsideCaps = await bob.transaction(["UPDATE notes SET body = 'no' WHERE id = 1"])
    await expectLocalRejection(outsideCaps, 'policy:notes:update')

    // The grantee may renounce the grant.
    await expectLocalAcceptance((await bob.ownership.revoke(share.id)).handle)
    expect(await list(bob, ownershipQueries.grantsReceived(bobKey))).toEqual([])

    // A team: Alice creates it and invites Bob, who sees the invitation and accepts.
    const team = await alice.ownership.createTeam({ invite: [bobKey] })
    await expectLocalAcceptance(team.handle)
    await seenBy(bob, team.handle)
    expect((await list(bob, ownershipQueries.invitations(bobKey))).map((entry) => entry.teamId)).toEqual([team.id])
    await expectLocalAcceptance((await bob.ownership.acceptInvitation(team.id)).handle)
    expect(await list(bob, ownershipQueries.teams(bobKey))).toEqual([
      { teamId: team.id, role: 'member', governance: { insert: 'member', update: 'member', delete: 'admin' } },
    ])
    expect((await list(bob, ownershipQueries.members(team.id))).map((member) => [member.role, member.state]).sort())
      .toEqual([['admin', 'active'], ['member', 'active']])

    // Bob writes a row owned by the team; Alice, a team member, may update it.
    const teamRow = await bob.transaction([{ sql: `INSERT INTO notes (id, body, chronolog_owner) VALUES (2, 'team note', ${OWNER_FOR_KEY_SQL})`, params: [team.id] }])
    await expectLocalAcceptance(teamRow)
    await seenBy(alice, teamRow)
    expect(await rows(alice, `SELECT ${ownerKeySql()} FROM notes WHERE id = 2`)).toEqual([[team.id]])
    await expectLocalAcceptance(await alice.transaction(["UPDATE notes SET status = 'reviewed' WHERE id = 2"]))
    // Governance: deleting team rows needs a team admin.
    const memberDelete = await bob.transaction(['DELETE FROM notes WHERE id = 2'])
    expect(parseRejectionCode((await expectLocalRejection(memberDelete, 'policy:notes:delete')).code))
      .toEqual({ kind: 'policy', table: 'notes', operation: 'delete' })

    // A transfer: Alice offers row 1 to Bob, who sees the offer and accepts it.
    const offer = await alice.ownership.offerRow({ table: 'notes', row: [1n], to: bobKey })
    await expectLocalAcceptance(offer.handle)
    await seenBy(bob, offer.handle)
    expect(await list(bob, ownershipQueries.incomingOffers(bobKey))).toEqual([
      { offerId: offer.id, table: 'notes', rowKey: encodeRowKey([1n]), from: aliceKey, to: bobKey, carry: false },
    ])
    expect((await list(alice, ownershipQueries.outgoingOffers(aliceKey))).map((entry) => entry.offerId)).toEqual([offer.id])
    await expectLocalAcceptance((await bob.ownership.acceptOffer(offer.id)).handle)
    expect(await rows(bob, `SELECT ${ownerKeySql()} FROM notes WHERE id = 1`)).toEqual([[bobKey]])
    expect(await list(bob, ownershipQueries.incomingOffers(bobKey))).toEqual([])
    // A second acceptance is refused with a platform reason.
    const again = await bob.ownership.acceptOffer(offer.id)
    expect(parseRejectionCode((await expectLocalRejection(again.handle, 'platform:offer_closed')).code))
      .toEqual({ kind: 'platform', reason: 'offer_closed' })

    // Alice is the schema administrator; Bob is not.
    expect(await list(alice, ownershipQueries.schemaAdmin(aliceKey))).toEqual([true])
    expect(await list(bob, ownershipQueries.schemaAdmin(bobKey))).toEqual([false])
  }, 60_000)

  it('replicates sealed BLOB columns with explicit readers, scoped writers and future-only reader removal', async () => {
    const { alice, bob } = await twoNodes()
    const [aliceId, bobId, aliceReader, bobReader] = await Promise.all([
      alice.identity(), bob.identity(), generateX25519KeyPair(), generateX25519KeyPair(),
    ])
    const created = await alice.transaction([
      'CREATE TABLE docs (id INTEGER PRIMARY KEY, body BLOB, label TEXT NOT NULL) STRICT',
      "INSERT INTO docs (id, label) VALUES (1, 'private document')",
    ])
    await expectLocalAcceptance(created)
    await seenBy(bob, created)

    // Each node signs its own reader-key registration; policies snapshot those keys.
    const aliceRegistration = await alice.sealed.registerKey(aliceReader.publicKeyBytes)
    await expectLocalAcceptance(aliceRegistration)
    await seenBy(bob, aliceRegistration)
    const bobRegistration = await bob.sealed.registerKey(bobReader.publicKeyBytes)
    await expectLocalAcceptance(bobRegistration)
    await seenBy(alice, bobRegistration)
    const readers = await alice.sealed.setReaders({ table: 'docs', row: [1n], readers: [bobId], expectedVersion: 0n })
    await expectLocalAcceptance(readers.handle)
    await seenBy(bob, readers.handle)
    expect(await bob.sealed.getPolicy('docs', [1n], { view: 'local' })).toMatchObject({
      policyId: readers.id, table: 'docs', rowKey: encodeRowKey([1n]), version: 1n, closed: false,
      readers: [{ readerId: bobId, publicKey: bobReader.publicKeyBytes }],
    })

    // This fixture has no policy watermark. Production defaults refuse to encrypt
    // until the policy is final; the override is explicit for this development fixture.
    await expect(alice.sealed.put(readers.id, 'body', utf8('first secret')))
      .rejects.toThrow('SEALED_POLICY_UNAVAILABLE')
    const first = await alice.sealed.put(readers.id, 'body', utf8('first secret'), {
      allowProvisionalPolicy: true, expectedPolicyVersion: 1n, expectedDataVersion: 0n,
    })
    await expectLocalAcceptance(first.handle)
    await seenBy(bob, first.handle)
    const saved = await bob.sealed.get(readers.id, 'body', { view: 'local' })
    expect(saved).not.toBeNull()
    expect(saved).toMatchObject({ policyVersion: 1n, dataVersion: 1n })
    const encoded = encodeSealedEnvelope(saved!.envelope)
    expect(await rows(alice, 'SELECT body FROM docs WHERE id = 1')).toEqual([[encoded]])
    expect(await rows(bob, 'SELECT body FROM docs WHERE id = 1')).toEqual([[encoded]])
    expect(await bob.sealed.decrypt(saved!, bobReader.privateKey, undefined, first.context)).toEqual(utf8('first secret'))
    // Ownership and schema administration add no implicit reader key wrap.
    await expect(alice.sealed.decrypt(saved!, aliceReader.privateKey)).rejects.toMatchObject({ code: 'INVALID_KEY' })

    // The ordinary column grant authorizes sealed writes through the normal UPDATE path.
    const share = await alice.ownership.share({ table: 'docs', row: [1n], with: bobId, operations: ['update'], columns: ['body'] })
    await expectLocalAcceptance(share.handle)
    await seenBy(bob, share.handle)
    const edited = await bob.sealed.put(readers.id, 'body', utf8('edited by the granted writer'), {
      allowProvisionalPolicy: true, expectedPolicyVersion: 1n, expectedDataVersion: 1n,
    })
    await expectLocalAcceptance(edited.handle)
    await seenBy(alice, edited.handle)
    const updated = await alice.sealed.get(readers.id, 'body', { view: 'local' })
    expect(updated).toMatchObject({ policyVersion: 1n, dataVersion: 2n })
    expect(await bob.sealed.decrypt(updated!, bobReader.privateKey)).toEqual(utf8('edited by the granted writer'))
    const outsideGrant = await bob.transaction(["UPDATE docs SET label = 'outside the grant' WHERE id = 1"])
    await expectLocalRejection(outsideGrant, 'policy:docs:update')

    // Replace the exact policy generation/version. The next value receives a new
    // content key and Alice's wrap only; Bob's saved historical value still opens.
    const removed = await alice.sealed.setReaders({
      table: 'docs', row: [1n], readers: [aliceId], expectedPolicyId: readers.id, expectedVersion: 1n,
    })
    await expectLocalAcceptance(removed.handle)
    await seenBy(bob, removed.handle)
    expect(await bob.sealed.getPolicy('docs', [1n], { view: 'local' })).toMatchObject({
      policyId: readers.id, version: 2n, readers: [{ readerId: aliceId, publicKey: aliceReader.publicKeyBytes }],
    })
    const future = await alice.sealed.put(readers.id, 'body', utf8('new audience only'), {
      allowProvisionalPolicy: true, expectedPolicyVersion: 2n, expectedDataVersion: 2n,
    })
    await expectLocalAcceptance(future.handle)
    await seenBy(bob, future.handle)
    const latest = await bob.sealed.get(readers.id, 'body', { view: 'local' })
    expect(latest).toMatchObject({ policyVersion: 2n, dataVersion: 3n })
    expect(latest!.envelope.wraps.map((wrap) => wrap.readerId)).toEqual([aliceId])
    expect(await alice.sealed.decrypt(latest!, aliceReader.privateKey, undefined, future.context)).toEqual(utf8('new audience only'))
    await expect(bob.sealed.decrypt(latest!, bobReader.privateKey)).rejects.toMatchObject({ code: 'INVALID_KEY' })
    expect(await bob.sealed.decrypt(saved!, bobReader.privateKey, undefined, first.context)).toEqual(utf8('first secret'))
  }, 60_000)
})

// This static-membership fixture deliberately never closes its final prefix.
async function expectLocalAcceptance(handle: TransactionHandle): Promise<void> {
  await expect(handle.provisional()).resolves.toMatchObject({ final: false, outcome: { type: 'accepted' } })
}
async function expectLocalRejection(handle: TransactionHandle, code: string) {
  const outcome = await handle.provisional()
  expect(outcome).toMatchObject({ final: false, outcome: { type: 'rejected', rejection: { code } } })
  if (outcome.outcome.type !== 'rejected') throw new Error('Expected a provisional rejection')
  return outcome.outcome.rejection
}

async function list<T>(client: ChronologClient, query: OwnershipQuery<T>): Promise<readonly T[]> {
  return query.decode((await client.query(query.sql, query.parameters, { view: 'local' })).result)
}

async function rows(client: ChronologClient, sql: string, parameters: readonly (Uint8Array | bigint)[] = []) {
  return (await client.query(sql, parameters, { view: 'local' })).result.rows
}

/** Waits until `client`'s node has applied a transaction submitted elsewhere. */
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
