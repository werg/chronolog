// Owner-controlled rows from an app's point of view: two nodes, Alice and
// Bob, each with its own ChronologClient. Rows belong to the key that wrote
// them; Alice shares one row with Bob, they work in a team, and Alice hands
// a note over to Bob. Run with `pnpm demo:ownership`.
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
import { InProcessRpcTransport, NodeRpcService, type TransactionOutcome } from '@chronolog/rpc'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'

const directory = await mkdtemp(join(tmpdir(), 'chronolog-shared-notes-'))
const [aliceKeys, bobKeys] = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
const network = new MemoryTransportNetwork()
const nodes: ChronologNode[] = []
// A controlled monotone clock makes the live closure visible without sleeps.
// Deployed validators drive these same heartbeats with heartbeatIntervalMs.
const clock = { now: Date.now() }
const cutoffLagMs = 100
const alice = await start('alice', aliceKeys, true)
const bob = await start('bob', bobKeys, false)
network.connectAll()
// In-process nodes keep nothing on the event loop while a client waits for
// an outcome (an HTTP client's open connection would), so hold the process open.
const keepAlive = setInterval(() => undefined, 1_000)

try {
  const aliceKey = await alice.identity()
  const bobKey = await bob.identity()
  const name = (key: Uint8Array): string => equalBytes(key, aliceKey) ? 'Alice' : equalBytes(key, bobKey) ? 'Bob' : 'a team'

  // Alice is the group's schema administrator: she creates the table. Every
  // table gets a chronolog_owner column; new rows belong to their signer.
  const setup = await alice.transaction([
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open') STRICT",
    "INSERT INTO notes (id, body) VALUES (1, 'Plan the offsite')",
  ])
  await requireFinalAcceptance(setup)
  await reached(bob, setup)

  // Bob cannot change Alice's note. The whole transaction is rejected, with a reason.
  const theft = await bob.transaction(["UPDATE notes SET status = 'done' WHERE id = 1"])
  const refused = await finalOutcome(theft)
  if (refused.outcome.type !== 'rejected') throw new Error('Expected the owner check to reject Bob')
  console.log('Bob editing Alice\'s note:', new TransactionRejectedError(theft.transactionId, refused.outcome.rejection).reason)

  // Alice lets Bob update the status of that one note.
  const share = await alice.ownership.share({ table: 'notes', with: bobKey, operations: ['update'], row: [1n], columns: ['status'] })
  await requireFinalAcceptance(share.handle)
  await reached(bob, share.handle)
  console.log('Bob\'s grants:', (await list(bob, ownershipQueries.grantsReceived(bobKey))).map((grant) => `${grant.operations.join('+')} ${grant.table}[${grant.rowKey}] ${grant.columns?.join(',')}`))
  await requireFinalAcceptance(await bob.transaction(["UPDATE notes SET status = 'in progress' WHERE id = 1"]))

  // A team: Alice creates it and invites Bob; Bob accepts and writes a team-owned note.
  const team = await alice.ownership.createTeam({ invite: [bobKey] })
  await requireFinalAcceptance(team.handle)
  await reached(bob, team.handle)
  console.log('Bob\'s invitations:', (await list(bob, ownershipQueries.invitations(bobKey))).length)
  await requireFinalAcceptance((await bob.ownership.acceptInvitation(team.id)).handle)
  await requireFinalAcceptance(await bob.transaction([{ sql: `INSERT INTO notes (id, body, chronolog_owner) VALUES (2, 'Book the venue', ${OWNER_FOR_KEY_SQL})`, params: [team.id] }]))

  // Alice hands note 1 over to Bob; it moves when he accepts.
  const offer = await alice.ownership.offerRow({ table: 'notes', row: [1n], to: bobKey })
  await requireFinalAcceptance(offer.handle)
  await reached(bob, offer.handle)
  const [incoming] = await list(bob, ownershipQueries.incomingOffers(bobKey))
  const accept = await bob.ownership.acceptOffer(incoming!.offerId)
  await requireFinalAcceptance(accept.handle)
  await reached(alice, accept.handle)

  for (const [id, body, status, owner] of (await alice.query(`SELECT id, body, status, ${ownerKeySql('n')} FROM notes AS n ORDER BY id`, [], { view: 'final' })).result.rows) {
    console.log(`note ${String(id)}: ${String(body)} (${String(status)}), owned by ${name(owner as Uint8Array)}`)
  }
} finally {
  clearInterval(keepAlive)
  await Promise.all([alice.close(), bob.close()])
  for (const node of nodes) await node.close()
  await rm(directory, { recursive: true, force: true })
}

/** Demo runtime: first ingest admission, then close author time with a real signed heartbeat. */
async function finalOutcome(handle: TransactionHandle): Promise<TransactionOutcome> {
  const deadline = Date.now() + 10_000
  while (!(await alice.getTransactionOutcome(handle.transactionId).catch(() => undefined))?.admissible) {
    if (Date.now() >= deadline) throw new Error('validator did not admit the proposal')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  await nodes[0]!.waitForIdle()
  clock.now = Math.max(clock.now, Number(handle.submission.authorTimestampMs)) + cutoffLagMs + 1
  await nodes[0]!.publishHeartbeat()
  return handle.final({ signal: AbortSignal.timeout(10_000) })
}

/** Application code chooses to fail a dependent workflow on a final rejection. */
async function requireFinalAcceptance(handle: TransactionHandle): Promise<void> {
  const result = await finalOutcome(handle)
  if (result.outcome.type === 'rejected') throw new TransactionRejectedError(handle.transactionId, result.outcome.rejection)
}

async function list<T>(client: ChronologClient, query: OwnershipQuery<T>): Promise<readonly T[]> {
  return query.decode((await client.query(query.sql, query.parameters, { view: 'final' })).result)
}

/** Waits until `client`'s node has the outcome of a transaction submitted through another node. */
async function reached(client: ChronologClient, handle: TransactionHandle): Promise<void> {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    const outcome = await client.getTransactionOutcome(handle.transactionId).catch(() => undefined)
    if (outcome !== undefined && outcome.final && outcome.outcome.type !== 'pending') return
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  throw new Error('transaction did not replicate')
}

async function start(name: string, identity: Ed25519KeyPair, validator: boolean): Promise<ChronologClient> {
  const capability = Uint8Array.of(7)
  const membership: MembershipResolver = {
    canWrite: ({ writerId }) => equalBytes(writerId, aliceKeys.publicKeyBytes) || equalBytes(writerId, bobKeys.publicKeyBytes),
    canValidate: ({ validatorId, validatorCapability }) =>
      equalBytes(validatorId, aliceKeys.publicKeyBytes) && equalBytes(validatorCapability, capability),
    threshold: () => 1,
    watermarkPolicy: () => ({ kind: 'threshold', policyId: 'alice-validator', validatorIds: [aliceKeys.publicKeyBytes], threshold: 1 }),
    liveFinalityPolicies: () => [{ kind: 'threshold', policyId: 'alice-validator', validatorIds: [aliceKeys.publicKeyBytes], threshold: 1 }],
    canUseTransportAuthor: ({ signingId, transportAuthor }) =>
      (equalBytes(signingId, aliceKeys.publicKeyBytes) && transportAuthor === 'alice') ||
      (equalBytes(signingId, bobKeys.publicKeyBytes) && transportAuthor === 'bob'),
  }
  const materializer = await DeterministicMaterializer.open({
    path: join(directory, `${name}.db`),
    executionManifest: createDoltLiteExecutionManifest(),
    // Every replica names the same genesis root administrator: Alice.
    rootAdministrator: aliceKeys.publicKeyBytes,
  })
  const node = new ChronologNode({
    groupId: bytes32(1),
    membershipRevision: bytes32(2),
    validationPolicy: bytes32(3),
    identity,
    transport: network.createNode(name),
    materialization: createDoltLiteMaterializationRuntime(materializer),
    membership,
    clock: { now: () => clock.now },
    ...(validator ? { validator: { capabilityId: capability, cutoffLagMs } } : {}),
  })
  await node.start()
  nodes.push(node)
  return new ChronologClient({
    groupId: Buffer.from(bytes32(1)).toString('base64url'),
    transport: new InProcessRpcTransport(new NodeRpcService({ node })),
  })
}

function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
