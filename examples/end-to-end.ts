// Two peers share one timestamp-ordered live group. Alice is its schema
// administrator and validator. Final setup authorizes Bob's guarded update;
// partitioned edits execute locally, then replay in signed timestamp order.
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { ChronologClient, platformOp, TransactionRejectedError, type TransactionHandle } from '@chronolog/client'
import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import {
  equalBytes,
  generateEd25519KeyPair,
  program,
  sqlStatement,
  type Ed25519KeyPair,
  type ChangeProgram,
} from '@chronolog/protocol'
import { InProcessRpcTransport, NodeRpcService, type TransactionOutcome } from '@chronolog/rpc'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'

const directory = await mkdtemp(join(tmpdir(), 'chronolog-example-'))
const [alice, bob] = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
const capability = Uint8Array.of(7)
const groupId = bytes32(1)
const network = new MemoryTransportNetwork()
// Drive a genuine finite live policy with a controlled monotone clock, so the
// example can show exactly when local results become final without wall sleeps.
const clock = { now: Date.now() }, cutoffLagMs = 100
const membership: MembershipResolver = {
  canWrite: ({ writerId }) => equalBytes(writerId, alice.publicKeyBytes) || equalBytes(writerId, bob.publicKeyBytes),
  canValidate: ({ validatorId, validatorCapability }) =>
    equalBytes(validatorId, alice.publicKeyBytes) && equalBytes(validatorCapability, capability),
  threshold: () => 1,
  watermarkPolicy: () => ({ kind: 'threshold', policyId: 'alice-validator', validatorIds: [alice.publicKeyBytes], threshold: 1 }),
  liveFinalityPolicies: () => [{ kind: 'threshold', policyId: 'alice-validator', validatorIds: [alice.publicKeyBytes], threshold: 1 }],
  // Each signing key may only publish through its own node's feed.
  canUseTransportAuthor: ({ role, signingId, transportAuthor }) =>
    (equalBytes(signingId, alice.publicKeyBytes) && transportAuthor === 'alice') ||
    (role === 'writer' && equalBytes(signingId, bob.publicKeyBytes) && transportAuthor === 'bob'),
}
const aliceNode = await startNode('alice', alice, true)
const bobNode = await startNode('bob', bob, false)
network.connectAll()
const keepAlive = setInterval(() => undefined, 1_000)

try {
  const setup = await aliceNode.client.submit(bootstrapProgram(), { operationId: 'create-accounts' })
  await requireFinalAcceptance(setup)
  await eventually(async () => (await bobNode.client.getTransactionOutcome(setup.transactionId).catch(() => undefined))?.final === true)
  console.log('owner of account 1 is Alice:',
    equalBytes((await aliceNode.client.query('SELECT p.key FROM accounts AS a JOIN chronolog_principals AS p ON p.id = a.chronolog_owner WHERE a.id = 1', [], { view: 'final' })).result.rows[0]![0] as Uint8Array, alice.publicKeyBytes))

  // Bob may publish SQL, but the owner check still rejects changing Alice's row.
  const theft = await bobNode.client.transaction(['UPDATE accounts SET balance = 0 WHERE id = 1'])
  console.log('Bob updating Alice\'s row:', (await finalOutcome(theft)).outcome)

  // Dependent work waits for a final grant and its final view on the other peer.
  const grant = await aliceNode.client.transaction([
    platformOp.grant({ table: 'accounts', grantee: bob.publicKeyBytes, operations: ['update'], rowKey: [1n], columns: ['balance'] }),
  ])
  await requireFinalAcceptance(grant)
  await eventually(async () => (await bobNode.client.getTransactionOutcome(grant.transactionId).catch(() => undefined))?.final === true)

  // Alice authors the earlier edit while the peers are disconnected. Bob can
  // still execute a later edit locally without a validator or a finality service.
  network.disconnect('alice', 'bob')
  clock.now += 1
  const predecessor = await aliceNode.client.submit(updateProgram(100n, 50n), { operationId: 'alice-edit' })
  const earlierLocal = await predecessor.local()
  if (earlierLocal.outcome.type !== 'accepted') throw new Error('Expected Alice\'s local edit to succeed')
  clock.now += 1
  const granted = await bobNode.client.submit(updateProgram(100n, 95n), { operationId: 'bob-edit' })
  const preview = await granted.local()
  if (preview.outcome.type !== 'accepted' || preview.final) throw new Error('Expected Bob\'s provisional success')
  console.log('Bob\'s disconnected local result:', preview.outcome)

  // Reconnection brings the signed predecessor. Replay replaces Bob's success
  // with a rejection; no external effect was dispatched from that local result.
  network.connectAll()
  await eventually(async () => (await bobNode.client.getTransactionOutcome(granted.transactionId)).outcome.type === 'rejected')
  await requireFinalAcceptance(predecessor)
  const final = await granted.final({ signal: AbortSignal.timeout(10_000) })
  if (final.outcome.type !== 'rejected') throw new Error('Expected the final guarded update to reject')
  console.log('Bob\'s final result:', final.outcome)
  console.log('final balance', (await aliceNode.client.query('SELECT balance FROM accounts WHERE id = ?', [1n], { view: 'final' })).result.rows)
  console.log('checkpoints', aliceNode.materializer.checkpoints().length)
} finally {
  clearInterval(keepAlive)
  await Promise.all([aliceNode.client.close(), bobNode.client.close()])
  await bobNode.node.close()
  await aliceNode.node.close()
  await rm(directory, { recursive: true, force: true })
}

async function startNode(name: string, identity: Ed25519KeyPair, validator: boolean) {
  const materializer = await DeterministicMaterializer.open({
    path: join(directory, `${name}.db`),
    executionManifest: createDoltLiteExecutionManifest(),
    rootAdministrator: alice.publicKeyBytes,
    checkpointEvery: 1,
  })
  const node = new ChronologNode({
    groupId,
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
  const client = new ChronologClient({ groupId: Buffer.from(groupId).toString('base64url'),
    transport: new InProcessRpcTransport(new NodeRpcService({ node })) })
  return { node, materializer, client }
}

function bootstrapProgram(): ChangeProgram {
  return program(
    sqlStatement('CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT'),
    sqlStatement('INSERT INTO accounts (id, balance) VALUES (?, ?)', [1n, 100n]),
  )
}

/** Sets the balance only if it still equals `expected` at the transaction's position. */
function updateProgram(expected: bigint, next: bigint): ChangeProgram {
  return program(
    sqlStatement("SELECT chronolog_assert((SELECT balance FROM accounts WHERE id = ?) = ?, 'balance_changed')", [1n, expected]),
    sqlStatement('UPDATE accounts SET balance = ? WHERE id = ?', [next, 1n]),
  )
}

async function eventually(predicate: () => boolean | Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 10_000
  while (!await predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

/** Demo runtime: close time only after the validator has ingested the proposal. */
async function finalOutcome(handle: TransactionHandle): Promise<TransactionOutcome> {
  await eventually(async () => (await aliceNode.client.getTransactionOutcome(handle.transactionId).catch(() => undefined))?.admissible === true)
  await aliceNode.node.waitForIdle()
  clock.now = Math.max(clock.now, Number(handle.submission.authorTimestampMs)) + cutoffLagMs + 1
  await aliceNode.node.publishHeartbeat()
  return handle.final({ signal: AbortSignal.timeout(10_000) })
}

async function requireFinalAcceptance(handle: TransactionHandle): Promise<void> {
  const result = await finalOutcome(handle)
  if (result.outcome.type === 'rejected') throw new TransactionRejectedError(handle.transactionId, result.outcome.rejection)
}

function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
