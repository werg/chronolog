// Two nodes share one group. Alice is the root administrator and the
// validator; Bob is a writer. Alice creates and registers a table, Bob's
// attempt to change Alice's row is rejected by the owner check, Alice grants
// Bob access to that row, and a late predecessor flips a later transaction
// during replay.
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { ChronologClient, platformOp } from '@chronolog/client'
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
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'

const directory = await mkdtemp(join(tmpdir(), 'chronolog-example-'))
const [alice, bob] = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
const capability = Uint8Array.of(7)
const groupId = bytes32(1)
const network = new MemoryTransportNetwork()
const membership: MembershipResolver = {
  canWrite: ({ writerId }) => equalBytes(writerId, alice.publicKeyBytes) || equalBytes(writerId, bob.publicKeyBytes),
  canValidate: ({ validatorId, validatorCapability }) =>
    equalBytes(validatorId, alice.publicKeyBytes) && equalBytes(validatorCapability, capability),
  threshold: () => 1,
  // Each signing key may only publish through its own node's feed.
  canUseTransportAuthor: ({ role, signingId, transportAuthor }) =>
    (equalBytes(signingId, alice.publicKeyBytes) && transportAuthor === 'alice') ||
    (role === 'writer' && equalBytes(signingId, bob.publicKeyBytes) && transportAuthor === 'bob'),
}
const aliceNode = await startNode('alice', alice, true)
const bobNode = await startNode('bob', bob, false)
network.connectAll()

const client = new ChronologClient({
  groupId: Buffer.from(groupId).toString('base64url'),
  transport: new InProcessRpcTransport(new NodeRpcService({ node: aliceNode.node })),
})
try {
  // Alice (the root administrator) creates the table and registers it: rows
  // now belong to the key that signed their insert.
  await settled(aliceNode.node, await aliceNode.node.publish({ authorTimestampMs: 1n, program: bootstrapProgram() }), 'accepted')
  console.log('owner of account 1 is Alice:',
    equalBytes((await client.query('SELECT p.key FROM accounts AS a JOIN chronolog_principals AS p ON p.id = a.chronolog_owner WHERE a.id = 1', [], { view: 'local' })).result.rows[0]![0] as Uint8Array, alice.publicKeyBytes))

  // Bob may write, but not Alice's row.
  const theft = await bobNode.node.publish({ authorTimestampMs: 2n, program: program('UPDATE accounts SET balance = 0 WHERE id = 1') })
  console.log('Bob updating Alice\'s row:', await settled(aliceNode.node, theft))

  // Alice grants Bob updates of the balance column of that one row.
  await settled(aliceNode.node, await aliceNode.node.publish({
    authorTimestampMs: 3n,
    program: program(platformOp.grant({ table: 'accounts', grantee: bob.publicKeyBytes, operations: ['update'], rowKey: [1n], columns: ['balance'] })),
  }), 'accepted')
  const granted = await bobNode.node.publish({ authorTimestampMs: 10n, program: updateProgram(100n, 95n) })
  console.log('Bob updating the balance with a grant:', await settled(aliceNode.node, granted))

  // A late predecessor: Alice's update at time 5 sorts before Bob's at time
  // 10, so Bob's guarded update is replayed after it and now rejected.
  const predecessor = await aliceNode.node.publish({ authorTimestampMs: 5n, program: updateProgram(100n, 50n) })
  await settled(aliceNode.node, predecessor, 'accepted')
  await eventually(() => aliceNode.node.outcome(granted.txId)?.rejectionCode === 'assert:balance_changed')
  console.log('Bob\'s update after replay:', aliceNode.node.outcome(granted.txId)?.rejectionCode)
  console.log('balance', (await client.query('SELECT balance FROM accounts WHERE id = ?', [1n], { view: 'local' })).result.rows)
  console.log('checkpoints', aliceNode.materializer.checkpoints().length)
} finally {
  await client.close()
  await bobNode.node.close()
  await aliceNode.node.close()
  await rm(directory, { recursive: true, force: true })
}

async function startNode(name: string, identity: Ed25519KeyPair, validator: boolean) {
  const materializer = await DeterministicMaterializer.open({
    path: join(directory, `${name}.db`),
    executionManifest: createDoltLiteExecutionManifest(),
    // Every replica of the group names the same genesis root administrator.
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
    ...(validator ? { validator: { capabilityId: capability, cutoffLagMs: Number.MAX_SAFE_INTEGER } } : {}),
  })
  await node.start()
  return { node, materializer }
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

async function eventually(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 10_000
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

/** Waits until the transaction has an outcome on `node`; returns `accepted` or the rejection code. */
async function settled(node: ChronologNode, published: { readonly txId: Uint8Array }, expected?: string): Promise<string> {
  const deadline = Date.now() + 10_000
  while (node.outcome(published.txId) === null) {
    if (Date.now() >= deadline) throw new Error('transaction did not settle')
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  const outcome = node.outcome(published.txId)!
  const result = outcome.rejectionCode ?? outcome.outcome
  if (expected !== undefined && result !== expected) throw new Error(`expected ${expected}, got ${result}`)
  return result
}

function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
