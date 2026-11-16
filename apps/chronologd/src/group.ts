// Offline group membership tooling. Run with the daemon stopped:
//
//   pnpm group descriptor OUT_FILE
//       Write the public descriptor (signed genesis + group route) of this
//       node's group so other nodes can join it.
//   pnpm group join DESCRIPTOR_FILE
//       Initialize an empty data directory as a member of that group and print
//       the grant files the group administrator must submit.
//   pnpm group fork ARCHIVE_DIRECTORY --signer BASE64URL_KEY
//       Initialize an empty data directory as the root of a NEW group forked
//       from a signed snapshot, and write the seed plan (fork-seed.json) that
//       recreates the snapshot's tables and rows as ordinary transactions.
//       Start the daemon, then run `chronolog seed @fork-seed.json`.
//   pnpm group verify-fork ARCHIVE_DIRECTORY
//       Compare every application table (rows and owners) and the ownership
//       state (registered tables, teams, memberships, grants, offers) of this
//       (stopped) fork with the snapshot it was seeded from.
//
// See docs/governance.md ("Joining a group" and "Forking a group").
import { createHash } from 'node:crypto'
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { decodeSignedGenesis, encodeSignedGenesis, type SignedGenesis } from '@chronolog/capabilities'
import { executionManifestArtifacts, type ExecutionManifest } from '@chronolog/protocol'
import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  openReadOnlyDatabase,
  readMaterializedRootAdministrator,
} from '@chronolog/materializer-doltlite'
import { decodeSignedSnapshotManifest, stageSnapshotArchive, type TrustedSnapshotManifest } from '@chronolog/node-core'
import { equalBytes } from '@chronolog/protocol'
import { FeedTransport } from '@chronolog/transport-ssb'

import { fromBase64, loadOrCreateConfig } from './config.js'
import { acquireDataDirectoryLock } from './data-lock.js'
import { applicationTableDigests, buildForkSeedPlan, platformTableDigests } from './fork-seed.js'
import { loadOrCreateGovernanceBootstrap } from './governance-config.js'
import { daemonSecretStoreFromEnvironment } from './secret-store.js'

interface GroupDescriptor {
  readonly format: 'chronolog-group-descriptor-v1'
  readonly groupId: string
  readonly groupRoute: string
  readonly signedGenesis: string
}

const USAGE = 'Usage: pnpm group <descriptor OUT_FILE | join DESCRIPTOR_FILE | fork ARCHIVE_DIRECTORY --signer KEY | verify-fork ARCHIVE_DIRECTORY>'
const args = process.argv.slice(2)
const command = args.shift()
const target = args.shift()
if (command === undefined || target === undefined || !['descriptor', 'join', 'fork', 'verify-fork'].includes(command)) {
  process.stderr.write(`${USAGE}\n`)
  process.exit(2)
}
const dataDirectory = resolve(process.env.CHRONOLOG_DATA_DIR ?? '.chronolog')
const lock = await acquireDataDirectoryLock(dataDirectory, `group-${command}`)
try {
  if (command === 'descriptor') await writeDescriptor(resolve(target))
  else if (command === 'join') await joinGroup(parseDescriptor(JSON.parse(await readFile(resolve(target), 'utf8'))))
  else if (command === 'fork') await forkGroup(resolve(target), required(option('--signer'), 'fork requires --signer BASE64URL_PUBLIC_KEY'))
  else await verifyFork(resolve(target))
} finally {
  await lock.release()
}

async function writeDescriptor(outFile: string): Promise<void> {
  const config = JSON.parse(await readFile(join(dataDirectory, 'config.json'), 'utf8')) as { groupId: string; groupRoute: string }
  const governance = JSON.parse(await readFile(join(dataDirectory, 'governance.json'), 'utf8')) as { signedGenesis: string }
  const genesis = decodeSignedGenesis(fromBase64(governance.signedGenesis))
  const descriptor: GroupDescriptor = {
    format: 'chronolog-group-descriptor-v1',
    groupId: b64(genesis.manifest.groupId),
    groupRoute: b64(fromBase64(config.groupRoute)),
    signedGenesis: b64(encodeSignedGenesis(genesis)),
  }
  if (descriptor.groupId !== b64(fromBase64(config.groupId))) throw new Error('GROUP_DESCRIPTOR_CONFIG_MISMATCH')
  await writeFile(outFile, `${JSON.stringify(descriptor, null, 2)}\n`, { flag: 'wx' })
  output({ descriptor: outFile, groupId: descriptor.groupId, forkedFrom: forkOrigin(genesis) })
}

async function joinGroup(descriptor: GroupDescriptor): Promise<void> {
  const genesis = decodeSignedGenesis(b64bytes(descriptor.signedGenesis))
  const groupId = genesis.manifest.groupId
  if (b64(groupId) !== descriptor.groupId) throw new Error('GROUP_DESCRIPTOR_INVALID')
  await assertEmptyDataDirectory()
  await initialize({ groupId, groupRoute: b64bytes(descriptor.groupRoute, 32) }, { adopt: genesis })
}

async function forkGroup(archiveDirectory: string, signerText: string): Promise<void> {
  await assertEmptyDataDirectory()
  const signer = b64bytes(signerText, 32)
  const snapshotBytes = await readFile(join(archiveDirectory, 'snapshot.cbor'))
  const executionManifest = createDoltLiteExecutionManifest()
  const scratch = await mkdtemp(join(dataDirectory, '.fork-source-'))
  try {
    // Same trust checks as a snapshot import: archive evidence, the operator-chosen
    // signer, the execution manifest, and the database's materialized evidence.
    const { executionManifestDigest } = await executionManifestArtifacts(executionManifest)
    const sourceGroup = await snapshotGroup(archiveDirectory)
    const staged = await stageSnapshotArchive({
      archiveDirectory,
      targetDatabasePath: join(scratch, 'source.db'),
      expectations: { groupId: sourceGroup, executionManifestDigest, authorizedSigners: [signer] },
      validateDatabase: async (path, manifest) => validateMaterializer(path, executionManifest, manifest),
    })
    const snapshotManifestSha256 = createHash('sha256').update(snapshotBytes).digest()
    const source = openReadOnlyDatabase(staged.databasePath)
    let plan
    try {
      plan = buildForkSeedPlan(source, {
        sourceGroupId: b64(staged.manifest.groupId),
        snapshotManifestSha256: snapshotManifestSha256.toString('hex'),
        sourceRevision: staged.manifest.materializedRevision,
      })
    } finally { source.close() }
    const forkedFrom = {
      groupId: staged.manifest.groupId,
      snapshotManifestSha256: Uint8Array.from(snapshotManifestSha256),
      materializedRevision: staged.manifest.materializedRevision,
    }
    const identityInfo = await initialize(
      { groupId: crypto.getRandomValues(new Uint8Array(32)), groupRoute: crypto.getRandomValues(new Uint8Array(32)) },
      { forkedFrom },
      true,
    )
    const planPath = join(dataDirectory, 'fork-seed.json')
    await writeFile(planPath, `${JSON.stringify(plan, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
    output({
      forked: true,
      groupId: identityInfo.groupId,
      forkedFrom: { groupId: b64(forkedFrom.groupId), snapshotManifestSha256: snapshotManifestSha256.toString('hex'), revision: forkedFrom.materializedRevision.toString(10) },
      seedPlan: planPath,
      seedBatches: plan.batches.length,
      next: 'Start chronologd on this data directory, then run: chronolog seed @fork-seed.json',
    })
  } finally {
    await rm(scratch, { recursive: true, force: true })
  }
}

async function verifyFork(archiveDirectory: string): Promise<void> {
  const governance = JSON.parse(await readFile(join(dataDirectory, 'governance.json'), 'utf8')) as { signedGenesis: string }
  const genesis = decodeSignedGenesis(fromBase64(governance.signedGenesis))
  const origin = genesis.manifest.forkedFrom
  if (origin === undefined) throw new Error('GROUP_NOT_A_FORK')
  const snapshotSha256 = createHash('sha256').update(await readFile(join(archiveDirectory, 'snapshot.cbor'))).digest()
  if (!snapshotSha256.equals(origin.snapshotManifestSha256)) throw new Error('FORK_SNAPSHOT_MISMATCH')
  const sourceDigests = digestsOf(join(archiveDirectory, 'application.db'))
  const forkDigests = digestsOf(join(dataDirectory, 'application.db'))
  // Owners are ordinary columns of each row, so the table digests compare them too.
  const tables = [...new Set([...Object.keys(sourceDigests), ...Object.keys(forkDigests)])].sort()
  const mismatched = tables.filter((table) => sourceDigests[table] !== forkDigests[table])
  output({ identical: mismatched.length === 0, tables: tables.length, mismatched })
  if (mismatched.length > 0) process.exitCode = 1
}

async function initialize(
  group: { readonly groupId: Uint8Array; readonly groupRoute: Uint8Array },
  bootstrap: { readonly adopt: SignedGenesis } | { readonly forkedFrom: NonNullable<SignedGenesis['manifest']['forkedFrom']> },
  root = false,
): Promise<{ readonly groupId: string }> {
  const secretStore = daemonSecretStoreFromEnvironment(process.env)
  const { identity } = await loadOrCreateConfig(dataDirectory, secretStore, group)
  const transport = await FeedTransport.open({ path: join(dataDirectory, 'ssb') })
  const transportAuthor = transport.identity
  await transport.close()
  // The daemon creates the database on first start, once the genesis names its root administrator.
  const { executionManifestDigest: schemaId } = await executionManifestArtifacts(createDoltLiteExecutionManifest())
  const loaded = await loadOrCreateGovernanceBootstrap({
    dataDirectory,
    groupId: group.groupId,
    schemaId,
    identity,
    transportAuthor,
    bootstrap,
    ...(secretStore === undefined ? {} : { secretStore }),
  })
  const subject = b64(identity.publicKeyBytes)
  const grant = (role: string, extra: Record<string, string> = {}) => ({
    subjectId: subject, signingPublicKey: subject, transportAuthor, role, ...extra,
  })
  if (!root) {
    output({
      joined: true,
      groupId: b64(group.groupId),
      forkedFrom: forkOrigin(loaded.genesis),
      node: { signingPublicKey: subject, transportAuthor, readerHpkePublicKey: b64(loaded.recipientPublicKey) },
      // Submit the roles this node should hold with `chronolog governance grant`
      // on the administrator node, then `chronolog governance rotate` so the new
      // reader receives the current epoch key. Validators stay fixed at genesis.
      suggestedGrants: {
        reader: grant('reader', { hpkePublicKey: b64(loaded.recipientPublicKey) }),
        writer: grant('writer'),
      },
      next: 'Add the administrator node to CHRONOLOG_SSB_PEERS, then start chronologd.',
    })
  }
  return { groupId: b64(group.groupId) }
}

/**
 * The source group is whatever the archive says; a fork does not need to be a
 * member of it. Trust comes from the operator-chosen signer, which
 * stageSnapshotArchive checks together with the signature and evidence.
 */
async function snapshotGroup(archiveDirectory: string): Promise<Uint8Array> {
  const signed = decodeSignedSnapshotManifest(Uint8Array.from(await readFile(join(archiveDirectory, 'snapshot.cbor'))))
  return signed.manifest.groupId
}

async function validateMaterializer(
  path: string,
  executionManifest: ExecutionManifest,
  manifest: TrustedSnapshotManifest,
): Promise<void> {
  // A snapshot database carries its own group's root administrator.
  const materializer = await DeterministicMaterializer.open({ path, executionManifest, rootAdministrator: readMaterializedRootAdministrator(path) })
  try {
    if (materializer.revision !== manifest.materializedRevision || materializer.orderLength !== manifest.orderLength ||
        materializer.databaseContentHash !== manifest.databaseContentHash ||
        !equalBytes(await materializer.transactionLogDigest(), manifest.transactionLogDigest)) {
      throw new Error('SNAPSHOT_MATERIALIZED_EVIDENCE_MISMATCH')
    }
  } finally { materializer.close() }
}

function digestsOf(path: string): Record<string, string> {
  const database = openReadOnlyDatabase(path)
  try {
    const platform = Object.entries(platformTableDigests(database)).map(([name, digest]) => [`platform:${name}`, digest] as const)
    return { ...applicationTableDigests(database), ...Object.fromEntries(platform) }
  } finally { database.close() }
}

function forkOrigin(genesis: SignedGenesis) {
  const origin = genesis.manifest.forkedFrom
  return origin === undefined ? null : {
    groupId: b64(origin.groupId),
    snapshotManifestSha256: Buffer.from(origin.snapshotManifestSha256).toString('hex'),
    revision: origin.materializedRevision.toString(10),
  }
}

function parseDescriptor(value: unknown): GroupDescriptor {
  const record = value as Record<string, unknown>
  if (typeof value !== 'object' || value === null || record.format !== 'chronolog-group-descriptor-v1' ||
      typeof record.groupId !== 'string' || typeof record.groupRoute !== 'string' || typeof record.signedGenesis !== 'string') {
    throw new Error('GROUP_DESCRIPTOR_INVALID')
  }
  return record as unknown as GroupDescriptor
}

async function assertEmptyDataDirectory(): Promise<void> {
  for (const file of ['config.json', 'governance.json', 'application.db', 'ssb']) {
    if (await exists(join(dataDirectory, file))) throw new Error(`GROUP_DATA_DIRECTORY_NOT_EMPTY:${file}`)
  }
}

async function exists(path: string): Promise<boolean> {
  try { await access(path); return true } catch { return false }
}
function option(name: string): string | undefined {
  const index = args.indexOf(name)
  return index < 0 ? undefined : args[index + 1]
}
function required(value: string | undefined, usage: string): string { if (value === undefined) throw new Error(usage); return value }
function b64bytes(value: string, length?: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error('GROUP_BASE64URL_INVALID')
  const result = Uint8Array.from(Buffer.from(value, 'base64url'))
  if (b64(result) !== value || (length !== undefined && result.length !== length)) throw new Error('GROUP_BASE64URL_INVALID')
  return result
}
function b64(value: Uint8Array): string { return Buffer.from(value).toString('base64url') }
function output(value: unknown): void { process.stdout.write(`${JSON.stringify(value, null, 2)}\n`) }
