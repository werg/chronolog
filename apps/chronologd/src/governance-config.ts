import { chmod, mkdir, open, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import {
  decodeSignedGenesis,
  encodeSignedGenesis,
  signGenesis,
  validationPolicyId,
  type ForkOrigin,
  type GenesisManifest,
  type SignedGenesis,
  type ValidationPolicy,
} from '@chronolog/capabilities'
import {
  exportX25519PrivateKey,
  generateX25519KeyPair,
  importX25519PrivateKey,
} from '@chronolog/crypto'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import type { DaemonSecretStore } from './secret-store.js'

export interface LoadedGovernanceBootstrap {
  readonly genesis: SignedGenesis
  readonly validationPolicyId: Uint8Array
  readonly recipientId: Uint8Array
  readonly recipientPublicKey: Uint8Array
  readonly recipientPrivateKey: CryptoKey
}

interface GovernanceDocument {
  readonly format: 'chronolog-governance-bootstrap-v1'
  readonly signedGenesis: string
  readonly recipientId: string
  readonly recipientPublicKey: string
  readonly recipientPrivateKeyPkcs8: string
}

interface GovernanceDocumentV2 extends Omit<GovernanceDocument, 'format' | 'recipientPrivateKeyPkcs8'> {
  readonly format: 'chronolog-governance-bootstrap-v2'
  readonly recipientPrivateKeyRef: string
}

type StoredGovernanceDocument = GovernanceDocument | GovernanceDocumentV2

interface ResolvedGovernanceDocument {
  readonly signedGenesis: string
  readonly recipientId: string
  readonly recipientPublicKey: string
  readonly recipientPrivateKeyPkcs8: string
}

export async function loadOrCreateGovernanceBootstrap(options: {
  readonly dataDirectory: string
  readonly groupId: Uint8Array
  readonly schemaId: Uint8Array
  readonly identity: Ed25519KeyPair
  readonly transportAuthor: string
  readonly now?: () => number
  readonly secretStore?: DaemonSecretStore
  /** Immutable selection for a new group; changing an existing group is rejected. */
  readonly historyPolicy?: 'peer' | 'coordinated'
  /**
   * Used only when `governance.json` does not exist yet. By default a new
   * genesis is created with this node as root. `adopt` joins an existing
   * group's genesis; `forkedFrom` records the source of a forked group.
   */
  readonly bootstrap?: { readonly adopt: SignedGenesis } | { readonly forkedFrom: ForkOrigin }
}): Promise<LoadedGovernanceBootstrap> {
  const path = join(options.dataDirectory, 'governance.json')
  let document: StoredGovernanceDocument
  try {
    document = parseDocument(JSON.parse(await readFile(path, 'utf8')))
    await chmod(path, 0o600)
  } catch (error) {
    if (!isMissing(error)) throw error
    const recipient = await generateX25519KeyPair()
    const genesis = options.bootstrap !== undefined && 'adopt' in options.bootstrap
      ? options.bootstrap.adopt
      : await createGenesis(options, recipient.publicKeyBytes,
        options.bootstrap !== undefined && 'forkedFrom' in options.bootstrap ? options.bootstrap.forkedFrom : undefined)
    const inlineDocument: GovernanceDocument = {
      format: 'chronolog-governance-bootstrap-v1',
      signedGenesis: base64(encodeSignedGenesis(genesis)),
      recipientId: base64(options.identity.publicKeyBytes),
      recipientPublicKey: base64(recipient.publicKeyBytes),
      recipientPrivateKeyPkcs8: base64(await exportX25519PrivateKey(recipient.privateKey)),
    }
    document = options.secretStore === undefined
      ? inlineDocument
      : await externalizeDocument(inlineDocument, options.groupId, options.secretStore)
    await atomicWrite(path, `${JSON.stringify(document, null, 2)}\n`)
  }
  if (document.format === 'chronolog-governance-bootstrap-v1' && options.secretStore !== undefined) {
    document = await externalizeDocument(document, options.groupId, options.secretStore)
    await atomicWrite(path, `${JSON.stringify(document, null, 2)}\n`)
  }
  const resolved = await resolveDocument(document, options.secretStore)
  const genesis = decodeSignedGenesis(unbase64(resolved.signedGenesis))
  if (!sameBytes(genesis.manifest.groupId, options.groupId)) throw new Error('GOVERNANCE_GROUP_MISMATCH')
  if (options.historyPolicy !== undefined && genesis.manifest.historyPolicy?.kind !== options.historyPolicy) {
    throw new Error('GOVERNANCE_HISTORY_POLICY_MISMATCH')
  }
  if (!sameBytes(genesis.manifest.historyPolicy?.executionManifestDigest ?? genesis.manifest.schemaId, options.schemaId)) {
    throw new Error('GOVERNANCE_EXECUTION_PROFILE_MISMATCH')
  }
  return {
    genesis,
    validationPolicyId: await validationPolicyId(genesis.manifest.validationPolicies[0]!),
    recipientId: unbase64(resolved.recipientId),
    recipientPublicKey: unbase64(resolved.recipientPublicKey),
    recipientPrivateKey: await importX25519PrivateKey(unbase64(resolved.recipientPrivateKeyPkcs8), false),
  }
}

async function createGenesis(
  options: {
    readonly groupId: Uint8Array
    readonly schemaId: Uint8Array
    readonly identity: Ed25519KeyPair
    readonly transportAuthor: string
    readonly now?: () => number
    readonly historyPolicy?: 'peer' | 'coordinated'
  },
  recipientPublicKey: Uint8Array,
  forkedFrom: ForkOrigin | undefined,
): Promise<SignedGenesis> {
  const policy: ValidationPolicy = {
    version: 1n,
    minimumValidators: 1n,
  }
  const common = {
    subjectId: options.identity.publicKeyBytes,
    signingPublicKey: options.identity.publicKeyBytes,
    transportAuthor: options.transportAuthor,
    validFromRevision: 0n,
  }
  const manifest: GenesisManifest = {
    groupId: options.groupId,
    schemaId: options.schemaId,
    historyPolicy: options.historyPolicy === 'coordinated'
      ? { kind: 'coordinated', executionManifestDigest: options.schemaId,
        historyId: `h_${Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('hex')}`,
        authorityPublicKey: options.identity.publicKeyBytes }
      : { kind: 'peer', executionManifestDigest: options.schemaId },
    rootAdminPublicKey: options.identity.publicKeyBytes,
    schemaAdminPublicKey: options.identity.publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode(options.transportAuthor),
    initialCapabilities: [
      { ...common, role: 'administrator' },
      // This is an explicit trusted owner grant. Other devices receive only the
      // SQL, event-topic and ephemeral rights selected during their enrollment.
      { ...common, role: 'writer', program: { sql: true, topics: ['*'], signals: ['*'] } },
      { ...common, role: 'validator', minimumAuthorTimestampMs: 0n },
      { ...common, role: 'reader', hpkePublicKey: recipientPublicKey },
    ],
    validationPolicies: [policy],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 60_000n, heartbeatIntervalMs: 30_000n },
    resourcePolicy: { maxCandidateBytes: 16_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 1_000n, maxMutations: 1_000n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM',
    createdAtMs: BigInt(Math.trunc(options.now?.() ?? Date.now())),
    ...(forkedFrom === undefined ? {} : { forkedFrom }),
  }
  return signGenesis(manifest, options.identity.privateKey)
}

function parseDocument(value: unknown): StoredGovernanceDocument {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('GOVERNANCE_CONFIG_INVALID')
  const record = value as Record<string, unknown>
  if (record.format === 'chronolog-governance-bootstrap-v2') return parseExternalDocument(record)
  const allowed = new Set([
    'format', 'signedGenesis', 'recipientId', 'recipientPublicKey',
    'recipientPrivateKeyPkcs8',
  ])
  if (record.format !== 'chronolog-governance-bootstrap-v1' || Object.keys(record).some((key) => !allowed.has(key)) ||
      typeof record.signedGenesis !== 'string' || typeof record.recipientId !== 'string' ||
      typeof record.recipientPublicKey !== 'string' || typeof record.recipientPrivateKeyPkcs8 !== 'string') {
    throw new Error('GOVERNANCE_CONFIG_INVALID')
  }
  return record as unknown as GovernanceDocument
}

function parseExternalDocument(record: Record<string, unknown>): GovernanceDocumentV2 {
  const allowed = new Set([
    'format', 'signedGenesis', 'recipientId', 'recipientPublicKey',
    'recipientPrivateKeyRef',
  ])
  if (Object.keys(record).some((key) => !allowed.has(key)) ||
      typeof record.signedGenesis !== 'string' || typeof record.recipientId !== 'string' ||
      typeof record.recipientPublicKey !== 'string' || typeof record.recipientPrivateKeyRef !== 'string') {
    throw new Error('GOVERNANCE_CONFIG_INVALID')
  }
  validateReference(record.recipientPrivateKeyRef)
  return record as unknown as GovernanceDocumentV2
}

async function externalizeDocument(
  document: GovernanceDocument,
  groupId: Uint8Array,
  secretStore: DaemonSecretStore,
): Promise<GovernanceDocumentV2> {
  const suffix = Buffer.from(groupId).toString('base64url')
  const recipientPrivateKeyRef = `groups/${suffix}/governance-recipient`
  await secretStore.set(recipientPrivateKeyRef, document.recipientPrivateKeyPkcs8)
  return {
    format: 'chronolog-governance-bootstrap-v2',
    signedGenesis: document.signedGenesis,
    recipientId: document.recipientId,
    recipientPublicKey: document.recipientPublicKey,
    recipientPrivateKeyRef,
  }
}

async function resolveDocument(
  document: StoredGovernanceDocument,
  secretStore: DaemonSecretStore | undefined,
): Promise<ResolvedGovernanceDocument> {
  if (document.format === 'chronolog-governance-bootstrap-v1') return document
  if (secretStore === undefined) throw new Error('DAEMON_SECRET_STORE_REQUIRED')
  return {
    signedGenesis: document.signedGenesis,
    recipientId: document.recipientId,
    recipientPublicKey: document.recipientPublicKey,
    recipientPrivateKeyPkcs8: await secretStore.get(document.recipientPrivateKeyRef),
  }
}

function validateReference(reference: string): void {
  if (!/^[A-Za-z0-9._:/-]{1,256}$/u.test(reference)) throw new Error('GOVERNANCE_SECRET_REFERENCE_INVALID')
}

async function atomicWrite(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.tmp`
  await writeFile(temporary, contents, { encoding: 'utf8', mode: 0o600 })
  await chmod(temporary, 0o600)
  const handle = await open(temporary, 'r')
  try { await handle.sync() } finally { await handle.close() }
  await rename(temporary, path)
}

function base64(value: Uint8Array): string { return Buffer.from(value).toString('base64') }
function unbase64(value: string): Uint8Array { return Uint8Array.from(Buffer.from(value, 'base64')) }
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}
function isMissing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: unknown }).code === 'ENOENT'
}
