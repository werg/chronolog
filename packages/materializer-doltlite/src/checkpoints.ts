import { bytesToHex, createSha256 } from '@chronolog/canonical'

import type {
  DatabaseLike,
  DoltBranchInfoLike,
  MaterializerCheckpointInfo,
  TransactionLogRow,
} from './types.js'

export const HEAD_BRANCH = 'chronolog_head' as const
export const FINAL_BRANCH = 'chronolog_final' as const
const FINAL_PREFIX = 'chronolog_final_rev_'
const FINAL_PATTERN = /^chronolog_final_rev_r([0-9]+)_p([0-9]+)_([0-9a-f]{16})$/u
const CHECKPOINT_PREFIX = 'chronolog_cp_'
const REVISION_PREFIX = 'chronolog_rev_'
const REPLAY_PREFIX = 'chronolog_replay_'

const CHECKPOINT_PATTERN = /^chronolog_cp_p([0-9]+)_r([0-9]+)_([0-9a-f]{16})$/u
const REVISION_PATTERN = /^chronolog_rev_r([0-9]+)_p([0-9]+)_([0-9a-f]{16})$/u

export interface PublishedRef {
  readonly revision: bigint
  readonly prefixLength: number
  readonly branchRef: string
  readonly doltCommitHash: string
  readonly contentHash: string
  readonly orderDigest: string
}

export function discoverFinalRef(database: DatabaseLike): PublishedRef | null {
  const branches = database.doltBranches()
  const head = branches.find((branch) => branch.name === FINAL_BRANCH)
  if (head === undefined) return null
  const matches = branches.filter((branch) => branch.hash === head.hash && FINAL_PATTERN.test(branch.name))
  if (matches.length !== 1) throw new Error('MATERIALIZER_FINAL_REVISION_REF_INVALID')
  const marker = matches[0]!
  const match = FINAL_PATTERN.exec(marker.name)!
  return {
    revision: BigInt(match[1]!), prefixLength: safeInteger(match[2]!, 'MATERIALIZER_FINAL_PREFIX_INVALID'),
    branchRef: marker.name, doltCommitHash: marker.hash,
    contentHash: database.doltHashOf(FINAL_BRANCH), orderDigest: match[3]!,
  }
}

export function publishFinalRef(database: DatabaseLike, revision: bigint, log: readonly TransactionLogRow[], commitHash: string): PublishedRef {
  const digest = orderDigest(log)
  const branchRef = `${FINAL_PREFIX}r${revision}_p${log.length}_${digest}`
  if (!database.doltBranches().some((branch) => branch.name === branchRef)) database.doltBranch(branchRef, commitHash)
  const result: PublishedRef = {
    revision, prefixLength: log.length, branchRef, doltCommitHash: commitHash,
    contentHash: database.doltHashOf(commitHash), orderDigest: digest,
  }
  database.doltForceBranch(FINAL_BRANCH, commitHash)
  return result
}

export function discoverPublishedRef(database: DatabaseLike): PublishedRef | null {
  const branches = database.doltBranches()
  const head = branches.find((branch) => branch.name === HEAD_BRANCH)
  if (head === undefined) return null
  const matching = branches
    .map((branch) => ({ branch, parsed: parseRevisionBranch(branch) }))
    .filter(
      (entry): entry is { branch: DoltBranchInfoLike; parsed: Omit<PublishedRef, 'doltCommitHash' | 'contentHash'> } =>
        entry.parsed !== null && entry.branch.hash === head.hash,
    )
  if (matching.length !== 1) throw new Error('MATERIALIZER_PUBLISHED_REVISION_REF_INVALID')
  const marker = matching[0]!
  return {
    ...marker.parsed,
    doltCommitHash: head.hash,
    contentHash: database.doltHashOf(HEAD_BRANCH),
  }
}

export function discoverCheckpoints(database: DatabaseLike): MaterializerCheckpointInfo[] {
  return database
    .doltBranches()
    .map((branch) => {
      const match = CHECKPOINT_PATTERN.exec(branch.name)
      if (match === null) return null
      const prefixLength = safeInteger(match[1]!, 'MATERIALIZER_CHECKPOINT_PREFIX_INVALID')
      const createdAtRevision = BigInt(match[2]!)
      return {
        prefixLength,
        branchRef: branch.name,
        doltCommitHash: branch.hash,
        contentHash: database.doltHashOf(branch.name),
        createdAtRevision,
      } satisfies MaterializerCheckpointInfo
    })
    .filter((value): value is MaterializerCheckpointInfo => value !== null)
    .sort((left, right) => left.prefixLength - right.prefixLength)
}

export function checkpointOrderDigest(branchRef: string): string {
  const match = CHECKPOINT_PATTERN.exec(branchRef)
  if (match === null) throw new Error('MATERIALIZER_CHECKPOINT_REF_INVALID')
  return match[3]!
}

export function createCheckpointRef(
  database: DatabaseLike,
  prefixLength: number,
  revision: bigint,
  commitHash: string,
  log: readonly TransactionLogRow[],
): MaterializerCheckpointInfo {
  const digest = orderDigest(log)
  const branchRef = checkpointBranch(prefixLength, revision, digest)
  database.doltBranch(branchRef, commitHash)
  return {
    prefixLength,
    branchRef,
    doltCommitHash: commitHash,
    contentHash: database.doltHashOf(branchRef),
    createdAtRevision: revision,
  }
}

export function createRevisionRef(
  database: DatabaseLike,
  revision: bigint,
  prefixLength: number,
  commitHash: string,
  log: readonly TransactionLogRow[],
): PublishedRef {
  const digest = orderDigest(log)
  const branchRef = revisionBranch(revision, prefixLength, digest)
  database.doltBranch(branchRef, commitHash)
  return {
    revision,
    prefixLength,
    branchRef,
    doltCommitHash: commitHash,
    contentHash: database.doltHashOf(branchRef),
    orderDigest: digest,
  }
}

export function createReplayBranch(database: DatabaseLike, revision: bigint, fromRef: string): string {
  const nonce = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(6)))
  const branch = `${REPLAY_PREFIX}r${revision}_${nonce}`
  database.doltBranch(branch, fromRef)
  return branch
}

export function publishRef(database: DatabaseLike, published: PublishedRef): void {
  database.doltForceBranch(HEAD_BRANCH, published.doltCommitHash)
}

export function removeBranchIfPresent(database: DatabaseLike, branchRef: string): void {
  if (database.doltBranches().some((branch) => branch.name === branchRef)) {
    database.doltDeleteBranch(branchRef)
  }
}

export function cleanupOrphanBranches(
  database: DatabaseLike,
  published: PublishedRef,
  retainedCheckpoints: readonly MaterializerCheckpointInfo[],
): void {
  const retained = new Set([
    HEAD_BRANCH,
    published.branchRef,
    ...retainedCheckpoints.map((checkpoint) => checkpoint.branchRef),
  ])
  const active = database.doltActiveBranch()
  for (const branch of database.doltBranches()) {
    if (
      branch.name !== active &&
      !retained.has(branch.name) &&
      (branch.name.startsWith(REPLAY_PREFIX) || branch.name.startsWith(REVISION_PREFIX))
    ) {
      database.doltDeleteBranch(branch.name)
    }
  }
}

export function orderDigest(log: readonly Pick<TransactionLogRow, 'txId'>[]): string {
  const hash = createSha256()
  for (const row of log) {
    const length = new Uint8Array(4)
    new DataView(length.buffer).setUint32(0, row.txId.length, false)
    hash.update(length)
    hash.update(row.txId)
  }
  return bytesToHex(hash.digest()).slice(0, 16)
}

export function verifyPublishedLog(published: PublishedRef, log: readonly TransactionLogRow[]): void {
  if (log.length !== published.prefixLength || orderDigest(log) !== published.orderDigest) {
    throw new Error('MATERIALIZER_PUBLISHED_LOG_MISMATCH')
  }
}

function checkpointBranch(prefix: number, revision: bigint, digest: string): string {
  return `${CHECKPOINT_PREFIX}p${prefix}_r${revision}_${digest}`
}

function revisionBranch(revision: bigint, prefix: number, digest: string): string {
  return `${REVISION_PREFIX}r${revision}_p${prefix}_${digest}`
}

function parseRevisionBranch(
  branch: DoltBranchInfoLike,
): Omit<PublishedRef, 'doltCommitHash' | 'contentHash'> | null {
  const match = REVISION_PATTERN.exec(branch.name)
  if (match === null) return null
  return {
    revision: BigInt(match[1]!),
    prefixLength: safeInteger(match[2]!, 'MATERIALIZER_REVISION_PREFIX_INVALID'),
    branchRef: branch.name,
    orderDigest: match[3]!,
  }
}

function safeInteger(value: string, code: string): number {
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(code)
  return parsed
}
