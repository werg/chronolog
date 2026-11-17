import { APPLICATION_COLLECTIVE_ID, bytesToHex, equalBytes } from '@chronolog/protocol'
import type { PeerExecutionControl, PeerExecutionControls, ReplayProposal } from '@chronolog/materializer'
import type { DatabaseLike } from './types.js'

/** These are already authenticated by the shared authority verifier, never by SQL callbacks. */
export function validatePeerExecutionControls(context: PeerExecutionControls | undefined, transactions: readonly ReplayProposal[]): PeerExecutionControls {
  if (context === undefined || context.applicationId.length !== 32 || !Number.isSafeInteger(context.currentRevision) ||
      context.currentRevision < 0 || context.revisions.length !== context.currentRevision + 1 || context.revisions.length > 4096) throw new Error('MATERIALIZER_PEER_CONTROLS_REQUIRED')
  const digests = new Set<string>()
  for (const [index, control] of context.revisions.entries()) {
    if (control.revision !== index || control.digest.length !== 32 || control.members.length > 1024) throw new Error('MATERIALIZER_PEER_CONTROLS_INVALID')
    const digest = bytesToHex(control.digest)
    if (digests.has(digest)) throw new Error('MATERIALIZER_PEER_CONTROLS_INVALID')
    digests.add(digest)
    const members = new Set<string>()
    for (const member of control.members) {
      const key = bytesToHex(member.publicKey)
      if (member.publicKey.length !== 32 || members.has(key) || (member.role !== 'member' && member.role !== 'admin')) throw new Error('MATERIALIZER_PEER_CONTROLS_INVALID')
      members.add(key)
    }
  }
  for (const transaction of transactions) if (!equalBytes(transaction.core.groupId, context.applicationId) ||
      !digests.has(bytesToHex(transaction.core.membershipRevision))) throw new Error('MATERIALIZER_PEER_CONTROL_MISMATCH')
  return structuredClone(context)
}

export function peerControlFor(context: PeerExecutionControls, transaction: ReplayProposal): PeerExecutionControl {
  const result = context.revisions.find(control => equalBytes(control.digest, transaction.core.membershipRevision))
  if (result === undefined) throw new Error('MATERIALIZER_PEER_CONTROL_MISMATCH')
  return result
}
export function hasCurrentPeerControl(database: DatabaseLike, context: PeerExecutionControls): boolean {
  const row = database.prepare('SELECT application_id, digest FROM chronolog_peer_control WHERE singleton = 1').get()
  return row !== undefined && !Array.isArray(row) && row.application_id instanceof Uint8Array && row.digest instanceof Uint8Array &&
    equalBytes(row.application_id, context.applicationId) && equalBytes(row.digest, context.revisions[context.currentRevision]!.digest)
}

/** Once controls own application permissions, replay cannot silently omit that projection. */
export function hasPeerExecutionControl(database: DatabaseLike): boolean {
  return database.prepare('SELECT 1 FROM chronolog_peer_control WHERE singleton = 1').get() !== undefined
}

/**
 * Applies only the reserved application collective. Inherited commands replay
 * under historical controls inside a private candidate. Before publication the
 * latest control is reapplied, so application-tail rollback cannot revive rights.
 * These writes carry a control digest, not a fabricated device-authored command.
 */
export function applyPeerExecutionControl(database: DatabaseLike, applicationId: Uint8Array, control: PeerExecutionControl): void {
  const previous = database.prepare('SELECT application_id, digest FROM chronolog_peer_control WHERE singleton = 1').get()
  if (previous !== undefined) {
    if (Array.isArray(previous) || !(previous.application_id instanceof Uint8Array) || !equalBytes(previous.application_id, applicationId)) throw new Error('DATABASE_PEER_APPLICATION_MISMATCH')
    if (previous.digest instanceof Uint8Array && equalBytes(previous.digest, control.digest)) return
  }
  database.prepare('INSERT OR IGNORE INTO chronolog_principals (key) VALUES (?)').run(APPLICATION_COLLECTIVE_ID)
  database.prepare(`INSERT OR IGNORE INTO chronolog_collectives
    (collective_id, kind, insert_role, update_role, delete_role, created_tx)
    VALUES (?, 'team', 'member', 'member', 'member', ?)`).run(APPLICATION_COLLECTIVE_ID, control.digest)
  database.prepare(`UPDATE chronolog_collective_members SET state = 'left', left_tx = ? WHERE collective_id = ?`).run(control.digest, APPLICATION_COLLECTIVE_ID)
  for (const member of [...control.members].sort((a, b) => bytesToHex(a.publicKey).localeCompare(bytesToHex(b.publicKey)))) {
    database.prepare(`INSERT INTO chronolog_collective_members (collective_id, member_key, role, state, joined_tx, left_tx)
      VALUES (?, ?, ?, 'active', ?, NULL)
      ON CONFLICT (collective_id, member_key) DO UPDATE SET role = excluded.role, state = 'active', left_tx = NULL`).run(
      APPLICATION_COLLECTIVE_ID, member.publicKey, member.role, control.digest)
  }
  database.prepare(`INSERT INTO chronolog_peer_control (singleton, application_id, revision, digest) VALUES (1, ?, ?, ?)
    ON CONFLICT (singleton) DO UPDATE SET revision = excluded.revision, digest = excluded.digest`).run(applicationId, control.revision, control.digest)
}
