import { APPLICATION_COLLECTIVE_ID, bytesToHex, compareBytes, equalBytes } from '@chronolog/protocol'
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

/** Recovery can change proposals, but cannot roll back already observed membership authority. */
export function assertPeerControlAdvance(database: DatabaseLike, context: PeerExecutionControls): void {
  const row = database.prepare('SELECT application_id, revision, digest FROM chronolog_peer_control WHERE singleton = 1').get()
  if (row === undefined) return
  if (Array.isArray(row) || !(row.application_id instanceof Uint8Array) || !(row.digest instanceof Uint8Array) ||
      !equalBytes(row.application_id, context.applicationId)) throw new Error('DATABASE_PEER_APPLICATION_MISMATCH')
  const revision = Number(row.revision)
  if (!Number.isSafeInteger(revision) || revision < 0 || revision > context.currentRevision ||
      !equalBytes(row.digest, context.revisions[revision]!.digest)) throw new Error('MATERIALIZER_PEER_CONTROL_REGRESSION')
}

/**
 * Applies only the reserved application collective. Inherited commands replay
 * under historical controls inside a private candidate. Before publication the
 * latest control is reapplied, so application-tail rollback cannot revive rights.
 * These writes carry a control digest, not a fabricated device-authored command.
 */
export function applyPeerExecutionControl(database: DatabaseLike, context: PeerExecutionControls, control: PeerExecutionControl): void {
  const { applicationId } = context
  const previous = database.prepare('SELECT application_id, digest FROM chronolog_peer_control WHERE singleton = 1').get()
  if (previous !== undefined) {
    if (Array.isArray(previous) || !(previous.application_id instanceof Uint8Array) || !equalBytes(previous.application_id, applicationId)) throw new Error('DATABASE_PEER_APPLICATION_MISMATCH')
    if (previous.digest instanceof Uint8Array && equalBytes(previous.digest, control.digest)) return
  }
  database.prepare('INSERT OR IGNORE INTO chronolog_principals (key) VALUES (?)').run(APPLICATION_COLLECTIVE_ID)
  database.prepare(`INSERT INTO chronolog_collectives
    (collective_id, kind, insert_role, update_role, delete_role, created_tx)
    VALUES (?, 'team', 'member', 'member', 'member', ?)
    ON CONFLICT (collective_id) DO UPDATE SET kind = 'team', insert_role = 'member',
      update_role = 'member', delete_role = 'member', created_tx = excluded.created_tx`).run(APPLICATION_COLLECTIVE_ID, context.revisions[0]!.digest)
  // Project the exact historical prefix. Updating only current rows would leave
  // future members or path-dependent join/leave metadata in a replay checkpoint.
  // The reserved collective's principal identity and all other collectives stay intact.
  database.prepare('DELETE FROM chronolog_collective_members WHERE collective_id = ?').run(APPLICATION_COLLECTIVE_ID)
  for (const member of membershipAt(context, control.revision)) {
    database.prepare(`INSERT INTO chronolog_collective_members (collective_id, member_key, role, state, joined_tx, left_tx)
      VALUES (?, ?, ?, ?, ?, ?)`).run(
      APPLICATION_COLLECTIVE_ID, member.publicKey, member.role, member.state, member.joined, member.left)
  }
  database.prepare(`INSERT INTO chronolog_peer_control (singleton, application_id, revision, digest) VALUES (1, ?, ?, ?)
    ON CONFLICT (singleton) DO UPDATE SET revision = excluded.revision, digest = excluded.digest`).run(applicationId, control.revision, control.digest)
}

interface Membership {
  readonly publicKey: Uint8Array
  readonly role: 'member' | 'admin'
  readonly state: 'active' | 'left'
  readonly joined: Uint8Array
  readonly left: Uint8Array | null
}

function membershipAt(context: PeerExecutionControls, revision: number): readonly Membership[] {
  const memberships = new Map<string, Membership>()
  for (const control of context.revisions.slice(0, revision + 1)) {
    const active = new Set(control.members.map(member => bytesToHex(member.publicKey)))
    for (const [key, previous] of memberships) {
      if (previous.state === 'active' && !active.has(key)) {
        memberships.set(key, { ...previous, state: 'left', left: control.digest })
      }
    }
    for (const member of control.members) {
      const key = bytesToHex(member.publicKey), previous = memberships.get(key)
      memberships.set(key, { ...member, state: 'active',
        joined: previous?.state === 'active' ? previous.joined : control.digest, left: null })
    }
  }
  return [...memberships.values()].sort((a, b) => compareBytes(a.publicKey, b.publicKey))
}
