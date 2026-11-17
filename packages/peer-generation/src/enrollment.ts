import { DOMAINS } from '@chronolog/protocol'
import { check, hex, object, peerDigest, signPeerValue, uint, verifyPeerValue } from './codec.js'
import { PEER_GENERATION_PROFILE, type ApplicationDescriptor, type PeerIdentity, type Signed } from './control-types.js'
import type { PeerAuthority } from './control.js'

/** The device proves which encryption key belongs to its authenticated signer. */
export interface ApplicationRecipient {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly publicKey: string
  readonly encryptionKey: string
}
export type SignedApplicationRecipient = Signed<ApplicationRecipient>

/** Opaque to the host. Authority is the signed control, never possession of a URL. */
export interface EpochKeyPackage {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly controlRevision: number
  readonly controlDigest: string
  readonly epoch: number
  readonly keyDigest: string
  readonly sender: string
  readonly recipient: SignedApplicationRecipient
  readonly encapsulatedKey: string
  readonly ciphertext: string
}
export type SignedEpochKeyPackage = Signed<EpochKeyPackage>
export type EpochKeyContext = Omit<EpochKeyPackage, 'encapsulatedKey' | 'ciphertext'>

function recipientFields(value: ApplicationRecipient): void {
  object(value, ['applicationId', 'profile', 'publicKey', 'encryptionKey'])
  hex(value.applicationId); hex(value.publicKey); hex(value.encryptionKey)
  check(value.profile === PEER_GENERATION_PROFILE, 'PEER_SCOPE_MISMATCH')
}
export async function signApplicationRecipient(value: ApplicationRecipient, identity: PeerIdentity): Promise<SignedApplicationRecipient> {
  recipientFields(value)
  check(value.publicKey === identity.publicKey, 'PEER_RECIPIENT_KEY_MISMATCH')
  return signPeerValue(DOMAINS.peerDeviceEnrollment, value, identity)
}
export async function verifyApplicationRecipient(value: SignedApplicationRecipient, descriptor: ApplicationDescriptor): Promise<void> {
  object(value, ['payload', 'signature'])
  recipientFields(value.payload)
  check(value.payload.applicationId === descriptor.applicationId, 'PEER_SCOPE_MISMATCH')
  await verifyPeerValue(DOMAINS.peerDeviceEnrollment, value, value.payload.publicKey)
}

/** Exact HPKE info and AAD. Both the intended recipient and authorization are bound. */
export function epochKeyContext(value: EpochKeyPackage): EpochKeyContext {
  const { applicationId, profile, controlRevision, controlDigest, epoch, keyDigest, sender, recipient } = value
  return { applicationId, profile, controlRevision, controlDigest, epoch, keyDigest, sender, recipient }
}
function packageFields(value: EpochKeyPackage): void {
  object(value, ['applicationId', 'profile', 'controlRevision', 'controlDigest', 'epoch', 'keyDigest', 'sender', 'recipient', 'encapsulatedKey', 'ciphertext'])
  hex(value.applicationId); uint(value.controlRevision); hex(value.controlDigest); uint(value.epoch)
  hex(value.keyDigest); hex(value.sender); hex(value.encapsulatedKey); hex(value.ciphertext, 48)
  check(value.profile === PEER_GENERATION_PROFILE, 'PEER_SCOPE_MISMATCH')
  object(value.recipient, ['payload', 'signature']); hex(value.recipient.signature, 64)
  recipientFields(value.recipient.payload)
}
export async function signEpochKeyPackage(value: EpochKeyPackage, identity: PeerIdentity): Promise<SignedEpochKeyPackage> {
  packageFields(value)
  check(value.sender === identity.publicKey, 'PEER_KEY_SENDER_MISMATCH')
  return signPeerValue(DOMAINS.peerKeyPackage, value, identity)
}
export async function verifyEpochKeyPackage(value: SignedEpochKeyPackage, authority: PeerAuthority): Promise<void> {
  object(value, ['payload', 'signature'])
  packageFields(value.payload)
  const payload = value.payload, control = authority.controlAt(payload.controlRevision)
  check(payload.applicationId === authority.descriptor.applicationId, 'PEER_SCOPE_MISMATCH')
  check(payload.controlDigest === await peerDigest(control), 'PEER_KEY_CONTROL_MISMATCH')
  const sender = authority.grant(payload.sender, payload.controlRevision)
  check(sender?.reader === true && sender.administrator, 'PEER_KEY_SENDER_FORBIDDEN')
  const recipient = payload.recipient.payload.publicKey
  check(authority.grant(recipient, payload.controlRevision)?.reader === true && authority.grant(recipient)?.reader === true, 'PEER_KEY_RECIPIENT_FORBIDDEN')
  check(authority.bundle.controls.slice(0, payload.controlRevision + 1).some(entry =>
    entry.payload.epoch === payload.epoch && entry.payload.keyDigest === payload.keyDigest), 'PEER_EPOCH_KEY_MISMATCH')
  await verifyApplicationRecipient(payload.recipient, authority.descriptor)
  await verifyPeerValue(DOMAINS.peerKeyPackage, value, payload.sender)
}
