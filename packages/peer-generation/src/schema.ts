import { DOMAINS, decodeChangeProgram, type ChangeProgram } from '@chronolog/protocol'
import { check, hex, hexToBytes, object, peerDigest, signPeerValue, verifyPeerValue } from './codec.js'
import type { ApplicationDescriptor, ApplicationSchema, PeerIdentity, SignedApplicationSchema } from './control-types.js'

function validateSchema(value: ApplicationSchema): void {
  object(value, ['applicationId', 'definitionDigest', 'executionManifestDigest', 'program'])
  hex(value.applicationId); hex(value.definitionDigest); hex(value.executionManifestDigest)
  check(typeof value.program === 'string' && value.program.length <= 2 * 262_144 && /^(?:[0-9a-f]{2})+$/u.test(value.program), 'PEER_SCHEMA_PROGRAM_INVALID')
  decodeChangeProgram(hexToBytes(value.program))
}
export async function signApplicationSchema(payload: ApplicationSchema, signer: PeerIdentity): Promise<SignedApplicationSchema> {
  validateSchema(payload); return signPeerValue(DOMAINS.peerSchema, payload, signer)
}
/** A trusted schema authority signs genesis state, independently of the control host. */
export async function verifyApplicationSchema(schema: SignedApplicationSchema, descriptor: ApplicationDescriptor): Promise<ChangeProgram> {
  validateSchema(schema.payload)
  check(schema.payload.applicationId === descriptor.applicationId && schema.payload.definitionDigest === descriptor.definitionDigest &&
    schema.payload.executionManifestDigest === descriptor.executionManifestDigest && descriptor.schemaDigest === await peerDigest(schema), 'PEER_SCHEMA_BINDING_MISMATCH')
  await verifyPeerValue(DOMAINS.peerSchema, schema, descriptor.schemaAdministrator)
  return decodeChangeProgram(hexToBytes(schema.payload.program))
}
