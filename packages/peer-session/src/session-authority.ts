import { assertAuthorityExtension, decodePeerValue, encodePeerValue, verifyAuthorityBundle,
  type AuthorityBundle, type PeerAuthority } from '@chronolog/peer-generation/control'
import type { ApplicationDevice } from './device.js'
import { updateDeviceMetadata } from './metadata.js'

/** All protocol lifetimes share one monotonic signed authority anchor. */
export async function retainApplicationAuthority(device: ApplicationDevice, input: AuthorityBundle): Promise<PeerAuthority> {
  const proposed = await verifyAuthorityBundle(input)
  const bytes = await updateDeviceMetadata(device.store, `peer-session/authority/${proposed.descriptor.applicationId}`, async current => {
    if (current === null) return encodePeerValue(proposed.bundle)
    const previous = await verifyAuthorityBundle(decodePeerValue<AuthorityBundle>(current), proposed.bundle.descriptor)
    const [older, newer] = previous.bundle.generations.length <= proposed.bundle.generations.length &&
      previous.bundle.controls.length <= proposed.bundle.controls.length ? [previous, proposed] : [proposed, previous]
    assertAuthorityExtension(older, newer)
    return encodePeerValue(newer.bundle)
  })
  return verifyAuthorityBundle(decodePeerValue<AuthorityBundle>(bytes), proposed.bundle.descriptor)
}
