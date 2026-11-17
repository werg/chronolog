import type { ApplicationDescriptor, AuthorityBundle, PeerGrant, PeerIdentity, SignedGeneration } from '@chronolog/peer-generation/control'
import type { PeerReplica } from '@chronolog/peer-generation'
import type { ApplicationContent } from './content.js'
import type { ApplicationKeyring } from './keys.js'
import type { ApplicationRecovery } from './recovery.js'

/** The single durable facet attached to an already authenticated participant. */
export interface ApplicationDataPort {
  readonly replica: PeerReplica
  readonly keys: ApplicationKeyring
  readonly content: ApplicationContent
  readonly recovery: ApplicationRecovery
}

/** Protocol metadata and membership never require a local database. */
export interface ApplicationParticipant {
  readonly device: PeerIdentity
  readonly storageId: string
  readonly descriptor: ApplicationDescriptor
  readonly authority: AuthorityBundle
  readonly generation: SignedGeneration
  readonly isCoordinator: boolean
  grant(publicKey: string): PeerGrant | null
  adoptAuthority(authority: AuthorityBundle): Promise<void>
  subscribe(listener: () => void): () => void
  readonly data: ApplicationDataPort | undefined
  openData(): Promise<ApplicationDataPort>
}
