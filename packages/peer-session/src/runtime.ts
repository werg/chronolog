import type { GenesisBlock } from '@chronolog/protocol'
import type { BlockchainAnchorVerifier } from '@chronolog/authority'
import type { QuickJsSandboxOptions } from '@chronolog/materializer'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import type { ApplicationDefinition } from './definition.js'
import { ApplicationSession, type SessionCasNode } from './session.js'

export interface CreateApplicationSessionOptions<D extends ApplicationDefinition = ApplicationDefinition> extends QuickJsSandboxOptions {
  readonly device: ApplicationDevice
  readonly genesis?: GenesisBlock | Uint8Array
  readonly chainId?: string
  /** Optional host-level application scope ID (defaults to `chainId`). */
  readonly applicationId?: string
  readonly casNodes?: readonly SessionCasNode[]
  readonly epochKeys?: ReadonlyMap<number, Uint8Array>
  readonly definition?: D
  readonly blindHostMode?: boolean
  readonly blockchainVerifier?: BlockchainAnchorVerifier
  readonly sqliteWasmModule?: WebAssembly.Module
  readonly sqliteWasmBytes?: Uint8Array
  readonly maxOperations?: number
}

/** Opens a Chronolog v2 local-first ApplicationSession on the claimed device. */
export async function createApplicationSession<const D extends ApplicationDefinition = ApplicationDefinition>(
  options: CreateApplicationSessionOptions<D>,
): Promise<ApplicationSession<D>> {
  const release = claimApplicationDevice(options.device)
  try {
    const storage = await options.device.openStorage()
    return await ApplicationSession.open({
      ...options,
      store: storage.store,
      async release() {
        release()
        await options.device.close()
      },
    })
  } catch (error) {
    release()
    await options.device.close()
    throw error
  }
}
