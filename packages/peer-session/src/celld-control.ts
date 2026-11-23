import {
  createGenerationRegistry, type AuthorityBundle, type PeerIdentity, type SignedApplicationDescriptor,
  type SignedControlRevision, type SignedGeneration, type SignedTransitionRequest,
} from '@chronolog/peer-generation/control'
import { CelldBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions } from '@chronolog/records/celld'
import type { ApplicationControlHost } from './recovery.js'

export interface CelldApplicationControl extends ApplicationControlHost {
  selectGeneration(request: SignedTransitionRequest, options?: {
    readonly signal?: AbortSignal
    readonly control?: SignedControlRevision
  }): Promise<SignedGeneration>
  close(): Promise<void>
}

const hostedApplications = new WeakMap<CelldBytesStorage, Set<string>>()

/** Own the current signed generation registry in a celld control object. */
export async function openCelldApplicationControl(options: {
  readonly storage: CelldBytesStorage
  readonly descriptor: SignedApplicationDescriptor
  readonly controls: readonly SignedControlRevision[]
  readonly signer: PeerIdentity
  readonly create?: true
  readonly limits?: CelldBytesStoreOptions
}): Promise<CelldApplicationControl> {
  const { storage } = options
  const descriptor = structuredClone(options.descriptor)
  const controls = structuredClone(options.controls)
  const applicationId = descriptor.payload.applicationId
  let applications = hostedApplications.get(storage)
  if (!applications) {
    applications = new Set()
    hostedApplications.set(storage, applications)
  }
  if (applications.has(applicationId)) throw new Error('CELLD_CONTROL_ALREADY_OPEN')
  const ownedApplications = applications
  ownedApplications.add(applicationId)

  let store: CelldBytesStore | undefined
  try {
    const ownedStore = new CelldBytesStore(storage, options.limits)
    store = ownedStore
    const registry = await createGenerationRegistry({
      store: ownedStore, descriptor, controls,
      signer: { ...options.signer },
      requireExisting: options.create !== true,
    })
    const pending = new Set<Promise<unknown>>()
    let closing: Promise<void> | undefined
    const run = <T>(signal: AbortSignal | undefined, operation: () => Promise<T>): Promise<T> => {
      if (closing) return Promise.reject(new Error('CELLD_CONTROL_CLOSED'))
      const task = Promise.resolve().then(async () => {
        signal?.throwIfAborted()
        const result = await operation()
        signal?.throwIfAborted()
        return result
      })
      pending.add(task)
      void task.then(() => pending.delete(task), () => pending.delete(task))
      return task
    }
    return {
      application(request = {}): Promise<AuthorityBundle> {
        return run(request.signal, () => registry.read())
      },
      selectGeneration(request, { control, signal } = {}) {
        const input = structuredClone(request)
        const revision = structuredClone(control)
        return run(signal, () => registry.select(input, revision === undefined ? undefined : { control: revision }))
      },
      close() {
        return closing ??= Promise.allSettled([...pending]).then(() => {
          ownedStore.close()
          ownedApplications.delete(applicationId)
        })
      },
    }
  } catch (error) {
    store?.close()
    ownedApplications.delete(applicationId)
    throw error
  }
}
