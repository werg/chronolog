import { createAuthorityProvider } from '@chronolog/authority'
import { ApplicationContent } from './content.js'
import { sessionFixture } from './test-fixture.js'

export async function contentFixture(count = 2) {
  const fixture = await sessionFixture({ count })
  const authorities = await Promise.all(fixture.stores.map(store => createAuthorityProvider({ store, bundle: fixture.bundle, epochKeys: new Map([[0, fixture.epochKey]]) })))
  const contents = fixture.stores.map((store, index) => new ApplicationContent({ store, authority: authorities[index]!, identity: fixture.identities[index]!, storageId: `storage-${index}` }))
  return { ...fixture, authorities, contents,
    reopen: (index: number) => new ApplicationContent({ store: fixture.stores[index]!, authority: authorities[index]!, identity: fixture.identities[index]!, storageId: `storage-${index}` }),
    close: () => Promise.all(contents.map(content => content.close())),
  }
}
export function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
export function payload(size: number): Uint8Array { return Uint8Array.from({ length: size }, (_, index) => index % 251) }
