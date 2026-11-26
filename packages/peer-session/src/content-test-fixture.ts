import { ApplicationContent, type ContentAuthority } from './content.js'
import { sessionFixture } from './test-fixture.js'

export async function contentFixture(count = 2) {
  const fixture = await sessionFixture({ count })
  const readers = new Set(fixture.identities.map(i => i.publicKey))
  const authorities: ContentAuthority[] = fixture.identities.map(() => ({
    applicationId: fixture.applicationId,
    isReader: (pk: string) => readers.has(pk),
    currentEpoch: () => 0,
    epochKey: (epoch: number) => (epoch === 0 ? fixture.epochKey : null),
  }))
  const contents = fixture.stores.map((store, index) => new ApplicationContent({
    store,
    authority: authorities[index]!,
    identity: fixture.identities[index]!,
    storageId: `storage-${index}`,
  }))
  return {
    ...fixture,
    readers,
    authorities,
    contents,
    reopen: (index: number) => new ApplicationContent({
      store: fixture.stores[index]!,
      authority: authorities[index]!,
      identity: fixture.identities[index]!,
      storageId: `storage-${index}`,
    }),
    close: () => Promise.all(contents.map(content => content.close())),
  }
}

export function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

export function payload(size: number): Uint8Array {
  return Uint8Array.from({ length: size }, (_, index) => index % 251)
}
