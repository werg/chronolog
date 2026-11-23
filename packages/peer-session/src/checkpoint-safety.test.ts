import { expect, it, vi } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { exportDeviceCheckpoint, restoreDeviceCheckpoint, isDeviceRetired, generateCheckpointKey } from './checkpoint.js'
import { openApplicationDevice, claimApplicationDevice } from './device.js'
function deferred<T>() {let resolve!:(value:T)=>void;const promise=new Promise<T>(yes=>{resolve=yes});return {resolve,promise}}
it('persists before retirement; persistence failure leaves the original identity usable',async()=>{
 const store=new MemoryBytesStore(),device=await openApplicationDevice({store,create:true}),original=Error('disk full')
 await expect(exportDeviceCheckpoint(store,{secret:generateCheckpointKey()})).rejects.toMatchObject({code:'CHECKPOINT_PERSISTENCE_REQUIRED'})
 await expect(exportDeviceCheckpoint(store,{secret:generateCheckpointKey(),persist:async()=>{expect((await isDeviceRetired(store)).retired).toBe(false);throw original}})).rejects.toBe(original)
 expect((await isDeviceRetired(store)).retired).toBe(false);expect((await openApplicationDevice({store})).identity.publicKey).toBe(device.identity.publicKey)
})
it('fences a live session and new device claims throughout persistence and after retirement',async()=>{
 const store=new MemoryBytesStore(),device=await openApplicationDevice({store,create:true}),release=claimApplicationDevice(device),persist=vi.fn()
 await expect(exportDeviceCheckpoint(store,{secret:generateCheckpointKey(),persist})).rejects.toMatchObject({code:'CHECKPOINT_SOURCE_IN_USE'});release()
 const gate=deferred<void>(),started=deferred<void>()
 const task=exportDeviceCheckpoint(store,{secret:generateCheckpointKey(),persist:async()=>{started.resolve();await gate.promise}})
 await started.promise;expect(()=>claimApplicationDevice(device)).toThrow('CHECKPOINT_SOURCE_IN_USE');gate.resolve();await task
 expect(()=>claimApplicationDevice(device)).toThrow('DEVICE_RETIRED_BY_CHECKPOINT');expect(persist).not.toHaveBeenCalled()
})
it('atomically refuses nonempty targets and unsupported storage without changing retained identity',async()=>{
 const source=new MemoryBytesStore(),secret=generateCheckpointKey();await source.put('identity',new Uint8Array([1]))
 const cp=await exportDeviceCheckpoint(source,{secret,retireSource:false}),target=new MemoryBytesStore();await target.put('identity',new Uint8Array([9]))
 await expect(restoreDeviceCheckpoint(target,cp.bytes,{secret})).rejects.toMatchObject({code:'CHECKPOINT_TARGET_NOT_EMPTY'})
 expect(await target.get('identity')).toEqual(new Uint8Array([9]));const put=vi.fn()
 await expect(restoreDeviceCheckpoint({get:async()=>null,put},cp.bytes,{secret})).rejects.toMatchObject({code:'CHECKPOINT_RESTORE_UNSUPPORTED'});expect(put).not.toHaveBeenCalled()
})
it('sorts readback independently of adapter iteration order',async()=>{
 const source=new MemoryBytesStore(),secret=generateCheckpointKey();await source.put('z',new Uint8Array([1]));await source.put('a',new Uint8Array([2]))
 const cp=await exportDeviceCheckpoint(source,{secret,retireSource:false}),target=new MemoryBytesStore(),entries=target.entries.bind(target)
 target.entries=async()=>[...await entries()].reverse();await expect(restoreDeviceCheckpoint(target,cp.bytes,{secret})).resolves.toMatchObject({restoredEntries:2})
})
it('invalid headers and ciphertext cannot write the target',async()=>{
 const source=new MemoryBytesStore(),secret=generateCheckpointKey(),cp=await exportDeviceCheckpoint(source,{secret,retireSource:false})
 for(const mutate of [(b:Uint8Array)=>{b[5]=128},(b:Uint8Array)=>{b[6]=1},(b:Uint8Array)=>{b[b.length-1]!^=1}]){
  const bytes=cp.bytes.slice();mutate(bytes);const target=new MemoryBytesStore();await expect(restoreDeviceCheckpoint(target,bytes,{secret})).rejects.toBeInstanceOf(Error);expect(await target.entries()).toEqual([])
 }
})

it('refuses an unrestorable source key before persisting or retiring it',async()=>{
 const source=new MemoryBytesStore(),persist=vi.fn();await source.put('',new Uint8Array([1]))
 await expect(exportDeviceCheckpoint(source,{secret:generateCheckpointKey(),persist})).rejects.toMatchObject({code:'CHECKPOINT_CORRUPT'})
 expect(persist).not.toHaveBeenCalled();expect((await isDeviceRetired(source)).retired).toBe(false)
})

it('keeps the source usable when the durable retirement marker cannot be written', async () => {
  const store = new MemoryBytesStore(), device = await openApplicationDevice({ store, create: true })
  const put = store.put.bind(store), original = Error('retirement I/O failure')
  store.put = async (key, value) => {
    if (key === 'peer-session/checkpoint-retired/v1') throw original
    await put(key, value)
  }
  await expect(exportDeviceCheckpoint(store, { secret: generateCheckpointKey(), persist: () => undefined })).rejects.toBe(original)
  expect((await isDeviceRetired(store)).retired).toBe(false)
  const release = claimApplicationDevice(device)
  release()
  store.put = put
  await expect(exportDeviceCheckpoint(store, { secret: generateCheckpointKey(), persist: () => undefined })).resolves.toMatchObject({ retiredSource: true })
})

it('round-trips a store exceeding both old checkpoint entry and raw-byte limits', async () => {
  const store = new MemoryBytesStore(), secret = generateCheckpointKey()
  for (let index = 0; index < 4500; index++) await store.put(`record/${index}`, Uint8Array.of(index % 256))
  const body = new Uint8Array(17 * 1024 * 1024).fill(42)
  await store.put('content', body)
  const checkpoint = await exportDeviceCheckpoint(store, { secret, retireSource: false }), target = new MemoryBytesStore()
  expect((await restoreDeviceCheckpoint(target, checkpoint.bytes, { secret })).restoredEntries).toBe(4501)
  const restored = await target.get('content')
  expect(restored?.length).toBe(body.length)
  expect(restored?.every(byte => byte === 42)).toBe(true)
})

it('authenticates bounded passphrase KDF parameters and rejects wrong passphrases', async () => {
  const store = new MemoryBytesStore(), secret = 'a sufficiently long passphrase'
  await store.put('key', Uint8Array.of(7))
  const checkpoint = await exportDeviceCheckpoint(store, { secret, retireSource: false })
  expect(checkpoint.bytes[5]).toBe(2)
  expect(checkpoint.bytes[6]).toBe(1)
  expect(new DataView(checkpoint.bytes.buffer).getUint32(7)).toBe(600_000)
  const target = new MemoryBytesStore()
  await restoreDeviceCheckpoint(target, checkpoint.bytes, { secret })
  expect(await target.get('key')).toEqual(Uint8Array.of(7))
  await expect(restoreDeviceCheckpoint(new MemoryBytesStore(), checkpoint.bytes, { secret: 'a different long passphrase' })).rejects.toMatchObject({ code: 'CHECKPOINT_DECRYPT_FAILED' })
  const altered = checkpoint.bytes.slice()
  new DataView(altered.buffer).setUint32(7, 600_001)
  await expect(restoreDeviceCheckpoint(new MemoryBytesStore(), altered, { secret })).rejects.toMatchObject({ code: 'CHECKPOINT_DECRYPT_FAILED' })
  new DataView(altered.buffer).setUint32(7, 0xffff_ffff)
  await expect(restoreDeviceCheckpoint(new MemoryBytesStore(), altered, { secret })).rejects.toMatchObject({ code: 'CHECKPOINT_CORRUPT' })
})

it('restores legacy passphrase checkpoints with the original PBKDF2 work factor', async () => {
  const store = new MemoryBytesStore(), raw = generateCheckpointKey(), secret = 'legacy passphrase secret'
  await store.put('legacy', Uint8Array.of(9))
  const checkpoint = await exportDeviceCheckpoint(store, { secret: raw, retireSource: false })
  const aad = new TextEncoder().encode('chronolog-device-checkpoint-v1')
  const rawKey = await crypto.subtle.importKey('raw', new Uint8Array(raw), 'AES-GCM', false, ['decrypt'])
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: checkpoint.bytes.slice(22, 34), additionalData: aad }, rawKey, checkpoint.bytes.slice(34))
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12))
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext))
  const legacy = new Uint8Array(34 + ciphertext.length)
  legacy.set(checkpoint.bytes.slice(0, 5)); legacy[5] = 0
  legacy.set(salt, 6); legacy.set(iv, 22); legacy.set(ciphertext, 34)
  const target = new MemoryBytesStore()
  await restoreDeviceCheckpoint(target, legacy, { secret })
  expect(await target.get('legacy')).toEqual(Uint8Array.of(9))
})
