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
 for(const mutate of [(b:Uint8Array)=>{b[5]=128},(b:Uint8Array)=>{b[6]=2},(b:Uint8Array)=>{b[b.length-1]!^=1}]){
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
  expect(checkpoint.bytes[5]).toBe(0) // passphrase-derived key (1 = raw key)
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
