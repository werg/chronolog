import { existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it, vi } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
vi.mock('node:crypto',async original=>({...await original<typeof import('node:crypto')>(),randomUUID:()=>`test-failed-disposable-${process.pid}`}))
import { openDisposableNativeDevice } from './native.js'
it('cleans its managed SQL directory when storage construction fails',async()=>{
 const path=join(tmpdir(),`tendriller-disposable-test-failed-disposable-${process.pid}`)
 try{await expect(openDisposableNativeDevice({sql:true,quotaBytes:0})).rejects.toThrow('BYTES_STORE_QUOTA_INVALID');expect(existsSync(path)).toBe(false)}
 finally{rmSync(path,{recursive:true,force:true})}
})
it('enforces explicit limits for memory storage, including atomic checkpoint initialization',async()=>{
 const store=new MemoryBytesStore({quotaBytes:3,maxValueBytes:2})
 await store.put('a',new Uint8Array([1,2]));await expect(store.put('b',new Uint8Array([3,4]))).rejects.toThrow('QUOTA')
 await store.put('a',new Uint8Array([9]));await store.put('b',new Uint8Array([3,4]))
 expect(await store.get('a')).toEqual(new Uint8Array([9]))
 const fresh=new MemoryBytesStore({quotaBytes:1})
 await expect(fresh.putAllIfEmpty([{key:'a',value:new Uint8Array([1,2])}])).rejects.toThrow('QUOTA');expect(await fresh.entries()).toEqual([])
 await expect(openDisposableNativeDevice({quotaBytes:0})).rejects.toThrow('QUOTA')
})
