import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { NativeBytesStore } from './native.js'
it('atomically initializes a fresh native store and accounts for its quota',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'chronolog-atomic-'))
 const store=await NativeBytesStore.open(join(dir,'device.sqlite'),{quotaBytes:4,maxValueBytes:4})
 try{
  expect(await store.putAllIfEmpty([{key:'a',value:new Uint8Array([1,2])},{key:'b',value:new Uint8Array([3])}])).toBe(true)
  expect(store.usageBytes()).toBe(3)
  expect(await store.putAllIfEmpty([{key:'a',value:new Uint8Array([9])}])).toBe(false)
  expect(await store.get('a')).toEqual(new Uint8Array([1,2]))
  await expect(store.put('c',new Uint8Array([5,6]))).rejects.toThrow('QUOTA')
 }finally{await store.close();rmSync(dir,{recursive:true,force:true})}
})
it('invalid or over-quota restore writes leave native identity entirely absent',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'chronolog-atomic-')),store=await NativeBytesStore.open(join(dir,'device.sqlite'),{quotaBytes:2,maxValueBytes:2})
 try{
  await expect(store.putAllIfEmpty([{key:'identity',value:new Uint8Array([1,2])},{key:'binding',value:new Uint8Array([3])}])).rejects.toThrow('QUOTA')
  expect(await store.entries()).toEqual([])
  await expect(store.putAllIfEmpty([{key:'identity',value:new Uint8Array([1])},{key:'identity',value:new Uint8Array([2])}])).rejects.toThrow('DUPLICATE')
  expect(await store.entries()).toEqual([])
 }finally{await store.close();rmSync(dir,{recursive:true,force:true})}
})
