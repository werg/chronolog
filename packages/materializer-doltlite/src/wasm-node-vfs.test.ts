import { mkdtempSync, readdirSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { installNodeFsVfs, writeFileAtomicSync, type NodeChronologWasmModule } from './wasm-node.js'
function fixture() {
 const heap=new Uint8Array(1024*1024),view=new DataView(heap.buffer),encoder=new TextEncoder();let next=128
 const allocate=(size=64)=>{const p=next;next+=size;return p}
 const string=(value:string)=>{const bytes=encoder.encode(value),p=allocate(bytes.length+1);heap.set(bytes,p);return p}
 class Struct {static structInfo={sizeof:32};pointer=allocate();$iVersion=0;$szOsFile=0;$mxPathname=0;$zName=0;installMethods(){};dispose(){}}
 let io:Record<string,(...args:number[])=>number>,vfs:typeof io
 const module={capi:{sqlite3_vfs:Struct,sqlite3_io_methods:Struct,sqlite3_file:Struct},wasm:{
  allocCString:string,cstrToJs:(p:number)=>new TextDecoder().decode(heap.subarray(p,heap.indexOf(0,p))),
  heap8u:()=>heap,poke32:(p:number,v:number)=>view.setInt32(p,v,true),pokePtr:(p:number,v:number)=>view.setInt32(p,v,true),
  poke64:(p:number,v:bigint)=>view.setBigInt64(p,v,true),poke:()=>{},peek8:(p:number)=>heap[p],
 },vfs:{installVfs(options:{io:{methods:typeof io};vfs:{methods:typeof vfs}}){io=options.io.methods;vfs=options.vfs.methods}}} as unknown as NodeChronologWasmModule
 installNodeFsVfs(module)
 const open=(path:string)=>{const p=allocate();return {p,rc:vfs.xOpen!(0,string(path),p,0x106,0)}}
 return {module,open,get io(){return io},get vfs(){return vfs},allocate,view}
}
it('fences independent WASM modules until the last connection releases ownership',()=>{
 const dir=mkdtempSync(join(tmpdir(),'chronolog-vfs-')),a=fixture(),b=fixture(),path=join(dir,'app.db')
 try{
  const left=a.open(path),sibling=a.open(path);expect(left.rc).toBe(0);expect(sibling.rc).toBe(0)
  expect(b.open(path).rc).toBe(14)
  a.io.xClose!(left.p);expect(b.open(path).rc).toBe(14)
  a.io.xClose!(sibling.p);const winner=b.open(path);expect(winner.rc).toBe(0);b.io.xClose!(winner.p)
  expect(readdirSync(dir)).toEqual(['app.db'])
 }finally{rmSync(dir,{recursive:true,force:true})}
})
it('implements shared/reserved/pending/exclusive locks and reserved-lock observation',()=>{
 const dir=mkdtempSync(join(tmpdir(),'chronolog-vfs-')),f=fixture(),path=join(dir,'app.db')
 const a=f.open(path),b=f.open(path),out=f.allocate()
 try{
  expect(f.io.xLock!(a.p,1)).toBe(0);expect(f.io.xLock!(b.p,1)).toBe(0)
  expect(f.io.xLock!(a.p,2)).toBe(0);expect(f.io.xCheckReservedLock!(b.p,out)).toBe(0);expect(f.view.getInt32(out,true)).toBe(1)
  expect(f.io.xLock!(b.p,2)).toBe(5);expect(f.io.xLock!(a.p,4)).toBe(5)
  const c=f.open(path);expect(f.io.xLock!(c.p,1)).toBe(5);f.io.xClose!(c.p)
  expect(f.io.xUnlock!(b.p,0)).toBe(0);expect(f.io.xLock!(a.p,4)).toBe(0)
  f.io.xUnlock!(a.p,0);f.io.xCheckReservedLock!(b.p,out);expect(f.view.getInt32(out,true)).toBe(0)
 }finally{f.io.xClose!(a.p);f.io.xClose!(b.p);rmSync(dir,{recursive:true,force:true})}
})
it('removes a staged atomic file after rename failure',()=>{
 const dir=mkdtempSync(join(tmpdir(),'chronolog-vfs-')),target=join(dir,'target');mkdirSync(target)
 try{expect(()=>writeFileAtomicSync(target,new Uint8Array([1]))).toThrow();expect(readdirSync(dir)).toEqual(['target'])}
 finally{rmSync(dir,{recursive:true,force:true})}
})
