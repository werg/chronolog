import { expect, it } from 'vitest'
import { win32 } from 'node:path'
import { nodeVfsFileIdentity, nodeVfsFullPath } from './node-vfs-path.js'
it('gives portable DoltLite slash-delimited drive and UNC filenames for sibling graph locks',()=>{
 for(const input of ['D:\\private space\\app.db','\\\\server\\share\\data\\app.db']){
  const name=nodeVfsFullPath(input,true)
  expect(name).not.toContain('\\')
  // The actual chunk-store csLockPath() algorithm uses strrchr(path, '/').
  const slash=name.lastIndexOf('/'),lock=name.slice(0,slash+1)+'.'+name.slice(slash+1)+'-lock'
  expect(win32.dirname(lock)).toBe(win32.dirname(name));expect(win32.basename(lock)).toBe('.app.db-lock')
  expect(win32.resolve(name)).toBe(win32.resolve(input))
 }
})
it('preserves literal backslashes on POSIX hosts',()=>{expect(nodeVfsFullPath('/data/literal\\name.db',false)).toBe('/data/literal\\name.db')})
it('shares an owner for case aliases by file identity without conflating distinct files',()=>{
 expect(nodeVfsFileIdentity('D:\\Data\\APP.db',{dev:1n,ino:2n})).toBe(nodeVfsFileIdentity('d:\\data\\app.db',{dev:1n,ino:2n}))
 expect(nodeVfsFileIdentity('D:\\data\\app.db',{dev:1n,ino:3n})).not.toBe(nodeVfsFileIdentity('D:\\Data\\APP.db',{dev:1n,ino:2n}))
})
