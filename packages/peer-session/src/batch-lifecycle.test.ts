import { expect, it, vi } from 'vitest'
import { createAppClient, submitBatch, type ErgonomicSession } from './ergonomics.js'
function deferred<T>() { let resolve!: (v:T)=>void; const promise=new Promise<T>(yes=>{resolve=yes}); return {promise,resolve} }
function fixture() {
 const state={status:'saved' as const,operationId:'op',attemptId:'a',generation:'generation'}
 const get=vi.fn(async()=>state),command=vi.fn(async()=>({get,applied:async()=>{throw Error('offline')}}))
 const session:ErgonomicSession={applicationId:'app',deviceId:'device',query:async()=>{throw Error('unused')},command,operations:{get,inspect:async()=>null}}
 return {session,state,get,command}
}
it('preserves uncertain saved state after a command call fails instead of declaring rejection',async()=>{
 const f=fixture();f.command.mockImplementation(async()=>{throw Error('lost reply')})
 const [result]=await submitBatch(f.session,[{operationId:'op',command:'write',input:null}])
 expect(result).toMatchObject({lifecycle:'recorded',state:f.state,error:{code:'OPERATION_OUTCOME_UNKNOWN'}})
})
it('does not transmit after a cancelled pre-submission persistence hook, or mutate the retained intent',async()=>{
 const f=fixture(),gate=deferred<void>(),started=deferred<void>(),stop=new AbortController()
 const entry={operationId:'op',command:'write',input:{text:'original'}}
 const task=submitBatch(f.session,[entry],{signal:stop.signal,beforeSubmit:async saved=>{started.resolve();(saved.input as {text:string}).text='mutated';await gate.promise}})
 const rejected=expect(task).rejects.toThrow('cancel');await started.promise;stop.abort(Error('cancel'));await rejected;gate.resolve();await Promise.resolve()
 expect(f.command).not.toHaveBeenCalled();expect(entry.input.text).toBe('original')
})
it('does not infer transmission from a saved handle and accepts protocol-sized IDs',async()=>{
 const f=fixture(),operationId='x'.repeat(512);f.state.operationId=operationId
 expect((await submitBatch(f.session,[{operationId,command:'write',input:null}],{wait:'recorded'}))[0]?.lifecycle).toBe('recorded')
})
it('client close is idempotent and fences an in-flight persistence hook before transmission',async()=>{
 const f=fixture(),gate=deferred<void>(),started=deferred<void>(),close=vi.fn()
 const client=createAppClient(f.session,{beforeSubmit:async()=>{started.resolve();await gate.promise},close})
 const task=client.submitCommand({operationId:'op',command:'write',input:null});const rejected=expect(task).rejects.toThrow('APPLICATION_CLIENT_CLOSED')
 await started.promise;const first=client.close();expect(client.close()).toBe(first);await first;await rejected;gate.resolve();await Promise.resolve()
 expect(f.command).not.toHaveBeenCalled();expect(close).toHaveBeenCalledOnce();await expect(client.query('q')).rejects.toThrow('APPLICATION_CLIENT_CLOSED')
})
