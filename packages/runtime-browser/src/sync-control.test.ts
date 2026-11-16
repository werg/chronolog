import { describe, expect, it } from 'vitest'
import { ControlStore } from '@chronolog/control-store/browser'
import { SyncControlPersistence, type SyncDurableFile } from './sync-control.js'

class File implements SyncDurableFile {
  durable = new Uint8Array()
  working = new Uint8Array()
  cutAfter: number | null = null
  failFlush = false
  closed = false
  getSize() { return this.working.length }
  read(output: Uint8Array, { at }: { at: number }) { const value = this.working.subarray(at, at + output.length); output.set(value); return value.length }
  write(input: Uint8Array, { at }: { at: number }) {
    const length = Math.min(input.length, this.cutAfter ?? input.length)
    const bytes = new Uint8Array(Math.max(this.working.length, at + length))
    bytes.set(this.working); bytes.set(input.subarray(0, length), at); this.working = bytes
    return length
  }
  truncate(size: number) { this.working = this.working.slice(0, size) }
  flush() { if (this.failFlush) throw new Error('disk failed'); this.durable = this.working.slice() }
  close() { this.closed = true }
  reopen({ flushTorn = false } = {}) { const next = new File(); next.durable = flushTorn ? this.working.slice() : this.durable.slice(); next.working = next.durable.slice(); return next }
}
describe('SQL-free synchronous browser control durability', () => {
  it('persists private signing cutoffs before reporting success and retains them across restart', () => {
    const file = new File(), persistence = new SyncControlPersistence(file), store = new ControlStore(persistence)
    const signer = new Uint8Array(32).fill(7)
    store.persistValidatorCutoff(signer, 10n)
    expect(file.durable.length).toBeGreaterThan(0)
    persistence.close()
    const reopened = new ControlStore(new SyncControlPersistence(file.reopen()))
    expect(reopened.validatorCutoff(signer)).toBe(10n)
    expect(() => reopened.persistValidatorCutoff(signer, 9n)).toThrow('REGRESSION')
  })
  it('poisons a failed handle and never advances the in-memory signing cutoff', () => {
    const file = new File(), persistence = new SyncControlPersistence(file), store = new ControlStore(persistence)
    const signer = new Uint8Array(32).fill(8)
    store.persistValidatorCutoff(signer, 10n)
    file.failFlush = true
    expect(() => store.persistValidatorCutoff(signer, 20n)).toThrow('disk failed')
    expect(store.validatorCutoff(signer)).toBe(10n)
    expect(() => store.persistValidatorCutoff(signer, 30n)).toThrow('REOPEN_REQUIRED')
    expect(new ControlStore(new SyncControlPersistence(file.reopen())).validatorCutoff(signer)).toBe(10n)
  })
  it('drops an interrupted trailing write and fails closed for damaged complete frames', () => {
    const file = new File(), persistence = new SyncControlPersistence(file)
    const signer = new Uint8Array(32).fill(9)
    persistence.saveValidatorCutoff({ validatorId: signer, acceptedAboveMs: 10n })
    const committed = file.durable.length
    file.cutAfter = 39
    expect(() => persistence.saveValidatorCutoff({ validatorId: signer, acceptedAboveMs: 20n })).toThrow('WRITE_INCOMPLETE')
    const torn = file.reopen({ flushTorn: true })
    const recovered = new SyncControlPersistence(torn)
    expect(torn.durable.length).toBe(committed)
    expect(recovered.loadValidatorCutoffs()[0]?.acceptedAboveMs).toBe(10n)
    const corrupt = file.reopen()
    corrupt.working[38] = corrupt.working[38]! ^ 1
    expect(() => new SyncControlPersistence(corrupt)).toThrow('FRAME_CORRUPT')
    expect(corrupt.closed).toBe(true)
  })
  it('reports quota exhaustion before damaging acknowledged state', () => {
    const file = new File(), persistence = new SyncControlPersistence(file, { maxBytes: 1024 })
    for (let i = 0; i < 8; i++) persistence.saveValidatorCutoff({ validatorId: new Uint8Array(32).fill(i), acceptedAboveMs: BigInt(i) })
    const committed = file.durable.slice()
    let rejected = false
    for (let i = 8; i < 30; i++) {
      try { persistence.saveValidatorCutoff({ validatorId: new Uint8Array(32).fill(i), acceptedAboveMs: BigInt(i) }) }
      catch (error) { expect(String(error)).toContain('QUOTA_EXCEEDED'); rejected = true; break }
    }
    expect(rejected).toBe(true)
    expect(file.durable.subarray(0, committed.length)).toEqual(committed)
    expect(() => new SyncControlPersistence(file.reopen(), { maxBytes: 1024 })).not.toThrow()
  })
})
