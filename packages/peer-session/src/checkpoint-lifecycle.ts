import type { BytesStore } from '@chronolog/records'
const states = new WeakMap<BytesStore, { users: number; checkpoint: boolean; retired: boolean }>()
function state(store: BytesStore) {
  let value = states.get(store)
  if (value === undefined) { value = { users: 0, checkpoint: false, retired: false }; states.set(store, value) }
  return value
}
export function useDeviceStore(store: BytesStore): () => void {
  const value = state(store)
  if (value.retired) throw Object.assign(new Error('DEVICE_RETIRED_BY_CHECKPOINT'), { code: 'DEVICE_RETIRED_BY_CHECKPOINT' })
  if (value.checkpoint) throw Object.assign(new Error('CHECKPOINT_SOURCE_IN_USE'), { code: 'CHECKPOINT_SOURCE_IN_USE' })
  value.users++
  let released = false
  return () => { if (!released) { released = true; value.users-- } }
}
export function reserveCheckpointStore(store: BytesStore): () => void {
  const value = state(store)
  if (value.users !== 0 || value.checkpoint) throw Object.assign(new Error('CHECKPOINT_SOURCE_IN_USE'), { code: 'CHECKPOINT_SOURCE_IN_USE' })
  value.checkpoint = true
  return () => { value.checkpoint = false }
}
export function retireDeviceStore(store: BytesStore): void { state(store).retired = true }
