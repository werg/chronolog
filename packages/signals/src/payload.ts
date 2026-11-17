export type SignalPayload = null | boolean | number | string | readonly SignalPayload[] | { readonly [key: string]: SignalPayload }

export function assertSignalTopic(topic: string): void {
  if (typeof topic !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(topic) || topic.length > 128) throw new Error('SIGNAL_TOPIC_INVALID')
}

/** Strict JSON, copied before asynchronous work; no accessors or lossy values. */
export function canonicalSignalPayload(payload: SignalPayload): string {
  let nodes = 0
  const visit = (value: SignalPayload, depth: number): string => {
    if (depth > 32 || ++nodes > 4096) throw new Error('SIGNAL_PAYLOAD_TOO_COMPLEX')
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new Error('SIGNAL_PAYLOAD_INVALID')
      return JSON.stringify(value)
    }
    if (Array.isArray(value)) {
      if (Reflect.ownKeys(value).length !== value.length + 1) throw new Error('SIGNAL_PAYLOAD_INVALID')
      const entries: string[] = []
      for (let i = 0; i < value.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, i)
        if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable) throw new Error('SIGNAL_PAYLOAD_INVALID')
        entries.push(visit(descriptor.value as SignalPayload, depth + 1))
      }
      return `[${entries.join(',')}]`
    }
    if (typeof value !== 'object' || value === null ||
        (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
        Reflect.ownKeys(value).length !== Object.keys(value).length) throw new Error('SIGNAL_PAYLOAD_INVALID')
    return `{${Object.keys(value).sort().map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!
      if (!('value' in descriptor)) throw new Error('SIGNAL_PAYLOAD_INVALID')
      return `${JSON.stringify(key)}:${visit(descriptor.value as SignalPayload, depth + 1)}`
    }).join(',')}}`
  }
  const result = visit(payload, 0)
  if (new TextEncoder().encode(result).length > 16_384) throw new Error('SIGNAL_FRAME_TOO_LARGE')
  return result
}
