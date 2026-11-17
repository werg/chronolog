import { awaitOwnedTask } from './lifetime.js'

/** Lazy acquisition preserves the underlying stream's cancellation and pull bound. */
export function deferredStream<T>(open: (signal: AbortSignal) => Promise<AsyncIterable<T>>, options: {
  readonly signal: AbortSignal
  readonly concurrentNextError: string
  readonly abort: 'done' | 'throw'
}): AsyncIterable<T> {
  return { [Symbol.asyncIterator]() {
    const controller = new AbortController(), signal = AbortSignal.any([options.signal, controller.signal])
    let iterator: AsyncIterator<T> | undefined, opening: Promise<AsyncIterator<T>> | undefined
    let closed = false, pulling = false, closing: Promise<void> | undefined
    const finish = (): Promise<void> => {
      if (closed) return closing ?? Promise.resolve()
      closed = true; signal.removeEventListener('abort', aborted)
      controller.abort(new Error('APPLICATION_STREAM_CLOSED'))
      closing = Promise.resolve().then(async () => { await iterator?.return?.() })
      return closing
    }
    const aborted = (): void => { void finish().catch(() => undefined) }
    signal.addEventListener('abort', aborted, { once: true }); if (signal.aborted) aborted()
    const acquire = (): Promise<AsyncIterator<T>> => opening ??= Promise.resolve().then(async () => {
      signal.throwIfAborted()
      const acquired = (await open(signal))[Symbol.asyncIterator]()
      if (closed) await acquired.return?.()
      else iterator = acquired
      return acquired
    })
    return {
      async next(): Promise<IteratorResult<T>> {
        if (closed) {
          if (options.abort === 'throw') options.signal.throwIfAborted()
          return { done: true, value: undefined }
        }
        if (pulling) throw new Error(options.concurrentNextError)
        pulling = true
        try {
          const acquired = await awaitOwnedTask(signal, acquire)
          const value = await awaitOwnedTask(signal, () => acquired.next())
          if (value.done) await finish()
          return value
        } catch (error) {
          const cancelled = signal.aborted
          await finish().catch(() => undefined)
          if (cancelled && (options.abort === 'done' || !options.signal.aborted)) return { done: true, value: undefined }
          throw error
        } finally { pulling = false }
      },
      async return() { await finish(); return { done: true, value: undefined } },
    }
  } }
}
