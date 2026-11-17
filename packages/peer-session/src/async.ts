/** Bound actual work, even when its caller stops waiting for a result. */
export class BoundedTasks {
  #pending = 0
  constructor(readonly limit: number, readonly limitError: string) {}

  run<T>(start: () => T | Promise<T>, signal?: AbortSignal): Promise<T> {
    signal?.throwIfAborted()
    if (this.#pending >= this.limit) throw new Error(this.limitError)
    this.#pending++
    const task = Promise.resolve().then(() => { signal?.throwIfAborted(); return start() }).finally(() => { this.#pending-- })
    if (signal === undefined) return task
    return new Promise<T>((resolve, reject) => {
      const abort = (): void => { signal.removeEventListener('abort', abort); reject(signal.reason) }
      signal.addEventListener('abort', abort, { once: true })
      void task.then(value => { signal.removeEventListener('abort', abort); resolve(value) }, error => {
        signal.removeEventListener('abort', abort); reject(error)
      })
      if (signal.aborted) abort()
    })
  }
}
