/** Stop this owner's wait without claiming that an already started effect was cancelled. */
export function awaitOwnedTask<T>(signal: AbortSignal, call: () => T | PromiseLike<T>): Promise<T> {
  signal.throwIfAborted()
  return new Promise<T>((resolve, reject) => {
    const clear = (): void => signal.removeEventListener('abort', abort)
    const abort = (): void => { clear(); reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    let result: T | PromiseLike<T>
    try { result = call() }
    catch (error) { clear(); reject(error); return }
    void Promise.resolve(result).then(value => {
      clear()
      if (signal.aborted) reject(signal.reason)
      else resolve(value)
    }, error => { clear(); reject(error) })
  })
}
