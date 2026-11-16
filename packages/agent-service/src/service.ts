import { validateConsumerId } from './event-source.js'

export interface ResidentTask {
  readonly id: string
  /** A long-lived loop that exits when signal is aborted and reports failures. */
  run(signal: AbortSignal): Promise<void>
}

/** Independent of model turns: persistence, synchronization, timers and workers run concurrently. */
export class ResidentAgentService {
  readonly #tasks: readonly ResidentTask[]
  #controller: AbortController | null = null
  #failure: { readonly taskId: string; readonly error: unknown } | null = null

  constructor(tasks: readonly ResidentTask[]) {
    const seen = new Set<string>()
    for (const task of tasks) {
      validateConsumerId(task.id)
      if (seen.has(task.id)) throw new Error('RESIDENT_TASK_DUPLICATE')
      seen.add(task.id)
    }
    if (tasks.length === 0) throw new Error('RESIDENT_TASK_REQUIRED')
    this.#tasks = [...tasks]
  }

  get status(): { readonly running: boolean; readonly failedTask: string | null } {
    return { running: this.#controller !== null, failedTask: this.#failure?.taskId ?? null }
  }

  async run(signal?: AbortSignal): Promise<void> {
    if (this.#controller !== null) throw new Error('RESIDENT_SERVICE_ALREADY_RUNNING')
    const controller = new AbortController()
    this.#controller = controller
    this.#failure = null
    const abort = (): void => controller.abort()
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) controller.abort()
    try {
      const results = await Promise.allSettled(this.#tasks.map(async (task) => {
        try {
          await task.run(controller.signal)
          if (!controller.signal.aborted) throw new Error('RESIDENT_TASK_STOPPED_UNEXPECTEDLY')
        }
        catch (error) {
          if (!controller.signal.aborted) this.#failure = { taskId: task.id, error }
          controller.abort()
          throw error
        }
      }))
      const failure = this.#failure as { readonly taskId: string; readonly error: unknown } | null
      if (failure !== null) throw new Error(`RESIDENT_TASK_FAILED: ${failure.taskId}`, { cause: failure.error })
      // A task can reject during explicit shutdown. Its signal owns cancellation,
      // so this does not manufacture a service failure after the requested stop.
      void results
    } finally {
      signal?.removeEventListener('abort', abort)
      this.#controller = null
    }
  }

  stop(): void { this.#controller?.abort() }
}

export function waitForAbortableDelay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0 || milliseconds > 60_000) throw new Error('RESIDENT_DELAY_INVALID')
  return new Promise((resolve) => {
    const done = (): void => { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve() }
    const timer = setTimeout(done, milliseconds)
    signal?.addEventListener('abort', done, { once: true })
    if (signal?.aborted) done()
  })
}
