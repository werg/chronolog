/** Coalesced application invalidation, independent of durable event delivery. */
export interface ApplicationChange {
  readonly view: 'local' | 'final'
  readonly revision: string
  readonly finalRevision: string
}
export interface ApplicationChangeOptions {
  /** Defaults to the confirmed final view. */
  readonly view?: 'local' | 'final'
  readonly signal?: AbortSignal
}
