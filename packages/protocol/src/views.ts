/** Coalesced application invalidation, independent of durable event delivery. */
export interface ViewChange {
  readonly view: 'local' | 'final'
  readonly revision: string
  readonly finalRevision: string
}
export interface ViewChangeOptions {
  readonly view?: 'local' | 'final'
  readonly signal?: AbortSignal
}
