import type { FeedLink } from '@chronolog/records'

type Kind = 'feed' | 'evidence' | 'payload'
interface RangeTrace {
  id: number; kind: Kind; startedAtMs: number; feed?: string; after?: string; limit?: number
  elapsedMs?: number; records?: number; bytes?: number; error?: string
}

/** Passive bounded diagnostics around the actual authenticated range port. */
export function observeFeedLink(source: FeedLink) {
  const totals = Object.fromEntries((['feed', 'evidence', 'payload'] as const).map(kind => [kind, {
    calls: 0, completed: 0, failed: 0, elapsedMs: 0, maximumMs: 0, records: 0, bytes: 0,
  }])) as Record<Kind, { calls: number; completed: number; failed: number; elapsedMs: number
    maximumMs: number; records: number; bytes: number }>
  const pending = new Map<number, RangeTrace>(), recent: RangeTrace[] = []
  let sequence = 0, hints = 0
  async function read<T extends readonly Uint8Array[] | Uint8Array | null>(kind: Kind,
    range: Pick<RangeTrace, 'feed' | 'after' | 'limit'>, run: () => Promise<T>): Promise<T> {
    const trace: RangeTrace = { id: ++sequence, kind, startedAtMs: performance.now(), ...range }, total = totals[kind]
    pending.set(trace.id, trace); total.calls++
    try {
      const result = await run()
      const values: readonly Uint8Array[] = result === null ? [] : result instanceof Uint8Array ? [result] : result
      const bytes = values.reduce((sum, value) => sum + value.length, 0)
      trace.records = values.length; trace.bytes = bytes
      total.records += values.length; total.bytes += bytes
      return result
    } catch (error) { total.failed++; trace.error = String(error).slice(0, 256); throw error }
    finally {
      trace.elapsedMs = performance.now() - trace.startedAtMs
      total.completed++; total.elapsedMs += trace.elapsedMs; total.maximumMs = Math.max(total.maximumMs, trace.elapsedMs)
      pending.delete(trace.id); recent.push(trace)
      if (recent.length > 24) recent.shift()
    }
  }
  const link: FeedLink = {
    identity: source.identity,
    read: (feed, after, limit) => read('feed', { feed, after: String(after), limit }, () => source.read(feed, after, limit)),
    readEvidence: (after, limit) => read('evidence', { after: String(after), limit }, () => source.readEvidence(after, limit)),
    readPayload: hash => read('payload', { limit: 1 }, () => source.readPayload(hash)),
    async *watch(signal) {
      for await (const hint of source.watch(signal)) { hints++; yield hint }
    },
  }
  return { link, snapshot() {
    const now = performance.now()
    const describe = ({ startedAtMs, ...trace }: RangeTrace) => ({ ...trace, elapsedMs: trace.elapsedMs ?? now - startedAtMs })
    return { identity: source.identity, hints, totals: structuredClone(totals), pendingCount: pending.size,
      pending: [...pending.values()].slice(0, 8).map(describe), recent: recent.map(describe) }
  } }
}
