import type { NativeFinalityService } from '@chronolog/agent-service'
import type { OrderedRecordEntry, OrderedRecordHead } from '@chronolog/node-core/history'

/** Collect one fixed retained interval; later closure ticks cannot extend the measurement. */
export async function collectRetainedRange(source: Pick<NativeFinalityService, 'read'>,
  after: OrderedRecordHead, through: OrderedRecordHead): Promise<readonly OrderedRecordEntry[]> {
  let cursor = { ...after }
  const target = { ...through }, retained: OrderedRecordEntry[] = []
  const validHead = (head: OrderedRecordHead): boolean => Number.isSafeInteger(head.position) && head.position >= 0 &&
    typeof head.historyId === 'string' && head.historyId.length > 0 && typeof head.root === 'string' && head.root.length > 0
  if (!validHead(cursor) || !validHead(target) || cursor.historyId !== target.historyId || cursor.position > target.position) {
    throw new Error('THIN_WORKLOAD_RANGE_BOUNDS_INVALID')
  }
  const expectedLength = target.position - cursor.position
  while (cursor.position < target.position) {
    const limit = Math.min(128, target.position - cursor.position)
    const page = await source.read({ after: cursor.position, limit })
    if (!validHead(page.head) || page.head.historyId !== target.historyId || page.head.position < target.position || page.entries.length > limit) {
      throw new Error('THIN_WORKLOAD_RANGE_BOUNDS_INVALID')
    }
    if (page.entries.length === 0) throw new Error('THIN_WORKLOAD_RANGE_NO_PROGRESS')
    for (const entry of page.entries) {
      if (entry.historyId !== target.historyId || entry.position !== cursor.position + 1 || entry.position > target.position ||
          entry.previousRoot !== cursor.root || typeof entry.root !== 'string' || entry.root.length === 0) {
        throw new Error('THIN_WORKLOAD_RANGE_DISCONTINUOUS')
      }
      retained.push(entry)
      cursor = { historyId: entry.historyId, position: entry.position, root: entry.root }
    }
    if (page.hasMore !== (cursor.position < page.head.position) || cursor.position === page.head.position && cursor.root !== page.head.root) {
      throw new Error('THIN_WORKLOAD_RANGE_COVERAGE_INVALID')
    }
  }
  if (cursor.root !== target.root || retained.length !== expectedLength) throw new Error('THIN_WORKLOAD_RANGE_COVERAGE_INVALID')
  return retained
}

