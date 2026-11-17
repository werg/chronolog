import type { AgentApplication, AgentApplicationContext } from '@chronolog/agent-service'

/**
 * A runnable provider-free example for CHRONOLOG_AGENT_MODULE. It demonstrates
 * durable final-intent handling; replace dispatch with an application provider
 * only after choosing its real idempotency/reconciliation contract.
 */
export function createAgent(context: AgentApplicationContext): AgentApplication {
  return {
    effects: [{
      resultTopic: 'job-results',
      handler: {
        id: 'summarize-task', version: '1', topics: ['job-requests'], recovery: 'idempotent',
        async dispatch({ event, signal }) {
          const request = event.payload
          if (request === null || typeof request !== 'object' || !('type' in request) ||
              request.type !== 'job.requested' || request.version !== 1 || request.kind !== 'summarize-task' ||
              typeof request.jobId !== 'string' || typeof request.taskId !== 'string' ||
              request.jobId.length === 0 || request.jobId.length > 128 || request.taskId.length === 0 || request.taskId.length > 128) {
            return { type: 'job.ignored', version: 1, reason: 'Unsupported task-summary intent' }
          }
          // Progress is expendable live UI state. A disconnected reader must
          // never delay the durable job or cause a second provider dispatch.
          void context.signals.send('job-progress', { jobId: request.jobId, phase: 'reading-task' },
            { ttlMs: 5_000, signal }).catch(() => undefined)
          // This provider-free example reads shared final data and formats a
          // result. Repeating this read has no external effect to duplicate.
          const view = await context.node.readView({ view: 'final' })
          try {
            const row = view.query('SELECT title, status FROM tasks WHERE id = ?', [{ kind: 'text', value: request.taskId }]).rows[0]
            if (row === undefined) return { type: 'job.failed', version: 1, jobId: request.jobId, taskId: request.taskId, text: 'Task is no longer available.' }
            const title = row[0], status = row[1]
            if (title?.kind !== 'text' || status?.kind !== 'text') throw new Error('TASK_SUMMARY_SCHEMA_INVALID')
            return { type: 'job.completed', version: 1, jobId: request.jobId, taskId: request.taskId,
              text: `${title.value.slice(0, 1000)} — status: ${status.value.slice(0, 80)}.` }
          } finally { view.release() }
        },
      },
    }],
  }
}
