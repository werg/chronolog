import type { AgentApplication } from '@chronolog/agent-service'

/**
 * A runnable provider-free example for CHRONOLOG_AGENT_MODULE. It demonstrates
 * durable final-intent handling; replace dispatch with an application provider
 * only after choosing its real idempotency/reconciliation contract.
 */
export function createAgent(): AgentApplication {
  return {
    effects: [{
      resultTopic: 'agent.echo.results',
      handler: {
        id: 'echo', version: '1', topics: ['agent.echo.requests'], recovery: 'idempotent',
        dispatch: async ({ event }) => ({ echo: event.payload }),
      },
    }],
  }
}
