import type { CommandOptions as InlineCommandOptions } from './session-types.js'
import type { ApplicationSession } from './session.js'
import { normalizeJsonValue } from '@chronolog/protocol'

/** Host adapter is structurally typed, portable and carries no host ordering authority. */
export function createApplicationBackend(session: ApplicationSession) {
  return {
    applicationId: session.applicationId,
    identity: session.identity,
    get status() { return session.status },
    signal: session.signal,
    onStatus: session.onStatus.bind(session),
    submit: session.submit.bind(session),
    command: session.command.bind(session),
    query: session.query.bind(session),
    topic: session.topic.bind(session),
    describe: session.describe.bind(session),
    changes: session.changes.bind(session),
    readView: session.readView.bind(session),
    operations: session.operations,
    events: {
      publish: (topic: string, payload: unknown, options: InlineCommandOptions = {}) =>
        session.submit({ ...options, updates: [{ topic, input: normalizeJsonValue(payload) }] }),
      read: session.readEvents.bind(session),
    },
  }
}
