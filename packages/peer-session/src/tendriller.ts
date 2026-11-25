import type { CommandOptions as InlineCommandOptions } from './session-types.js'
import type { ApplicationSession } from './session.js'
import { emit, program, type EventPayload } from '@chronolog/protocol'
/** Host adapter is structurally typed, portable and carries no host ordering authority. */
export function createApplicationBackend(session: ApplicationSession) {
  return { applicationId: session.applicationId, identity: session.identity, get status() { return session.status }, signal: session.signal,
    onStatus: session.onStatus.bind(session), submit: session.submit.bind(session), changes: session.changes.bind(session), readView: session.readView.bind(session), operations: session.operations,
    events: { publish: (topic: string, payload: unknown, options: InlineCommandOptions = {}) => session.submit({ ...options, program: program(emit(topic, payload as EventPayload)) }), read: session.readEvents.bind(session) },
  }
}
