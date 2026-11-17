# Application projections, effects and timers

`@chronolog/peer-session` supplies maintained consumers for the
`peer-generation-v1` history contract. A selected generation can be replaced by
an earlier authenticated prefix. Derived application state follows that
selection; an external action already performed cannot be undone by selecting
different history.

| Consumer | Rebuilt after selection changes | Retained independently |
| --- | --- | --- |
| `ApplicationProjection` | Pure reducer state and its event cursor | Consumer identity, version and checkpoint binding |
| `ApplicationEffectWorker` | Source cursor and applicability of pending intents | Original requester, provider key, uncertain/completed fact and result-publication observations |
| `ApplicationTimerScheduler` | Active schedules and next due times | Original configuration, occurrence identity and ordinary command attempts |

These consumers use verified captured views and the session's existing signed
command journal. They do not add a second command outbox. Applications explicitly
open and run them; opening a session does not start provider calls or timers.

## Ownership and durable identity

Construct a consumer with `id`, `version`, `session` and an atomic `PeerStore`.
For a native agent or an owning browser Worker, `device.store` is the usual
private checkpoint store. Use the same durable store when reopening. The
namespace includes application, history, consumer kind and ID; the saved binding
also checks the semantic version and configuration. An incompatible binding
fails instead of being reset or migrated. Change the version when reducer,
authorization, provider or publication semantics change.

Projections and timer publication can use the maintained Worker facade. Its
captured views have asynchronous `query`, `readEvents` and `release` methods.
External-effect workers require the owning `ApplicationSession`; passing a page
facade fails with `APPLICATION_EFFECT_OWNER_REQUIRED` before checkpoint IO.
Provider dispatch must compare authorization with the actual current runtime
state, rather than a communicated revision snapshot.

Each consumer exclusively owns its namespace while open. Concurrent mutation
turns fail with `APPLICATION_CONSUMER_BUSY`; run one loop per owner. Read-only
`inspect()` remains available during that loop and returns the last atomic
durable checkpoint, with at most 16 concurrent observations. Consumers register with
the session before their first durable IO. `close()` cancels observation and
waits for active checkpoint writes, and session shutdown closes its consumers
before releasing device storage. Provider cancellation stops waiting; a remote
provider may still finish a call that it already received.

Journals reload after each turn, including after an ambiguous storage
acknowledgment. Defaults are 8 MiB per consumer, at most 1,024 effect entries,
and at most 4,096 timer schedules and occurrences. Limits are configurable within
explicit hard bounds. Exhaustion is a visible refusal; there is no silent
deletion of an uncertain call, completed effect or abandoned timer occurrence.

## Rebuild a projection

Reducers are pure. They may validate payloads and produce a bounded JSON value,
but must never send messages or perform external work.

```ts
import { ApplicationProjection, parseApplicationInput } from '@chronolog/peer-session'

const noteSchema = {
  type: 'object',
  properties: { id: { type: 'string' }, text: { type: 'string' } },
  required: ['id', 'text'],
} as const

const notes = await ApplicationProjection.open({
  id: 'notes-by-id', version: '1', session, store: device.store,
  topics: ['note.recorded'],
  initial: (): Record<string, string> => ({}),
  reduce: (state, event) => {
    const note = parseApplicationInput(noteSchema, event.payload)
    return { ...state, [note.id]: note.text }
  },
})

const checkpoint = await notes.catchUp()
render(checkpoint.state, checkpoint.revision)
for await (const update of notes.follow({ signal })) {
  render(update.state, update.revision)
}
```

`catchUp()` captures one verified SQL/event revision, reads bounded pages, and
atomically saves the complete state and cursor. Ordinary appends are reduced
incrementally. A generation or control-selection change starts from `initial()`
and rebuilds from the selected history; `reset` reports that rebuild.
`inspect()` returns the last complete checkpoint. A reducer failure cannot
replace it with a partly rebuilt view, and an already captured view remains
coherent until released.

## Dispatch an authorized external effect

The application provides a policy and provider adapter. The policy receives
the verified event author and a fresh captured view. A payload field named
`author`, `origin` or `requestedBy` supplies no authority.

```ts
import { ApplicationEffectWorker, parseApplicationInput } from '@chronolog/peer-session'

const requestSchema = {
  type: 'object',
  properties: { intentId: { type: 'string' }, message: { type: 'string' } },
  required: ['intentId', 'message'],
} as const

const effects = await ApplicationEffectWorker.open({
  id: 'notifications', version: '1', session, store: device.store,
  topics: ['notification.requested'],
  intentKey: event => parseApplicationInput(requestSchema, event.payload).intentId,
  authorize: async ({ event, view, signal }) =>
    policy.mayNotify(event.author, view, { signal }),
  recovery: 'reconcile',
  dispatch: async ({ event, idempotencyKey, signal, deadlineAtMs }) =>
    provider.send(parseApplicationInput(requestSchema, event.payload), {
      idempotencyKey, signal, deadlineAtMs,
    }),
  reconcile: async ({ idempotencyKey, signal }) =>
    provider.lookup(idempotencyKey, { signal }),
})

await effects.run({ signal })
```

`policy`, `provider`, `render` and `signal` in these sketches are application
integrations. The provider returns a bounded JSON receipt. Its lookup returns
`{ kind: 'completed', result }`, `{ kind: 'not-performed' }` or
`{ kind: 'uncertain' }`.

An effect ID binds application, history, consumer ID/version, verified requester
and intent key. Without `intentKey`, the original event ID is used. A domain key
lets deliberate reapplication restore application state without sending the
same completed logical action again. Reusing it for different content is
rejected; a new logical action needs a new key.

Before new dispatch, the worker checks that an observed intent remains selected
and evaluates current authorization. It rechecks the exact captured generation,
control revision, selected head and materialization revision after asynchronous
policy evaluation and durable preparation, then again immediately before entering
the provider callback. A known change before any call begins returns
`APPLICATION_CONSUMER_VIEW_CHANGED` and leaves the undispatched record retryable.
This establishes the known-current boundary; future cancellation cannot
atomically retract an external request.

The dispatching marker is durable before the provider call. A lost reply,
timeout or exception after entry raises `ApplicationEffectUncertainError` and
retains the same provider key. A normal `processNext()` or `run()` never silently
repeats it.

| Retained fact | Explicit recovery operation |
| --- | --- |
| `dispatching`, provider guarantees idempotency | `retry(effectId)` with `recovery: 'idempotent'`; current applicability and authorization are checked again |
| `dispatching`, provider can look up the result | `reconcile(effectId)`; observing a completed fact remains valid even if its original intent was abandoned |
| `dispatching`, application has reviewed independent evidence | `resolve(effectId, { kind: 'completed', result })` or `{ kind: 'not-performed' }` |
| `not-performed` | A deliberate `retry(effectId)` can start work if still selected and authorized |
| `completed` | Preserve the receipt and original identity; recovery never dispatches it again |

Declaring idempotency is a provider contract; the SDK cannot infer it from a
key. Calls and authorization waits have a deadline. A callback that ignores
cancellation retains its in-process slot until it settles, so reopening the same
consumer cannot accumulate parallel forgotten calls.

`processNext()` performs a bounded manual turn. `run()` owns the change
subscription and drains bounded batches. Both stop at unresolved uncertainty,
leaving `inspect()` and the explicit recovery operations available. Original
provider facts are never reset with the source cursor.

### Publish a result through the ordinary session

The optional `publishResult(entry, options)` callback returns a normal command
handle. Use the supplied `operationId`; when `reapplyOf` is non-null, call
`session.reapply(reapplyOf, command, input, { operationId })`. The SDK inspects
the existing operation rather than retaining another signed attempt.

A completed provider action stays completed if its result command is later
abandoned. `republish(effectId, { operationId })` deliberately restores that
result with a linked new command. It does not call the provider. The default
result observation remains abandoned until that explicit decision.

## Schedule guarded SQL timer occurrences

`createApplicationTimerPrograms` supplies shared SQL schedule tables, unique
configuration generations, guarded due slots, and configuration events. The
domain decides who may configure timers and which signer may publish a due
occurrence.

```ts
import {
  ApplicationTimerScheduler, applicationTimerCancellationSchema,
  applicationTimerOccurrenceSchema, applicationTimerScheduleSchema,
  createApplicationTimerPrograms, defineApplication, defineCommand,
  emit, parseApplicationInput, program,
} from '@chronolog/peer-session'

const payloadSchema = {
  type: 'object', properties: { message: { type: 'string', maxLength: 2000 } },
  required: ['message'],
} as const
const timers = createApplicationTimerPrograms({ configurationTopic: 'timer.configuration' })
const occurrenceSchema = applicationTimerOccurrenceSchema(payloadSchema)
const definition = defineApplication({
  id: 'reminders', version: '1', schema: timers.schema,
  commands: {
    schedule: defineCommand({ description: 'Schedule a reminder',
      input: applicationTimerScheduleSchema(payloadSchema),
      prepare: input => timers.schedule(input) }),
    cancel: defineCommand({ description: 'Cancel a reminder version',
      input: applicationTimerCancellationSchema,
      prepare: input => timers.cancel(input) }),
    fire: defineCommand({ description: 'Publish the due reminder',
      input: occurrenceSchema,
      prepare: occurrence => program(
        ...schedulerAuthorization(occurrence).steps,
        ...timers.fire(occurrence).steps,
        emit('notification.requested', {
          intentId: occurrence.occurrenceId, message: occurrence.payload.message,
        }),
      ) }),
  }, queries: {},
})

const scheduler = await ApplicationTimerScheduler.open({
  id: 'reminders', version: '1', session, store: device.store,
  configurationTopic: 'timer.configuration',
  authorize: ({ configuration, view, signal }) =>
    policy.maySchedule(configuration.author, view, { signal }),
  publish: (occurrence, { operationId, basedOn, reapplyOf }) => {
    const input = parseApplicationInput(occurrenceSchema, occurrence)
    return reapplyOf === null
      ? session.command('fire', input, { operationId, basedOn })
      : session.reapply(reapplyOf, 'fire', input, { operationId, basedOn })
  },
})
await scheduler.run({ signal })
```

`schedulerAuthorization` is the application's deterministic SQL guard for the
actual `chronolog_actor()`, using its authorized scheduler configuration. A
copied author in the input cannot grant that role. The helper's tables use
application-collective ownership, so current data roles remain effective after
recovery and creator departure. Add domain guards when configuration rights are
narrower than that shared role.

Schedule takes `{ timerId, generation, dueAtMs, intervalMs?, payload,
expectedGeneration }`. `generation` is a caller-allocated unique configuration
version, such as a UUID, distinct from the peer protocol generation.
`expectedGeneration: null` creates a timer; a string replaces exactly that
previous version. A non-null positive `intervalMs` creates a recurring timer.
Cancellation names the exact timer ID and configuration generation.

The `schedule` helper's configuration must be the first emitted event in that
command. Preceding SQL authorization steps are permitted; append other
application events after the helper. This binds the stored configuration ID to
the authenticated transaction and its first event ordinal.

An occurrence preserves the original verified configuration event, scheduled
time, observed time and payload. Its stable identity binds that configuration
event and due slot. The SQL fire guard checks the stored configuration ID and
author, active version, exact next due time and payload. Only then can the same
atomic program advance the schedule and emit the notification. A cancellation
or replacement that wins the race rejects with
`assert:timer_inactive_configuration`; the scheduler records a cancelled
occurrence without emitting. A different rejection raises
`ApplicationTimerRejectedError` and remains inspectable. Losing a recurring due
slot to another scheduler advances from the committed configuration event;
later slots remain available.

`observedAtMs` is a participant's clock observation. The helper does not create a
globally trusted clock or authorize arbitrary signers to claim that a deadline
passed. The domain's scheduler policy decides who may make that observation.

`tick(nowMs?)` performs a bounded turn, defaulting to 32 due occurrences, and
returns `emitted`, `cancelled`, `hasMore`, `awaitingReconciliation`, `reset` and
`nextDueAtMs`. `run({ signal })` owns change and clock wakeups. Its clock and
wake interval are injectable for controlled tests.

Recovery reconstructs schedules from the selected prefix and retains recorded
occurrences. A missing selected configuration cannot start a new occurrence.
A saved command is retried with its exact operation identity and original input,
including the original observed time. An abandoned occurrence is not silently
reauthored: inspect it, then deliberately call
`reapply(occurrenceId, { operationId })` when restoring that action is appropriate.
`retry(occurrenceId)` keeps the existing attempt. A cancelled configuration needs
a new explicit configuration version.

Event-only applications may provide their own `timer.scheduled` and
`timer.cancelled` configuration events and ordinary publication callback. Such a
callback alone does not establish an atomic cancellation-versus-publication
guard. Use the SQL helper when that invariant is required.

The chronological `FinalEventSource` and its append-only consumers remain a
different contract. Generation sessions use the consumers documented here;
`applied()` and `shared()` do not turn selected history into an immutable final
prefix. See [peer application sessions](README.md) for ownership, enrollment and
ordinary command recovery.
