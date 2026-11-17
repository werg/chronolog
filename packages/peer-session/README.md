# Peer application sessions

`@chronolog/peer-session` exposes the `peer-generation-v1` application profile.
One eligible peer issues signed inclusion receipts. Ordinary commands, queries,
history and live signals need no hosted request while that generation is healthy. A signed
control service selects a successor during takeover. Recovery can abandon a
recent suffix, which remains inspectable and requires explicit reapplication.

Application execution uses the shared order `(signed author timestamp, signing
public key, stable proposal ID)`. Receipt sequence describes authenticated
inclusion and recovery ancestry; it does not choose execution order. An applied
result is accepted or rejected at an observed `PeerRevision`. Later included work
can sort earlier and change that result even within the same generation. This
package has no final state, frontier, `final()` wait or final-intent worker.
Tendriller's default live adapter remains a separate profile.

## Native events application

Create or enroll a device explicitly before opening a session. Resuming a device
never replaces missing keys. The native store holds an exclusive SQLite writer
lock; the browser entry holds an exclusive Web Lock and uses OPFS in the owning
Worker. A second owner receives a busy error.

```ts
import { defineApplication, defineCommand, defineQuery, emit, program,
  type ApplicationReadView } from '@chronolog/peer-session'
import { openNativeDevice, openNativeApplication } from '@chronolog/peer-session/native'

const definition = defineApplication({
  id: 'conversation', version: '1',
  commands: {
    say: defineCommand({
      description: 'Post a message',
      input: { type: 'object', properties: { text: { type: 'string', minLength: 1, maxLength: 2000 } }, required: ['text'] },
      prepare: ({ text }) => program(emit('message', { text })),
    }),
  },
  queries: {
    messages: defineQuery({ description: 'Read messages at one revision', input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents({ topics: ['message'] }),
    }),
  },
})
const device = await openNativeDevice({ path: './device.sqlite' })
const session = await openNativeApplication({ device, definition, authority, epochKeys })
try {
  const before = await session.query('messages', null)
  const operation = await session.command('say', { text: 'Hello' }, {
    operationId: crypto.randomUUID(), observedRevision: before.revision,
  })
  const result = await operation.applied()
  console.log(result.revision, result.generation, result.sequence, result.outcome)
} finally { await session.close() }
```

`authority` is the verified signed descriptor/control/generation bundle obtained
from the configured control service. `epochKeys` contains explicitly enrolled
decryption keys. `applicationDefinitionDigest(definition)` binds the published
schemas and semantic version. Obtain the shared author-time event engine's
execution manifest with `eventExecutionManifest()`. Applied and live wrappers
use that same engine; the live wrapper adds its separate finality contract.

The definition digest does not hash the JavaScript `prepare` and `read`
callbacks. Command schemas and names provide shared application DX, not
authorization: an authorized writer can still author a raw program. A command
name, version or payload claim cannot grant private-tool rights. Check the
authenticated signer and current application policy before privileged work.

`observedRevision` checks that the reviewed ancestry is still selected. It does
not implement compare-and-swap, reserve an execution position or guarantee that a
previous query remains true. Put required business assertions in the program.

Only first device setup passes `{ create: true }`. Ordinary reopening omits it.
The session owns one signed attempt journal in the device store. A disconnected
command remains `saved`; connecting resumes its exact original attempt.
Cancelling `applied({ signal })` cancels that waiter only.

## Recovery and inspection

`operations.get(id)` returns saved, applied, abandoned or needsReapply.
`operations.inspect(id, { author })` includes the retained original signed
attempt, preserving real signer provenance. `operation.retry()` reuses those
bytes and observes the current replay result.
`operations.subscribe({ operationId, author, signal })` coalesces current
observations and continues after an applied result, since later replay can change
it. `changes()` reports applied-view
changes, including revisions within a generation; `onRecovery()` also reports
explicit generation recovery. A held view stays tied to its original revision.
A cursor from another revision throws `ChangedViewError`; rebuild the new
projection explicitly. These cursors are not final-event worker checkpoints.

An adopted generation is not ready merely because its authority is known or a
peer is connected. The session remains `waiting` while selected bodies are
missing; it exposes an applied view only after complete verified replay.

After inspecting abandoned work, call
`reapply(oldId, name, currentArguments, { operationId: newId, observedRevision })`. This
prepares a new signed attempt linked by `reapplyOf`; it never admits the old
attempt silently. Use `originalAuthor` when deliberately reapplying retained
work from another signer. Current permissions and domain guards still apply.

`operation.shared()` observes independently retained complete coverage. It is
separate from `applied()` and does not block ordinary commands or freeze execution
outcomes. A retained copy is not a claim that its peer is currently reachable.

`connectApplications(a, b)` is a built-in in-process transport for embedded peers
and independent-store qualification. It carries commands, verified history,
retention acknowledgments and signed live signals. It is not a measurement of
Internet WebRTC routing. No recipe needs its own application retry queue.

This session's signal policy permits current readers. It does not inherit the
live profile's topic-specific writer policy. The signed signal channel keeps
expiry, replay protection and bounded queues separate from durable commands.

The portable entry and the browser entry are SQL-free. SQL applications supply
an `AppliedMaterializationRuntime` with the same authenticated profile; the pinned
schema is initialized before application history. The default event path uses
`createAppliedEventMaterializationRuntime`. Native SQL uses
`AppliedMaterializer.open` and `createDoltLiteAppliedMaterializationRuntime` through
the `/sql-native` entry. Applied runtimes expose no final fields or disabled
finality methods. Row and schema authorization remain separate execution policy.

Irreversible effects require an application policy for idempotency, recovery and
reconciliation. An applied accepted event alone cannot authorize automatic
final-intent dispatch, because subsequent replay may remove that event.

## Implementation and qualification scope

The native session tests exercise saved offline intent, reconnect after a lost
reply, cancellation of one waiter, coherent recovery, explicit reapplication,
close/reopen and exclusive store ownership. Replica tests cover authenticated
history and retained-prefix selection; native SQL tests exercise deterministic
execution and rollback. See [the profile contract](../../docs/peer-generation-v1.md)
for the authority and recovery invariants.

`connectApplications` calls peer sessions in process. These tests do not establish
browser/native Internet connectivity, every storage crash boundary or a global
recovery-loss bound. The browser entry provides Worker/OPFS ownership, but requires
separate browser-session qualification. This package is not automatically installed
by Tendriller's live adapter, and it does not implement general branch merging.

## Build a packed preview

Run `node tools/package-peer-session.mjs`. The tarball includes shared ESM chunks,
self-contained TypeScript declarations, and commit/tree/file-hash provenance.
`--allow-dirty` produces an explicitly marked development artifact. Native and
browser entries share session classes and ownership state through those chunks.
