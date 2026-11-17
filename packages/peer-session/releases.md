# Signed page releases

The `/releases` entry makes publication a Chronolog control facet. A page release
is a signed manifest of exact authored bytes. An independently signed publisher
policy authorizes its author. A signed activation selects one complete release
with compare-and-set against the preceding activation. The application-data
generation and the release selection have separate histories.

The host is a selective participant: it retains the authorized release content,
verifies manifests, signs control selections, serves the selected page, and sends
optional activation hints. It does not receive private application keys, execute
application commands, or participate in ordinary live signals. Publication
rights are separate from data membership and from schema authority.

## Publish from an owned application

The publisher shares an application's signer, durable store, and lifetime. Call
the factory in the native process or owning browser Worker; signing keys remain
with that owner.

```ts
import { createReleasePublisher } from '@chronolog/peer-session/releases'

const releases = await createReleasePublisher({ session, host: client.peers.releases })
await releases.refresh() // Explicitly learn the current publisher policy.
const prepared = await releases.prepare({
  operationId: 'release-2026-11-17',
  entry: 'index.html',
  assets: [
    { path: 'index.html', mediaType: 'text/html', bytes: htmlBytes },
    { path: 'assets/app.js', mediaType: 'text/javascript', bytes: javascriptBytes },
  ],
})
await releases.publish(prepared.operationId)
const state = await releases.state()
const selected = await releases.activate(prepared.id, {
  requestId: 'activate-2026-11-17',
  expectedActivation: state.activations.at(-1)?.id ?? null,
})
```

The factory binds the manifest to the session's verified history, definition,
execution manifest, and schema. Activation requires that exact configured
application boundary. Updating the page does not silently change the application
definition or reinterpret existing data. An explicit `application` binding is
available when preparing a release for a separately configured application.

Before an application exists, use `openReleasePublisher({ device,
applicationId, controlPublicKey, host })`. The trusted control key comes from the
authenticated host bootstrap. This standalone publisher claims the device and
releases it on close. It can prepare an unbound page shell, which the host will
activate only while no application boundary has been configured. The owning
account grants publisher public keys through `client.peers.releases.configure`;
data membership does not grant publication rights.

## Interrupted publication and explicit rollback

`prepare()` snapshots and hashes the supplied bytes, stages them in bounded
chunks, then durably saves the signed manifest before making a transport call.
The operation ID names those exact inputs. Reusing it with different content
fails. `publish(operationId)` resumes from those staged bytes and marks the
publication acknowledged only after the host verifies the complete asset graph.

`activate()` saves the exact signed activation request before dispatch. If the
reply is lost, `inspectActivation(requestId)` exposes the saved request and
`retry(requestId)` sends that same request. It does not mint a replacement ID,
change the expected selection, or re-sign under a newer policy. Already
acknowledged results can be read offline even after publisher revocation. New
work requires current authorization. A storage acknowledgement failure fences
the publisher until reopening reads the durable outcome.

Reopening a cached publisher requires no host request. `state()` reads the local
verified control history; `refresh()` explicitly fetches and learns a newer
history. A host cannot roll that learned policy or activation history backward.
To select an older release, a currently authorized publisher makes a new
activation against the current selection. Application-data recovery does not
modify the release policy, current page, or publication journal.

`watch({ signal })` explicitly opens the host's optional activation-hint stream.
Every hint must appear in a fully verified extension of the learned control
history. Observations coalesce to the current selected release. The publisher
does not poll, automatically reload a page, or install a background network
lifecycle. Closing it cancels remote waits and settles active durable writes.
Closing a shared publisher leaves its application session open; closing the
session closes its registered publisher before releasing storage.

## Observe updates without a signing key

An open page can observe approved releases without owning a device, joining the
application, or receiving publication rights:

```ts
import { openReleaseObserver } from '@chronolog/peer-session/releases'

const observer = await openReleaseObserver({
  applicationId, controlPublicKey,
  host: client.peers.releases,
  store: pageControlStore,
  initial: bootstrap.peerRelease,
})
const available = await observer.refresh()
if (available.selection !== null) offerUpdate(available.selection)
```

The observer requires only state, manifest, content-read, and optional watch
capabilities. The supplied `PeerStore` must have one storage owner; the observer
also prevents duplicate observers for the same application within that owner.
Its private namespace persists the verified policy and activation history.
Learned controls become durable before asset verification, so missing content
cannot permit a later stale head to erase a learned revocation or activation.

`state()` and `refresh()` return `{ state, selection }`. A selection becomes
available only after verifying its signed manifest and every asset's length and
digest. Unavailable or corrupt bytes reject the refresh and leave the new
verified state retained with no applicable selection. Reopening rechecks selected
bytes; cached controls do not imply that content remains available. An older
bootstrap or signed host response cannot roll retained controls backward.

`watch({ signal })` verifies bounded activation hints through the same path.
The UI owns the decision to apply or defer an update and preserve a draft.
The observer never polls or reloads. Close it before closing its store; shutdown
cancels active reads and awaits admitted durable writes. Content verification
has one 30-second deadline across the selected graph, propagated into active
host reads.

## Content and resource boundaries

Manifests permit at most 256 safe relative asset paths, 32 MiB per asset and
128 MiB in total. Assets are digest-addressed and verified as exact bytes. The
host's release-content namespace is distinct from private attachment storage;
knowing a private blob hash does not make it publishable. Authored HTML remains
separate from the trusted host runtime injected into the served response.

The publisher admits eight concurrent calls and four explicit watches. It
retains at most 128 prepared publications, 256 activation requests, 4,096 unique
assets and 128 MiB of staged bytes. Remote calls have a 30-second deadline.
These bounds are part of the current pre-release storage envelope; exceeding
them fails explicitly. The publisher does not prune uncertain operations or
discard history needed to detect a control rollback.

The application publisher and host protocol are tested separately and through
the public packed-package acceptance. Unit tests exercise actual Ed25519
signatures and the durable control registry, including committed-but-lost
replies, learned-state regression, revoked publishers, corrupted staged bytes,
and storage ownership during shutdown.
