# Device storage and application authorization qualification

This runbook supports [contrib issue #17](https://github.com/werg/tendriller-contrib/issues/17)
and the membership-store portion of [issue #16](https://github.com/werg/tendriller-contrib/issues/16).
It separates automated, reproducible browser and protocol evidence from the
deployment and physical-device observations that still require an operator.

## Automated scenarios

Run the existing browser workflow on the exact PR commit. It installs its pinned
Chromium and builds the real SQL/WASM engine before running the browser gates.
The event-only gate can also run independently where Chromium, OPFS, Web Locks
and native loopback sockets are available:

```sh
node --import tsx tools/test-browser-events.ts
```

`artifacts/browser-events/report.json` includes the exact browser version,
assertions, quota method, original/replacement public identities, original and
retried proposal IDs, preserved checkpoint, and the distinction between browser
storage loss and missing native history. `bundle.json` audits the emitted Worker
code to establish that this profile loads no SQL/WASM implementation.

| Boundary | Executed scenario | Required result |
| --- | --- | --- |
| Exclusive ownership | Two Workers open the same origin and peer name. | The contender receives `BROWSER_STORAGE_IN_USE`; it cannot share a signing journal. |
| Durable restart | Terminate the Worker before/after checkpoint publication and after a private cutoff flush. | Each reopened state/cursor pair is atomic; original accepted operations retain their exact proposal. |
| Private stores | Save distinct native-agent and browser-device markers under the same private key. | Values remain local; record/event counts do not change. This is a synthetic isolation check, not a review of a deployed agent's data classification. |
| Independent devices | Open the same peer name in an isolated browser context. | Existing keys are absent, implicit opening fails, and explicit setup creates independent public keys. |
| Actual quota failure | Set the origin quota to one byte through Chromium DevTools, then replace a checkpoint and submit application work through the real OPFS Worker. | OPFS rejects the writes, the old checkpoint survives, and failed preparation creates neither a local operation nor a native record. |
| Quota recovery | Restore the origin quota and reopen the Worker. | Original identity/checkpoint remain, an accepted exact retry adds no records, and the previously unprepared operation can be deliberately submitted. |
| Partial storage loss | Delete only the real OPFS feed manifest while retaining device keys and the initialization marker. | Opening fails with `BROWSER_FEED_MANIFEST_MISSING`; restoring the exact saved manifest retains the original identity/proposal without a new native record. |
| Storage loss | Close the Worker and clear origin storage through Chromium DevTools. | Opening fails with `ENROLLMENT_IDENTITY_MISSING`; explicit replacement uses new keys with no inherited grants. Native history remains intact. |

Quota enforcement uses Chromium's actual storage implementation with a controlled
quota. It does not reproduce filesystem exhaustion, operating-system eviction,
mobile power management, or another browser's storage policy. Browser contexts
provide isolated profiles, not physically independent devices. The native peer
and browser use authenticated loopback framing; no public network is claimed.

The thin-membership gate additionally restarts the actual packaged Cloudflare
Durable Object after completed writer and reader revocations. It compares the
root descriptor, full public roster/decision metadata, certified descriptor
pages, and exact approval/revocation receipts. A conflicting retry fails, a
removed reader remains denied, and retries add no native position. Its report is
`artifacts/thin-membership/ci/report.json`. This is real workerd storage reopening;
it is not a deployed Cloudflare volume-loss or portable root-key move rehearsal.

## Authorization regression checks

```sh
pnpm exec vitest run \
  packages/node-core/src/enrollment.test.ts \
  packages/node-core/src/publisher.test.ts \
  packages/node-core/src/capability-membership.test.ts \
  packages/node-core/src/coordinated-governed.integration.test.ts \
  packages/agent-service/src/signals.test.ts \
  packages/agent-service/src/peer-link.test.ts
```

The limited publisher tests submit correctly signed, forbidden topic, SQL and
platform programs directly to ingress, bypassing the convenient publisher API.
They also mutate a signature, retry original signed bytes, reopen the original
journal, and revoke the writer. A signing-only collector has no reader key or
history grant. Authenticated transport tests refuse keys without a read grant,
recheck grants after asynchronous payload lookup, validate received bodies, and
bound outstanding requests.

The governed integration orders a delayed old-grant operation across revocation
and regrant of the same key. The old operation remains rejected; an accepted
exact retry keeps its original result. Signal checks cover signed identity,
mutation, expiry, out-of-order/replayed sequences, revocation, bounded replay
state and outgoing queues, and replacement of slow-consumer values. Transient
signals create no durable event cursor.

One peer-link test uses the native SSB transport and requires network-interface
enumeration. A restricted environment that rejects that OS operation must run
that scenario in CI or a suitable host; passing the portable-link cases does not
stand in for the native transport test.

## Recovery behavior applications must present

Ordinary `openBrowserPeer` and `openBrowserEventPeer` calls load existing keys.
Only an explicit first-device setup passes `createIdentity: true` or creates keys
in its separate enrollment stage. Do not catch a missing/corrupt identity and
automatically call creation. The page must say that this device's local history
or keys are unavailable and offer a deliberate recovery/new-device decision.

Keep original operation references for review when they survived elsewhere.
Erased local keys and unpublished drafts cannot be reconstructed from replicated
application history. A replacement device needs a new identity and reviewed
enrollment; obtain only the history keys that policy authorizes. Revoke a lost
device through the administrator. A new grant must not turn an old rejected or
unresolved intent into a fresh command automatically.

## Checks that require another setting

Use a deployed Cloudflare version and separately authenticated owner and
participant accounts. Record the deployed version, identity-provider settings,
public artifact hashes, native authority configuration, browser/OS versions and
device identities. Perform live request, owner review, capability activation,
authorized historical-key delivery and payload catch-up as separate stages.

Use at least two physical devices and the browsers the product supports. Repeat
storage pressure, background suspension/resume, browser restart, persistence
permission denial and deliberate site-data removal. Save screenshots of the
recovery decision and verify that retained drafts/operation references are
handled honestly. Capture behavior when the operating system kills the browser,
not just when the test terminates a Worker.

Audit the actual agent inputs and data-export code, then use tagged private test
records in that deployment to prove that secrets and private files never enter
shared SQL, events, logs or blob metadata. Compare authorized and revoked
devices at the wire/key boundary. Reader revocation prevents future epoch access;
it cannot erase keys or plaintext already obtained. This profile does not promise
per-topic private histories. Host login/page access alone grants no application
membership.

Do not close the deployment issue on synthetic account, isolated browser
context, loopback, quota-override or unit-test evidence alone. Preserve each raw
report with its exact source/artifact pairing and label the setting used.
