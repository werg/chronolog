# Compact membership proofs

Participant administration retains governance records and a constant-sized
application checkpoint. It does not download, store, or replay application
descriptors, application bodies, or every intervening finality closure.

The signed-inclusion provider is `signed-inclusion-v2`. This is a breaking
prerelease protocol; v1 closure and membership wire formats have no compatibility
adapter.

## One ledger, two authenticated views

Full replicas still verify the original complete receipt ledger and every
historical closure. That path determines application admission, chronological
execution, and finality. The application order remains signed author timestamp,
author key, and proposal identity.

Each finality closure additionally signs the count and rolling root of the
complete finalized control projection. When a closure first covers a receipt,
every valid typed `capability` or `epoch-manifest` descriptor contributes:

- Its consecutive control index and preceding control root.
- The exact original ordered entry, including its application receipt position
  and original receipt hash.
- The author-time cutoff of that first covering closure.

The initial control root binds the entire history configuration, including the
group, genesis, execution profile, authority key, provider ID, and parameters.
Each subsequent root hashes a domain-separated canonical encoding of the prior
root, index, exact ordered entry, and original cutoff. Application descriptors
and malformed generic log records do not contribute. Typed controls for another
group remain committed and are ignored by the ordinary governance interpreter.
That deterministic classification prevents a transport from deciding which
potential governance records to omit.

Full replicas recompute the projection from every original receipt and reject
a correctly signed closure if its control count or root disagrees. A thin
consumer verifies the cumulative control chain against the same signed closure.
The authority remains the genesis-pinned inclusion and time authority; no host
login, TLS identity, or unsigned server filter can make a governance record
effective.

A thin consumer trusts that authority to commit the complete projection. It
cannot audit a signed omission without the original application receipts; full
replicas perform that audit. Persisted checkpoints detect local rollback and
conflicting roots, but discovering an otherwise unseen authority fork requires
exchanging evidence. This is the existing single-authority inclusion model,
with the projection commitment made explicit.

## Compact pages and independent cursors

`NativeAuthority.certifiedControlRead({ after, limit })` returns at most 128
controls and at most 1 MiB of encoded control entries, with:

- `entries`: consecutive `FinalizedControl` values.
- `checkpoint`: the latest committed closure entry, or `null` for an empty log.
- `certificate`: the authority's prefix certificate covering that exact closure
  entry.
- `hasMore`: whether controls remain after this page.

The client verifies the original entry hashes, cumulative roots, closure
signature, genesis configuration, and covering certificate. It requires
increasing original receipt positions, nondecreasing original cutoffs, and a
checkpoint that cannot regress. Removing, reordering, or rewriting a control or
its cutoff breaks the committed root. A failed transfer can restart from the
last verified control index. Partial pages cannot activate grants and are not
saved as a verified checkpoint.

`ControlHistory` bounds pending and retained controls to 16 MiB and 65,536
entries. A deployment can configure a lower byte quota. The limit is checked
while each partial page arrives, before the transfer completes. Durable storage
failure leaves the preceding verified checkpoint effective.

| Progress field | Meaning |
| --- | --- |
| `receivedThrough` | Control entries received in the current transfer, including an unverified partial suffix. |
| `verifiedThrough` | Number of control entries authenticated by a complete signed checkpoint. This is the membership `after` cursor. |
| `root` | Verified cumulative control root. |
| `receiptThrough` | Application receipt position included by the latest verified closure. |
| `checkpointThrough` | Receipt position of the committed closure marker itself. |
| `closedThroughMs` | Latest verified closed author-time frontier. |

Application activity can advance the last three fields while the control count
and retained control bytes remain unchanged. A participant request obtains the
latest checkpoint; there is no idle Cloudflare polling or write-per-application
operation. Key-wrap size and retained governance still grow with participant
changes, which is an explicit membership cost.

Each administrator sync pins the first authenticated checkpoint and reads only
through its control count. Participant changes that arrive during pagination
are left for the next operation, so they cannot extend an in-flight host request
indefinitely.

## Enrollment and peer ownership

`MembershipAdministrator` uses this proof store instead of the full inclusion
ledger verifier. It applies each control using the existing governance verifier
and its original cutoff. Exact approval/revocation operation identities and
epoch rotation recovery remain durable. Captured enrollment targets still name
the original application receipt root and closed time.

A fresh full replica calls `governed.ingestMembership(page)` to verify these
proofs, establish active reader grants, and unwrap its epoch keys. This step
retains no application receipts and cannot make application enrollment ready.
The replica then authenticates its WebRTC peer and obtains the complete original
application history over that connection. Application finality independently
verifies the complete ledger, including recomputation of the control projection.
The bootstrap proof is durable so a restarted Worker can authenticate again
without asking the host for the same governance history.

The native membership HTTP handler can repair delivery of its retained evidence
to a local replica sink after a failed administrative append. Those complete
receipt entries stay inside Chronolog; only compact controls and the checkpoint
enter the HTTP membership response.

## Verification

Focused tests exercise omitted and reordered controls, altered bodies and
cutoffs, foreign configuration, invalid checkpoints, a substituted chain with
valid individual hashes, rollback and signed equivocation, interrupted pages,
memory limits, restart, and failed durable writes. Full replica tests reject an
authority-signed projection that omits a control. Membership tests append a
large application-only prefix and verify zero additional application descriptor
bytes at the administrator.

The current native cost report format is `chronolog-membership-cost/v2`; the
browser membership format is `chronolog-thin-membership/v3`. They require zero
application descriptor and body bytes at the administrator, distinguish control
and receipt progress, and retain the actual native/browser RTC qualification.
Historical reports identify their earlier source versions and do not qualify
this protocol.
