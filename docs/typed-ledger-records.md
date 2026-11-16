# Typed ledger records and detached application payloads

The inclusion receipt log retains small Chronolog descriptors. Exact-byte IDs,
receipt positions, a hash chain and prefix certificates authenticate that data.
Signed closure records additionally prove which author timestamps are closed.
Application execution always uses the shared chronological comparator; receipt
positions never select execution order. Membership controls occupy this same
ledger and follow their signed causal chains. The configuration binds the group,
genesis, execution profile and finality provider identity/parameters.

Genesis uses wire version 2 and the signing domain `chronolog/genesis/v2`.
It explicitly authenticates two independent public keys: `rootAdminPublicKey`
issues roster and key-distribution operations; `schemaAdminPublicKey` initializes
the SQL `group` collective. The default Cloudflare administrator holds the former
and the native application owner holds the latter. Roster administration gives
no implicit SQL membership or schema privilege. Readers require both fields;
there is no fallback that assigns the SQL role to the roster issuer.

The canonical genesis map is contiguous: version (0), group (1), execution profile
(2), roster root (3), schema administrator (4), capability feed (5), initial
capabilities (6), validation policies (7), clock policy (8), resource policy (9),
encryption suite (10), creation time (11), optional fork origin (12), and optional
history policy and verifier selection (13). The signed wrapper is also version 2. Version 1 input is
rejected; this prerelease change defines a new authenticated group configuration.

`@chronolog/node-core/ledger` defines the descriptor boundary. A descriptor has a
kind, group route, encryption epoch, SHA-256 payload address and exact payload
length. Application candidates are detached references to their original signed
and encrypted envelope bytes. Capability revisions and epoch manifests carry
their original unencrypted, signed envelopes inline.

The log's committed kind determines interpretation. A full participant may not
fetch a candidate and then reinterpret its bytes as governance. Before any
application decryption or execution, `verifyLedgerPayload` checks the exact hash,
length, envelope kind, group route and encryption epoch. The ordinary Chronolog
wire and governance verifiers still check signatures and authorization. A valid
descriptor by itself does not establish the inner message's validity.

`decodeLedgerRecord` validates inline control bytes immediately, so a membership
administrator can scan every certified descriptor and every governance operation
without requesting application ciphertext. It must still verify the complete
receipt prefix, including signed finality closures. Filtering out descriptors
or closures on the server would not establish
the absence of an omitted membership change. Unknown or malformed descriptors
are deterministically invalid records; readers must not fall back to treating
them as the previous envelope-in-ledger format.

## Storage and availability

`createLedgerRecord(envelopeBytes)` returns `recordBytes`, its decoded `record`,
and `detachedPayload` for a candidate. Persist the original payload before
appending the descriptor. Keep both exact values for lost-response retries;
reencrypting the same intent would create a different payload address.

`resolveLedgerPayload(record, getPayload)` fetches only detached candidates.
Inline controls never invoke the provider. A missing body produces
`LEDGER_PAYLOAD_UNAVAILABLE`; a storage/provider failure remains a storage/provider
failure. Neither means that the application position may be skipped or that the
proposal was rejected. Certified inclusion, closed author time, body availability, effective roster
state and applied application state are separate progress conditions.

A provider response that does not match the committed hash is still unavailable
trusted input. In contrast, once that exact hash matches, an inconsistent
committed length, malformed envelope, or contradictory kind/route/epoch proves
an invalid ledger position. The full reader deterministically advances past it
without manufacturing a proposal outcome. Provider failures are kept outside
this classification; arbitrary failed fetches cannot erase a candidate.

For application admission, the epoch on the verified envelope must match the
rotation effective at its signed author timestamp. Receiving a later key wrap
does not rewrite earlier activation. A stale prepared operation gets
`ENCRYPTION_EPOCH_CLOSED`, or `FINALITY_TIMESTAMP_CLOSED` when first included behind
an already closed time, under its original proposal ID. An exact previously
finalized retry preserves its result. If the epoch and its causal predecessors
were absent from the candidate's first covered inclusion set, the descriptor
is invalid there and is skipped without claiming an unverified proposal ID.
A later manifest cannot retroactively satisfy that inclusion dependency. If the epoch
was issued but its key is locally missing, application still waits for authorized
key delivery. Unavailable bytes remain pending. This fence does not prevent an
authorized participant from separately disclosing data or keys it already possesses.

The descriptor format does not promise payload replication or availability. Its
payload store and peer transport must enforce their own durability, authorization,
bounded requests and retention rules. It also does not declare an application
result final without the normal execution and publication boundary.

## Bounds

| Value | Maximum |
| --- | --- |
| Encoded ledger descriptor | 262,144 bytes (256 KiB) |
| Inline governance envelope | 261,632 bytes (512 bytes reserved for descriptor metadata) |
| Detached application envelope | 1,048,576 bytes (1 MiB) |
| Opaque encryption-epoch identifier | 32 bytes |

Governance records can grow with recipient key wraps. The inline bound is
explicit: an oversized operation fails with `LEDGER_CONTROL_TOO_LARGE` and its
byte limit; it is not silently detached or truncated. Application descriptors
contain no candidate payload, regardless of the detached envelope's size.

These helpers define and test the portable byte boundary. Runtime, host-admin,
payload-provider and real-browser integration are qualified by their respective
gates; this codec alone makes no deployment qualification claim.
