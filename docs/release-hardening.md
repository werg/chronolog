# Qualification and release evidence

Qualification targets one application composition: an owned session with explicit
participant roles and transport adapters. Tests of removed daemon, hosted-data,
RPC and resident products are not current acceptance evidence.

## Semantic and lifecycle gates

`pnpm test` covers signed controls, author/coordinator separation, encrypted
history, lost replies, exact retries, selection races, three-generation ancestry,
revocation, missing bodies, coherent recovery, retained content, bounded streams,
device ownership and session shutdown. Deterministic model traces supplement the
real replica and materializer tests.

`pnpm test:publication-crash` kills a real native child process at publication
boundaries, reopens the materializer and checks published SQL, outcomes and events.
`pnpm test:fuzz` exercises canonical encodings and SQL inputs.
`pnpm test:soak` measures repeated materialization, replay and reopen.
`pnpm test:native-sanitizers` runs the patched C engine under sanitizers.

`pnpm conformance` compares the common execution adapter with the materializer
and emits engine and execution digests. Linux/macOS comparison requires matching
portable semantics; operational platform metadata remains distinct. The WASM
workflow builds the pinned engine and runs
`packages/materializer-doltlite/src/wasm-conformance.test.ts` against native results.

## Independent public consumers

Build clean archives with `package-peer-session.mjs` and
`package-peer-generation-control.mjs`. The session packager records source commit,
tree, every input, emitted file hashes, optional RTC dependency and exact native
SQL engine identity. Default imports are SQL-free and share ESM chunks so separate
entry points cannot create duplicate session classes or ownership registries.

The contrib recipes consume archives without sibling-source imports. They cover
conversation and guarded SQL tasks, native RTC, browser Worker/OPFS ownership and
Tendriller's actual hosted participant contract. Hosted checks include role
filtering, account and signed authority, zero steady-state command traffic, lost
transition responses, signed page publication, served assets and restart.

Evidence must name its exact source and artifact identities. A development
`--allow-dirty` archive is not clean release evidence. A skipped test or blocked
browser launch is not a pass. Reports preserve the transport, engine and limits
actually exercised.

## Deployment gate

Local native RTC and Worker tests do not qualify representative home, mobile or
restrictive networks. Before deployment promotion, record actual authentication,
discovery/control, direct and relayed RTC, browser suspension, storage limits,
content transfer, churn and recovery. Measure hosted requests, stored bytes,
peer CPU/memory/bandwidth, retained-prefix age and time to usable state under a
specified workload. Do not infer provider savings or a universal loss bound from
loopback behavior.

Automatic irreversible effects are disabled. Any optional protected effect
service requires its own authorization, prerequisite retention, idempotency and
uncertain-result reconciliation evidence.
