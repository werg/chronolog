# Browser/native route qualification

This gate supports [contrib issue #14](https://github.com/werg/tendriller-contrib/issues/14).
It runs the real task-board/chat pages, independently persisted browser replicas,
the native SQL authority and final-intent worker, and public Tendriller packages.
The native ordering identity and application history remain unchanged when the
selected byte route changes.

## Reproduce the automated gate

After building the pinned SQL/WASM engine and public Tendriller packages, run:

```sh
node --import tsx tools/application-pilot.ts \
  --contrib /checkout/tendriller-contrib \
  --tendriller-runtime /public-artifacts/runtime \
  --tendriller-engine /public-artifacts/engine \
  --wasm artifacts/wasm \
  --output artifacts/application-pilot/new-route-run
```

The output directory must be new. Omitting `--tendriller-engine` retains the
existing HTTP loopback fixture for focused page checks. The browser workflow
supplies the engine and therefore exercises the WSS/relay qualification. It
checks out exact public artifact sources, builds the engine and both layouts,
and preserves reports, screenshots, bundle provenance and `route-trace.ndjson`.
`--build-only` builds and audits assets without claiming a browser execution.

| Route | Actual local topology | Authentication boundary |
| --- | --- | --- |
| Direct | Chromium → local TLS WebSocket endpoint → native application peer | Real signed group/read-grant handshake |
| Relay | Chromium → local TLS bridge → packaged workerd paired relay → native application peer | Real relay account/session validation with an explicitly synthetic page-session bridge, followed by the same signed application handshake |

The bridge is part of the recorded topology. It passes opaque frames and supplies
a synthetic authenticated page session to workerd; it does not expose the agent
token to the browser. This fixture does **not** establish a deployed browser login,
cookie/origin route, tunnel/NAT behavior or public Cloudflare service. Its
ephemeral TLS certificate is trusted only by this local qualification browser.
The simulator's location metadata fetch and telemetry are disabled.

## What the scenario establishes

The board initially uses direct WSS and the compact layout initially uses the
packaged relay. They independently catch up, author competing claims while
disconnected, retain one final acceptance and one final rejection, deliver
ephemeral typing, and process the final agent intent once. Delayed replies and
abrupt page/Worker replacement preserve each device's original operation and
draft. Host application persistence stays disabled throughout.

Both replicas must expose identical effective event transactions and durable
scan cursors. Their local publication revision tokens need not match. Original
operation receipts are compared on their authoring devices; another replica's
effective history does not create a second author outbox.

The gate then selects direct WSS for both replicas and disables relay admission.
A warm direct session must still finalize a new chat message. This checks loss
of the relay alongside already unavailable host application persistence; static
assets, bootstrap and authentication services are not all shut down.

Next, both replicas disconnect. The native peer publishes a message and four
192-KiB payload samples. Reconnection explicitly swaps the selected routes,
recovers missing history, and preserves the original accepted/rejected outcomes.
There is no automatic authority change or hidden fallback writer.

## Measurements and limits

`report.json` records exact sources/artifact hashes, Chromium version, cold
bootstrap and reconnect/catch-up timings, native/public browser session byte
counters, per-domain counts, sampled queue sizes and a stable final-event digest.
`route-trace.ndjson` contains one fixture-relative clock, session IDs, route,
direction, domain and encoded byte length. It contains no frame payloads,
credentials or private keys.

- SDK counters include the three-byte Tendriller envelope, record fragmentation
  and application protocol overhead. They exclude WebSocket/TLS/TCP overhead.
- Raw per-domain observations additionally count relay readiness and credit text.
  These observations overlap SDK totals; do not add them as separate traffic.
- Native queue high-water observations are sampled every 10 ms. They are neither
  an exhaustive maximum nor a saturation stress test. Public protocol/relay tests
  separately exercise the configured receive/send/credit bounds.
- Catch-up application bytes count the four authored string bodies. The elapsed
  time includes connection/authentication and replay; it is not a network-only
  transfer rate or latency guarantee.
- Page performance metrics are end-of-scenario snapshots and exclude Worker/WASM
  memory. Native peak RSS includes this qualification harness and excludes
  workerd and browser child processes. Whole-device peak memory remains unmeasured.

The separate thin-membership gate counts descriptors, inline controls and
detached application envelopes at its real administrator/peer boundaries. Route
frame bytes are not a substitute for that semantic accounting. The administrator
must still receive zero application bodies; provider relays carrying those
bodies remain a separate bandwidth/cost responsibility.

## What must run in a different setting

Use a deployed public host and native authority with the actual identity-provider
configuration. Record exact public package hashes, deployed version, browser/OS,
native process/volume configuration, DNS/TLS endpoints, every tunnel or relay and
the selected network. Repeat the same workload on home Wi-Fi, mobile hotspot and
a restrictive corporate network. Record unsupported routes as failures or
unsupported cases, never inferred direct success.

For each network, measure connection establishment, cold and warm catch-up,
actual wire/provider bytes, whole-browser/Worker/native peak memory and queue
behavior under deliberate slow readers. Exercise real browser suspension,
native process restart, interrupted connections and the available fallback.
With an already established direct session, stop the deployed host services and
record exactly which operations remain usable. Keep signed history/outcomes
identical when comparing routes; host application-state requests must stay zero.

Select the production route and fallback from those measurements. Direct WSS is
a candidate when the native agent is publicly reachable; the paired WSS relay
is the implemented fallback candidate. No WebRTC adapter, mobile/corporate route,
provider billing or production route selection is claimed by this local gate.
