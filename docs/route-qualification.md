# Browser/native WebRTC qualification

This gate supports [contrib issue #14](https://github.com/werg/tendriller-contrib/issues/14).
It runs the real task-board/chat pages, independently persisted browser replicas,
the native SQL authority and final-intent worker, and public Tendriller packages.
Chronolog owns the original signed history, authorization, execution and finality.
The page host introduces a connection; ordinary application frames use WebRTC.

## Reproduce the application gate

After building the pinned SQL/WASM engine and public Tendriller packages, run:

```sh
node --import tsx tools/application-pilot.ts \
  --contrib /checkout/tendriller-contrib \
  --tendriller-runtime /public-artifacts/runtime \
  --tendriller-engine /public-artifacts/engine \
  --wasm artifacts/wasm \
  --output artifacts/application-pilot/new-rtc-run
```

The output directory must be new. A runtime qualification requires the packaged
engine; there is no implicit HTTP or hosted application-data fallback. The browser
workflow checks out exact public artifact sources, builds the engine and both
layouts, and preserves reports, screenshots, bundle provenance and
`route-trace.ndjson`. `--build-only` compiles and audits assets without claiming
that browser scenarios ran. The runtime report format is
`chronolog-application-pilot/v2`.

| Boundary | Actual local topology | Responsibility |
| --- | --- | --- |
| Page assets | Local HTTP server → Chromium | Initial HTML, public bundles, Worker and WASM assets. |
| Optional host introduction | Chromium → local TLS bridge → packaged workerd rendezvous → native peer | One complete SDP description per endpoint, followed by signaling closure. |
| Application data | Chromium Worker ↔ reliable ordered WebRTC DataChannel over loopback UDP ↔ native peer | Signed records, bodies, finality evidence and ephemeral signals. |
| Application authentication | The same Chronolog session at both RTC endpoints | Nonce/signature authentication and current reader-capability checks. |

The TLS bridge supplies an explicitly synthetic authenticated page session to
the actual packaged workerd rendezvous. It does not forward application frames
or expose the native agent token to the browser. The fixture arranges both
endpoints' participation; this is not an idle resident discovery mechanism.
Its local certificate is accepted only by the qualification browser. Real
identity-provider login, public DNS and Internet NAT behavior are outside this
gate. Simulator telemetry and location metadata fetching are disabled.

## Separate direct resident introduction

Production pages can instead use a configured resident HTTPS endpoint, with no
Tendriller involvement in connection setup. The public transport package provides
`createHttpWebRtcSignaling` and `createWebRtcOfferHandler`; the contrib cookbook
provides the Window-to-Worker connection recipe and an actual native HTTPS
resident task. See [the transport guide](../packages/transport-webrtc/README.md).

Two smaller gates exercise that path independently of the SQL application pilot:

```sh
node --import tsx tools/test-resident-webrtc.ts \
  --contrib /checkout/tendriller-contrib --output artifacts/resident-webrtc
node --import tsx tools/test-browser-webrtc.ts --output artifacts/browser-webrtc
```

The resident gate uses the exact public recipe, a trusted generated TLS
certificate, bounded HTTP admission and the real native RTC adapter. It checks
that introduction permission alone cannot read history, that admitted peers
still need an active Chronolog reader grant, and that abort/bind-error cleanup
releases the listener and peer resources.

The browser gate transfers the untouched RTCDataChannel from the Window into
the exclusive OPFS Worker. It physically stops its combined page/introduction
HTTP listener, then exchanges new operations and a 512 KiB content-addressed
body, retries an original operation, and compares final events and original
record digests. Its report separates signaling, host requests and subsequent
logical RTC frame bytes. Build-only output is not passing runtime evidence.

## Application scenarios and replay lifetime

Both layouts initially connect through the bounded workerd SDP introduction.
They independently catch up, author competing task claims while disconnected,
retain one final acceptance and one final rejection, deliver expiring typing
signals, and process the winning final agent intent once. The fixture holds the
native closure clock only while both competing proposals are authored and
included; it does not assert that an arbitrary old offline write remains
admissible after its timestamp has closed.

Delayed replies and abrupt page/Worker replacement preserve each device's
original operation and draft. Both replicas must expose identical effective
event transactions and durable scan cursors. Their local observation timestamps
and materialization revision tokens are not operation identities. Original
receipts are checked on their authoring devices; replicated history does not
create a second author outbox.

The gate waits for every introduction socket to close, then stops the TLS
host/introduction listener. A warm authenticated RTC session must finalize a
new chat message. Signaling counters must remain unchanged, logical RTC bytes
must increase, and host application requests and writes must remain zero. This
application scenario leaves its separate static-asset server running; the
smaller browser gate above independently stops the combined page/introduction
listener.

Next, both replicas disconnect. The native peer publishes another message and
four 192 KiB programs, each containing sixteen 12 KiB events within the public
per-event limit. Fresh introductions must recover the complete retained history
and preserve the original accepted/rejected outcomes. Signed-record digests,
active capability digests and final ordered positions must match the native
replica. No authority identity changes during reconnection.

An authenticated connection and completed history application are distinct
states. The Worker attachment command finishes after authentication and feed
attachment. Startup explicitly awaits its schema/team history before using it;
the reconnect scenario separately observes committed record, ingestion and
finality frontiers. Replay is bounded by its own deadline. Observation polling
must not queue another full catch-up behind ongoing SQL/WASM materialization or
extend a deadline indefinitely when a Worker observation stops answering.

## Measurements and limits

`report.json` records exact sources/artifact hashes, Chromium version, cold
bootstrap, connection attachment and replay timings, native/browser session byte
counters, signaling observations, sampled queue sizes and a final-event digest.
`route-trace.ndjson` records a fixture-relative clock, session transitions and
encoded signaling sizes without credentials, private keys or frame payloads.

- RTC counters measure logical authenticated peer-frame payload bytes. They
  exclude RTC framing headers/credits and SCTP/DTLS/UDP/IP overhead. SDP JSON
  envelopes are counted separately; these observations are not provider billing.
- Native queue high-water observations are sampled every 10 ms. They are not
  exhaustive maxima or whole-device memory measurements. Transport tests
  separately exercise configured frame, queue and credit bounds.
- Catch-up application bytes count the four authored string bodies. Elapsed
  time includes connection/authentication and durable SQL replay; it is not a
  network-only throughput or latency guarantee.
- Page performance snapshots exclude Worker/WASM memory. Native peak RSS
  includes the qualification harness and excludes workerd/browser children.

The separate thin-membership gate uses authenticated native/browser RTC for
application transfer and signed HTTP requests for participant administration.
It counts descriptors, inline controls and detached application envelopes at
the actual administrator/peer boundaries. The administrator must receive zero
application bodies. It still verifies the required certified descriptors when
invoked; these checks do not establish a sparse control-proof protocol.

## Deployment qualification

Use a deployed page host and reachable resident HTTPS endpoint with the actual
identity-provider and introduction-admission configuration. Record exact public
package hashes, browser/OS, native process/volume configuration, DNS/TLS
endpoints, ICE configuration, selected candidate pair and every configured TURN
relay. A successful RTC connection alone is not evidence of a direct route.

Repeat the workload on home Wi-Fi, a mobile hotspot and a restrictive corporate
network. Record unsupported routes explicitly. Measure cold/warm connection and
replay, actual wire/provider bytes, browser/Worker/native memory, slow-reader
queues, suspension, native restart and interruption recovery. Stop the deployed
host after connection and identify which existing operations still work.

The resident's HTTPS endpoint and an ICE route must be reachable for a cold
connection. An unreachable resident needs an explicit wake/discovery provider
or an existing peer path. STUN/TURN and reconnection policy are deployment
configuration; there is no implicit hosted application relay. These local gates
do not establish Internet direct-connect rates, TURN interoperability, mobile
storage behavior or measured provider savings.
