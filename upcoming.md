# Upcoming Work

Status: active ordered roadmap for the unreleased prototype

This file is the execution queue; work proceeds from top to bottom. What
already works is in [implementation status](docs/implementation-status.md).
The 2026-11-13 redesign replaced the earlier SQL compiler, dialect, result
envelopes, blob replication and ssb-db2/EBT transport; the projects that built
them are not tracked here any more (see git history).

## Project 1 — Release and operational hardening

Status: in progress

Done: deterministic codec fuzz corpora, native ASan/UBSan runner, publication
crash matrix, replay soak and characterization, SBOM/provenance/OIDC
attestations, self-verifying Linux/macOS archives with a same-build
replacement drill, Linux Secret Service key storage, feed-fork quarantine and
signed-head repair, signed snapshot export/import, health/metrics/doctor,
external-vantage reachability proof, the internal threat review, and the
governance RPC/CLI.

Remaining:

- [ ] Cross-platform (Linux/macOS) replay comparison of the pinned engine
      build and resource characterization on release hardware.
- [ ] Verify the macOS, Windows and command key providers on real hosts.
- [ ] Execute and record the snapshot-repair, traversal, alert and
      previous-version upgrade drills ([drill evidence](docs/drill-evidence.md)).
- [ ] Resolve or accept every finding in the
      [threat review](docs/security-threat-review.md) and commission the
      independent external security assessment.

Acceptance:

- [ ] No unresolved release-blocking fuzz, sanitizer, crash, or security finding.
- [ ] Pilot operators can install, onboard, rotate, fork, inspect, and
      upgrade without editing internal stores.
- [x] The active manifest advertises no unimplemented or unproven feature.

## Project 2 — Workerd execution target

Status: analysis only

Follow the staged plan in
[workerd-reconstruction-plan.md](docs/workerd-reconstruction-plan.md). The
native daemon stays the production path until workerd meets the criteria in
[production execution](docs/production-execution.md#reconsidering-workerd).
