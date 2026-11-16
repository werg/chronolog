# Documentation index

Chronolog is an unreleased prototype. A transaction is a list of ordinary
SQLite statements; determinism comes from a pinned engine with fixed
per-transaction inputs. Documents are classified as follows.

| Class | Meaning |
| --- | --- |
| **Normative** | Defines behavior. |
| **Status** | Describes the current boundary or roadmap; must track the code. |
| **Operational** | How to run, verify, or recover the system. |
| **Background** | Useful context, not a requirement. |

Run `pnpm docs:check` to verify that every relative Markdown link and anchor
resolves.

## Read first

- **Developer:** [README](../README.md), then [design](design.md) and
  [Specification 10](implementation-specs/10-deterministic-sql-transactions.md).
- **Operator:** [Pilot runbook](pilot-runbook.md), then
  [governance](governance.md), [snapshot recovery](snapshot-recovery.md) and
  [release hardening](release-hardening.md).
- **Reviewer / security:** [Implementation status](implementation-status.md),
  [security threat review](security-threat-review.md), then
  [upcoming work](../upcoming.md).

## Normative

| Document | Status | Contents |
| --- | --- | --- |
| [design.md](design.md) | Normative | How the system works: transactions, determinism, admission, ordering, replication, membership, materialization. |
| [implementation-specs/10-deterministic-sql-transactions.md](implementation-specs/10-deterministic-sql-transactions.md) | Normative | Replicated SQL transactions: values, program, execution, block-list, transaction log. |
| [implementation-specs/README.md](implementation-specs/README.md) | Normative index | Where the contract lives; no-compatibility rule. |

## Status and roadmap

| Document | Status | Contents |
| --- | --- | --- |
| [implementation-status.md](implementation-status.md) | Status | What works end to end and what remains. |
| [../upcoming.md](../upcoming.md) | Status (ordered roadmap) | Project queue and acceptance checks. |
| [security-threat-review.md](security-threat-review.md) | Status | Internal authorizer/protocol review and open findings. |
| [design-owner-rows.md](design-owner-rows.md) | Implemented | Owner-controlled rows: the signing key owns its rows; generated write checks, app triggers narrow (write half of Namlu design K). |
| [app-ownership.md](app-ownership.md) | Guide | Owned rows in app code: identity, typed rejections, sharing, teams, transfers, ownership queries and React hooks. |
| [sealed-data.md](sealed-data.md) | Guide | Explicit per-row reader policies, encrypted BLOB columns, key rotation, finality and confidentiality limits. |
| [production-execution.md](production-execution.md) | Decision record | Why the first pilot is the native daemon, and criteria to reconsider workerd. |

## Operational

| Document | Status | Contents |
| --- | --- | --- |
| [pilot-runbook.md](pilot-runbook.md) | Operational | Install, onboard, capacity, backup, upgrade, recovery, mandatory drills. |
| [governance.md](governance.md) | Operational | Capabilities, epochs, key storage, joining and forking groups. |
| [snapshot-recovery.md](snapshot-recovery.md) | Operational | Signed snapshots, restore, feed-fork repair. |
| [release-hardening.md](release-hardening.md) | Operational | Fuzz, sanitizer, crash, soak, distribution, observability gates. |
| [chaos-testing.md](chaos-testing.md) | Operational | Container fault and load testing. |
| [drill-evidence.md](drill-evidence.md) | Operational | Recording, signing, verifying, and gating release drill evidence. |

## Background

| Document | Status | Contents |
| --- | --- | --- |
| [../packages/materializer/README.md](../packages/materializer/README.md), [../packages/runtime-workerd/README.md](../packages/runtime-workerd/README.md) | Background | Portable materializer contract and experimental workerd adapter. |
| [workerd-reconstruction-plan.md](workerd-reconstruction-plan.md) | Background | Options and staged plan for a real workerd execution target. |
| [handover-2026-10-23.md](handover-2026-10-23.md) | Historical (dated) | Review and hardening pass before the 2026-11-13 redesign. |
