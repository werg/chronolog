# Native SQL reader resource qualification

The [measurement tool](../tools/measure-materializer-readers.ts) qualifies native
captured-reader ownership at increasing retained histories and after prefix
recovery. It uses the materializer's existing database-factory diagnostic seam;
it changes no engine, retention or garbage-collection behavior.

The [recorded run](qualification/native-readers-5ab5b9e.json) passed from clean
commit `5ab5b9e895594e4feeaae92a874f0b2627bf580d`, with source tree, tool hash,
materializer hash, native engine digest and execution manifest in the report.
It ran on Linux x64 with Node `v24.22.1` and the pinned native engine reporting
SQLite `3.54.0`. The captured-reader implementation is unchanged from the
`c195ad2` reader-lease increment.

## Reproduce

From a checkout with its pinned native dependencies built, use a fresh output
directory:

```sh
node --import tsx tools/measure-materializer-readers.ts \
  --output artifacts/native-reader-resources --captures 128
```

The tool keeps its disposable database beside `report.json`. It refuses an
existing output directory and exits unsuccessfully if a measured invariant
fails. Inputs are synthetic canonical SQL replay commands and preverified control
context at the materializer boundary. This isolates SQL publication and read
ownership; the result does not claim peer transport, full session or deployed
volume qualification.

Each command inserts one row containing 128 payload bytes. Checkpoints occur
every eight commands and retain eight checkpoints. Each measurement captures
and queries 128 sequential views, then fills the total 16-handle allowance and
checks that a seventeenth handle is refused. Existing held views count toward
that allowance.

## Observed results

| Selected commands and phase | Database bytes before reads | Live reader connections | Additional connections during reads | Branch/publication method calls during reads | File growth during reads |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0 | 222,080 | 2 | 0 | 0 | 0 |
| 8 | 386,672 | 2 | 0 | 0 | 0 |
| 32, with the eight-row view held | 1,126,767 | 3 | 0 | 0 | 0 |
| Recovered to 4, with eight- and 32-row views held | 1,153,967 | 4 | 0 | 0 | 0 |
| Reopened at 4 | 1,167,254 | 2 | 0 | 0 | 0 |

Every read phase recorded zero database opens and closes, branch creations,
deletions and moves, checkouts, resets and commits. Its complete observed file
sizes were unchanged. Publication, recovery, retirement and reopen remain
separate mutation boundaries; their counters and file sizes are retained in the
raw report.

The held views continued to return eight and 32 rows after the current selected
prefix changed to four. Releasing the first held view reduced live reader
connections and reader branches from four to three; releasing the second reduced
them to two. The observed peak was four reader connections for this workload.
This is a measured peak, not a general upper bound on distinct retained
revisions. Shutdown closed all 40 opened connections exactly once and left zero
active connections. Reopen read the recovered four-row prefix.

## What this establishes

Capturing and querying an already published revision reuses its immutable SQL
reader. It requires no new database connection or branch/publication method
call in any measured phase. Older captured revisions retain their own reader
until the final lease is released, including across prefix recovery.

Retained physical storage still grows with publication. Logical recovery to an
earlier prefix did not shrink it; the database was 1,168,317 bytes after final
close. This measurement performs no compaction or garbage collection and does
not infer long-run growth from 32 commands.

Physical bytes read and written are **unknown**: there is no filesystem tracing
or native VFS instrumentation in this tool. Unchanged file sizes do not prove
the absence of every possible in-place write. No separately named WAL file was
exposed, so separate WAL bytes are also recorded as `null`; this does not prove
the absence of an internal append log. The report supports the explicit
connection/ref-ownership claims above, without asserting zero physical I/O.
