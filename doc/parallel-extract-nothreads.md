# Thread-free extraction experiment

The `parallel-extract-nothreads` branch drives io_uring from the main
thread and applies unsupported metadata operations synchronously. It
creates no userspace worker threads. The kernel can still use io-wq
workers to service asynchronous requests.

This is an experiment, not an established performance improvement. Removing
the metadata pool loses substantial throughput when timestamp restoration
has latency; `--touch` avoids that work but intentionally changes extraction
semantics and is not a substitute for restoring timestamps.

## Measurement

Measured on 2026-09-20, as a non-root user, on x86-64 Linux
`6.16.1-0_fbk5_0_g0e127f210adc`, using local Btrfs on `/dev/vda4`.
The threaded baseline is commit `461b91be`. Both binaries extracted the
same uncompressed GNU-format archive into fresh directories: 5,000 regular
files of 256 bytes, 200 subdirectories, and the root directory, totaling
5,201 members. Archive data was warm in the page cache. No sparse files,
links, compression, or cold-cache behavior were measured.

Times below are seconds. Brackets give the range of three trials; entries
without brackets are single control trials. Sub-second local runs are
particularly sensitive to scheduling and measurement noise.

| Mode | Threaded baseline | Thread-free prototype |
|---|---:|---:|
| Local, default | 0.09 [0.08, 0.09] | 0.16 [0.14, 0.18] |
| Local, `--touch` | 0.09 [0.08, 0.09] | 0.14 [0.12, 0.19] |
| Local, `--no-parallel` | 0.14 [0.14, 0.14] | 0.14 [0.14, 0.14] |
| Synthetic timestamp latency, default | 1.37 [1.36, 1.38] | 26.84 [26.84, 26.85] |
| Synthetic timestamp latency, `--touch` | 0.56 | 0.50 |
| Synthetic timestamp latency, `--no-parallel` | 26.83 | 26.82 |
| Synthetic timestamp latency, `--no-parallel --touch` | 0.47 | 0.49 |

Reported CPU consumption also increased in the local default trials.
GNU time measured median system CPU time of 3.41 seconds [3.08, 3.64]
for the prototype versus 0.74 seconds [0.57, 0.79] for the threaded
baseline. Median user CPU time was 0.02 versus 0.04 seconds. These are
measurements of CPU accounting, not an attribution to a particular code
path. Removing userspace threads does not remove kernel io-wq workers.

The synthetic experiment uses strace 6.12 with
`-f -qq -c -w -e trace=utimensat,io_uring_setup,clone,clone3`
and `-e inject=utimensat:delay_enter=5ms`. Each userspace timestamp syscall
is delayed by 5 ms. This does **not** delay io_uring requests, directory
lookups, file creation, or storage I/O. Strace itself adds overhead; compare
the synthetic cases with each other, not with the untraced local cases.
No real NFS or other network-filesystem measurement was performed.

Both default engines issued 5,201 timestamp syscalls; `--touch` issued
none. The first synthetic threaded run made 137 `clone3` calls as its
metadata pool expanded. The prototype made no `clone` or `clone3` calls
and initialized one io_uring instance. Capping the old metadata pool at
one worker with `--parallel-meta-threads=1 --parallel-max-meta-threads=1`
took 26.66 seconds, confirming that concurrent timestamp calls account for
the threaded advantage in this experiment.

The approximately 19.6-fold synthetic slowdown is a real consequence of
serializing that workload, not evidence of a universal network-filesystem
slowdown. The local fixture also showed no speedup. Contents, object types,
modes, owners, groups, and exact modification times matched the threaded
baseline for every member; timestamp comparison was omitted for `--touch`.

## Reproducing

Keep a separately built threaded executable before building this branch:

```sh
scripts/benchmark-parallel-extract /path/to/threaded-tar ./src/tar
scripts/benchmark-parallel-extract --synthetic-delay=5ms \
  /path/to/threaded-tar ./src/tar
```

The script requires Python 3 and GNU `/usr/bin/time`; synthetic trials also
require strace with delay injection support. Before timing, each binary
must extract an empty archive with explicit `--parallel`, exit successfully,
and produce no diagnostic; this detects unsupported engines and startup
fallbacks that would invalidate the comparison. It saves copies and SHA256
hashes of both binaries, kernel/filesystem information, the deterministic
archive, per-run timing and trace logs, extracted files, and CSV results
in a fresh `mktemp` directory under `${TMPDIR:-/tmp}`. It does not remove
the results. Every extraction is verified outside the timed interval.
Local modes and synthetic default mode run three trials; synthetic control
modes run once. The optional 5 ms experiment takes roughly two minutes
on the measured host.

Measured binary SHA256 values:

- Threaded: `161306288b4bceee4f81c12d6675ece8c213a2759dc152c038ba2cfd1e6103c3`
- Thread-free: `36a3e733888d825ab5b6fa36a2685192f93e943ec6728e1cfb5d3f9aba6ea938`
