# SAPP output

[SAPP](https://github.com/facebook/sapp) is Meta's open source static analysis
post-processor. It stores results from static analyzers such as Pysa and
Mariana Trench and provides a UI for triaging them. `--format sapp-json` writes
a bundle that SAPP can ingest.

## Writing a bundle

```bash
node dist/index.js --project <path-to-project> \
  --format sapp-json --output-dir /tmp/prophecy-sapp
```

For one project root and no sharding, this writes `runner_metadata.json`,
`sapper_metadata.json`, `issues_1.sapp`, and `traceFrames_1.sapp`. Use a fresh
output directory, or SAPP will also ingest files left by an earlier scan.

`--sapp-project` sets the project name in the runner metadata; it defaults to
the first root's `package.json` name or directory name. `--sapp-commit` sets
the revision; it defaults to the checked-out Sapling revision, when there is
one. File paths are relative to `--repo-root`.

Each repeated `--project` root is analyzed separately and writes its own issue
and trace files into the same bundle. With `--rules auto`, each root selects
its own preset. Bundle metadata comes from the first root, so pass
`--sapp-project` to give a multi-root bundle a deliberate name. Findings with
the same handle are deduplicated across roots.

## Warning codes and features

Each issue's warning code comes from the first category of its sink rule, not
from the first sink reached in the program. The codes are listed under
[finding categories](../README.md#finding-categories), and
`sapper_metadata.json` names and describes each one.

Issues carry `prophecy-reporting-kind` and `prophecy-reporting-limitation`
features; see [reading reports](reading-reports.md). The bundle keeps one issue
per raw finding and every trace frame.

## Sharding large scans

To split one project across processes, run every shard index from `0` to
`--shard-count - 1` with the same source, options, root order, and output
directory. This runs **only shard 0 of 8**:

```bash
node dist/index.js --project <path-to-project> \
  --format sapp-json --output-dir /tmp/prophecy-sapp \
  --shard-index 0 --shard-count 8
```

Every shard parses the whole program and discovers the same entry points, then
analyzes a round-robin subset of them. Shard files are numbered
`shardIndex * 1000 + rootIndex + 1`, so keep each invocation below 1,000
project roots. SAPP ingests every `*.sapp` file in the bundle as one run.

After **all** shards finish successfully, remove duplicate issue rows:

```bash
node dist/index.js --merge-sapp-bundle /tmp/prophecy-sapp
```

This keeps the first issue row for each finding handle and every trace frame.
Do not merge while a shard is still writing.

Every process builds its own TypeScript program, so size concurrency to the
available memory.

## Long scans

- `--exclude` skips large vendored or community-contributed directories.
- `--entry-point-filter` reruns one slow entry point without the rest of the
  project.
- `--progress-log` appends phase lines and entry-point progress, about every
  five seconds, to a file you can `tail -f`. Progress is written between entry
  points, so one long entry point delays it. Each process also writes per-entry
  locations to stderr.

## Trace frames

An issue record holds the first hop into the trace graph. Standalone
`postcondition` frames lead back toward the source and end in `sources`
leaves; `precondition` frames lead toward the sink and end in `sinks` leaves.
Consecutive propagation steps on the same file and line share one source-side
frame.

An issue's `forward` and `backward` calls resolve to per-trace root callables
on port `prophecy`. The first standalone frames name that callable and port as
their `caller` and `caller_port`, which lets SAPP render the trace step by
step. The last frame on each side uses callee port `source` or `sink`.

## Issue identity

The SAPP issue handle is built from the sink's enclosing named scope and
syntactic site, the file, the warning code, the sink name, and the source
pattern. It leaves out line, column, and entry point, so triage state survives
unrelated line changes. Renaming the scope, moving the file, or adding an
identical sink earlier in the same scope changes it.
