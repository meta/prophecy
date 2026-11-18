# CLI reference

For installation and a first scan, see [Getting started](../README.md#getting-started).

## Flags

Analyze with exactly one of `--project` or `--patch-file`.
`--merge-sapp-bundle` is a separate mode for a finished SAPP bundle.

| Flag                   | Meaning                                                                        | Default                          |
| ---------------------- | ------------------------------------------------------------------------------ | -------------------------------- |
| `--project, -p`        | Project root to analyze; repeat for several roots                              | —                                |
| `--patch-file`         | Unified patch whose changed files select what to analyze                       | —                                |
| `--merge-sapp-bundle`  | Remove duplicate issue rows from a finished SAPP bundle, in place              | —                                |
| `--rules`              | `auto`, `vscode-extension`, `express`, `electron`, or `isl`                    | `auto`                           |
| `--spec, -s`           | [Custom spec JSON](custom-specs.md); replaces the preset                       | —                                |
| `--format, -f`         | `text`, `json`, `mermaid`, `lint`, or `sapp-json`                              | `text`                           |
| `--output-dir, -o`     | Output directory; required for `sapp-json`                                     | —                                |
| `--sapp-project`       | Project name in SAPP metadata                                                  | First root's package or dir name |
| `--sapp-commit`        | Revision in SAPP metadata                                                      | Sapling revision, if available   |
| `--repo-root`          | Root for relative SAPP paths and patch screening                               | See below                        |
| `--require-types`      | Fail on missing type declarations                                              | `false`                          |
| `--max-depth`          | Maximum interprocedural call depth                                             | `5`                              |
| `--exclude`            | Skip source files whose path contains this substring; repeatable               | —                                |
| `--shard-index`        | Zero-based index of this process's shard                                       | `0`                              |
| `--shard-count`        | Number of shards                                                               | `1`                              |
| `--progress-log`       | File to append progress lines to in `json`, `lint`, and `sapp-json` modes      | —                                |
| `--entry-point-filter` | Debugging: analyze only entry points whose `file:line` contains this substring | —                                |
| `--analysis-stats`     | Debugging: print how many matches were type-resolved versus heuristic          | `false`                          |
| `--analysis-debug`     | Debugging: print JSON about matching decisions                                 | `false`                          |

Without `--repo-root`, project mode uses the nearest parent directory that has
an `.arcconfig`, and patch mode runs `sl root`; outside Sapling, pass
`--repo-root`. `--exclude`, sharding, and `--entry-point-filter` apply only to
project mode. See the [CI guide](scan-workflows.md#using-prophecy-in-ci)
for exit codes.

## Environment variables

| Environment variable     | Effect                                                               | Default |
| ------------------------ | -------------------------------------------------------------------- | ------- |
| `PROPHECY_EP_BUDGET_MS`  | Time budget per entry point, in milliseconds; `0` disables it        | `90000` |
| `PROPHECY_STRICT`        | `1` fails the scan on unexpected analyzer errors                     | unset   |
| `PROPHECY_STACK_SIZE_MB` | Stack size of the analysis worker thread                             | `64`    |
| `PROPHECY_CACHE_ENTRIES` | Maximum cached call results per entry point                          | `1500`  |
| `PROPHECY_NO_WORKER`     | `1` runs analysis on the main thread, with Node's default stack size | unset   |
