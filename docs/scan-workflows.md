# Scan workflows

Follow [Getting started](../README.md#getting-started) to build Prophecy and
install the dependencies of the project you want to scan. Run the examples
below from the Prophecy project directory.

## Screening a patch

```shell
node dist/index.js --patch-file /tmp/change.patch --repo-root /path/to/repo
```

The patch selects files; it is **not applied**. Check out the revision you want
to scan first. Prophecy analyzes the projects that contain changed TypeScript
files and keeps findings whose source, sink, or propagation steps touch a
changed file. It does not limit analysis to changed lines or compare against
the parent revision, so findings can predate the patch.

Changed paths must exist inside `--repo-root`. Each changed file is assigned to
the project of its nearest `tsconfig.json` within that root, then its nearest
`package.json`, then its own directory.

## Using Prophecy in CI

Prophecy exits 0 whenever the scan finishes, with or without findings. To fail
a CI step on findings, check the JSON output with `jq`:

```shell
node dist/index.js --project /path/to/project --require-types --format json \
  > prophecy.json &&
  jq -e 'length == 0' prophecy.json
```

| Exit code | Meaning                                                                                        |
| --------- | ---------------------------------------------------------------------------------------------- |
| 0         | The scan finished, with or without findings. Some entry points may be incomplete.              |
| 1         | Invalid input: flags, spec, project configuration, syntax errors, or a SAPP bundle merge       |
| 2         | Unexpected exception, unsupported reference-only solution config, or `--require-types` failure |

The per-entry-point time budget depends on machine speed and load, so two runs
on the same code can differ. `PROPHECY_EP_BUDGET_MS=0` removes the time budget;
depth and state limits still apply. `PROPHECY_STRICT=1` fails the scan on
unexpected analyzer errors instead of skipping the entry point.
