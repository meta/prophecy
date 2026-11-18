<p align="center">
  <img src="docs/images/prophecy-banner.png" alt="Prophecy" width="832">
</p>

# Prophecy

Prophecy is a static taint analyzer for TypeScript. It tracks data from
configured sources to sinks without running the analyzed program. Built-in
specifications cover VS Code extensions, Electron main processes, and Express;
custom JSON specs can describe other APIs that fit the engine's supported
patterns.

> **Disclaimer.** Prophecy is a developer tool, not a security guarantee. It
> will likely miss real issues and will likely report flows that turn out to be
> safe. Treat every finding as a candidate for further review. Neither a finding
> nor the absence of findings should be read as a statement about the security
> of the analyzed code.

---

## What is taint analysis?

Taint analysis tracks untrusted data through a program to find injection
vulnerabilities. Prophecy's rules come in three kinds:

- **Sources** are where untrusted data enters, such as the `uri` passed to a
  VS Code URI handler or `req.query` in an Express route. Their values are
  tainted.
- **Sinks** are operations that are dangerous when they receive tainted data,
  such as `child_process.exec`, `Terminal.sendText`, or `res.redirect`.
- **Sanitizers** are transformations that make a value safe for some sinks,
  such as `parseInt` before the value is placed in a shell command. Each
  sanitizer covers only the sink categories or sink names it declares.

Taint propagates through assignments, function calls, string operations, and
other constructs. Prophecy reports a finding when tainted data reaches a sink
without passing through a sanitizer that covers that sink. It does this
statically, without running the analyzed code.

## How does Prophecy work?

Prophecy reads the TypeScript syntax tree and type information. It does not run
the program.

1. **Load the project and rules.** Build a TypeScript program from the
   project's `tsconfig.json`, then load sources, sinks, and sanitizers from a
   built-in preset or a custom spec.
2. **Find entry points.** Locate entry functions and registered callbacks, such
   as VS Code URI handlers and Express routes.
3. **Follow the data.** Propagate taint through assignments, properties,
   strings, branches, loops, and function calls, including calls across files.
4. **Report.** When tainted data reaches a sink without a covering sanitizer,
   report the source, the sink, and each step in between, as text, JSON,
   Mermaid, lint output, or data for [SAPP](https://github.com/facebook/sapp),
   Meta's open source static analysis post-processor.

For example, `uri.query` passed through a helper into `child_process.exec`
produces a trace from the URI-handler parameter, through the property read and
helper call, to the shell-execution sink.

Findings are rule-based. Prophecy does not use an LLM to detect flows, assign
severity, or write finding text: descriptions and severities come from the
matched sink rule.

See [limitations](#limitations) for what the analysis can miss, and
[architecture](docs/architecture.md) for how each step is implemented.

## Getting started

Prophecy needs Node.js 22.12 or later and pnpm 10.26.0 (pinned in
`package.json`).

```bash
npm install --global pnpm@10.26.0
pnpm install --frozen-lockfile
pnpm build
```

Install the dependencies of the project you want to analyze, including its type
declarations, then run:

```bash
node dist/index.js --project <path-to-project> --require-types
```

Prophecy uses the project's `tsconfig.json`, or the nearest one in a parent
directory. Without one, it analyzes every `.ts` and `.tsx` file outside
`node_modules`, `dist`, and `.git`. Missing type declarations make API matching
less accurate. `--require-types` fails on unresolved Node built-in imports and
on type libraries named in `tsconfig` that are not installed; it is not a full
type check.

An invalid or unreadable `tsconfig`, an unresolved `extends`, or a missing file
listed in the config is an error. A config that selects no files only prints a
warning, so if a scan finds nothing, check stderr first.

To try a bundled fixture, which passes `uri.query` to `child_process.exec`:

```text
$ node dist/index.js --project tests-unit/static/fixtures/uri-handler-rce

Analyzing /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce...
Using preset: auto

  → EP 1/2: Entry function: activate() @ /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:12:1
  → EP 2/2: URI handler (vscode:// deeplink) @ /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:15:13
Discovered 2 entry point(s)

Found 1 taint flow:
  CRITICAL  rce  1
Findings are candidates for further review, not confirmed security issues.

──────────────────────────────────────────────────────────────────────
[1/1] Security candidate (rce; 1 trace)
  Trace 1/1: CRITICAL: Command execution via child_process.exec
  Handle: handleUri.uri|exec|URI handler (vscode:// deeplink)|/path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts|17

  Source: URI handler parameter (attacker-controlled via vscode:// deeplink)
    at /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:15:23  [uri: vscode.Uri]

  Propagation:
    → accessed property 'query'
      at /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:16:32  [uri.query]
    → assigned to 'prompt'
      at /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:16:23  [prompt = uri.query]

  Sink: Command execution via child_process.exec
    at /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:17:17  [exec(prompt)]

──────────────────────────────────────────────────────────────────────
```

Entry-point lines (`→ EP`) go to stderr; the report goes to stdout. For the
parts of the report, see [reading reports](docs/reading-reports.md).

## Presets

A preset is a built-in spec: the sources, sinks, and sanitizers for one kind of
project.

| Preset             | Models                         | `--preset auto` selects it when `package.json` has |
| ------------------ | ------------------------------ | -------------------------------------------------- |
| `isl`              | Sapling's Interactive Smartlog | the package name `sapling-scm` or `isl-server`     |
| `vscode-extension` | VS Code extensions             | `engines.vscode` or a `@types/vscode` dependency   |
| `electron`         | Electron main processes        | an `electron` dependency                           |
| `express`          | Express servers                | an `express` or `@types/express` dependency        |

`auto` is the default. It reads the root `package.json`, including dev
dependencies, and checks the rows above in order. If nothing matches, or the
file is missing, it uses `vscode-extension`. Each project root gets one preset;
for a package that mixes frameworks, pass `--preset` or a custom spec.

**Shared Node sinks**, in every preset: child-process and Execa/cross-spawn
execution, dynamic code execution, fetch, Node HTTP and Axios requests, and
file reads, writes, appends, and streams. Separate rules cover the executable,
arguments, options, path, and content of a call, so one call can match more
than one rule. A file path sink does not make the file's contents a source.

**VS Code.** Sources are URI handlers, webview messages, debug configuration
callbacks, workspace settings, document content, file reads and names, selected
command output, clipboard reads, input dialogs, HTTP requests, and message
events. Sinks add terminals, commands, language-client launch options, debug
configuration fields that run commands, webview HTML, external URLs, and
workspace edits. Settings declared with `machine` or `application` scope stay
sources and are labeled with their scope. `process.env` is not a source,
because the extension host inherits it from the user's session.

**ISL.** The VS Code preset, plus sinks for ISL's command wrappers (`ejeca`,
`runCommand`, `Repository.runCommand`, `runOrQueueOperation`), the executable a
`RepositoryCache` context names, and file reads and deletes.

**Express.** Sources are request data in route and `use` handlers, including
`head`, `options`, and `app.route(path)` chains. State that middleware passes
through `next()`, including `res.locals`, is tracked for supported
registrations. Sinks add response bodies, redirects, template names, and served
file paths. `res.render` checks the view name, not the locals.

**Electron.** Sources are `ipcMain` handler payloads and the `open-url` URL.
Sinks add `shell.openExternal`. Event metadata from the host is not a source.

**Sanitizers.** Every preset includes `parseInt` and `Number` for
string-injection sinks; the resulting number stays tainted for other sinks.
The VS Code preset also models `shlex.quote`. A quoted argument to a fixed
command is reported as argument injection instead of command execution. A
quoted argument to a shell or interpreter on its denylist is still command
execution.

[Framework and API coverage](docs/framework-models.md) describes each model in
detail.

## Custom specs

`--spec <file.json>` replaces the preset; it does not extend one. The fields
are defined in [`src/static/spec/types.ts`](src/static/spec/types.ts).
Prophecy checks the file against those types before analysis and exits 1 on an
unknown field, a missing required field, or an invalid value.

This spec models a webhook library whose `onPush` callback receives an
untrusted event:

```json
{
  "sources": [
    {
      "kind": "parameter",
      "pattern": "onPush.event",
      "callbackRegistration": "onPush",
      "taintAllProperties": true,
      "description": "Push event payload from the webhook"
    }
  ],
  "sinks": [
    {
      "kind": "callArgument",
      "name": "exec",
      "pattern": "child_process.exec",
      "categories": ["rce"],
      "severity": "critical",
      "description": "Command execution via child_process.exec"
    }
  ],
  "sanitizers": [
    {
      "kind": "callReturnValue",
      "pattern": "parseInt",
      "categories": ["rce"],
      "description": "Integer parsing"
    }
  ]
}
```

Against this handler, the spec reports the first `exec`. The second is
sanitized by `parseInt`:

```ts
export function main() {
  onPush((event) => {
    exec(`git checkout ${event.branch}`);
    exec(`sleep ${parseInt(event.retries, 10)}`);
  });
}
```

```bash
node dist/index.js --project tests-unit/static/fixtures/custom-spec \
  --spec tests-unit/static/fixtures/custom-spec/spec.json
```

- `taintAllProperties` keeps taint on property reads such as `event.branch`.
  Without it, this example reports nothing.
- `callbackRegistration` matches the end of the call name, so `onPush` also
  matches `bot.onPush`.

A spec has these top-level fields:

- `sources`: tainted return values, property reads, and callback parameters.
- `sinks`: call arguments and property assignments to check.
- `sanitizers`: transformations, each scoped to sink `categories` or
  `sinkNames`.
- `entryFunctions`: named functions to analyze with clean parameters, such as
  `activate` or `main`.
- `handlerEntryPoints`: methods the host calls on a registered object, such as
  VS Code's `provideCodeLenses`, analyzed with clean parameters.
- `fixStrategies`: suggested repairs per sink, overriding the defaults.

To build on a preset, export it as JSON and edit the copy:

```bash
node -e 'console.log(JSON.stringify(require("./dist/spec/presets").builtinSpecs.express, null, 2))' > spec.json
```

APIs whose callback shapes, dispatch, or use-site semantics the engine does not
support need engine changes. See
[adding a pattern](docs/development.md#adding-a-pattern).

## Output formats

| Format      | Output                                                                                               |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| `text`      | Report grouped by source and sink (default)                                                          |
| `json`      | Array of findings with source, sink, propagation chain, and `reporting` metadata                     |
| `mermaid`   | One flowchart per group                                                                              |
| `lint`      | One JSON lint message per line, with suggested repairs                                               |
| `sapp-json` | A [SAPP](https://github.com/facebook/sapp) bundle in `--output-dir`; see [SAPP output](docs/sapp.md) |

Lint and SAPP output suggest repairs, such as `exec()` → `execFile()` or
`ShellExecution` → `ProcessExecution`. Review each one: replacing `exec` with
`execFile` means separating a trusted program from its arguments, and quoting a
whole terminal command is not a fix. The lint formatter marks every replacement
as unsafe to apply automatically.

## Screening a patch

```bash
node dist/index.js --patch-file /tmp/change.patch --repo-root <path-to-repo>
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
a build on findings, check the JSON output:

```bash
node dist/index.js --project . --require-types --format json > prophecy.json
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

## Limitations

- **Validation is not sanitization.** Guards such as
  `if (allowlist.includes(x))` or a regex test do not clear taint, so a
  validated value that reaches a sink is still reported. The
  `clean-uri-handler` fixture records this false positive.
- **Coverage is bounded.** Each entry point has a 90-second budget by default,
  plus call-depth (`--max-depth`, default 5), state, and iteration limits.
  Entry points cut short are listed on stderr, but some truncation is silent,
  and the scan still exits 0.
- **One trace per sink line.** Findings are deduplicated by source, sink, entry
  point, and sink line, so other paths to the same sink can be omitted.
- **Imports must resolve.** Taint crosses files only through imports and calls
  the TypeScript program resolves. Project references are not followed; pass
  each referenced project as its own `--project`.
- **Dynamic dispatch.** A call on an interface or base class expands to at most
  eight implementations in the program. Dynamic method names and structural
  implementations are not resolved.
- **Control flow.** Branches keep separate state and loops iterate to a bounded
  fixed point. `switch`, loop exits, and `try`/`catch`/`finally` are
  approximated; the analysis is not path-sensitive.
- **Callbacks.** `.map()` and `.filter()` are modeled. Callbacks passed to
  unknown higher-order functions, microtask ordering, and some aliasing are
  not.
- **Unresolved calls pass taint through.** A call Prophecy cannot resolve
  passes taint from its arguments and receiver to its result, so
  `uri.query.trim()` stays tainted. This reports more false positives in
  exchange for fewer missed flows.
- **Sanitizer context.** Only shell quoting is checked against how its result
  is used. `JSON.stringify` and `encodeURIComponent` are not sanitizers,
  because their safety depends on how the result is decoded or used.
- **File writes.** A file-content finding does not distinguish an inert cache
  from a file that is later executed, such as a task configuration or a shell
  startup file.

[Architecture](docs/architecture.md#analysis-limits) has the details.

## CLI reference

Analyze with exactly one of `--project` or `--patch-file`.
`--merge-sapp-bundle` is a separate mode for a finished SAPP bundle.

| Flag                   | Meaning                                                                        | Default                          |
| ---------------------- | ------------------------------------------------------------------------------ | -------------------------------- |
| `--project, -p`        | Project root to analyze; repeat for several roots                              | —                                |
| `--patch-file`         | Unified patch whose changed files select what to analyze                       | —                                |
| `--merge-sapp-bundle`  | Remove duplicate issue rows from a finished SAPP bundle, in place              | —                                |
| `--preset`             | `auto`, `vscode-extension`, `express`, `electron`, or `isl`                    | `auto`                           |
| `--spec, -s`           | Custom spec JSON; replaces the preset                                          | —                                |
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
project mode. Exit codes are listed under
[Using Prophecy in CI](#using-prophecy-in-ci).

| Environment variable     | Effect                                                               | Default |
| ------------------------ | -------------------------------------------------------------------- | ------- |
| `PROPHECY_EP_BUDGET_MS`  | Time budget per entry point, in milliseconds; `0` disables it        | `90000` |
| `PROPHECY_STRICT`        | `1` fails the scan on unexpected analyzer errors                     | unset   |
| `PROPHECY_STACK_SIZE_MB` | Stack size of the analysis worker thread                             | `64`    |
| `PROPHECY_CACHE_ENTRIES` | Maximum cached call results per entry point                          | `1500`  |
| `PROPHECY_NO_WORKER`     | `1` runs analysis on the main thread, with Node's default stack size | unset   |

## Finding categories

Every sink rule has a category. SAPP output uses the rule's first category as
its warning code; lint output uses `PROPHECY-<CATEGORY>`.

| Code | Name                       | Category           | Tainted data reaches                     |
| ---- | -------------------------- | ------------------ | ---------------------------------------- |
| 9001 | `Prophecy-RCE`             | `rce`              | Command execution                        |
| 9002 | `Prophecy-CodeInjection`   | `code_injection`   | Dynamic code execution, such as `eval`   |
| 9003 | `Prophecy-XSS`             | `xss`              | HTML output                              |
| 9004 | `Prophecy-SSRF`            | `ssrf`             | An outgoing request's destination        |
| 9005 | `Prophecy-FileWrite`       | `file_write`       | The path of a file write                 |
| 9006 | `Prophecy-OpenRedirect`    | `open_redirect`    | A redirect target                        |
| 9007 | `Prophecy-LFI`             | `lfi`              | Selection of a file or template to load  |
| 9008 | `Prophecy-SSTI`            | `ssti`             | Template source (no built-in rules)      |
| 9009 | `Prophecy-WorkspaceEdit`   | `workspace_edit`   | Edits to workspace files                 |
| 9010 | `Prophecy-ArgInjection`    | `arg_injection`    | Arguments of a fixed command             |
| 9011 | `Prophecy-PromptInjection` | `prompt_injection` | A model prompt (no built-in rules)       |
| 9012 | `Prophecy-FileIntegrity`   | `file_integrity`   | Content written to a file (low severity) |
| 9013 | `Prophecy-FileAccess`      | `file_access`      | The path of a file read (low severity)   |
| 9099 | `Prophecy-Unknown`         | Missing or unknown | —                                        |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[development guide](docs/development.md). [Architecture](docs/architecture.md)
explains how the analyzer is put together.

## Security

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).

## Author

Created by [Aaron Lichtman](https://github.com/alichtman).
