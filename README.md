<p align="center">
  <img src="docs/images/prophecy-banner.png" alt="Prophecy" width="832">
</p>

# Prophecy

Prophecy is a static taint analyzer for TypeScript. It tracks data from
configured sources to sinks without running the analyzed program. Built-in
specifications cover VS Code extensions, Electron main processes, and Express;
custom JSON specs can describe other APIs that fit the engine's supported
patterns.

> **Disclaimer.** Prophecy is a developer tool, not a security guarantee. Static
> analysis of this kind is inherently incomplete: findings are candidates for
> human review, real issues will be missed, and flows that turn out to be safe
> will sometimes be reported. Before treating a finding as exploitable, check
> the source's trust boundary, the sink's runtime behavior, and any validation
> in between. Neither a finding nor the absence of findings should be read as a
> statement about the security of the analyzed code.

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

Prophecy analyzes the TypeScript syntax tree and type information, rather than
executing the program or asking an AI model to review it:

1. **Load the project and rules.** Create a TypeScript program from the project's
   `tsconfig.json` and resolved imports, then use a built-in preset or custom spec
   to identify sources, sinks, and sanitizers.
2. **Find entry points.** Discover configured entry functions and registered
   callbacks, such as VS Code URI handlers or Express routes. Callback parameters
   start tainted where the source rule says they do; other sources introduce taint
   when their return values or properties are read.
3. **Follow the data.** Propagate taint forward through assignments, properties,
   strings, branches, loops, and resolvable function calls, including calls across
   files. Track which sink categories a sanitizer covers and retain the steps
   connecting a source to a sink.
4. **Report modeled flows.** When tainted data reaches a matching sink without a
   covering sanitizer, emit a finding with source and sink locations and a
   propagation trace. Format the results as text, JSON, Mermaid, lint output, or
   SAPP data.

For example, `uri.query` passed through a helper into `child_process.exec`
produces a trace from the URI-handler parameter, through the property read and
helper call, to the shell-execution sink.

Findings are rule-based, not AI-generated. Prophecy does not call an LLM to
detect flows, assign severity, or write finding text. Descriptions and severities
come from the matched sink rule; source and propagation labels come from the
spec and analysis state. Some rules refine the classification at the use site:
a quoted shell argument can be reported as argument injection rather than
command injection.

The engine follows supported patterns within analysis limits; a reported flow
is not proof of runtime reachability or exploitability. See the
[analysis pipeline](#analysis-pipeline) and
[limits and reproducibility](#limits-and-reproducibility) for the implementation
details and coverage boundaries.

## Getting started

Use Node.js 22.12 or later and pnpm 10.26.0 (pinned in `package.json`).

```bash
npm install --global pnpm@10.26.0
pnpm install --frozen-lockfile
pnpm build
pnpm test --runInBand
```

Install the dependencies of the project you want to analyze, including its type
declarations, then run:

```bash
node dist/index.js --project <path-to-project> --require-types
```

Prophecy uses the project's `tsconfig.json` and TypeScript's import resolution.
If no config is found in the project or its ancestors, it collects `.ts` and
`.tsx` files, excluding `node_modules`, `dist`, and `.git`. Missing declarations
reduce matching accuracy. `--require-types` fails on unresolved Node built-in
imports and missing `tsconfig` type libraries; it is not a complete type check.

To try a bundled fixture, which passes `uri.query` to `child_process.exec`:

```text
$ node dist/index.js --project tests-unit/static/fixtures/uri-handler-rce

Analyzing /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce...
Using preset: auto

  → EP 1/2: Entry function: activate() @ /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:12:1
  → EP 2/2: URI handler (vscode:// deeplink) @ /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce/extension.ts:15:13
Discovered 2 entry point(s)

Found 1 potential vulnerability:

──────────────────────────────────────────────────────────────────────
[1/1] CRITICAL: Command execution via child_process.exec

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

The per-entry-point `→ EP` lines go to stderr; the report goes to stdout.

### Presets and custom specs

`--preset auto` selects a spec from the root `package.json`:

- The package names `sapling-scm` and `isl-server` (Interactive Smartlog's VS
  Code extension and server) select `isl`.
- Otherwise, `engines.vscode` or a dependency on `@types/vscode` selects `vscode-extension`.
- Otherwise, `electron` is checked before `express` or `@types/express`.
- Unrecognized, missing, or unreadable package metadata falls back to
  `vscode-extension`.

Both dependencies and dev dependencies are checked. Each root selects one spec;
mixed-framework packages should select their intended model explicitly with
`--preset express`, `--preset vscode-extension`, or `--preset isl`, or supply a
combined `--spec <file.json>`, which takes precedence.
See [framework and API coverage](docs/framework-models.md) for modeled boundaries.

The spec types are in [`src/static/spec/types.ts`](src/static/spec/types.ts).
A `TaintSpec` defines:

- `entryFunctions`: named functions to analyze with initially untainted
  parameters: `activate` in the VS Code spec and `main` in the Express spec.
- `sources`: tainted return values, property reads, and callback parameters.
  `callbackRegistration` drives callback discovery; `callbackArgIndex`,
  `callbackArgIndices`, or `callbackArgStart` select the callback argument, and
  `handlerMethod` selects a method on a registered object.
  `callbackSource: "call"` instead analyzes callback-delivered data at its call
  site, such as `fs.readFile(path, cb)`, with `callbackTaint` controlling
  whether that data is a new source or inherits another argument's provenance.
- `handlerEntryPoints`: methods on registered objects to analyze with initially
  untainted parameters, such as VS Code's `provideCodeLenses`.
- `sinks`: call/constructor arguments and property assignments to check.
- `sanitizers`: transformations whose effect is scoped to sink categories or names.
- `fixStrategies`: optional overrides for suggested repairs.

A new API can often be modeled in the spec alone. Unsupported callback shapes,
dynamic dispatch, or use-site semantics may require engine changes. See
[Adding a pattern](docs/development.md#adding-a-pattern).

### Built-in coverage

The [VS Code spec](src/static/spec/vscodeExtension.ts) models URI handlers,
webview messages, debug configuration callbacks, workspace settings, document
content, file reads and names, selected command output, clipboard reads, input
dialogs, HTTP requests, and message events. These are modeled trust boundaries,
not proof that every value from these APIs is attacker-controlled.

Settings declared as `machine` or `application` are labeled with that scope;
they remain sources even though workspace settings cannot supply them.
`process.env` is deliberately not a source in this preset: the extension host's
environment comes from the user's session.

The [ISL spec](src/static/spec/isl.ts) is the VS Code spec plus sinks for
Interactive Smartlog, Sapling's web UI. Every Sapling command it runs goes
through one `spawn` call, and findings are deduplicated per sink line, so ISL's
command call sites (`ejeca`, `runCommand`, `Repository.runCommand`,
`runOrQueueOperation`) are sinks themselves. So are the executable a `RepositoryCache`
context names, and file reads and deletes.

The [Express spec](src/static/spec/express.ts) models request data in route and
`use` middleware handlers, including `head`, `options`, and chained
`app.route(path)` forms. Supported normal middleware advances through `next()`
with per-request shared state, including `res.locals`. It adds response-body,
redirect, template-selection, and file-serving sinks. `res.render` checks the
view name, not every locals value; engine-specific template execution and HTML
escaping need separate models.

Electron models renderer IPC payloads separately from host events. Modeled
registrations require recognizable API identity, not just a method named
`get`, `post`, or `on`.

[Shared Node models](src/static/spec/nodeApis.ts) cover child-process and
Execa/cross-spawn execution, dynamic code execution, fetch/Node HTTP/Axios
requests, and file reads, writes, appends, and streams. File path sinks do not
implicitly make all file contents sources; content-source rules are separate.
VS Code adds terminals, commands, language-client launch options, selected debug configuration fields,
webview HTML, external URLs, and workspace edits. Argument, binary, options,
path, and content positions are modeled separately where the rules distinguish
them; counts of rules are not counts of distinct vulnerabilities.

All built-in presets include `parseInt` and `Number`, scoped to string-injection
categories. The resulting numbers remain tainted for other sink categories.
The VS Code preset also models `shlex.quote` in supported shell contexts:
quoted arguments remain findings, classified as argument injection when the
context check succeeds. Commands on the sanitizer's denylist of shells,
interpreters, and execution wrappers retain command execution findings.
Quoting does not establish that an argument is safe for the selected program.

Sanitizers without a category or sink-name scope do not suppress findings.
Control-flow validation such as `if (allowlist.includes(x))` and regex guards is
not modeled as sanitization; the `clean-uri-handler` fixture records this known
false positive.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                               index.ts                               │
│    CLI — input mode, preset/spec selection, sharding, exclusions     │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │
                   ┌───────────────┴─────────────┐
                   ▼                             ▼
      ┌────────────────────────┐    ┌────────────────────────┐
      │        diff.ts         │    │      analyzer.ts       │
      │                        │    │                        │
      │  Patch or diff →       │───▶│ Orchestrates parsing,  │
      │  changed TypeScript    │    │ discovery, analysis,   │
      │  files → projects      │    │ and reporting          │
      │  (sourceControl.ts)    │    │                        │
      └────────────────────────┘    └────────────┬───────────┘
                                                 │
          ┌──────────────────┬───────────────────┼──────────────────┐
          ▼                  ▼                   ▼                  ▼
  ┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌───────────────┐
  │   parser.ts   │ │     taint/      │ │      spec/      │ │  reporter.ts  │
  │               │ │                 │ │                 │ │ sappFormatter │
  │ TypeScript    │ │interprocedural  │ │ types.ts        │ │     fix/      │
  │ program and   │ │  entry points,  │ │ sinks.ts        │ │               │
  │ type checker; │ │  command bridge │ │ vscodeExtension │ │ text, json,   │
  │ resolves      │ │taintTracker     │ │ express         │ │ mermaid,      │
  │ imports       │ │  forward        │ │                 │ │ lint,         │
  │               │ │  dataflow       │ │ sources, sinks, │ │ sapp-json     │
  │               │ │taintValue       │ │ sanitizers,     │ │               │
  │               │ │  chains         │ │ entry patterns  │ │ + fix         │
  │               │ │functionResolver │ │                 │ │   generation  │
  │               │ │nodeLocation     │ │                 │ │               │
  └───────────────┘ └─────────────────┘ └─────────────────┘ └───────────────┘
```

### Analysis pipeline

All paths below are relative to `src/static/`.

1. **Parse** (`parser.ts`): create a TypeScript `Program` and `TypeChecker`.
   Dependencies and `tsconfig` path mappings determine which imports resolve;
   taint crosses files only through imports and calls the program resolves.
2. **Index** (`analyzer.ts`, `taint/interprocedural.ts`): build the VS Code
   command registry, class hierarchy, and setting-scope metadata before entry
   point filtering or sharding. The registry maps statically resolved
   `registerCommand(name, handler)` names to their handlers.
3. **Discover entry points** (`taint/interprocedural.ts`): walk source ASTs,
   including nested declarations, for:
   - named entry functions (`entryFunctions`), whose parameters start
     untainted;
   - callback registrations (`callbackRegistration` on parameter sources),
     such as `createServer((req, res) => ...)` and
     `onDidReceiveMessage(handler)`, which taint the configured callback
     parameter. A registered object's handler can be a method or a property
     initialized with an arrow or function expression;
   - handler entry points (`handlerEntryPoints`), such as `provideCodeLenses`
     on a provider passed to `registerCodeLensProvider`, analyzed with
     untainted parameters;
   - `registerCommand` handlers, which start untainted. A statically resolved
     `executeCommand(name, ...args)` call passes its arguments' taint to the
     registered handler;
   - `.on`, `.once`, and `.addListener` listeners for the literal event
     `"message"` when the matching source is configured.

   If no entries are discovered, `analyzer.ts` falls back to top-level
   functions and class methods in the resolved package `main` file, or all
   parsed source files if it cannot resolve `main`. Discovery does not prove
   runtime reachability.

4. **Propagate taint** (`taint/taintTracker.ts`): track assignments,
   destructuring, string concatenation, template literals, ternaries, spreads,
   property accesses, branches, loops, and resolvable calls, recording the
   propagation chain for each finding. Calls are followed up to `--max-depth`
   (default 5). Supported constructors and method calls carry per-instance
   `this.field` state, so clean and tainted instances of one class are not
   merged, and a clean reassignment of a variable or `this` field replaces its
   taint. Unresolved calls can pass taint from arguments and receivers to their
   results, so chains such as `uri.query.trim().toLowerCase()` stay tainted.
   This trades false positives for fewer missed flows, but it does not model
   every callback, side effect, or dynamic operation.
5. **Report** (`findingUtils.ts`, `reporter.ts`, `sappFormatter.ts`, `fix/`):
   deduplicate by finding handle and format text, JSON, Mermaid flowcharts,
   lint JSON Lines, or SAPP NDJSON. Lint and SAPP modes also attach repair
   suggestions defined per sink, such as `exec()` → `execFile()` and
   `ShellExecution` → `ProcessExecution`.

Type-resolved API matching distinguishes, for example, `RegExp.exec` from
`child_process.exec`. Import/receiver identity and name-based fallbacks cover
some cases without declarations; they are less reliable than a complete type
environment.

### Limits and reproducibility

Analysis is rule-based, but coverage is bounded. A wall-clock budget (90 seconds
per entry point by default), call-depth limits, state/iteration limits, and
stack exhaustion can stop analysis before all flows are explored. Timing-based
cutoffs can change the findings between runs on the same source. Retained
traces are not an exhaustive set of execution paths.

The CLI reports incomplete entry points on stderr and can still exit 0. Some
state truncation is silent, so an empty incomplete-entry list does not establish
complete coverage. Set
`PROPHECY_STRICT=1` to fail on unexpected entry-point errors; ordinary coverage
limits still produce an incomplete report rather than a failing exit code.
`PROPHECY_EP_BUDGET_MS=0` disables the time budget, not the other limits.

Generated repairs require review. For example, replacing `exec` with `execFile`
requires separating a trusted program from its arguments; quoting an entire
terminal command is not a general repair. The lint formatter marks all
replacements as unsafe to apply automatically, including import edits. The
analyzer does not apply repairs or verify their runtime safety.

### Known limitations

- **Dynamic dispatch**: a call to an abstract or interface method declared in
  the program expands to implementations in the program, up to eight; beyond
  that, unresolved passthrough applies. Methods in declaration files,
  subclass overrides of a base-class method that has a body, object-literal
  implementations, union receiver types, and interface property signatures
  such as `run: (cmd: string) => void` are not expanded.
- **Instance and callback state**: instance identity through `.at()`,
  `.map()`, and `.filter()` is not modeled, object-literal methods are not
  tracked as function values, and callback return values from unresolved
  higher-order calls generally do not flow to the call's result.
- **Control flow**: branches use separate state and loops iterate to a bounded
  fixed point; loop exits, switch cases, and `try`/`catch`/`finally` are
  conservative. This is not a fully path-sensitive analysis.
- **Sanitizer context**: only shell composition has use-site context tracking.
  `JSON.stringify` and `encodeURIComponent` are not general sanitizers: their
  safety depends on how the result is used or decoded.
- **File-write content**: content findings do not distinguish an inert cache
  from an execution-bearing destination such as a task configuration or a shell
  startup file.

### Finding identity

Prophecy's in-memory `handle` combines the source pattern, sink name, entry
point, sink file, and line. Deduplication keeps the first finding for each
handle, so alternate paths may be omitted. Moving the sink to another line
changes that handle.

SAPP has a separate issue handle based on the sink's named scope and syntactic
site, file, warning code, sink name, and source pattern. It omits line/column
and entry-point identity to retain triage across unrelated line changes.
Renaming a scope, moving a file, or inserting an identical sink earlier in the
same scope can still change it.

## CLI reference

For analysis, supply exactly one of `--project`, `--patch-file`, or `--diff`.
`--merge-sapp-bundle` is a separate input mode for an already-completed SAPP
bundle.

| Flag                   | Meaning                                                                                                     | Default                                |
| ---------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `--project, -p`        | Project root; repeat for multiple roots                                                                     | —                                      |
| `--patch-file`         | Unified patch used to select changed files in the local checkout                                            | —                                      |
| `--diff`               | Code review diff to screen; requires an internal integration and otherwise exits with an error              | —                                      |
| `--diff-version`       | Version of the `--diff` revision whose changed paths are read                                               | Latest                                 |
| `--merge-sapp-bundle`  | Deduplicate issue rows in a completed SAPP bundle, in place                                                 | —                                      |
| `--preset`             | `auto`, `vscode-extension`, `express`, `electron`, or `isl`                                                 | `auto`                                 |
| `--spec, -s`           | Custom taint spec JSON                                                                                      | —                                      |
| `--format, -f`         | `text`, `json`, `mermaid`, `lint`, or `sapp-json`                                                           | `text`                                 |
| `--output-dir, -o`     | Required output directory for `sapp-json`                                                                   | —                                      |
| `--sapp-project`       | Project name in SAPP runner metadata                                                                        | First project's package/directory name |
| `--sapp-commit`        | Revision in SAPP runner metadata                                                                            | Sapling revision, when available       |
| `--exclude`            | Repeatable path substring; drops source files whose resolved path contains it (`String.prototype.includes`) | —                                      |
| `--shard-index`        | Zero-based process shard index                                                                              | `0`                                    |
| `--shard-count`        | Number of process shards                                                                                    | `1`                                    |
| `--entry-point-filter` | Debugging: repeatable substring of an entry point's `file:line`                                             | —                                      |
| `--require-types`      | Fail on detected missing type declarations                                                                  | `false`                                |
| `--progress-log`       | File to append phase/progress lines to in `json`, `lint`, and `sapp-json` modes                             | —                                      |
| `--repo-root`          | Root for relative SAPP paths and patch screening; code links when supported                                 | See below                              |
| `--max-depth`          | Maximum interprocedural call depth                                                                          | `5`                                    |
| `--analysis-stats`     | Print pattern-matching counts, type-resolved versus heuristic                                               | `false`                                |
| `--analysis-debug`     | Print structured JSON about analyzer matching decisions                                                     | `false`                                |

Project mode looks for an ancestor `.arcconfig` when `--repo-root` is omitted.
Patch mode invokes `sl root`; pass `--repo-root` explicitly outside Sapling.
Exclusions, sharding, and entry-point filters apply to project mode, not patch
screening.

Exit 0 means the scan finished, with or without findings; it does not imply
complete coverage. Exit 1 covers handled input, syntax, and bundle-merge errors.
Exit 2 covers exceptions, including `--require-types` failures.

### Patch screening

```bash
node dist/index.js --patch-file /tmp/change.patch --repo-root <path-to-repo>
```

The patch selects files; it is **not applied**. Prepare the local checkout at
the revision you want to scan. Prophecy analyzes projects containing changed
TypeScript files, then retains findings whose source, sink, or propagation
trace touches a changed file. It does not restrict analysis to changed lines
or compare parent and patched findings.

### SAPP output and sharding

```bash
node dist/index.js --project <path-to-project> \
  --format sapp-json --output-dir /tmp/prophecy-sapp
```

For one root and the default shard index, this writes `runner_metadata.json`,
`sapper_metadata.json`, `issues_1.sapp`, and `traceFrames_1.sapp`. Use a fresh
output directory to avoid ingesting files left by an earlier scan.

Issue records contain the first hop into the trace graph. Standalone
`postcondition` frames continue toward the source with `sources` leaves;
`precondition` frames point toward the sink with `sinks` leaves. Consecutive
propagation steps on the same file/line share a source-side frame. An issue's
`forward` and `backward` calls resolve to per-trace root callables on port
`prophecy`, which the first standalone frames name as their `caller` and
`caller_port`; that match lets SAPP render the step-by-step trace. The last
frame on each side uses callee port `source` or `sink`.

Repeated `--project` roots are analyzed separately and write separate issue/
trace pairs in one bundle. With `auto`, each root selects its own spec. Bundle
metadata comes from the first root; use `--sapp-project` for an explicit shared
name. Project mode deduplicates handles across roots before writing SAPP/JSON;
lint mode deduplicates identical output lines, while text/Mermaid concatenate
per-root reports.

To split a project across processes, run every index from `0` through
`--shard-count - 1` with the same source, options, root ordering, and output
directory. For example, this runs **only shard 0 of 8**:

```bash
node dist/index.js --project <path-to-project> \
  --format sapp-json --output-dir /tmp/prophecy-sapp \
  --shard-index 0 --shard-count 8
```

Each process parses the program and discovers the same entries, then analyzes
a round-robin subset. File numbers are `shardIndex * 1000 + rootIndex + 1`;
keep each invocation below 1,000 project roots to avoid cross-process filename
collisions. SAPP ingests all `*.sapp` files in the bundle.

After **all** shard processes finish successfully, remove duplicate issue rows:

```bash
node dist/index.js --merge-sapp-bundle /tmp/prophecy-sapp
```

This keeps the first issue row per Prophecy finding handle and preserves all
trace frames. Do not merge while any process is still writing the bundle.

For long scans, `--exclude` skips large vendored or community-contributed
subtrees, and `--entry-point-filter` reproduces one slow entry point without
rerunning the whole project. `--progress-log` receives phase lines and
entry-point progress throttled to about five seconds, which you can follow with
`tail -f`. It is not an independent heartbeat: a long synchronous entry-point
analysis can delay updates. Each process still writes per-entry locations to
stderr. Size process concurrency for available memory; every process builds its
own TypeScript program.

### Warning codes

The CLI's numeric SAPP warning code comes from the first category in the
finding's sink rule, not the first sink reached in the program. Codes in the
9001–9099 range are allocated to Prophecy, and `sapper_metadata.json` lists each
code's name and description. Lint output uses separate `PROPHECY-<CATEGORY>`
string codes.

| Code | Name                       | Category                    |
| ---- | -------------------------- | --------------------------- |
| 9001 | `Prophecy-RCE`             | `rce`                       |
| 9002 | `Prophecy-CodeInjection`   | `code_injection`            |
| 9003 | `Prophecy-XSS`             | `xss`                       |
| 9004 | `Prophecy-SSRF`            | `ssrf`                      |
| 9005 | `Prophecy-FileWrite`       | `file_write`                |
| 9006 | `Prophecy-OpenRedirect`    | `open_redirect`             |
| 9007 | `Prophecy-LFI`             | `lfi`                       |
| 9008 | `Prophecy-SSTI`            | `ssti`                      |
| 9009 | `Prophecy-WorkspaceEdit`   | `workspace_edit`            |
| 9010 | `Prophecy-ArgInjection`    | `arg_injection`             |
| 9011 | `Prophecy-PromptInjection` | `prompt_injection`          |
| 9099 | `Prophecy-Unknown`         | Unknown or missing category |

## Development

See the [development guide](docs/development.md) for test commands, adding
patterns, fixture expectations, and internal integration conventions.

## License

[MIT](LICENSE).

## Author

Created by [Aaron Lichtman](https://github.com/alichtman). See
[CONTRIBUTING.md](CONTRIBUTING.md) for the contribution flow.
