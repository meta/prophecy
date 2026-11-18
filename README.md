<p align="center">
  <img src="docs/images/prophecy-banner.png" alt="Prophecy" width="832">
</p>

# Prophecy

Prophecy is a static taint analyzer for TypeScript. It tracks data from
configured sources to sinks without running the analyzed program. Built-in
specifications cover VS Code extensions, Electron main processes, and Express;
custom JSON specs can describe other APIs that fit the engine's supported
patterns.

> **Disclaimer.** Prophecy is a security tool, not a guarantee. It
> can miss real issues and can report flows that turn out to be
> safe. Treat every finding as a candidate for further review. Neither a finding,
> nor the absence of findings, should be read as a statement about the security
> of the analyzed code.

---

## What is taint analysis?

Imagine a maze of pipes with several exits. Add a drop of red dye to the
water at one entrance. If an exit runs red, you know there's a path from
that entrance to that exit.

Prophecy uses the same idea. It marks untrusted input as **tainted**, like
adding dye to the water. Then it traces the code to see which operations
that input could reach.

To decide which traces to flag, Prophecy looks for three things:

- **Sources** are where untrusted data enters, such as the `uri` passed to a
  VS Code URI handler or `req.query` in an Express route. Their values are
  tainted.
- **Sinks** are functions that are dangerous when they receive tainted data,
  such as `child_process.exec`, `Terminal.sendText`, or `res.redirect`.
- **Sanitizers** are transformations that make a value safe for some sinks,
  such as `shlex.quote` before the value is placed in a shell command.

Taint propagates through assignments, function calls, string operations, and
other constructs. Prophecy reports a finding when tainted data reaches a sink
without passing through a sanitizer that covers that sink. It does this
statically, without running the analyzed code.

## How does Prophecy actually work?

Prophecy reads the TypeScript syntax tree and type information. It does not run
the program. Findings are rule-based. Prophecy does not use an LLM to detect flows, assign
severity, or write finding text: descriptions and severities come from the
matched sink rule.

1. **Load the project and rules.** Build a TypeScript program from the
   project's `tsconfig.json`, then load sources, sinks, and sanitizers from a
   built-in preset or a custom spec.
2. **Find entry points.** Locate entry functions and registered callbacks, such
   as VS Code URI handlers and Express routes.
3. **Follow the data.** Propagate taint through assignments, properties, branches, loops, and function calls, including calls across files.
4. **Report.** When tainted data reaches a sink without a covering sanitizer,
   report the source, the sink, and each step in between, as text, JSON,
   Mermaid, lint output, or data for **[facebook/SAPP](https://github.com/facebook/sapp)**,
   Meta's open source Static Analysis Post-Processor.

See [limitations](#limitations) for what the analysis can miss, and
[architecture](docs/architecture.md) for how each step is implemented.

## Getting started

Prophecy needs Node.js 22.12 or later and pnpm 10.26.0 (pinned in
`package.json`).

```shell
pnpm install --frozen-lockfile
pnpm build
```

Install the dependencies of the project you want to analyze, including its type
declarations, then run:

```shell
node dist/index.js --project <path-to-project> --require-types
```

Prophecy uses the project's `tsconfig.json`, or the nearest one in a parent
directory. Without one, it analyzes every `.ts` and `.tsx` file outside
`node_modules`, `dist`, and `.git`. Missing type declarations make API matching
less accurate. `--require-types` fails on unresolved Node built-in imports and
on type libraries named in `tsconfig` that are not installed; it is not a full
type check.

To see how Prophecy traces `uri.query` from a VS Code URI handler to
`child_process.exec`, try this bundled fixture:

```shell
$ node dist/index.js --project tests-unit/static/fixtures/uri-handler-rce

Analyzing /path/to/prophecy/tests-unit/static/fixtures/uri-handler-rce...
Using rules: auto

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

See the [CLI reference](docs/cli-reference.md) for flags and environment
variables, or [scan workflows](docs/scan-workflows.md) for patch screening
and CI.

## Detection rules

Prophecy has built-in rules for VS Code extensions (`vscode-extension`),
Sapling's Interactive Smartlog (`isl`), Electron main processes (`electron`),
and Express servers (`express`).

By default, Prophecy picks a rule set from the project's `package.json`. If
nothing matches, it uses `vscode-extension`. To choose one yourself, pass
`--rules`, for example `--rules express`.

See [Framework and API coverage](docs/framework-models.md) for how Prophecy
picks a preset and what each one checks. To write your own rules, see
[Custom specs](docs/custom-specs.md).

## Output formats

| Format      | Output                                                                                               |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| `text`      | Report grouped by source and sink (default)                                                          |
| `json`      | Array of findings with source, sink, propagation chain, and `reporting` metadata                     |
| `mermaid`   | One flowchart per group                                                                              |
| `lint`      | One JSON lint message per line, with suggested repairs                                               |
| `sapp-json` | A [SAPP](https://github.com/facebook/sapp) bundle in `--output-dir`; see [SAPP output](docs/sapp.md) |

Lint and SAPP output suggest repairs, such as `exec()` → `execFile()` in Node.js
or `vscode.ShellExecution` → `vscode.ProcessExecution` in VS Code tasks. Review
each one -- they are not always safe to automatically apply.

## Limitations

- **Imports must resolve.** Taint crosses files only through imports and calls
  the TypeScript program resolves. Project references are not followed; pass
  each referenced project as its own `--project`.
- **Coverage is bounded.** Each entry point has a 90-second budget by default,
  plus call-depth (`--max-depth`, default 5), state, and iteration limits.
  Entry points cut short are listed on stderr, and the scan still exits 0.
- **Control flow.** Branches keep separate state and loops iterate to a bounded
  fixed point. `switch`, loop exits, and `try`/`catch`/`finally` are
  approximated; the analysis is not path-sensitive.
- **Prophecy can't follow every call.** If Prophecy can't tell what code a
  call will run, it may treat the result as tainted based on the input. It can
  still miss flows inside the call.
- **Callbacks.** `.map()` and `.filter()` are modeled. Callbacks passed to
  unknown higher-order functions, microtask ordering, and some aliasing are
  not.
- **Reports can omit alternate paths.** When several paths produce the same
  finding, Prophecy shows one trace for it.
- **Sanitizers have limits.** Prophecy gives sanitizers credit only in the
  cases it models. A flow can still be flagged after an allowlist or regex
  check.
- **File writes.** Prophecy can flag code that writes untrusted data into a
  file. The finding doesn't tell you whether anything later uses that data
  as instructions.

[Architecture](docs/architecture.md#analysis-limits) has more details.

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
