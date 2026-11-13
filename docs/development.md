# Development

Run the commands below from the Prophecy project root. For installation and
analysis commands, see [Getting started](../README.md#getting-started).

Tests include inline source cases, multi-file fixtures, CLI behavior, and
output-format checks. To run a subset, pass a Jest filter:

```bash
pnpm test --runInBand --testPathPattern=e2e
pnpm test --runInBand --testNamePattern=websocket
pnpm test:pnpm  # install/build/scan a pnpm-isolated VS Code extension
```

Lint with [oxlint](https://oxc.rs/docs/guide/usage/linter) and format with
[oxfmt](https://oxc.rs/docs/guide/usage/formatter). Both skip
`tests-unit/static/fixtures/`: fixtures are analyzer inputs, and the tests
assert their line and column numbers.

```bash
pnpm lint          # oxlint, configured in .oxlintrc.jsonc
pnpm format        # rewrite files in place with oxfmt, configured in .oxfmtrc.jsonc
pnpm format:check  # list files oxfmt would change; exits 1 if any
```

## Adding a pattern

1. Add a `SourceSpec`, `SinkSpec`, or `SanitizerSpec` entry to the relevant
   spec in `src/static/spec/`. Every sanitizer must declare `categories` or
   `sinkNames`; a sanitizer scope asserts that the transformation stays safe
   for every matching sink.
2. Optionally add a repair in `src/static/fix/fixStrategy.ts` or the spec's
   `fixStrategies`. Strategies match by `sinkName`, then by `category`, and
   spec-level strategies override the defaults.
3. Add a fixture under `tests-unit/static/fixtures/<name>/` with its own
   `tsconfig.json`, copied from a comparable fixture. VS Code fixtures export
   `activate()` from `extension.ts`.
4. Assert the expected findings, including zero for safe controls, in
   [`tests-unit/static/e2e.test.ts`](../tests-unit/static/e2e.test.ts), then run
   `pnpm test`.

A new project type needs a `TaintSpec` in `src/static/spec/`, auto-detection in
`detectSpec()` in `src/static/analyzer.ts`, and a preset in
`src/static/index.ts` if it should be usable without `--spec`. Engine changes
are needed when the framework's callback shapes, dispatch, or dataflow fall
outside the supported models.

## Test fixtures

Each fixture models an attack pattern, an analyzer capability, or a robustness
case. Expectations live in the tests, mostly
[`tests-unit/static/e2e.test.ts`](../tests-unit/static/e2e.test.ts); a fixture
name alone does not establish whether it should produce findings.

**Expected to report findings:**

| Fixture                          | Pattern                                                                                                   |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `uri-handler-rce`                | Direct `uri.query` → `exec`                                                                               |
| `exec-injection`                 | String concatenation into `exec`                                                                          |
| `template-literal-injection`     | Template literal into `exec`                                                                              |
| `interprocedural-injection`      | Taint through a helper function                                                                           |
| `class-uri-handler-terminal`     | Class URI handler → `terminal.sendText`                                                                   |
| `imported-class-uri-handler-rce` | Imported handler class instantiated at the registration site                                              |
| `handler-property-rce`           | Handlers declared as function-valued properties                                                           |
| `multi-file-rce`                 | Taint across four files                                                                                   |
| `executecommand-bridge-rce`      | `executeCommand` → `registerCommand` bridge                                                               |
| `command-handler-multi-arg-rce`  | Command handler whose dangerous parameter is not the first                                                |
| `deeplink-assistant-rce`         | Assistant deeplink query → `executeCommand` bridge → terminal                                             |
| `deeplink-prompt-rce`            | Deeplink prompt → `exec`, without a model in the flow                                                     |
| `deeplink-fragment-injection`    | Deeplink `uri.fragment` → string concatenation → terminal                                                 |
| `deeplink-debug-config-rce`      | Deeplink → debug configuration → `startDebugging`                                                         |
| `debug-config-property-sink`     | Only execution-bearing `DebugConfiguration` fields are sinks                                              |
| `document-content-rce`           | Open document text → shell sink                                                                           |
| `file-write-path`                | File-write path and content sinks are separate                                                            |
| `workspace-config-rce`           | Workspace setting → `execFile`                                                                            |
| `workspace-config-object-rce`    | Nested workspace setting object → `exec`                                                                  |
| `promisified-exec-rce`           | Workspace setting → `promisify(exec)` exported from another module                                        |
| `abstract-dispatch-rce`          | Workspace setting → `exec` in an override of an abstract method                                           |
| `codelens-provider-rce`          | Workspace setting → `exec` reached only from `provideCodeLenses`                                          |
| `config-closure-arrow-rce`       | Workspace settings through arrow constants, default parameters, parameter properties, and stored closures |
| `workspace-command-output-rce`   | Names printed by a CLI run in the workspace folder → `exec`                                               |
| `setting-scope-source`           | Setting sources labeled by the scope `package.json` declares                                              |
| `language-client-shell-rce`      | Workspace setting → language server argv with `shell: true`, through a client subclass                    |
| `untyped-node-module-rce`        | `cp.exec` matched by its import when `@types/node` is missing                                             |
| `filename-source-rce`            | Filenames as a taint source                                                                               |
| `http-server-rce`                | HTTP server request → `exec`                                                                              |
| `websocket-server-rce`           | WebSocket message → `executeCommand`                                                                      |
| `void-expression-sink`           | A `void expr` operand still reaches the sink                                                              |
| `express-rce`                    | Express routes → web and shared Node.js sinks                                                             |

**Discovery, sanitizers, and robustness:**

| Fixture                 | Pattern                                                                                                               |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `package-json-entry`    | `package.json` `main` alongside framework entry points                                                                |
| `diff-repos`            | Synthetic repository tree for patch screening                                                                         |
| `sanitized-input`       | Numeric conversion removes a shell-injection flow                                                                     |
| `shell-quote-sanitizer` | Quoting after a fixed command is argument injection; a quoted whole command or `sh -c` code remains command execution |
| `clean-uri-handler`     | Allowlist guard that is not modeled, reported as a known false positive                                               |
| `zero-entry-points`     | Valid TypeScript with no entry points                                                                                 |
| `empty-project`         | Project with no source files                                                                                          |
| `syntax-errors`         | Unparseable source must not crash                                                                                     |
| `malformed-tsconfig`    | Valid TypeScript with a malformed `tsconfig.json`                                                                     |

## Internal integrations

Environment-specific behavior lives in `facebook/` directories, which are not
part of the open source release. `src/static/Internal.ts` is the only file that
references them, through lines ending in `// @fb-only` that are commented out on
export. It exports `Internal`, a `Partial<InternalApi>` that is empty in open
source builds, so callers use `Internal.foo?.()`. Tests run against both the
internal and open source builds. The internal implementation supplies:

- code browser links in text and Mermaid output
- changed-file lookup for `--diff`
- SAPP runner `repository_name` and `job_instance`
- sinks for commands of internal VS Code extensions

Without them, locations print as file paths, `--diff` exits with an error (use
`--patch-file`), SAPP `repository_name` is `unknown`, and `job_instance` is
omitted.
