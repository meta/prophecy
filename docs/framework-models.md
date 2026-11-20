# Framework and API coverage

A preset defines which inputs Prophecy treats as untrusted. It does not show
that a deployment is exploitable. Install the analyzed project's type
declarations where they exist: framework and wrapper rules match on API
identity, established through imports, supported factories, host callback
types, or declarations. A local method with the same name does not match.

## Choosing a preset

`--rules auto` is the default. Prophecy checks each project root's
`package.json` in the order below. It checks both regular and development
dependencies.

| Preset             | Selects when `package.json` has                  |
| ------------------ | ------------------------------------------------ |
| `isl`              | The package name `sapling-scm` or `isl-server`   |
| `vscode-extension` | `engines.vscode` or a `@types/vscode` dependency |
| `electron`         | An `electron` dependency                         |
| `express`          | An `express` or `@types/express` dependency      |

If nothing matches or Prophecy can't load `package.json`, it uses
`vscode-extension`. Each project root gets one preset. If a project mixes
frameworks, choose a preset with `--rules` or provide a
[custom spec](custom-specs.md).

## Presets

| Preset             | Sources                                                                                                                                                                                                                       | Sinks and exclusions                                                                                                                                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vscode-extension` | URI handler and webview message parameters, debug configuration callbacks, workspace settings, document content, file reads and names, selected command output, clipboard reads, input dialogs, HTTP requests, message events | Shared Node sinks; terminals, commands, language-client launch options, debug configuration fields that run commands, webview HTML, external URLs, and workspace edits. `process.env` is not a source                |
| `isl`              | Same as `vscode-extension`, plus the output of commands run through `ejeca` and the WebSocket upgrade request of the standalone server                                                                                        | Adds ISL's command wrappers and their standard input, the runners an operation can name besides Sapling, the executable a `RepositoryCache` context names, editor settings writes, and file opens, reads and deletes |
| `electron`         | `ipcMain.handle/handleOnce/on/once/addListener` payload parameters after the event; the `app` `open-url` URL argument                                                                                                         | Shared Node sinks and `shell.openExternal`. Host event metadata and unrelated application events are not sources                                                                                                     |
| `express`          | Request fields and header accessors in route callbacks and `use`, `head`, `options`, and `app.route(path)` handlers                                                                                                           | Shared Node sinks; response bodies, redirects, selected template names, and served file paths. The request's `app` and response metadata are not tainted as a whole                                                  |

The VS Code preset treats settings declared with `machine` or `application`
scope as sources and labels them with their scope. It excludes `process.env`
because the extension host inherits it from the user's session. The ISL preset
adds rules for `ejeca`, `runCommand`, `Repository.runCommand`, and
`runOrQueueOperation`, and for `runExternalCommand`, `runConfCommand`, and
`runArcanistCommand`, which run a program other than Sapling. Because `ejeca`
is also a source of command output there, calls to it are not analyzed further:
the ISL sinks report at each call instead of at the `spawn` inside it.

The Express preset also models Node `http` and `https` server requests. It
does not model authentication, middleware ordering beyond what is described
below, or a framework's full lifecycle.

## Express middleware

- Normal middleware passes request and response state, including `res.locals`,
  to later handlers through `next()`. A handler that does not call `next()`
  does not run the handlers after it.
- Registrations are linked only when they use the same receiver in one lexical
  scope with static paths. Within one statement list, direct `const` aliases
  and static-field `=` assignments tell receivers apart.
- Handler functions can be imported from another file, but registration order
  across modules is not inferred.
- One level of `app.use(staticPath, router)` passes earlier parent middleware
  state into the router's matching route.
- Not modeled as normal continuations: nested mounts, argument lists that mix
  callbacks and routers, dynamic or parameterized mount paths, error
  middleware, `next(error)`, and `next("route")`.
- Not tracked: receiver writes inside branches or helpers, computed paths,
  rebinding the root variable, and mutation from another module.

## Express templates and responses

`res.render(view, locals)` treats the view name as file selection (`lfi`).
Locals are data, not template source. Engine-specific options, unescaped
output, and templates compiled from strings need their own rules.

`res.send` reports a string or unknown body as an XSS candidate. Express
serializes object and array bodies as JSON by default, but Prophecy only treats
a body as JSON in a narrow case:

- the handler is written inline on a fresh `express()` or `Router()` created in
  the same file, and
- that file has no middleware and no possible header setter, in any handler.

Everything else stays a candidate:

- type assertions and declared object types, which do not prove the runtime
  shape;
- `res.send(JSON.stringify(value))`, which is a string response;
- visible header setters, nonstandard response operations, passing the response
  to other code, and opaque or fluent receivers;
- opaque application factories and imported application state.

## Shared Node APIs

Every preset checks child-process and dynamic code execution, outgoing HTTP
requests, and file access. Separate rules can match different parts of the same
call, such as an executable and its arguments or a file's path and content.
A file path sink does not make the file's contents a source.

- **Fetch.** Matches the standard global or its declarations, and the
  `node-fetch` default and `undici.fetch` exports. Native globals and their
  immutable aliases keep their identity; a visible replacement of the global
  invalidates later reads. A local function or method named `fetch` is not an
  HTTP sink. Typed factory results, fields, and parameters also match when
  they can be called like `fetch` and return a native `Promise<Response>` with
  a recognized DOM, Node, or fetch-library `Response`. This keeps URL flows
  through wrapped transports, and can also report type-compatible mocks. A
  match does not prove network I/O or that the attacker controls the
  destination.
- **Execa and cross-spawn.** The direct file, argv, and options forms, with
  separate rules for the executable, the arguments, and environment or shell
  options. Execa tagged templates, bound methods, `command`, and `node` are
  not modeled.
- **Axios.** URL and destination fields are separate from payload data, query
  parameters, and headers. URL overloads overwrite `config.url`. Clients from
  `axios.create()` pass their `baseURL`, `socketPath`, and proxy fields to each
  request; known clean per-call values override them, and proxy objects merge
  field by field. `url`, `method`, and `data` defaults are not inherited.
  Unknown config expressions and spreads stay conservative.
  `allowAbsoluteUrls` is not evaluated, so an absolute URL is not assumed to
  bypass `baseURL`.
- **Files.** `readFile`, `readFileSync`, and `createReadStream` check the input
  path. Writes and appends have separate path and content rules.
  `createWriteStream` checks the output path. A literal nonnegative integer
  `fd`, including `0`, makes a stream's path inactive; an unknown file handle
  does not. A read-path finding does not show that data reached an attacker,
  and directory confinement, symlinks, and destination semantics still need
  review.
- **File contents as sources.** `NodeFileSources` is opt-in. For callback
  APIs, the data parameter is the source, not the error or the returned
  handle. Promise and promisified reads deliver their result;
  `fs-extra.readFile` does so only when its arguments select the Promise
  overload, which opaque options or a possible callback do not. Read streams
  deliver data to their consumers, not through path or descriptor metadata. A
  preset that treats repository files as untrusted can use these sources; a
  server preset need not treat every local configuration file as
  attacker-controlled.

API identity comes from ES imports, CommonJS `require`, `import = require`,
awaited literal `import("module")`, and supported constant aliases and
destructuring. An unawaited import Promise or a computed module name does not
establish identity. Prophecy does not check whether a module export or mutable
property is replaced at runtime.

`Map` and `Set` size reads keep their input's provenance but cannot carry HTML,
template, or code syntax. This needs native getter declarations and a known
constructor or immutable-alias origin for every possible value. Casts, unknown
typed parameters, receivers that escape, replaced getters or prototypes, and
local lookalike classes do not qualify, and opaque fields and return values
stay conservative. A size that selects a file, executable, or argument is
still reported: a number is not a general sanitizer for resource selection.

## Sanitizers

Every preset includes `parseInt` and `Number` for string-injection sinks; the
resulting number stays tainted for other sinks. The VS Code preset also models
`shlex.quote`. A quoted argument to a fixed command is reported as argument
injection instead of command execution. A quoted argument to a shell or
interpreter on its denylist is still command execution.

Custom HTML or XML escaping, JSON script-data encoders, and local shell-quoting
helpers generally stay candidates. A helper's name says nothing about its
implementation or where its result is used, and serialized JSON or an encoded
string can become unsafe when it is decoded or used in another context.

## Compatibility

The models are tested against small declaration fixtures for the supported API
signatures. The tests do not launch Electron, run framework servers, or
exercise browser or network policy, so framework versions with different
signatures may not match.
