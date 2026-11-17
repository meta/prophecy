# Framework and API coverage

A preset defines a trust boundary, not a proof that a deployment is exploitable.
Install the analyzed project's declarations where available. New framework and
wrapper rules require API identity through imports, supported factories, host
callback types, or external declarations; a local method with the same name is
not sufficient.

## Presets

| Preset     | Modeled input                                                                                                     | Selected sinks and exclusions                                                                                                                      |
| ---------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `electron` | `ipcMain.handle/handleOnce/on/once/addListener` payload parameters after the event; `app` `open-url` URL argument | Shared Node sinks and `shell.openExternal`; host event metadata and unrelated application events are not input sources                             |
| `express`  | Request fields and header accessors; route callbacks, `use`, `head`, `options`, and `app.route(path)` handlers    | Shared Node sinks; response body, redirects, selected template name, and served file paths; request `app`/response metadata is not blanket-tainted |

The Express preset includes scoped Node HTTP/HTTPS server request models.
These models do not claim complete framework coverage or establish a
framework's entire lifecycle, authentication, or middleware ordering.

`auto` chooses one preset per root, in this order: ISL package names, VS Code,
Electron, Express.
Unrecognized metadata retains the VS Code fallback. Use `--preset` for an
explicit selection or `--spec` for a composed model.

## Express middleware

Normal middleware can carry request and response instance state through
`next()`, including `res.locals`. A terminal handler that does not call `next()`
does not automatically execute downstream handlers. The model is bounded to
supported same-receiver registrations, lexical registration scope, and static
path relationships. Within one statement list, direct `const` aliases and
static-field `=` writes distinguish receiver identities. Branch/helper writes,
computed paths, root-variable rebinding, and cross-module mutation are not
tracked. Handler functions may be imported from another file;
arbitrary registration order across modules is not inferred. One-level direct
`app.use(staticPath, router)` mounts can pass earlier parent middleware state
into the router's matching route. Nested mounts, mixed callback/router argument
lists, dynamic or parameterized mount paths, error middleware, and
`next(error)`/`next("route")` transitions are not modeled as normal continuations.

`res.render(view, locals)` treats the view name as template-file selection
(`lfi`). Ordinary locals are data, not automatically template source. This does
not prove that every locals key or template is safe: engine-specific options,
unescaped output, and dynamically compiled template strings require separate
sink/context rules.

`res.send` keeps string and unknown bodies as HTML/XSS candidates. Runtime object
and array constructions can use Express's default JSON serialization. Type
assertions or a declared object type do not prove that runtime shape. The
precise JSON case requires a direct inline handler on a fresh, locally known
`express()` or `Router()` allocation, with no middleware or potential header
setters in that file. Opaque application factories and imported application
state remain candidates. This does not grant
JSON strings sanitizer credit: `res.send(JSON.stringify(value))` is still a
string response. Visible header setters, nonstandard response operations,
response handoffs, and opaque or fluent receivers keep object-body candidates.
The content-type check is deliberately conservative: a potential header setter
in another handler in the same file also disables precision. It does not infer
arbitrary middleware/application setup as a whole-program response invariant.

## Shared Node APIs

- **Fetch:** requires standard global/declaration identity or the supported
  `node-fetch` default / `undici.fetch` package exports. Native globals and
  supported immutable aliases retain their identity; visible global replacement
  invalidates later reads. An unrelated local function or installer method named
  `fetch` is not an HTTP request sink. Typed factory results, fields and function
  parameters also match a request-like callable contract returning a native
  `Promise<Response>` with recognized DOM/Node/fetch-library response declarations.
  This retains URL flows through wrapped transports; type-compatible mocks can
  also produce conservative candidates. The contract is not proof that a function
  performs network I/O, and a candidate does not establish arbitrary destination control.
- **Execa and cross-spawn:** model the direct file/argv/options forms, separating
  executable selection, argument injection, and execution-bearing environment/
  shell options. Execa tagged templates, bound methods, `command`, and `node`
  forms are not interchangeable with these signatures and are not modeled here.
- **Axios:** distinguish URL/destination fields from payload data, query
  parameters, and headers. URL overloads overwrite `config.url`. Clients created
  by `axios.create()` carry inherited `baseURL`, `socketPath`, and proxy
  destination fields into requests. Known clean per-call values override them;
  proxy objects merge by field. Axios does not inherit `url`, `method`, or
  `data` defaults into these requests. Unknown config expressions/spreads remain
  conservative. The model does not evaluate `allowAbsoluteUrls` or prove that a
  supplied absolute URL makes `baseURL` inactive.
- **Files:** `readFile`, `readFileSync`, and `createReadStream` check input paths;
  writes/appends distinguish path and content; `createWriteStream` checks the
  output path. A proven nonnegative integer `fd` (including `0`) makes a stream's
  path inactive; unknown or nonliteral file handles remain conservative. A
  read-path finding does not establish that data was disclosed to
  an attacker. Directory confinement, symlinks, and destination semantics still
  require review.
- **Content sources:** `NodeFileSources` is opt-in. Callback file data is the
  callback's data parameter, not its error or the API's return handle. Promise
  and promisified reads deliver their result; `fs-extra.readFile` does so when
  its arguments establish a Promise overload. Opaque options or a possible
  callback do not establish that overload. Read streams deliver data to
  consumers, not through path/file-descriptor metadata. A preset that treats
  repository files as untrusted may use these sources; a server preset need not
  treat every local configuration file as attacker-controlled.

Import identity includes ES imports, CommonJS `require`, `import = require`,
awaited literal `import("module")`, and supported constant aliases/destructuring.
An unawaited import Promise or a computed module name does not establish the
module's API identity. This is not a whole-program proof that a module export
or mutable property was never replaced at runtime.

Native `Map`/`Set` cardinality reads retain their input provenance but cannot
carry HTML, template, or dynamic-code string syntax. The model requires native
getter declarations plus bounded constructor/immutable-alias origin proof for
every observed alternative. Casts, unknown typed parameters, opaque receiver
escapes, known getter/prototype replacements, and local lookalikes do not prove
native cardinality. Opaque field or return origins remain conservative.
Cardinality remains a candidate when it selects a file, executable,
or argument; numeric data is not a general resource-selection sanitizer.

Custom HTML/XML escaping, JSON script-data encoders, and local shell-quoting
helpers generally remain conservative candidates. A helper name does not prove
its implementation or use-site context. In particular, serialized JSON or an
encoded string can become unsafe when decoded or used in a different context.

Effect writeback from helper branches and callback wrappers remains partial,
including writes to object parameters. Missing taint after such a call does not
prove that a field stays clean.

## Regression coverage

The focused suites include positive flows, clean controls, unrelated API names,
and cross-file helpers:

```bash
pnpm build
pnpm exec jest --config jest.static.config.js --runInBand \
  --testPathPattern='frameworkCoverage|nodeApi|apiBoundary|presetCoverage|httpRequest|eventFlowRequest|discovery'
```

The tests use small declaration fixtures for supported API signatures; they do
not launch Electron, run framework servers, or exercise browser/network policy.
Framework-version differences outside those signatures remain a compatibility
limit. See the [development guide](development.md) for full-suite commands and
fixture conventions.
