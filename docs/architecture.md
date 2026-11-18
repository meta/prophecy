# Architecture

This page describes how the analyzer turns a project into findings, and where
each step stops. For usage, see the [README](../README.md).

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
  │   parser.ts   │ │      taint/     │ │      spec/      │ │  reporter.ts  │
  │               │ │                 │ │                 │ │ sappFormatter │
  │ TypeScript    │ │interprocedural  │ │ types.ts        │ │      fix/     │
  │ program and   │ │  entry points,  │ │ validate.ts     │ │               │
  │ type checker; │ │  command bridge │ │ presets.ts      │ │ text, json,   │
  │ resolves      │ │taintTracker     │ │ vscodeExtension │ │ mermaid,      │
  │ imports       │ │  forward        │ │ isl             │ │ lint,         │
  │               │ │  dataflow       │ │ express         │ │ sapp-json     │
  │               │ │taintValue       │ │ electron        │ │               │
  │               │ │  chains         │ │ nodeApis, http  │ │ + fix         │
  │               │ │functionResolver │ │ sinks,          │ │   generation  │
  │               │ │apiIdentity      │ │ sanitizers      │ │               │
  └───────────────┘ └─────────────────┘ └─────────────────┘ └───────────────┘
```

## Analysis pipeline

Paths below are relative to `src/static/`.

1. **Parse** (`parser.ts`): create a TypeScript `Program` and `TypeChecker`.
   The project's dependencies and `tsconfig` path mappings decide which imports
   resolve. Taint crosses files only through imports and calls the program
   resolves.
2. **Index** (`analyzer.ts`, `taint/interprocedural.ts`): build the VS Code
   command registry, class hierarchy, and setting-scope metadata before entry
   points are filtered or sharded. The registry maps statically resolved
   `registerCommand(name, handler)` names to their handlers.
3. **Discover entry points** (`taint/interprocedural.ts`): walk every source
   file, including nested declarations, for:
   - named entry functions (`entryFunctions`), whose parameters start clean;
   - callback registrations (`callbackRegistration` on parameter sources), such
     as `createServer((req, res) => ...)` and `onDidReceiveMessage(handler)`,
     which taint the configured callback parameter. A registered object's
     handler can be a method or a property holding an arrow or function
     expression;
   - handler entry points (`handlerEntryPoints`), such as `provideCodeLenses`
     on a provider passed to `registerCodeLensProvider`, whose parameters start
     clean;
   - `registerCommand` handlers, whose parameters start clean. A statically
     resolved `executeCommand(name, ...args)` call passes its arguments' taint
     to the registered handler;
   - `.on`, `.once`, and `.addListener` listeners for the literal event
     `"message"`, when the matching source is configured.

   Sources other than callback parameters introduce taint where their return
   values or properties are read. If discovery finds no entry points,
   `analyzer.ts` falls back to the top-level functions and class methods of the
   package's `main` file, or of every parsed file if `main` does not resolve.
   Being discovered does not make an entry point reachable at runtime.

4. **Propagate taint** (`taint/taintTracker.ts`): follow assignments,
   destructuring, string concatenation, template literals, ternaries, spreads,
   property reads, branches, loops, and resolvable calls, recording each step.
   Calls are followed to `--max-depth` (default 5). Supported constructors and
   method calls keep per-instance `this.field` state, so clean and tainted
   instances of one class stay separate, and a clean reassignment of a variable
   or `this` field replaces its taint. A call that cannot be resolved passes
   taint from its arguments and receiver to its result.
5. **Report** (`findingUtils.ts`, `reporter.ts`, `sappFormatter.ts`, `fix/`):
   deduplicate by finding handle and write text, JSON, Mermaid, lint JSON
   Lines, or SAPP NDJSON. Lint and SAPP output attach the repair defined for
   the sink, such as `exec()` → `execFile()`.

API matching prefers the type checker, which tells `RegExp.exec` apart from
`child_process.exec`. Without declarations, Prophecy falls back to import and
receiver identity, then to names; these are less reliable.

## Analysis limits

**Time and size.** Each entry point has a cooperative 90-second budget
(`PROPHECY_EP_BUDGET_MS`; `0` disables it). Call depth, state, and iteration
limits, and native stack exhaustion, can also stop an entry point early.
Because the budget is wall-clock time, findings can change between runs on the
same source. The retained traces are not every execution path.

The CLI lists incomplete entry points on stderr and can still exit 0. Some
state truncation is silent, so an empty list does not mean complete coverage.
`PROPHECY_STRICT=1` fails the scan on unexpected entry-point errors; ordinary
coverage limits still produce an incomplete report.

**Project references.** Referenced TypeScript projects are not traversed. A
solution config with only references is rejected rather than reported as an
empty scan; pass each referenced project as its own `--project`.

**Method calls.** If Prophecy knows the object's concrete class, it can follow
that class's method, including overrides and function-valued properties. If it
only knows an interface or base class, it can look for possible implementations
in the program. If the search finds more than eight, Prophecy discards that list.
It can still analyze method bodies it knows about from the concrete class or
base class, but it doesn't assume that any of them will run. Type declarations
alone don't supply a method body, and Prophecy cannot enumerate every target of
a computed method name or an interface implemented only by shape.

When Prophecy cannot resolve a call, it may carry taint from the arguments or
the object receiving the call into the result. That can flag results that do
not depend on the input. It does not model what the unknown code does with the
input, such as writing a field or invoking a callback.

**Instances and callbacks.** Supported `.map()` calls use the callback's
results; `.filter()` keeps the original elements. Function values can carry
captured instance state. Instance identity through `.at()`, microtask ordering,
and callbacks passed to unknown higher-order functions are not modeled.
Writes made inside helper branches and callback wrappers, including writes to
object parameters, are only partly propagated back to the caller, so a field
without taint after such a call may still be tainted at runtime.

**Control flow.** Branches keep separate state, and loops iterate to a bounded
fixed point. Loop exits, `switch` cases, and `try`/`catch`/`finally` are
handled conservatively. The analysis is not path-sensitive.

**Validation and sanitizers.** Guards such as `if (allowlist.includes(x))` and
regex tests do not clear taint. A sanitizer only applies to the sink categories
or sink names its rule covers. When analyzing shell text, Prophecy checks where
a quoted value is used. A recognized numeric conversion can preserve the
context for later quoted arguments if its result stays a number and is used as
an argument to a known command.
`JSON.stringify` and `encodeURIComponent` are not general sanitizers.

**File writes.** File-content findings do not distinguish an inert cache from
a file that is later executed, such as a task configuration or a shell startup
file.

## Finding identity

A finding's `handle` combines the source pattern, sink name, entry point, sink
file, and sink line. Several findings can share a line if their handles differ.
Prophecy keeps the first trace for each handle, except that a command execution
finding can replace an earlier argument injection finding with the same handle.
This can omit alternate paths. Moving the sink to another line changes the
handle. SAPP issues use a separate handle that survives line changes; see
[issue identity](sapp.md#issue-identity).
