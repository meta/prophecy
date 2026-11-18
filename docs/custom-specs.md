# Custom specs

`--spec <file.json>` tells Prophecy to use your own rules in place of a preset.
Prophecy validates the spec before scanning and exits with code 1 on an unknown
field, a missing required field, or an invalid value.

## Example

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

After [building Prophecy](../README.md#getting-started), run the fixture
from the Prophecy project directory:

```bash
node dist/index.js --project tests-unit/static/fixtures/custom-spec \
  --spec tests-unit/static/fixtures/custom-spec/spec.json
```

- `taintAllProperties` keeps taint on property reads such as `event.branch`.
  Without it, this example reports nothing.
- `callbackRegistration` matches the end of the call name, so `onPush` also
  matches `bot.onPush`.

## Spec fields

See the [type definitions](../src/static/spec/types.ts) for the shape of each
rule.

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

## Start from a preset

To build on a preset, export it as JSON and edit the copy:

```shell
node -e 'console.log(JSON.stringify(require("./dist/spec/presets").builtinSpecs.express, null, 2))' > spec.json
```

A spec can only use patterns Prophecy already understands. To support a new
pattern, [change the analyzer](development.md#adding-a-pattern).
