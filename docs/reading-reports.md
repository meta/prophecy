# Reading reports

Every finding is a candidate for review. Before treating one as exploitable,
check the source's trust boundary, the sink's runtime behavior, and any
validation in between. An empty report means Prophecy found no modeled flow.
Check stderr for incomplete entry points before reading it as clean.

## The text report

```text
$ node dist/index.js --project tests-unit/static/fixtures/file-write-path
...
Found 4 taint flows:
  HIGH  file_write      3
  LOW   file_integrity  1
Findings are candidates for further review, not confirmed security issues.

──────────────────────────────────────────────────────────────────────
[1/4] Security candidate (file_write; 1 trace)
  Trace 1/1: HIGH: File write to attacker-controlled path via Node.js fs module
  Handle: handleUri.uri|writeFile_path|URI handler (vscode:// deeplink)|/path/to/prophecy/tests-unit/static/fixtures/file-write-path/extension.ts|17
  ...
```

The header counts flows by severity and sink category. Each numbered group
below it has one source and one sink site; its title gives the finding kind,
the categories, and the number of traces. Each trace shows its severity and
sink, its handle, the source, every propagation step, and the sink.

The handle combines the source pattern, sink name, entry point, file, and line.
Traces in the same group differ by entry point or by path.

## Finding kinds

| Kind                 | Meaning                                                               | Built-in rules                                                      |
| -------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `security_candidate` | Input reaches a security-relevant sink                                | Severity and warning code from the sink rule                        |
| `file_access`        | Input controls the path of a file read; disclosure is not established | `readFile`, `readFileSync`, and `createReadStream` paths; low, 9013 |
| `persistence_trace`  | Input reaches file content, with no known consumer that executes it   | File-write content; low, `file_integrity`, 9012                     |

File-write paths stay high-severity security candidates. A destination named
like a task configuration or a shell startup file does not change the kind of a
content write, and neither does an unresolved destination.

Custom rules are security candidates unless every category is `file_access`.
`SinkSpec.reportingKind` overrides the kind for presentation only; matching,
sanitizers, and finding identity do not change.

## Groups

Text and Mermaid output group traces that share a source root and a sink site.
The source key is the source rule, its parameter selector, and its exact
location. The sink key is the location, syntactic site, rule, operand
positions, and categories. Traces with different recorded roots are never
merged. Every trace is still printed inside its group, and Mermaid draws one
chart per group with one subgraph per trace.

Grouping only affects presentation. JSON keeps every finding and adds
`reporting: {kind, limitation}`. SAPP keeps one issue per finding, with
`prophecy-reporting-kind` and `prophecy-reporting-limitation` features. No
group key is used for deduplication.

## Multiple project roots

JSON and SAPP output deduplicate findings by handle across roots. Lint output
drops identical lines. Text and Mermaid print one report per root.
