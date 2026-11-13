# Precision reporting and file access

Reports describe modeled flows, not confirmed vulnerabilities or known-safe
executions. A source model does not establish an attacker boundary.

- `security_candidate`: a modeled flow into a security-relevant sink. Deployment
  reachability and exploitability still require validation.
- `file_access`: an input-dependent read path. Disclosure and privilege crossing
  have not been established. The shared Node `readFile`, `readFileSync` and
  `createReadStream` path rules use low severity and warning code 9013,
  `Prophecy-FileAccess`. File-content sources and propagation remain unchanged.
- `persistence_trace`: generic content persistence without an established
  destination/consumer security impact. Built-in content rules explicitly declare
  this classification and use low-severity `file_integrity` / 9012. Literal names
  such as task configuration or shell startup files do not prove privileged
  consumption; unresolved destinations also remain unverified traces. Argument
  position alone never changes a custom rule's meaning. Path-write rules remain
  high-severity security candidates.

Custom `lfi` rules retain their categories, severities and code 9007. A
`SinkSpec.reportingKind` override controls presentation only; it does not change
matching, scoped sanitizers, provenance or finding identity. A separately added
persistence category can use `reportingKind: "persistence_trace"` explicitly.

## Lossless presentation groups

Text and Mermaid group rows with the same observed source root and sink
site/category. The source key includes the source rule, description, parameter
selector and exact file/line/column; the sink key includes file/line/column,
syntactic site, rule name/pattern, operand positions and categories. Independent
roots and distinct sink contracts remain separate.
The key uses the root already recorded in each finding, not an inferred common
ancestor. Distinct recorded roots are deliberately not coalesced.

Every raw row, handle/entry context and propagation path is displayed inside its
group. Mermaid uses one chart per group and one complete subgraph per row. Group
counts do not replace raw-flow counts. Neither formatter mutates or deduplicates
the raw library findings.

JSON retains the array and every raw row, with additive
`reporting: {kind, limitation}` metadata. SAPP retains one issue per raw finding
and all trace frames, with `prophecy-reporting-kind` and
`prophecy-reporting-limitation` features. Existing security-candidate handles remain unchanged except for corrected API
identity matches. Read handles remint when 9007 becomes 9013; generic content
handles remint when 9005 becomes 9012. These are classification changes, not proof
that the old records were exploitable. All retained roots and traces remain
available.
No presentation group key is used as a raw or SAPP deduplication key.

An empty report means no modeled flows were detected, not proof of safety or
complete coverage. Inspect analysis diagnostics and incomplete entry points.

## Focused regression coverage

`tests-unit/static/precisionReporting.test.ts` covers alternate entry contexts,
independent roots/categories/sites, complete JSON/SAPP output, generic content
persistence, custom LFI compatibility and a composed-preset fixture retaining
read-path and read-content-to-execution flows. The fixture comparison against
legacy read classification checks unchanged raw handles, roots and paths and
limits SAPP handle changes to read traces. It is not a whole-corpus or runtime
exploitability test.
