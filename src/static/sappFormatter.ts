/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Emit SAPP issue and trace-frame NDJSON (one object per line, no header)
 * and the associated runner/sapper metadata.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { PROPHECY_BUILD_REVISION } from "./buildInfo";
import { CodeLocation, PropagationStep, TaintFinding, SinkCategory } from "./spec/types";
import { Internal } from "./Internal";
import { findingReporting, findingKindLabels } from "./findingUtils";

// Warning‑code mapping (9001–9099 range, allocated for Prophecy)

const CATEGORY_TO_CODE: Record<string, number> = {
    rce: 9001,
    code_injection: 9002,
    xss: 9003,
    ssrf: 9004,
    file_write: 9005,
    file_integrity: 9012,
    open_redirect: 9006,
    lfi: 9007,
    ssti: 9008,
    workspace_edit: 9009,
    arg_injection: 9010,
    prompt_injection: 9011,
    // 9012 is reserved for file_integrity, not file access.
    file_access: 9013,
};

const DEFAULT_CODE = 9099;

const SAPP_RULES: ReadonlyArray<{ code: number; name: string; description: string }> = [
    {
        code: 9001,
        name: "Prophecy-RCE",
        description: "Modeled remote-code-execution candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9002,
        name: "Prophecy-CodeInjection",
        description: "Modeled code-injection candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9003,
        name: "Prophecy-XSS",
        description: "Modeled cross-site-scripting candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9004,
        name: "Prophecy-SSRF",
        description:
            "Modeled server-side-request-forgery candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9005,
        name: "Prophecy-FileWrite",
        description:
            "Modeled file-write candidate or generic content-persistence trace; inspect reporting-kind features, exploitability not established",
    },
    {
        code: 9006,
        name: "Prophecy-OpenRedirect",
        description: "Modeled open-redirect candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9007,
        name: "Prophecy-LFI",
        description: "Modeled local-file-inclusion candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9008,
        name: "Prophecy-SSTI",
        description:
            "Modeled server-side-template-injection candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9009,
        name: "Prophecy-WorkspaceEdit",
        description: "Modeled workspace-edit candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9010,
        name: "Prophecy-ArgInjection",
        description: "Modeled argument-injection candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9011,
        name: "Prophecy-PromptInjection",
        description: "Modeled prompt-injection candidate; exploitability and attacker boundary not established",
    },
    {
        code: 9013,
        name: "Prophecy-FileAccess",
        description: "Input-dependent file-access trace; disclosure and privilege crossing not established",
    },
    {
        code: DEFAULT_CODE,
        name: "Prophecy-Unknown",
        description: "Modeled tainted data flow with an unknown category; exploitability not established",
    },
    {
        code: 9012,
        name: "Prophecy-FileIntegrity",
        description: "Content-persistence trace; destination and consumer impact not established",
    },
];

// SAPP ingests all *.sapp shards as one bundle. Each analyzed project writes
// its own issue/trace pair; sapper metadata supplies the filename glob.
export function sappIssuesFilename(shard: number): string {
    return `issues_${shard}.sapp`;
}

export function sappTraceFramesFilename(shard: number): string {
    return `traceFrames_${shard}.sapp`;
}
export const SAPP_RUNNER_METADATA_FILENAME = "runner_metadata.json";
export const SAPP_SAPPER_METADATA_FILENAME = "sapper_metadata.json";

const SAPP_FILENAME_GLOB = "*.sapp";
const SAPP_ROOT = "N/A";
const SAPP_TOOL = "prophecy";
const SAPP_VERSION = PROPHECY_BUILD_REVISION || "unknown";

export interface SappRule {
    code: number;
    name: string;
    description: string;
}

export interface SappRunnerMetadata {
    commit?: string;
    root: string;
    version: string;
    repository_name: string;
    project: string;
    job_instance?: string;
}

export interface SappSapperMetadata {
    filename_glob: string;
    tool: string;
    rules: ReadonlyArray<SappRule>;
}

export interface SappMetadata {
    runner: SappRunnerMetadata;
    sapper: SappSapperMetadata;
}

/**
 * Build the metadata files that SAPP reads via its *metadata.json glob.
 */
export function generateSappMetadata(project: string, commit?: string): SappMetadata {
    const jobInstance = Internal.sappJobInstance?.();
    return {
        runner: {
            ...(commit ? { commit } : {}),
            root: SAPP_ROOT,
            version: SAPP_VERSION,
            repository_name: Internal.sappRepositoryName?.() ?? "unknown",
            project,
            ...(jobInstance ? { job_instance: jobInstance } : {}),
        },
        sapper: {
            filename_glob: SAPP_FILENAME_GLOB,
            tool: SAPP_TOOL,
            rules: SAPP_RULES,
        },
    };
}

// Public: NDJSON formatting

/**
 * Write one issue per line without allocating a bundle-sized NDJSON string.
 * The findings array and each serialized issue must still fit in memory.
 * An empty findings array produces an empty file.
 */
export function writeFindingsSappStream(outputPath: string, findings: TaintFinding[], repoRoot?: string): void {
    const fd = fs.openSync(outputPath, "w");
    try {
        for (const f of findings) {
            fs.writeSync(fd, JSON.stringify(buildSappIssue(f, repoRoot)) + "\n");
        }
    } finally {
        fs.closeSync(fd);
    }
}

/**
 * Stream the standalone SAPP trace frames for `findings` directly to
 * `outputPath`, one frame per line. See `writeFindingsSappStream` for
 * rationale.
 */
export function writeTraceFramesSappStream(outputPath: string, findings: TaintFinding[], repoRoot?: string): void {
    const fd = fs.openSync(outputPath, "w");
    try {
        for (const finding of findings) {
            for (const frame of buildSourceTraceFrames(finding, repoRoot)) {
                fs.writeSync(fd, JSON.stringify(frame) + "\n");
            }
            for (const frame of buildSinkTraceFrames(finding, repoRoot)) {
                fs.writeSync(fd, JSON.stringify(frame) + "\n");
            }
        }
    } finally {
        fs.closeSync(fd);
    }
}

const TRACE_CONTINUATION_PORT = "prophecy";
const SOURCE_LEAF_PORT = "source";
const SINK_LEAF_PORT = "sink";

/** Resolve a warning code from the first category on the sink. */
function getWarningCode(categories: SinkCategory[]): number {
    if (categories.length === 0) return DEFAULT_CODE;
    return CATEGORY_TO_CODE[categories[0]] ?? DEFAULT_CODE;
}

/** Make a file path relative to repo root (if provided). */
function relativize(fileName: string, repoRoot?: string): string {
    if (!repoRoot) return fileName;
    const absFile = path.resolve(fileName);
    const absRoot = path.resolve(repoRoot);
    if (absFile.startsWith(absRoot + path.sep)) {
        return absFile.slice(absRoot.length + 1);
    }
    return fileName;
}

/**
 * Compute the SAPP issue handle, which SAPP uses to match an issue across
 * runs. It must not contain lines, columns, or the entry point: any of those
 * re-mints the issue (and drops its triage) when unrelated code moves.
 *
 * Format: "{callable}:{code}:{sinkName}:{hash16}", where the hash also covers
 * the sink site and source pattern. Truncation preserves the suffix while
 * fitting SAPP's VARCHAR(255) limit.
 */
function computeSappHandle(filename: string, callable: string, finding: TaintFinding, code: number): string {
    const prefix = `${callable}:${code}:${finding.sink.name}`;
    const identity = [filename, finding.sinkSite, code, finding.sink.name, finding.source.pattern].join("\u0000");
    const hash = crypto.createHash("md5").update(identity).digest("hex").slice(0, 16);
    const hashSuffix = `:${hash}`;
    const handle = `${prefix}${hashSuffix}`;
    if (handle.length <= 255) return handle;

    return `${prefix.slice(0, 255 - hashSuffix.length)}${hashSuffix}`;
}

/** The named scopes enclosing the sink, without the site itself. */
function sinkScope(sinkSite: string): string {
    return sinkSite.slice(0, sinkSite.lastIndexOf(">"));
}

/** Short stable id used to connect issue traces with standalone trace frames. */
function computeTraceId(handle: string): string {
    return crypto.createHash("md5").update(handle).digest("hex").slice(0, 12);
}

/**
 * Parse the Prophecy handle to extract the entry‑point name.
 *
 * Prophecy handles have the form:
 *   sourcePattern|sinkName|entryPointName|fileName|line
 */
function extractEntryPointName(handle: string): string {
    const parts = handle.split("|");
    return parts.length >= 3 ? parts[2] : "unknown";
}

/** Compute the end column from CodeLocation (column + text length, or +1). */
function endColumn(col: number, text?: string): number {
    return col + (text ? text.length : 1);
}

function sappPosition(location: CodeLocation): Record<string, number> {
    return {
        line: location.line,
        start: location.column,
        end: endColumn(location.column, location.text),
    };
}

/** Max length for fix_info JSON string in SAPP. */
const FIX_INFO_MAX_CHARS = 767;

/** Build a single SAPP NDJSON issue object from a TaintFinding. */
function buildSappIssue(finding: TaintFinding, repoRoot?: string): Record<string, unknown> {
    const code = getWarningCode(finding.sink.categories);
    const filename = relativize(finding.sinkLocation.fileName, repoRoot);
    const callable = `${filename}::${sinkScope(finding.sinkSite)}`;
    const sinkEnd = endColumn(finding.sinkLocation.column, finding.sinkLocation.text);
    const traceId = computeTraceId(finding.handle);
    const reporting = findingReporting(finding.sink);

    const features: string[] = [
        `prophecy-reporting-kind:${reporting.kind}`,
        `prophecy-reporting-limitation:${reporting.limitation}`,
        `prophecy-handle:${finding.handle}`,
        `prophecy-entrypoint:${extractEntryPointName(finding.handle)}`,
        `prophecy-sink-site:${finding.sinkSite}`,
        `prophecy-source-kind:${finding.source.description}`,
        `prophecy-sink-kind:${finding.sink.name}`,
        `prophecy-severity:${finding.sink.severity || "high"}`,
    ];
    for (const cat of finding.sink.categories) {
        features.push(`prophecy-category:${cat}`);
    }
    if (finding.quotedArgumentOf != null) {
        features.push(`prophecy-quoted-argument-to:${finding.quotedArgumentOf}`);
    }

    const forwardTrace = buildIssueCallTrace(
        "forward",
        sourceTraceRootCallable(traceId),
        finding.sinkLocation,
        finding.source.description,
        finding.source.pattern,
        sourceTraceFrameCount(finding),
    );

    const backwardTrace = buildIssueCallTrace(
        "backward",
        sinkTraceRootCallable(traceId),
        finding.sinkLocation,
        finding.sink.name,
        finding.sink.pattern,
        sinkTraceFrameCount(),
    );

    const propagationSteps = finding.propagationChain.map((step) => ({
        kind: step.kind,
        location: {
            line: step.location.line,
            start: step.location.column,
            end: endColumn(step.location.column, step.location.text),
        },
        description: step.description,
    }));

    let fixInfo: Record<string, unknown> | undefined;
    if (finding.fix) {
        const candidate = {
            filePath: relativize(finding.fix.filePath, repoRoot),
            original: finding.fix.original,
            replacement: finding.fix.replacement,
            applicability: finding.fix.applicability,
        };
        if (JSON.stringify(candidate).length <= FIX_INFO_MAX_CHARS) {
            fixInfo = candidate;
        }
    }

    const handle = computeSappHandle(filename, callable, finding, code);

    const issue: Record<string, unknown> = {
        kind: "issue",
        code,
        handle,
        callable,
        callable_line: finding.sinkLocation.line,
        filename,
        position: {
            line: finding.sinkLocation.line,
            start: finding.sinkLocation.column,
            end: sinkEnd,
        },
        description: `${findingKindLabels[reporting.kind]}: Data from [${finding.source.description}] source(s) may reach [${finding.sink.name}] sink(s). ${reporting.limitation}`,
        traces: [forwardTrace, backwardTrace],
        features,
    };

    if (fixInfo) {
        issue.fix_info = fixInfo;
    }
    if (propagationSteps.length > 0) {
        issue.propagation_steps = propagationSteps;
    }

    return issue;
}

function buildIssueCallTrace(
    direction: "forward" | "backward",
    rootCallable: string,
    location: CodeLocation,
    leafKind: string,
    leafName: string,
    traceLength: number,
): Record<string, unknown> {
    return {
        [direction]: {
            call: {
                position: sappPosition(location),
                resolves_to: [rootCallable],
                port: TRACE_CONTINUATION_PORT,
            },
            kinds: [{ kind: leafKind, trace_len: traceLength }],
            leaves: [{ name: leafName }],
            local_trace: { positions: [] as Array<Record<string, number>> },
        },
    };
}

type IndexedStep = { step: PropagationStep; index: number };

/**
 * The propagation chain from the sink back to the source, split into runs of
 * consecutive steps on the same line of the same file. Each run is one trace
 * frame: SAPP stops reading a trace 30 frames from its root and then reports
 * it as having no source, and a single expression often contributes several
 * steps.
 */
function sourceTraceRuns(chain: PropagationStep[]): IndexedStep[][] {
    const runs: IndexedStep[][] = [];
    for (let index = chain.length - 1; index >= 0; index--) {
        const step = chain[index];
        const run = runs[runs.length - 1];
        const previous = run?.[run.length - 1].step.location;
        if (previous?.fileName === step.location.fileName && previous.line === step.location.line) {
            run.push({ step, index });
        } else {
            runs.push([{ step, index }]);
        }
    }
    return runs;
}

/** The span covering `locations`, which all lie on one line. */
function lineSpanPosition(locations: CodeLocation[]): Record<string, number> {
    return {
        line: locations[0].line,
        start: Math.min(...locations.map((location) => location.column)),
        end: Math.max(...locations.map((location) => endColumn(location.column, location.text))),
    };
}

function buildSourceTraceFrames(finding: TaintFinding, repoRoot?: string): Array<Record<string, unknown>> {
    const traceId = computeTraceId(finding.handle);
    const frames: Array<Record<string, unknown>> = [];
    const runs = sourceTraceRuns(finding.propagationChain);

    let caller = sourceTraceRootCallable(traceId);
    for (let i = 0; i < runs.length; i++) {
        const run = runs[i];
        const callee = sourceTraceStepCallable(traceId, run[0].index);
        frames.push(
            buildConditionFrame({
                type: "postcondition",
                caller,
                callee,
                calleePort: TRACE_CONTINUATION_PORT,
                calleePosition: lineSpanPosition(run.map(({ step }) => step.location)),
                filename: relativize(run[0].step.location.fileName, repoRoot),
                leafKey: "sources",
                leafKind: finding.source.description,
                depth: runs.length - i,
                features: run.map(({ step, index }) =>
                    traceFeature(`prophecy-step-${index}:${step.kind}: ${step.description}`, step.location),
                ),
            }),
        );
        caller = callee;
    }

    frames.push(
        buildConditionFrame({
            type: "postcondition",
            caller,
            callee: finding.source.pattern,
            calleePort: SOURCE_LEAF_PORT,
            calleePosition: sappPosition(finding.sourceLocation),
            filename: relativize(finding.sourceLocation.fileName, repoRoot),
            leafKey: "sources",
            leafKind: finding.source.description,
            depth: 0,
            features: [traceFeature(`prophecy-source-kind:${finding.source.description}`, finding.sourceLocation)],
        }),
    );

    return frames;
}

function buildSinkTraceFrames(finding: TaintFinding, repoRoot?: string): Array<Record<string, unknown>> {
    const traceId = computeTraceId(finding.handle);
    return [
        buildConditionFrame({
            type: "precondition",
            caller: sinkTraceRootCallable(traceId),
            callee: finding.sink.pattern,
            calleePort: SINK_LEAF_PORT,
            calleePosition: sappPosition(finding.sinkLocation),
            filename: relativize(finding.sinkLocation.fileName, repoRoot),
            leafKey: "sinks",
            leafKind: finding.sink.name,
            depth: 0,
            features: [traceFeature(`prophecy-sink-kind:${finding.sink.name}`, finding.sinkLocation)],
        }),
    ];
}

function buildConditionFrame({
    type,
    caller,
    callee,
    calleePort,
    calleePosition,
    filename,
    leafKey,
    leafKind,
    depth,
    features,
}: {
    type: "precondition" | "postcondition";
    caller: string;
    callee: string;
    calleePort: string;
    calleePosition: Record<string, number>;
    filename: string;
    leafKey: "sources" | "sinks";
    leafKind: string;
    depth: number;
    features: Array<Record<string, unknown>>;
}): Record<string, unknown> {
    return {
        type,
        caller,
        caller_port: TRACE_CONTINUATION_PORT,
        callee,
        callee_port: calleePort,
        callee_location: calleePosition,
        filename,
        [leafKey]: [{ kind: leafKind, depth }],
        type_interval: {},
        features,
    };
}

function traceFeature(name: string, location: CodeLocation): Record<string, unknown> {
    return {
        name,
        locations: [sappPosition(location)],
    };
}

function sourceTraceFrameCount(finding: TaintFinding): number {
    return sourceTraceRuns(finding.propagationChain).length + 1;
}

function sinkTraceFrameCount(): number {
    return 1;
}

function sourceTraceRootCallable(traceId: string): string {
    return traceCallable(traceId, "source", "root");
}

function sourceTraceStepCallable(traceId: string, stepIndex: number): string {
    return traceCallable(traceId, "source", `step:${stepIndex}`);
}

function sinkTraceRootCallable(traceId: string): string {
    return traceCallable(traceId, "sink", "root");
}

function traceCallable(traceId: string, direction: "source" | "sink", segment: string): string {
    return `prophecy:${traceId}:${direction}:${segment}`;
}
