/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { Worker, isMainThread, workerData } from "worker_threads";
import * as yargs from "yargs";
import * as path from "path";
import * as fs from "fs";
import { format } from "util";
import { analyze, AnalyzerOptions, AnalyzerResult, validateAnalysisOptions } from "./analyzer";
import { ProjectConfigurationError } from "./parser";
import { formatFindingsJSON } from "./reporter";
import { analyzeDiffScreening } from "./diff";
import { TaintSpec } from "./spec/types";
import { builtinSpecs, PresetSelection, presetChoices } from "./spec/presets";
import { validateSpec } from "./spec/validate";
import { formatAnalysisDebugLog, formatAnalysisMetrics } from "./metrics";
import { deduplicateFindings } from "./findingUtils";
import { deduplicateSappBundle } from "./sappBundle";
import { findNearestArcConfigRoot } from "./sourceControl";
import { Internal } from "./Internal";
import {
    SAPP_RUNNER_METADATA_FILENAME,
    SAPP_SAPPER_METADATA_FILENAME,
    sappIssuesFilename,
    sappTraceFramesFilename,
    writeFindingsSappStream,
    writeTraceFramesSappStream,
} from "./sappFormatter";

// Native stack size (MB) for the analysis worker. Recursive AST evaluation can
// exhaust the default stack on deeply nested expressions. This increases the
// available stack; it does not remove recursion limits or bound analysis time.
const STACK_SIZE_MB = (() => {
    const env = process.env.PROPHECY_STACK_SIZE_MB;
    if (env) {
        const n = Number.parseInt(env, 10);
        if (Number.isFinite(n) && n > 0) return n;
    }
    return 64;
})();

type OutputFormat = NonNullable<AnalyzerOptions["outputFormat"]>;

interface CliArgs {
    project?: string[];
    diff?: string;
    "diff-version"?: string;
    "patch-file"?: string;
    preset: PresetSelection;
    spec?: string;
    format: OutputFormat;
    "output-dir"?: string;
    "sapp-project"?: string;
    "sapp-commit"?: string;
    exclude?: string[];
    "shard-index": number;
    "shard-count": number;
    "entry-point-filter"?: string[];
    "require-types": boolean;
    "progress-log"?: string;
    "repo-root"?: string;
    "max-depth": number;
    "analysis-stats": boolean;
    "analysis-debug": boolean;
    "merge-sapp-bundle"?: string;
}

interface AnalysisWorkerData {
    argv: CliArgs;
}

/**
 * Main thread: parse CLI args, then run the analysis in a worker thread
 * with a large native stack. The worker writes all output to the shared
 * stdout/stderr and exits with the analysis exit code, which we mirror.
 *
 * `PROPHECY_NO_WORKER=1` runs on the main thread with its default stack limit;
 * deeply nested expressions may then hit the per-entry-point overflow guard.
 */
async function main() {
    const argv = parseArgv();

    if (process.env.PROPHECY_NO_WORKER === "1") {
        process.exit(await runAnalysis(argv));
    }

    const worker = new Worker(__filename, {
        // Round-trip through JSON so workerData is a plain, structured-
        // cloneable object regardless of any getters yargs attaches.
        workerData: { argv: JSON.parse(JSON.stringify(argv)) },
        resourceLimits: { stackSizeMb: STACK_SIZE_MB },
    });
    worker.on("exit", (code) => process.exit(code));
    worker.on("error", (err: any) => {
        // Prefer the stack trace — worker 'error' fires on uncaught worker
        // exceptions, where the trace is the only clue to what crashed.
        console.error(`Error: ${err?.stack ?? err?.message ?? err}`);
        process.exit(2);
    });
}

function parseArgv(): CliArgs {
    return yargs(process.argv.slice(2))
        .option("merge-sapp-bundle", {
            describe:
                "Deduplicate a completed SAPP process-shard bundle by stable finding handle before upload; exclusive with analysis inputs.",
            type: "string",
        })
        .option("project", {
            alias: "p",
            describe:
                "Project root to analyze. Repeat for multiple roots; auto selects a spec per root, while --preset or --spec applies to all roots. SAPP output uses one issue/trace pair per root.",
            type: "array",
            string: true,
        })
        .option("diff", {
            describe:
                "Code review diff to screen (e.g. D12345). Requires internal integration; use --patch-file otherwise.",
            type: "string",
        })
        .option("diff-version", {
            describe: "Optional Phabricator diff version for --diff mode",
            type: "string",
        })
        .option("patch-file", {
            describe: "Path to a unified diff/patch file to screen",
            type: "string",
        })
        .option("preset", {
            describe:
                "Built-in taint specification preset. 'auto' picks one from the project's package.json (see detectSpec).",
            choices: presetChoices,
            default: "auto" as const,
        })
        .option("spec", {
            alias: "s",
            describe: "Path to custom taint specification JSON file",
            type: "string",
        })
        .option("format", {
            alias: "f",
            describe: "Output format",
            choices: ["text", "json", "mermaid", "lint", "sapp-json"] as const,
            default: "text" as const,
        })
        .option("output-dir", {
            alias: "o",
            describe: "Output directory for sapp-json format (writes SAPP metadata and .sapp files)",
            type: "string",
        })
        .option("sapp-project", {
            describe:
                "SAPP project name used to group sapp-json uploads. Defaults to package.json name or the analyzed directory name.",
            type: "string",
        })
        .option("sapp-commit", {
            describe:
                "Commit hash to record in SAPP runner metadata. Defaults to the checked-out repo revision when available.",
            type: "string",
        })
        .option("exclude", {
            describe:
                "Path substring(s) to exclude from analysis. Source files whose resolved path contains any of these are dropped (use to skip large community-contributed extensions, etc.). Repeatable; matched with String.prototype.includes.",
            type: "array",
            string: true,
        })
        .option("shard-index", {
            describe:
                "0-based index of this shard when the scan is split across parallel processes. Entry points are partitioned round-robin, so every shard parses the same program but analyzes a disjoint slice.",
            type: "number",
            default: 0,
        })
        .option("shard-count", {
            describe:
                "Total number of shards the scan is split across. Each shard writes its own uniquely-numbered *.sapp pair into the shared --output-dir; SAPP globs *.sapp so they still ingest as ONE run.",
            type: "number",
            default: 1,
        })
        .option("entry-point-filter", {
            describe:
                "Debug: analyze only entry points whose file:line location contains this substring (repeatable). Use to reproduce one pathological handler without running the whole project.",
            type: "array",
            string: true,
        })
        .option("require-types", {
            describe:
                "Fail on unresolved Node built-in imports or missing tsconfig type libraries. Install the analyzed project's dependencies first; missing declarations can reduce coverage. This is not a full type check.",
            type: "boolean",
            default: false,
        })
        .option("progress-log", {
            describe:
                "Append phase and throttled entry-point progress in json, lint, or sapp-json mode. Updates run between entry points, not as an independent heartbeat.",
            type: "string",
        })
        .option("repo-root", {
            describe:
                "Absolute path to the repository root. Enables code browser links, when available, in text and mermaid output; project mode auto-detects parent .arcconfig when omitted.",
            type: "string",
        })
        .option("max-depth", {
            describe: "Maximum interprocedural analysis depth",
            type: "number",
            default: 5,
        })
        .option("analysis-stats", {
            describe: "Print pattern matching counts for type-resolved vs heuristic matching",
            type: "boolean",
            default: false,
        })
        .option("analysis-debug", {
            describe: "Print structured JSON debug data about analyzer decisions",
            type: "boolean",
            default: false,
        })
        .check((argv) => {
            validateAnalysisOptions({
                maxDepth: argv["max-depth"],
                shardCount: argv["shard-count"],
                shardIndex: argv["shard-index"],
            });
            return true;
        })
        .help().argv as CliArgs;
}

/**
 * Run the analysis described by `argv` and return the process exit code.
 * Exit codes: 0 on successful completion (findings are expected output,
 * not an error), 1 for handled errors (bad input, syntax errors), 2 for
 * uncaught exceptions (handled by the caller's catch).
 */
async function runAnalysis(argv: CliArgs): Promise<number> {
    const projectArgs: string[] = (argv.project ?? []).filter(
        (v: unknown): v is string => typeof v === "string" && v.length > 0,
    );
    const inputModes = [
        projectArgs.length > 0 || undefined,
        argv.diff,
        argv["patch-file"],
        argv["merge-sapp-bundle"],
    ].filter(Boolean);
    if (inputModes.length !== 1) {
        console.error("Error: exactly one of --project, --diff, --patch-file, or --merge-sapp-bundle is required");
        return 1;
    }
    if (argv["diff-version"] && !argv.diff) {
        console.error("Error: --diff-version can only be used with --diff");
        return 1;
    }
    if (argv.diff && !Internal.fetchDiffChangedPaths) {
        console.error("Error: --diff is not supported in this build; use --patch-file instead");
        return 1;
    }
    if (argv["merge-sapp-bundle"]) {
        try {
            const result = await deduplicateSappBundle(resolveExistingCliPath(argv["merge-sapp-bundle"]));
            console.log(`Merged SAPP bundle: ${result.kept} findings, ${result.removed} duplicate rows removed`);
            return 0;
        } catch (error) {
            console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
            return 1;
        }
    }

    // Load spec
    let spec: TaintSpec | undefined;
    if (argv.spec) {
        const specPath = resolveExistingCliPath(argv.spec);
        let parsed: unknown;
        try {
            parsed = JSON.parse(fs.readFileSync(specPath, "utf-8"));
        } catch (error) {
            console.error(
                `Error: cannot read spec ${specPath}: ${error instanceof Error ? error.message : String(error)}`,
            );
            return 1;
        }
        const errors = validateSpec(parsed);
        if (errors.length > 0) {
            console.error(`Error: invalid spec ${specPath}:\n${errors.map((message) => `  ${message}`).join("\n")}`);
            return 1;
        }
        spec = parsed as TaintSpec;
    } else if (argv.preset !== "auto") {
        spec = builtinSpecs[argv.preset];
    }
    // preset "auto" leaves spec undefined so analyze() calls detectSpec().

    const projectDirs: string[] = [];
    for (const rawProject of projectArgs) {
        const projectDir = resolveExistingCliPath(rawProject);

        if (!fs.existsSync(projectDir)) {
            console.error(`Error: project directory does not exist: ${projectDir}`);
            return 1;
        }

        if (!fs.statSync(projectDir).isDirectory()) {
            console.error(`Error: path is not a directory: ${projectDir}`);
            return 1;
        }

        projectDirs.push(projectDir);
    }

    if (argv.format === "sapp-json" && !argv["output-dir"]) {
        console.error("Error: --output-dir is required when --format sapp-json is used.");
        return 1;
    }

    const patchFile = argv["patch-file"] ? resolveExistingCliPath(argv["patch-file"]) : undefined;

    if (argv.format === "text" || argv.format === "mermaid") {
        console.log(`Analyzing ${projectDirs.length > 0 ? projectDirs.join(", ") : (argv.diff ?? patchFile)}...`);
        console.log(argv.spec ? `Using spec: ${argv.spec}` : `Using preset: ${argv.preset}`);
        console.log("");
    }

    const repoRoot = argv["repo-root"] ? path.resolve(argv["repo-root"]) : undefined;

    const excludePaths = (argv.exclude ?? []).filter(
        (s: unknown): s is string => typeof s === "string" && s.length > 0,
    );

    // Machine-readable output keeps phase/progress diagnostics on stderr.
    // Text and Mermaid modes omit this reporter.
    const cliStartMs = Date.now();
    // Append rather than truncate so repeated scans retain their progress history.
    // Per-entry-point location lines are written separately and are not mirrored.
    const progressLogPath = argv["progress-log"] ? path.resolve(argv["progress-log"]) : undefined;
    const progressReporter =
        argv.format === "text" || argv.format === "mermaid"
            ? undefined
            : (line: string) => {
                  const elapsed = ((Date.now() - cliStartMs) / 1000).toFixed(1);
                  process.stderr.write(`[prophecy +${elapsed}s] ${line}\n`);
                  if (progressLogPath) {
                      // Wall-clock timestamp as well as elapsed: a scan
                      // started hours ago in the background is easier to
                      // reason about with an absolute time on each line.
                      const stamp = new Date().toISOString();
                      try {
                          fs.appendFileSync(progressLogPath, `${stamp} +${elapsed}s ${line}\n`);
                      } catch {
                          // Never let progress bookkeeping kill a scan that
                          // has already done minutes of real work.
                      }
                  }
              };

    // Analyze roots sequentially, retaining their results for output merging.
    // Parsed programs need not all be live at once, but results still accumulate.
    const results: AnalyzerResult[] = [];
    for (const [index, projectDir] of projectDirs.entries()) {
        if (projectDirs.length > 1) {
            progressReporter?.(`analyzing project ${index + 1}/${projectDirs.length}: ${projectDir}`);
        }
        results.push(
            await analyze({
                projectDir,
                spec,
                maxDepth: argv["max-depth"],
                outputFormat: argv.format,
                repoRoot,
                analysisDebug: argv["analysis-debug"],
                sappProject: argv["sapp-project"],
                sappCommit: argv["sapp-commit"],
                excludePaths,
                entryPointFilter: (argv["entry-point-filter"] ?? []).filter(
                    (v: unknown): v is string => typeof v === "string" && v.length > 0,
                ),
                shardIndex: argv["shard-index"],
                shardCount: argv["shard-count"],
                requireTypes: argv["require-types"],
                progressReporter,
            }),
        );
    }
    if (projectDirs.length === 0) {
        results.push(
            await analyzeDiffScreening({
                diff: argv.diff,
                diffVersion: argv["diff-version"],
                patchFile,
                repoRoot,
                spec,
                maxDepth: argv["max-depth"],
                requireTypes: argv["require-types"],
                outputFormat: argv.format,
                analysisDebug: argv["analysis-debug"],
                sappProject: argv["sapp-project"],
                sappCommit: argv["sapp-commit"],
                progressReporter,
            }),
        );
    }

    // text and mermaid output have no progress reporter to carry it.
    if (progressReporter == null) {
        for (const r of results) {
            if (r.typeEnvironmentWarning != null) {
                console.error(`[prophecy] WARNING: ${r.typeEnvironmentWarning}`);
            }
        }
    }

    // Choose across all overlapping roots before assigning findings back to
    // them, so a later root's RCE trace can replace an earlier quoted argument.
    const preferredFindings = new Set(deduplicateFindings(results.flatMap((r) => r.findings)));
    for (const r of results) {
        r.findings = r.findings.filter((finding) => preferredFindings.delete(finding));
    }

    const result = mergeAnalyzerResults(results, argv.format);

    if (result.syntaxErrors.length > 0) {
        console.error(`Error: ${result.syntaxErrors.length} syntax error(s) detected in analyzed files:\n`);
        for (const err of result.syntaxErrors) {
            console.error(`  ${err}`);
        }
        return 1;
    }

    for (const warning of new Set(result.warnings)) {
        console.error(`[prophecy] WARNING: ${warning}`);
    }

    // Surface incomplete entry points, including context limits that retain
    // findings discovered before saturation. stderr keeps stdout clean for
    // json/sapp consumers. Routine analysis limits and
    // unexpected errors are reported separately so a possible analyzer bug
    // isn't lost among the expected skips.
    const limitSkips = result.skippedEntryPoints.filter((ep) => !ep.unexpected);
    const unexpectedSkips = result.skippedEntryPoints.filter((ep) => ep.unexpected);
    if (limitSkips.length > 0) {
        console.error(`\n[prophecy] ${limitSkips.length} entry point(s) incomplete (exceeded analysis limits):`);
        for (const ep of limitSkips) {
            console.error(`  - ${ep.description} @ ${ep.location}: ${ep.reason}`);
        }
        console.error("");
    }
    if (unexpectedSkips.length > 0) {
        console.error(
            `\n[prophecy] WARNING: ${unexpectedSkips.length} entry point(s) skipped due to an UNEXPECTED error (possible analyzer bug, not just an intractable handler; set PROPHECY_STRICT=1 to fail the scan on these):`,
        );
        for (const ep of unexpectedSkips) {
            console.error(`  ! ${ep.description} @ ${ep.location}: ${ep.reason}`);
        }
        console.error("");
    }

    const analysisDiagnostics = formatDiagnostics(result, argv);

    if (argv.format === "sapp-json") {
        const outputDir = path.resolve(argv["output-dir"]!);
        progressReporter?.(`writing SAPP bundle to ${outputDir}...`);
        const writeStart = Date.now();
        const writtenFiles = writeSappOutputBundle(outputDir, results, argv["shard-index"] ?? 0);
        const writeElapsed = ((Date.now() - writeStart) / 1000).toFixed(1);
        progressReporter?.(`wrote SAPP bundle in ${writeElapsed}s (${result.findings.length} findings)`);

        console.log(`SAPP output written to ${outputDir}/`);
        for (const file of writtenFiles) {
            console.log(`  ${path.basename(file)} (${fs.statSync(file).size} bytes)`);
        }
        for (const diagnostic of analysisDiagnostics) {
            console.log("");
            console.log(diagnostic);
        }
    } else {
        if (argv.format === "text" || argv.format === "mermaid") {
            console.log(`Discovered ${result.entryPointCount} entry point(s)`);
            for (const diagnostic of analysisDiagnostics) {
                console.log("");
                console.log(diagnostic);
            }
            console.log("");
        } else if (analysisDiagnostics.length > 0) {
            console.error(analysisDiagnostics.join("\n\n"));
        }
        console.log(result.formattedOutput);
    }

    // Findings and incomplete-entry reports do not make the scan fail.
    return 0;
}

if (isMainThread) {
    main().catch((err: any) => {
        console.error(`Error: ${err?.stack ?? err?.message ?? err}`);
        process.exit(err instanceof ProjectConfigurationError ? 1 : 2);
    });
} else {
    // Write synchronously to the shared descriptors: process.exit() can end
    // the worker before its piped console output has drained.
    redirectConsoleToFileDescriptors();
    runAnalysis((workerData as AnalysisWorkerData).argv)
        .then((code) => process.exit(code))
        .catch((err: any) => {
            console.error(`Error: ${err?.stack ?? err?.message ?? err}`);
            process.exit(err instanceof ProjectConfigurationError ? 1 : 2);
        });
}

function formatDiagnostics(result: AnalyzerResult, argv: Pick<CliArgs, "analysis-stats" | "analysis-debug">): string[] {
    const diagnostics: string[] = [];
    if (argv["analysis-stats"]) {
        diagnostics.push(formatAnalysisMetrics(result.metrics, result.cacheHits));
    }
    if (argv["analysis-debug"]) {
        diagnostics.push(
            "Analysis debug log:\n" +
                formatAnalysisDebugLog(result.metrics, {
                    entryPointCount: result.entryPointCount,
                    findingCount: result.findings.length,
                    cacheHits: result.cacheHits,
                    warningCount: result.warnings.length,
                    syntaxErrorCount: result.syntaxErrors.length,
                }),
        );
    }
    return diagnostics;
}

function redirectConsoleToFileDescriptors(): void {
    const writeLine = (fd: number, args: unknown[]): void => {
        fs.writeSync(fd, format(...args) + "\n");
    };
    console.log = (...args: unknown[]) => writeLine(1, args);
    console.info = (...args: unknown[]) => writeLine(1, args);
    console.error = (...args: unknown[]) => writeLine(2, args);
    console.warn = (...args: unknown[]) => writeLine(2, args);
}

/**
 * Merge counts, diagnostics, and non-SAPP output across roots. SAPP writers
 * consume the separate results. The metrics object comes from the first root;
 * cacheHits and entryPointCount are summed, so the counters have mixed scope.
 */
function mergeAnalyzerResults(results: AnalyzerResult[], outputFormat: string): AnalyzerResult {
    if (results.length === 1) return results[0];
    const findings = results.flatMap((r) => r.findings);
    const merged: AnalyzerResult = {
        ...results[0],
        findings,
        formattedOutput: formatMergedOutput(results, findings, outputFormat),
        entryPointCount: results.reduce((n, r) => n + r.entryPointCount, 0),
        cacheHits: results.reduce((n, r) => n + r.cacheHits, 0),
        warnings: results.flatMap((r) => r.warnings),
        skippedEntryPoints: results.flatMap((r) => r.skippedEntryPoints),
        syntaxErrors: results.flatMap((r) => r.syntaxErrors),
    };
    return merged;
}

function formatMergedOutput(
    results: AnalyzerResult[],
    findings: AnalyzerResult["findings"],
    outputFormat: string,
): string {
    if (outputFormat === "json") {
        return formatFindingsJSON(findings);
    }

    if (outputFormat === "lint") {
        return [
            ...new Set(results.flatMap((r) => r.formattedOutput.split("\n").filter((line) => line.length > 0))),
        ].join("\n");
    }

    return results.map((r) => r.formattedOutput).join("\n");
}

function writeSappOutputBundle(outputDir: string, results: AnalyzerResult[], shardIndex: number): string[] {
    const first = results[0];
    if (!first?.sappMetadata) {
        throw new Error("sapp-json output missing SAPP metadata");
    }

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const runnerMetadataPath = path.join(outputDir, SAPP_RUNNER_METADATA_FILENAME);
    const sapperMetadataPath = path.join(outputDir, SAPP_SAPPER_METADATA_FILENAME);

    // Bundle metadata comes from the first result. Callers combining roots
    // should supply a shared --sapp-project rather than rely on inferred names.
    writeJsonFile(runnerMetadataPath, first.sappMetadata.runner);
    writeJsonFile(sapperMetadataPath, first.sappMetadata.sapper);
    // Stream rows to avoid building a bundle-sized string. Findings and each
    // finding's trace frames still need to fit in memory.
    const shardPaths: string[] = [];
    for (const [index, result] of results.entries()) {
        // Reserve 1,000 file numbers per process shard. More roots per process
        // can collide with another shard's range. SAPP does not require contiguous IDs.
        const fileNumber = shardIndex * 1000 + index + 1;
        const issuesPath = path.join(outputDir, sappIssuesFilename(fileNumber));
        const traceFramesPath = path.join(outputDir, sappTraceFramesFilename(fileNumber));
        writeFindingsSappStream(issuesPath, result.findings, result.sappRepoRoot);
        writeTraceFramesSappStream(traceFramesPath, result.findings, result.sappRepoRoot);
        shardPaths.push(issuesPath, traceFramesPath);
    }

    return [runnerMetadataPath, sapperMetadataPath, ...shardPaths];
}

function writeJsonFile(filePath: string, contents: unknown): void {
    fs.writeFileSync(filePath, JSON.stringify(contents, null, 2) + "\n");
}

function resolveExistingCliPath(inputPath: string): string {
    const cwdPath = path.resolve(inputPath);
    if (path.isAbsolute(inputPath) || fs.existsSync(cwdPath)) {
        return cwdPath;
    }

    const repoRoot = findNearestArcConfigRoot(process.cwd());
    if (repoRoot) {
        const repoPath = path.resolve(repoRoot, inputPath);
        if (fs.existsSync(repoPath)) {
            return repoPath;
        }
    }

    return cwdPath;
}
