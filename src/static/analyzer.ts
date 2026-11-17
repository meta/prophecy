/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import * as fs from "fs";
import * as path from "path";

import { ParsedProject, parseProject, parseSourceForAnalysis } from "./parser";
import { TaintSpec, TaintFinding } from "./spec/types";
import { InterproceduralAnalyzer, EntryPoint, SkippedEntryPoint } from "./taint/interprocedural";
import { memberFunction } from "./taint/functionResolver";
import { initTaintValueHashing } from "./taint/taintValue";
import { vscodeExtensionSpec } from "./spec/vscodeExtension";
import { builtinSpecs } from "./spec/presets";
import { islSpec, ISL_PACKAGE_NAMES } from "./spec/isl";
import { formatFindings, formatFindingsJSON, formatFindingsMermaid } from "./reporter";
import { generateFixes, formatFindingsLint } from "./fix";
import { generateSappMetadata, SappMetadata } from "./sappFormatter";
import { AnalysisMetrics, createAnalysisMetrics, indexPatternMatches } from "./metrics";
import { findNearestArcConfigRoot, getSaplingRevision } from "./sourceControl";
import { deduplicateFindings } from "./findingUtils";
import { describeTypeEnvironmentGaps, findTypeEnvironmentGaps } from "./typeEnvironment";

export interface AnalyzerOptions {
    /** Path to the project root (must contain tsconfig.json or .ts files). */
    projectDir?: string;
    /** Raw TypeScript source (for testing). */
    source?: string;
    /** Filename to use when parsing raw source. Default: "test.ts". */
    fileName?: string;
    /** Taint spec; otherwise auto-detect from package.json, falling back to VS Code. */
    spec?: TaintSpec;
    /** Maximum interprocedural analysis depth. Default: 5. */
    maxDepth?: number;
    /** Output format. Default: "text". */
    outputFormat?: "text" | "json" | "mermaid" | "lint" | "sapp-json";
    /** Absolute path to the repository root. Used for code browser links in text and mermaid output. */
    repoRoot?: string;
    /** Collect structured matcher debug data for --analysis-debug output. */
    analysisDebug?: boolean;
    /** SAPP project name for grouping uploaded runs. Defaults to the analyzed package name or directory name. */
    sappProject?: string;
    /** Commit hash to record in SAPP runner metadata. Defaults to the checked-out repo revision when available. */
    sappCommit?: string;
    /**
     * Exclude matching root files before parsing and filter matching source files
     * afterward. Imports may still pull excluded files into the TypeScript program.
     * Each nonempty entry is a path substring, not a regular expression.
     */
    excludePaths?: string[];
    /** Analyze only entries whose `file:line` location contains a supplied substring. */
    entryPointFilter?: string[];
    /** Select raw traces before choosing a representative for each stable handle. */
    findingFilter?: (finding: TaintFinding) => boolean;
    /** 0-based shard index when the scan is split across parallel processes. */
    shardIndex?: number;
    /** Total shard count; 1 (the default) analyzes every entry point. */
    shardCount?: number;
    /**
     * Fail instead of warning when the project's type declarations are
     * missing (see `findTypeEnvironmentGaps`), so a scan run before its
     * dependencies were installed cannot silently report fewer flows.
     */
    requireTypes?: boolean;
    /**
     * Phase and throttled entry-point progress, one line per call without a
     * trailing newline. Independent per-entry-point diagnostics still go to
     * stderr when this callback is omitted.
     */
    progressReporter?: (line: string) => void;
}

export interface AnalyzerResult {
    findings: TaintFinding[];
    formattedOutput: string;
    entryPointCount: number;
    cacheHits: number;
    metrics: AnalysisMetrics;
    warnings: string[];
    /** Entries with incomplete coverage due to analysis limits or unexpected errors. */
    skippedEntryPoints: SkippedEntryPoint[];
    syntaxErrors: string[];
    /** Set when the project's type declarations are missing; see `requireTypes`. */
    typeEnvironmentWarning?: string;
    /** Present only when outputFormat is "sapp-json". */
    sappMetadata?: SappMetadata;
    /**
     * Repo root for relative paths in SAPP streaming output. SAPP mode returns
     * findings and metadata rather than a bundle-sized formattedOutput string.
     */
    sappRepoRoot?: string;
}

/**
 * Main analyzer: parses a TypeScript project, discovers entry points,
 * runs taint analysis, and reports findings.
 */
export async function analyze(options: AnalyzerOptions): Promise<AnalyzerResult> {
    validateAnalysisOptions(options);
    const totalStart = Date.now();
    const spec = options.spec || detectSpec(options.projectDir);
    const maxDepth = options.maxDepth ?? 5;
    const metrics = createAnalysisMetrics({
        enableDebug: options.analysisDebug,
    });
    const releaseIndex = indexPatternMatches(metrics);
    return analyzeWithMetrics(options, totalStart, spec, maxDepth, metrics).finally(releaseIndex);
}

export function validateAnalysisOptions(
    options: Pick<AnalyzerOptions, "maxDepth" | "shardCount" | "shardIndex">,
): void {
    const maxDepth = options.maxDepth ?? 5;
    const shardCount = options.shardCount ?? 1;
    const shardIndex = options.shardIndex ?? 0;
    if (!Number.isSafeInteger(maxDepth) || maxDepth < 0) {
        throw new Error("--max-depth must be a nonnegative safe integer");
    }
    if (!Number.isSafeInteger(shardCount) || shardCount < 1) {
        throw new Error("--shard-count must be a positive safe integer");
    }
    if (!Number.isSafeInteger(shardIndex) || shardIndex < 0 || shardIndex >= shardCount) {
        throw new Error("--shard-index must be an integer from 0 through --shard-count - 1");
    }
}

async function analyzeWithMetrics(
    options: AnalyzerOptions,
    totalStart: number,
    spec: TaintSpec,
    maxDepth: number,
    metrics: AnalysisMetrics,
): Promise<AnalyzerResult> {
    const report = options.progressReporter ?? (() => {});

    // Load the xxhash-wasm module once before any propagate() call, so the
    // synchronous hashCacheParts() inside the taint walk can use the
    // already-loaded API without awaiting from inside that hot path.
    await initTaintValueHashing();

    if (options.projectDir) {
        if (!fs.existsSync(options.projectDir)) {
            throw new Error(`Project directory does not exist: ${options.projectDir}`);
        }
        if (!fs.statSync(options.projectDir).isDirectory()) {
            throw new Error(`Path is not a directory: ${options.projectDir}`);
        }
    }

    let parsed: ParsedProject;
    let typeEnvironmentWarning: string | undefined;
    const parseStart = Date.now();
    if (options.source) {
        parsed = parseSourceForAnalysis(options.source, options.fileName);
    } else if (options.projectDir) {
        report(`parsing project ${options.projectDir}...`);
        parsed = parseProject(options.projectDir, options.excludePaths);
        report(`parsed ${parsed.sourceFiles.length} source files in ${elapsedSecs(parseStart)}s`);
        typeEnvironmentWarning = describeTypeEnvironmentGaps(options.projectDir, findTypeEnvironmentGaps(parsed));
        if (typeEnvironmentWarning != null) {
            if (options.requireTypes) throw new Error(typeEnvironmentWarning);
            report(`WARNING: ${typeEnvironmentWarning}`);
        }
    } else {
        throw new Error("Must provide either projectDir or source");
    }
    metrics.performance.parseMs += Date.now() - parseStart;

    const syntaxDiagnosticsStart = Date.now();
    const syntaxErrors = parsed.program.getSyntacticDiagnostics().map((d) => {
        const msg = ts.flattenDiagnosticMessageText(d.messageText, "\n");
        if (d.file && d.start !== undefined) {
            const { line, character } = d.file.getLineAndCharacterOfPosition(d.start);
            return `${d.file.fileName}:${line + 1}:${character + 1}: ${msg}`;
        }
        return msg;
    });
    metrics.performance.syntaxDiagnosticsMs += Date.now() - syntaxDiagnosticsStart;

    const interproc = new InterproceduralAnalyzer(parsed.checker, spec, maxDepth, metrics);

    report(`building VS Code command registry from ${parsed.sourceFiles.length} files...`);
    const commandRegistryStart = Date.now();
    // Build from every source file before entry-point filtering or sharding;
    // executeCommand may target a registration outside the selected set.
    interproc.buildVSCodeCommandRegistry(parsed.sourceFiles);
    metrics.performance.commandRegistryMs += Date.now() - commandRegistryStart;
    report(`built command registry in ${elapsedSecs(commandRegistryStart)}s`);

    const subtypeIndexStart = Date.now();
    interproc.indexSubtypes(parsed.sourceFiles);
    report(`indexed class hierarchy in ${elapsedSecs(subtypeIndexStart)}s`);

    if (spec.sources.some((source) => source.settingScopeDescriptions != null)) {
        interproc.indexSettingScopes(parsed.sourceFiles);
    }

    const mainFile = options.projectDir ? resolveMainEntryFile(options.projectDir, parsed.sourceFiles) : undefined;

    // Computed early so the per-EP log lines below can strip the repo
    // prefix from absolute source-file paths. Also reused by the
    // SAPP-output and formatter branches further down.
    const outputRepoRoot = resolveOutputRepoRoot(options, parsed);

    report(`discovering entry points...`);
    const entryDiscoveryStart = Date.now();
    const entryPoints = interproc.discoverEntryPoints(parsed.sourceFiles);
    // If discovery finds no framework entry points, fall back to top-level
    // function declarations, function-valued variables, and class methods
    // (including function-valued properties) in the main file (or all files
    // when package.json has no resolvable main).
    if (entryPoints.length === 0) {
        const fallbackFiles = mainFile ? [mainFile] : parsed.sourceFiles;
        for (const file of fallbackFiles) {
            ts.forEachChild(file, (node) => {
                if (ts.isFunctionDeclaration(node) && node.body) {
                    entryPoints.push({
                        kind: "activate",
                        node,
                        taintedParams: new Map(),
                        description: `Top-level function: ${node.name?.text || "anonymous"}`,
                    });
                }

                if (ts.isVariableStatement(node)) {
                    for (const decl of node.declarationList.declarations) {
                        if (
                            decl.initializer &&
                            (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))
                        ) {
                            entryPoints.push({
                                kind: "activate",
                                node: decl.initializer,
                                taintedParams: new Map(),
                                description: `Top-level function: ${decl.name.getText()}`,
                            });
                        }
                    }
                }

                if (ts.isClassDeclaration(node)) {
                    for (const member of node.members) {
                        const method = memberFunction(member);
                        if (method?.body && member.name) {
                            const className = node.name?.text || "anonymous";
                            const methodName = member.name.getText();
                            entryPoints.push({
                                kind: "activate",
                                node: method,
                                taintedParams: new Map(),
                                description: `Class method: ${className}.${methodName}`,
                            });
                        }
                    }
                }
            });
        }
    }

    metrics.performance.entryDiscoveryMs += Date.now() - entryDiscoveryStart;
    report(`discovered ${entryPoints.length} entry points in ${elapsedSecs(entryDiscoveryStart)}s`);

    // Every shard must use the same discovered entry list. Round-robin
    // partitioning spreads adjacent entries across processes; their analysis
    // costs can still differ substantially.
    const shardCount = options.shardCount ?? 1;
    const shardIndex = options.shardIndex ?? 0;
    if (shardCount > 1) {
        const before = entryPoints.length;
        const mine = entryPoints.filter((_, i) => i % shardCount === shardIndex);
        entryPoints.length = 0;
        entryPoints.push(...mine);
        report(`shard ${shardIndex + 1}/${shardCount}: analyzing ${entryPoints.length} of ${before} entry points`);
    }

    if (options.entryPointFilter && options.entryPointFilter.length > 0) {
        const filters = options.entryPointFilter;
        const before = entryPoints.length;
        const kept = entryPoints.filter((ep) => {
            const loc = interproc.describeEntryPointLocation(ep);
            return filters.some((f) => loc.includes(f));
        });
        entryPoints.length = 0;
        entryPoints.push(...kept);
        report(`--entry-point-filter kept ${entryPoints.length} of ${before} entry points`);
    }

    // Progress runs between entry points, throttled to about five seconds.
    // It cannot provide a heartbeat during a long synchronous entry-point walk.
    report(`analyzing ${entryPoints.length} entry points...`);
    const entryAnalysisStart = Date.now();
    const PROGRESS_INTERVAL_MS = 5_000;
    let lastReportAt = 0;
    // Write each location synchronously before entering the analysis. A timer
    // cannot run while the synchronous walk occupies the event loop, and a
    // buffered stream may not flush before a stall or worker exit.
    let prevEpStartedAt = Date.now();
    let prevEp: EntryPoint | undefined;
    let prevEpLocation = "";
    const SLOW_EP_THRESHOLD_MS = 1_000;
    // Retain the slowest completed entries for end-of-run diagnostics.
    const SLOWEST_EP_COUNT = 10;
    const slowestEps: Array<{ ms: number; description: string; location: string }> = [];
    const recordEpDuration = (ms: number, description: string, location: string) => {
        // Linear scan over a 10-element array, once per EP — cheaper than
        // maintaining a heap, and negligible against per-EP analysis cost.
        if (slowestEps.length < SLOWEST_EP_COUNT) {
            slowestEps.push({ ms, description, location });
            slowestEps.sort((a, b) => b.ms - a.ms);
            return;
        }
        if (ms <= slowestEps[slowestEps.length - 1].ms) {
            return;
        }
        slowestEps[slowestEps.length - 1] = { ms, description, location };
        slowestEps.sort((a, b) => b.ms - a.ms);
    };
    // Include a location because registration descriptions need not be unique.
    const epLocation = (ep: EntryPoint): string => {
        const sf = ep.node.getSourceFile();
        const { line, character } = sf.getLineAndCharacterOfPosition(ep.node.getStart());
        const fileName =
            outputRepoRoot && sf.fileName.startsWith(outputRepoRoot + path.sep)
                ? sf.fileName.slice(outputRepoRoot.length + 1)
                : sf.fileName;
        return `${fileName}:${line + 1}:${character + 1}`;
    };
    const result = interproc.analyzeEntryPoints(
        entryPoints,
        (i, total, findings) => {
            const now = Date.now();
            if (i === 1 || i === total || now - lastReportAt >= PROGRESS_INTERVAL_MS) {
                const pct = total > 0 ? Math.floor((i / total) * 100) : 100;
                const heapMb = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
                const rssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
                const elapsedMs = now - entryAnalysisStart;
                // Mean-rate ETA. Per-EP cost is heavy-tailed, so this reads
                // optimistic whenever a cluster of expensive handlers is
                // still ahead — it answers "roughly how much longer", not
                // "exactly when". Good enough to decide whether to wait.
                const etaSecs = i > 0 && i < total ? Math.round(((elapsedMs / i) * (total - i)) / 1000) : 0;
                report(
                    `  ${i}/${total} (${pct}%) entry points, ${findings} findings, ` +
                        `elapsed ${Math.round(elapsedMs / 1000)}s` +
                        (i < total ? `, eta ~${etaSecs}s` : "") +
                        `, heap ${heapMb}MB / rss ${rssMb}MB`,
                );
                lastReportAt = now;
            }
        },
        (i, total, ep) => {
            const now = Date.now();
            const prevElapsedMs = now - prevEpStartedAt;
            // If the EP we just finished took >1s, surface it. Most EPs
            // complete in <100ms; the outliers are the diagnostic signal.
            if (prevEp) {
                recordEpDuration(prevElapsedMs, prevEp.description, prevEpLocation);
                if (prevElapsedMs > SLOW_EP_THRESHOLD_MS) {
                    fs.writeSync(
                        2,
                        `    [slow EP done] ${(prevElapsedMs / 1000).toFixed(1)}s: ${prevEp.description} @ ${prevEpLocation}\n`,
                    );
                }
            }
            // Print the EP we're ABOUT to enter, synchronously, so a
            // stall pinpoints the suspect as the last-printed line.
            const location = epLocation(ep);
            fs.writeSync(2, `  → EP ${i}/${total}: ${ep.description} @ ${location}\n`);
            prevEp = ep;
            prevEpLocation = location;
            prevEpStartedAt = now;
        },
    );
    metrics.performance.entryAnalysisMs += Date.now() - entryAnalysisStart;
    // The final completed entry has no next pre-iteration hook to time it.
    if (prevEp) {
        recordEpDuration(Date.now() - prevEpStartedAt, prevEp.description, prevEpLocation);
    }
    report(
        `analyzed ${entryPoints.length} entry points in ${elapsedSecs(entryAnalysisStart)}s ` +
            `(${result.findings.length} raw findings, ${interproc.cacheHits} cache hits)`,
    );
    if (slowestEps.length > 0) {
        const totalMs = Math.max(1, Date.now() - entryAnalysisStart);
        const shown = slowestEps.filter((e) => e.ms >= SLOW_EP_THRESHOLD_MS);
        if (shown.length > 0) {
            report(`slowest ${shown.length} entry point(s) of ${entryPoints.length}:`);
            for (const e of shown) {
                const pct = ((e.ms / totalMs) * 100).toFixed(1);
                report(`    ${(e.ms / 1000).toFixed(1)}s (${pct}%) ${e.description} @ ${e.location}`);
            }
        }
    }
    if (result.skippedEntryPoints.length > 0) {
        report(
            `${result.skippedEntryPoints.length} entry point(s) have incomplete coverage ` +
                `— see the skipped-entry-point list for analysis limits or errors`,
        );
    }

    const selected = options.findingFilter ? result.findings.filter(options.findingFilter) : result.findings;
    const deduped = deduplicateFindings(selected);
    if (selected.length !== deduped.length) {
        report(
            `deduplicated ${selected.length} → ${deduped.length} findings ` +
                `(${selected.length - deduped.length} dropped)`,
        );
    }

    const formattingStart = Date.now();

    let formattedOutput: string;
    if (options.outputFormat === "lint" || options.outputFormat === "sapp-json") {
        const fileContents = new Map<string, string>();
        for (const sf of parsed.sourceFiles) {
            fileContents.set(sf.fileName, sf.getFullText());
        }
        report(`generating fixes for ${deduped.length} findings...`);
        const fixStart = Date.now();
        const fixCount = generateFixes(deduped, fileContents, spec.fixStrategies);
        report(`generated ${fixCount} fixes in ${elapsedSecs(fixStart)}s`);
        if (options.outputFormat === "lint") {
            formattedOutput = formatFindingsLint(deduped, fileContents, options.projectDir, spec.fixStrategies, {
                fixesGenerated: true,
            });
        } else {
            // index.ts streams the SAPP rows from findings and sappRepoRoot;
            // do not allocate the entire NDJSON bundle as one string here.
            formattedOutput = "";
        }
    } else if (options.outputFormat === "json") {
        formattedOutput = formatFindingsJSON(deduped);
    } else if (options.outputFormat === "mermaid") {
        const rev = await getSaplingRevision(outputRepoRoot);
        formattedOutput = formatFindingsMermaid(deduped, outputRepoRoot, rev);
    } else {
        const rev = await getSaplingRevision(outputRepoRoot);
        formattedOutput = formatFindings(deduped, outputRepoRoot, rev);
    }

    let sappMeta: SappMetadata | undefined;
    if (options.outputFormat === "sapp-json") {
        report(`building SAPP metadata...`);
        const commit = options.sappCommit ?? (await getSaplingRevision(outputRepoRoot));
        sappMeta = generateSappMetadata(inferSappProjectName(options), commit);
    }
    metrics.performance.formattingMs += Date.now() - formattingStart;
    metrics.performance.totalMs += Date.now() - totalStart;

    return {
        findings: deduped,
        formattedOutput,
        entryPointCount: entryPoints.length,
        cacheHits: interproc.cacheHits,
        metrics: interproc.getMetrics(),
        warnings: [...new Set([...(parsed.warnings ?? []), ...result.warnings])],
        ...(typeEnvironmentWarning != null ? { typeEnvironmentWarning } : {}),
        // Relativize skipped-EP locations to the repo root for consistency
        // with the per-EP progress lines (e.g. xplat/vscode/... rather than
        // /data/.../fbsource/xplat/vscode/...).
        skippedEntryPoints: result.skippedEntryPoints.map((ep) => ({
            ...ep,
            location:
                outputRepoRoot && ep.location.startsWith(outputRepoRoot + path.sep)
                    ? ep.location.slice(outputRepoRoot.length + 1)
                    : ep.location,
        })),
        syntaxErrors,
        ...(sappMeta ? { sappMetadata: sappMeta } : {}),
        ...(options.outputFormat === "sapp-json" ? { sappRepoRoot: outputRepoRoot } : {}),
    };
}

function elapsedSecs(startMs: number): string {
    return ((Date.now() - startMs) / 1000).toFixed(1);
}

function resolveOutputRepoRoot(options: AnalyzerOptions, parsed: ParsedProject): string | undefined {
    if (options.repoRoot) {
        return path.resolve(options.repoRoot);
    }

    const candidates = [options.projectDir, options.fileName, parsed.sourceFiles[0]?.fileName].filter(
        (candidate): candidate is string => candidate != null,
    );

    for (const candidate of candidates) {
        const repoRoot = findNearestArcConfigRoot(candidate);
        if (repoRoot) {
            return repoRoot;
        }
    }

    return undefined;
}

export function inferSappProjectName(options: Pick<AnalyzerOptions, "projectDir" | "sappProject">): string {
    if (options.sappProject) {
        return options.sappProject;
    }

    if (!options.projectDir) {
        return "unknown";
    }

    const pkgPath = path.join(options.projectDir, "package.json");
    if (fs.existsSync(pkgPath)) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
            if (typeof pkg.name === "string" && pkg.name.length > 0) {
                return pkg.name;
            }
        } catch {
            // Fall through to the directory name below.
        }
    }

    return path.basename(path.resolve(options.projectDir)) || "unknown";
}

/**
 * Auto-detect which taint spec to use based on package.json.
 * Falls back to the VS Code spec if no project directory is provided
 * or if the project type can't be determined.
 */
export function detectSpec(projectDir?: string): TaintSpec {
    if (!projectDir) return vscodeExtensionSpec;

    const pkgPath = path.join(projectDir, "package.json");
    if (!fs.existsSync(pkgPath)) return vscodeExtensionSpec;

    try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        const allDeps = {
            ...pkg.dependencies,
            ...pkg.devDependencies,
        };

        // Interactive Smartlog's extension and server: the VS Code spec plus ISL sinks.
        if (ISL_PACKAGE_NAMES.includes(pkg.name)) {
            return islSpec;
        }

        if (pkg.engines?.vscode || allDeps?.["@types/vscode"]) {
            return vscodeExtensionSpec;
        }

        // Prefer host-specific specs when packages also depend on generic HTTP libraries.
        if (allDeps?.electron) return builtinSpecs.electron;
        if (allDeps?.express || allDeps?.["@types/express"]) {
            return builtinSpecs.express;
        }

        return vscodeExtensionSpec;
    } catch {
        return vscodeExtensionSpec;
    }
}

/**
 * Read package.json from a project directory and resolve the "main" field
 * to a TypeScript source file in the parsed program.
 */
function resolveMainEntryFile(projectDir: string, sourceFiles: ts.SourceFile[]): ts.SourceFile | undefined {
    const pkgPath = path.join(projectDir, "package.json");
    if (!fs.existsSync(pkgPath)) return undefined;

    try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        if (!pkg.main) return undefined;

        // Match literal paths or append .ts/.tsx. The dist-to-src fallback
        // retains any existing extension; it does not map extension.js to extension.ts.
        const mainRel = pkg.main.replace(/^\.\//, "");
        const candidates = [
            path.resolve(projectDir, mainRel + ".ts"),
            path.resolve(projectDir, mainRel + ".tsx"),
            path.resolve(projectDir, mainRel),
            // If main points to dist/, try the src/ equivalent
            path.resolve(projectDir, mainRel.replace(/^dist\//, "src/") + ".ts"),
            path.resolve(projectDir, mainRel.replace(/^dist\//, "src/")),
        ];

        for (const candidate of candidates) {
            const match = sourceFiles.find((sf) => path.resolve(sf.fileName) === candidate);
            if (match) return match;
        }
    } catch {
        // Invalid package.json — fall through
    }

    return undefined;
}
