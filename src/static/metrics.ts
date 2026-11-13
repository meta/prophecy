/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

export interface PatternMatchingMetrics {
    /** Calls that attempted TypeScript symbol resolution before matching. */
    typeResolutionAttempts: number;
    /** TypeScript symbol resolution produced a fully-qualified name. */
    typeResolutionSuccesses: number;
    /** The fully-qualified name matched the source/sink/sanitizer pattern. */
    typeResolvedMatches: number;
    /** Heuristic matcher calls when type resolution failed. */
    heuristicFallbackAttempts: number;
    /** Heuristic fallback calls that matched. */
    heuristicFallbackMatches: number;
    /** Source checks from paths that do not currently have an expression to resolve. */
    heuristicOnlyAttempts: number;
    /** Heuristic-only source checks that matched. */
    heuristicOnlyMatches: number;
    /** Optional aggregate debug entries, enabled only by --analysis-debug. */
    debugEntries?: PatternMatchDebugEntry[];
}

export interface AnalysisMetrics {
    patternMatching: PatternMatchingMetrics;
    performance: AnalysisPerformanceMetrics;
}

export interface AnalysisPerformanceMetrics {
    totalMs: number;
    parseMs: number;
    syntaxDiagnosticsMs: number;
    commandRegistryMs: number;
    entryDiscoveryMs: number;
    entryAnalysisMs: number;
    formattingMs: number;
    callExpressions: number;
    typeResolutionCacheHits: number;
    typeResolutionCacheMisses: number;
    taintValuesCreated: number;
    taintPropagations: number;
    maxPropagationChainLength: number;
    callCacheKeyBuilds: number;
    callResultCacheStores: number;
    maxCallResultCacheEntries: number;
    callResultCacheClears: number;
    callResultCacheEvictions: number;
}

type PatternMatchingCounter = keyof Omit<PatternMatchingMetrics, "debugEntries">;
type PerformanceCounter = Exclude<keyof AnalysisPerformanceMetrics, "maxPropagationChainLength">;

const PATTERN_MATCHING_COUNTERS = [
    "typeResolutionAttempts",
    "typeResolutionSuccesses",
    "typeResolvedMatches",
    "heuristicFallbackAttempts",
    "heuristicFallbackMatches",
    "heuristicOnlyAttempts",
    "heuristicOnlyMatches",
] as const satisfies readonly PatternMatchingCounter[];

const PERFORMANCE_COUNTERS = [
    "totalMs",
    "parseMs",
    "syntaxDiagnosticsMs",
    "commandRegistryMs",
    "entryDiscoveryMs",
    "entryAnalysisMs",
    "formattingMs",
    "callExpressions",
    "typeResolutionCacheHits",
    "typeResolutionCacheMisses",
    "taintValuesCreated",
    "taintPropagations",
    "callCacheKeyBuilds",
    "callResultCacheStores",
    "callResultCacheClears",
    "callResultCacheEvictions",
] as const satisfies readonly PerformanceCounter[];

export type PatternMatchStrategy =
    | "typeResolved"
    | "resolvedAccessPath"
    | "importedName"
    | "heuristicFallback"
    | "heuristicOnly";

export interface PatternMatchDebugEntry {
    context: string;
    strategy: PatternMatchStrategy;
    name: string;
    pattern: string;
    matched: boolean;
    count: number;
    resolvedName?: string;
}

export interface AnalysisMetricsOptions {
    enableDebug?: boolean;
}

export interface AnalysisDebugLogOptions {
    entryPointCount?: number;
    findingCount?: number;
    cacheHits?: number;
    warningCount?: number;
    syntaxErrorCount?: number;
}

export function createAnalysisMetrics(options: AnalysisMetricsOptions = {}): AnalysisMetrics {
    return {
        patternMatching: {
            typeResolutionAttempts: 0,
            typeResolutionSuccesses: 0,
            typeResolvedMatches: 0,
            heuristicFallbackAttempts: 0,
            heuristicFallbackMatches: 0,
            heuristicOnlyAttempts: 0,
            heuristicOnlyMatches: 0,
            ...(options.enableDebug ? { debugEntries: [] } : {}),
        },
        performance: {
            totalMs: 0,
            parseMs: 0,
            syntaxDiagnosticsMs: 0,
            commandRegistryMs: 0,
            entryDiscoveryMs: 0,
            entryAnalysisMs: 0,
            formattingMs: 0,
            callExpressions: 0,
            typeResolutionCacheHits: 0,
            typeResolutionCacheMisses: 0,
            taintValuesCreated: 0,
            taintPropagations: 0,
            maxPropagationChainLength: 0,
            callCacheKeyBuilds: 0,
            callResultCacheStores: 0,
            maxCallResultCacheEntries: 0,
            callResultCacheClears: 0,
            callResultCacheEvictions: 0,
        },
    };
}

export function mergeAnalysisMetrics(metrics: AnalysisMetrics[]): AnalysisMetrics {
    const merged: AnalysisMetrics = {
        patternMatching: mergePatternMatchingMetrics(metrics.map((metric) => metric.patternMatching)),
        performance: mergePerformanceMetrics(metrics.map((metric) => metric.performance)),
    };

    const releaseIndex = indexPatternMatches(merged);
    try {
        for (const metric of metrics) {
            for (const entry of metric.patternMatching.debugEntries ?? []) {
                recordPatternMatch(merged, entry);
            }
        }
        return merged;
    } finally {
        releaseIndex();
    }
}

function mergePerformanceMetrics(metrics: AnalysisPerformanceMetrics[]): AnalysisPerformanceMetrics {
    const merged = createAnalysisMetrics().performance;

    for (const metric of metrics) {
        for (const counter of PERFORMANCE_COUNTERS) {
            merged[counter] += metric[counter];
        }
        merged.maxPropagationChainLength = Math.max(merged.maxPropagationChainLength, metric.maxPropagationChainLength);
        merged.maxCallResultCacheEntries = Math.max(merged.maxCallResultCacheEntries, metric.maxCallResultCacheEntries);
    }

    return merged;
}

function mergePatternMatchingMetrics(metrics: PatternMatchingMetrics[]): PatternMatchingMetrics {
    const merged = createAnalysisMetrics({
        enableDebug: metrics.some((metric) => metric.debugEntries !== undefined),
    }).patternMatching;

    for (const metric of metrics) {
        for (const counter of PATTERN_MATCHING_COUNTERS) {
            merged[counter] += metric[counter];
        }
    }

    return merged;
}

const patternMatchIndexes = new WeakMap<PatternMatchDebugEntry[], Map<string, PatternMatchDebugEntry>>();

/**
 * Index privately owned metrics during recording. Release before exposing the
 * metrics to callers, whose debug-entry arrays and identity fields are mutable.
 */
export function indexPatternMatches(metrics: AnalysisMetrics): () => void {
    const debugEntries = metrics.patternMatching.debugEntries;
    if (!debugEntries) return () => {};

    const entries = new Map<string, PatternMatchDebugEntry>();
    for (const entry of debugEntries) {
        const key = patternMatchKey(entry);
        if (!entries.has(key)) entries.set(key, entry);
    }
    patternMatchIndexes.set(debugEntries, entries);
    return () => {
        patternMatchIndexes.delete(debugEntries);
    };
}

function patternMatchKey(entry: Omit<PatternMatchDebugEntry, "count">): string {
    return JSON.stringify([
        entry.context,
        entry.strategy,
        entry.name,
        entry.pattern,
        entry.matched,
        entry.resolvedName,
    ]);
}

export function recordPatternMatch(
    metrics: AnalysisMetrics,
    entry: Omit<PatternMatchDebugEntry, "count"> & { count?: number },
): void {
    const debugEntries = metrics.patternMatching.debugEntries;
    if (!debugEntries) return;

    const index = patternMatchIndexes.get(debugEntries);
    const existing = index
        ? index.get(patternMatchKey(entry))
        : debugEntries.find(
              (candidate) =>
                  candidate.context === entry.context &&
                  candidate.strategy === entry.strategy &&
                  candidate.name === entry.name &&
                  candidate.pattern === entry.pattern &&
                  candidate.matched === entry.matched &&
                  candidate.resolvedName === entry.resolvedName,
          );
    const count = entry.count ?? 1;
    if (existing) {
        existing.count += count;
        return;
    }

    const added = { ...entry, count };
    debugEntries.push(added);
    index?.set(patternMatchKey(entry), added);
}

export function formatAnalysisMetrics(metrics: AnalysisMetrics, cacheHits?: number): string {
    const pattern = metrics.patternMatching;
    const performance = metrics.performance;
    const lines = [
        "Analysis metrics:",
        ...(cacheHits === undefined ? [] : [`  Interprocedural cache hits: ${cacheHits}`]),
        `  Total analysis time: ${performance.totalMs} ms`,
        `  Parse time: ${performance.parseMs} ms`,
        `  Syntax diagnostics time: ${performance.syntaxDiagnosticsMs} ms`,
        `  Command registry time: ${performance.commandRegistryMs} ms`,
        `  Entry discovery time: ${performance.entryDiscoveryMs} ms`,
        `  Entry analysis time: ${performance.entryAnalysisMs} ms`,
        `  Formatting time: ${performance.formattingMs} ms`,
        `  Call expressions analyzed: ${performance.callExpressions}`,
        `  Type resolution attempts: ${pattern.typeResolutionAttempts}`,
        `  Type resolution successes: ${pattern.typeResolutionSuccesses}`,
        `  Type-resolved matches: ${pattern.typeResolvedMatches}`,
        `  Type resolution cache hits: ${performance.typeResolutionCacheHits}`,
        `  Type resolution cache misses: ${performance.typeResolutionCacheMisses}`,
        `  Heuristic fallback attempts: ${pattern.heuristicFallbackAttempts}`,
        `  Heuristic fallback matches: ${pattern.heuristicFallbackMatches}`,
        `  Heuristic-only source checks: ${pattern.heuristicOnlyAttempts}`,
        `  Heuristic-only source matches: ${pattern.heuristicOnlyMatches}`,
        `  Taint values created: ${performance.taintValuesCreated}`,
        `  Taint propagations: ${performance.taintPropagations}`,
        `  Max propagation chain length: ${performance.maxPropagationChainLength}`,
        `  Interprocedural cache key builds: ${performance.callCacheKeyBuilds}`,
        `  Interprocedural cache stores: ${performance.callResultCacheStores}`,
        `  Max interprocedural cache entries: ${performance.maxCallResultCacheEntries}`,
        `  Interprocedural cache clears: ${performance.callResultCacheClears}`,
        `  Interprocedural cache evictions: ${performance.callResultCacheEvictions}`,
    ];

    return lines.join("\n");
}

export function formatAnalysisDebugLog(metrics: AnalysisMetrics, options: AnalysisDebugLogOptions = {}): string {
    const pattern = metrics.patternMatching;
    const performance = metrics.performance;
    const entries = [...(metrics.patternMatching.debugEntries ?? [])].sort(
        (a, b) =>
            b.count - a.count ||
            a.context.localeCompare(b.context) ||
            a.strategy.localeCompare(b.strategy) ||
            a.name.localeCompare(b.name) ||
            a.pattern.localeCompare(b.pattern),
    );

    return JSON.stringify(
        {
            summary: {
                ...(options.entryPointCount === undefined ? {} : { entryPointCount: options.entryPointCount }),
                ...(options.findingCount === undefined ? {} : { findingCount: options.findingCount }),
                ...(options.cacheHits === undefined ? {} : { interproceduralCacheHits: options.cacheHits }),
                ...(options.warningCount === undefined ? {} : { warningCount: options.warningCount }),
                ...(options.syntaxErrorCount === undefined ? {} : { syntaxErrorCount: options.syntaxErrorCount }),
            },
            patternMatching: {
                counts: {
                    typeResolutionAttempts: pattern.typeResolutionAttempts,
                    typeResolutionSuccesses: pattern.typeResolutionSuccesses,
                    typeResolvedMatches: pattern.typeResolvedMatches,
                    heuristicFallbackAttempts: pattern.heuristicFallbackAttempts,
                    heuristicFallbackMatches: pattern.heuristicFallbackMatches,
                    heuristicOnlyAttempts: pattern.heuristicOnlyAttempts,
                    heuristicOnlyMatches: pattern.heuristicOnlyMatches,
                },
                entries,
            },
            performance: {
                timingsMs: {
                    total: performance.totalMs,
                    parse: performance.parseMs,
                    syntaxDiagnostics: performance.syntaxDiagnosticsMs,
                    commandRegistry: performance.commandRegistryMs,
                    entryDiscovery: performance.entryDiscoveryMs,
                    entryAnalysis: performance.entryAnalysisMs,
                    formatting: performance.formattingMs,
                },
                counts: {
                    callExpressions: performance.callExpressions,
                    typeResolutionCacheHits: performance.typeResolutionCacheHits,
                    typeResolutionCacheMisses: performance.typeResolutionCacheMisses,
                    taintValuesCreated: performance.taintValuesCreated,
                    taintPropagations: performance.taintPropagations,
                    maxPropagationChainLength: performance.maxPropagationChainLength,
                    callCacheKeyBuilds: performance.callCacheKeyBuilds,
                    callResultCacheStores: performance.callResultCacheStores,
                    maxCallResultCacheEntries: performance.maxCallResultCacheEntries,
                    callResultCacheClears: performance.callResultCacheClears,
                    callResultCacheEvictions: performance.callResultCacheEvictions,
                },
            },
        },
        null,
        2,
    );
}
