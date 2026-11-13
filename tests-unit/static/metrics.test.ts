/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import {
    AnalysisMetrics,
    PatternMatchDebugEntry,
    createAnalysisMetrics,
    formatAnalysisDebugLog,
    indexPatternMatches,
    mergeAnalysisMetrics,
    recordPatternMatch,
} from "../../src/static/metrics";

const entry: Omit<PatternMatchDebugEntry, "count"> = {
    context: "sink.callArgument",
    strategy: "typeResolved",
    name: "exec",
    pattern: "child_process.exec",
    matched: true,
};

function recordLinear(metrics: AnalysisMetrics, value: Omit<PatternMatchDebugEntry, "count"> & { count?: number }) {
    const entries = metrics.patternMatching.debugEntries;
    if (!entries) return;
    const existing = entries.find(
        (candidate) =>
            candidate.context === value.context &&
            candidate.strategy === value.strategy &&
            candidate.name === value.name &&
            candidate.pattern === value.pattern &&
            candidate.matched === value.matched &&
            candidate.resolvedName === value.resolvedName,
    );
    if (existing) existing.count += value.count ?? 1;
    else entries.push({ ...value, count: value.count ?? 1 });
}

describe("pattern match aggregation", () => {
    it("does not enable debugging or add serialized index fields", () => {
        const metrics = createAnalysisMetrics();
        const before = JSON.stringify(metrics);
        recordPatternMatch(metrics, entry);
        expect(JSON.stringify(metrics)).toBe(before);
        expect(metrics.patternMatching.debugEntries).toBeUndefined();
    });

    it("preserves insertion order, weighted counts, and zero counts", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(metrics, entry);
        recordPatternMatch(metrics, { ...entry, name: "readFile", count: 0 });
        recordPatternMatch(metrics, { ...entry, count: 4 });
        expect(metrics.patternMatching.debugEntries).toEqual([
            { ...entry, count: 5 },
            { ...entry, name: "readFile", count: 0 },
        ]);
        expect(Object.keys(metrics.patternMatching)).not.toContain("entries");
    });

    it.each([
        { context: "source" },
        { strategy: "heuristicOnly" as const },
        { name: "readFile" },
        { pattern: "fs.readFile" },
        { matched: false },
        { resolvedName: "" },
        { resolvedName: "child_process.exec" },
    ])("keeps every equality field distinct: %p", (difference) => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(metrics, entry);
        recordPatternMatch(metrics, { ...entry, ...difference });
        expect(metrics.patternMatching.debugEntries).toHaveLength(2);
    });

    it("does not collide on delimiters or escaped strings", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        const values = [
            { ...entry, context: "a|b", name: "c" },
            { ...entry, context: "a", name: "b|c" },
            { ...entry, context: 'a"b', name: "c\\d\n" },
            { ...entry, context: 'a\\"b', name: "c\\d\n" },
        ];
        for (const value of values) recordPatternMatch(metrics, value);
        for (const value of values) recordPatternMatch(metrics, value);
        expect(metrics.patternMatching.debugEntries).toEqual(values.map((value) => ({ ...value, count: 2 })));
    });

    it("indexes prepopulated arrays and keeps the first duplicate representative", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        const first = { ...entry, count: 3 };
        const second = { ...entry, count: 2 };
        metrics.patternMatching.debugEntries!.push(first, second);
        recordPatternMatch(metrics, entry);
        expect(first.count).toBe(4);
        expect(second.count).toBe(2);
        metrics.patternMatching.debugEntries!.push({ ...entry, name: "readFile", count: 2 });
        recordPatternMatch(metrics, { ...entry, name: "readFile" });
        expect(metrics.patternMatching.debugEntries![2].count).toBe(3);
        metrics.patternMatching.debugEntries!.length = 0;
        recordPatternMatch(metrics, entry);
        expect(metrics.patternMatching.debugEntries).toEqual([{ ...entry, count: 1 }]);
    });

    it("isolates arrays, replacements, and merged metrics", () => {
        const left = createAnalysisMetrics({ enableDebug: true });
        const right = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(left, { ...entry, count: 2 });
        recordPatternMatch(right, { ...entry, count: 3 });
        const merged = mergeAnalysisMetrics([left, right]);
        expect(merged.patternMatching.debugEntries).toEqual([{ ...entry, count: 5 }]);
        recordPatternMatch(merged, entry);
        expect(left.patternMatching.debugEntries![0].count).toBe(2);
        expect(right.patternMatching.debugEntries![0].count).toBe(3);
        left.patternMatching.debugEntries = [];
        recordPatternMatch(left, entry);
        expect(left.patternMatching.debugEntries).toEqual([{ ...entry, count: 1 }]);
    });

    it("preserves same-length array replacements after recording", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(metrics, entry);
        const replacement = { ...entry, count: 10 };
        metrics.patternMatching.debugEntries![0] = replacement;
        recordPatternMatch(metrics, entry);
        expect(replacement.count).toBe(11);
    });

    it("preserves in-place identity edits after recording", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(metrics, entry);
        metrics.patternMatching.debugEntries![0].name = "spawn";
        recordPatternMatch(metrics, { ...entry, name: "spawn" });
        expect(metrics.patternMatching.debugEntries).toEqual([{ ...entry, name: "spawn", count: 2 }]);
    });

    it("preserves same-length splices after recording", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(metrics, entry);
        metrics.patternMatching.debugEntries!.splice(0, 1, { ...entry, name: "spawn", count: 1 });
        recordPatternMatch(metrics, entry);
        expect(metrics.patternMatching.debugEntries).toEqual([
            { ...entry, name: "spawn", count: 1 },
            { ...entry, count: 1 },
        ]);
    });

    it("releases a private index before callers mutate its entries", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        const releaseIndex = indexPatternMatches(metrics);
        recordPatternMatch(metrics, entry);
        recordPatternMatch(metrics, { ...entry, count: 4 });
        expect(metrics.patternMatching.debugEntries).toEqual([{ ...entry, count: 5 }]);
        releaseIndex();
        releaseIndex();
        metrics.patternMatching.debugEntries![0] = { ...entry, count: 10 };
        recordPatternMatch(metrics, entry);
        expect(metrics.patternMatching.debugEntries![0].count).toBe(11);
        metrics.patternMatching.debugEntries![0].name = "spawn";
        recordPatternMatch(metrics, { ...entry, name: "spawn" });
        expect(metrics.patternMatching.debugEntries).toEqual([{ ...entry, name: "spawn", count: 12 }]);
    });

    it("does not retain an index on merged metrics returned to callers", () => {
        const metrics = createAnalysisMetrics({ enableDebug: true });
        recordPatternMatch(metrics, entry);
        const merged = mergeAnalysisMetrics([metrics]);
        merged.patternMatching.debugEntries![0] = { ...entry, count: 10 };
        recordPatternMatch(merged, entry);
        expect(merged.patternMatching.debugEntries![0].count).toBe(11);
    });

    it("releases an analyzer's private index before exposing the result", async () => {
        const result = await analyze({
            source: `import * as vscode from "vscode";
                import {exec} from "child_process";
                export function activate() {
                    vscode.window.registerUriHandler({handleUri(uri: vscode.Uri) {exec(uri.query);}});
                }`,
            fileName: "/src/extension.ts",
            analysisDebug: true,
            outputFormat: "json",
        });
        const entries = result.metrics.patternMatching.debugEntries!;
        expect(entries.length).toBeGreaterThan(0);
        const replacement = { ...entries[0], count: 10 };
        entries[0] = replacement;
        recordPatternMatch(result.metrics, { ...replacement, count: 1 });
        expect(replacement.count).toBe(11);
    });

    it("matches the linear implementation's entries and formatted output", () => {
        const indexed = createAnalysisMetrics({ enableDebug: true });
        const releaseIndex = indexPatternMatches(indexed);
        const linear = createAnalysisMetrics({ enableDebug: true });
        for (let pass = 0; pass < 3; pass++) {
            for (let i = 0; i < 1000; i++) {
                const value = {
                    ...entry,
                    context: `context:${i % 7}`,
                    name: `name:${i}`,
                    matched: i % 2 === 0,
                    resolvedName: i % 3 === 0 ? undefined : `resolved:${i}`,
                    count: pass,
                };
                recordPatternMatch(indexed, value);
                recordLinear(linear, value);
            }
        }
        releaseIndex();
        expect(indexed).toEqual(linear);
        expect(formatAnalysisDebugLog(indexed)).toBe(formatAnalysisDebugLog(linear));
    });
});
