/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { FindingKind, FindingReporting, SinkSpec, TaintFinding } from "./spec/types";

export function findingReporting(sink: SinkSpec): FindingReporting {
    let kind: FindingKind = sink.reportingKind ?? "security_candidate";
    if (!sink.reportingKind) {
        if (sink.categories.length > 0 && sink.categories.every((category) => category === "file_access")) {
            kind = "file_access";
        }
    }
    const limitations: Record<FindingKind, string> = {
        security_candidate: "Modeled security candidate; exploitability and attacker boundary not established.",
        file_access: "File-access trace; disclosure and privilege crossing not established.",
        persistence_trace:
            "Generic persistence trace; execution-bearing destination and attacker boundary not established.",
    };
    return { kind, limitation: limitations[kind] };
}

export const findingKindLabels: Record<FindingKind, string> = {
    security_candidate: "Modeled security candidate",
    file_access: "File-access trace",
    persistence_trace: "Generic persistence trace",
};

export interface FindingGroup {
    key: string;
    findings: TaintFinding[];
}

/** Presentation only: preserve every raw row, including alternate entry contexts. */
export function groupFindingsForPresentation(findings: TaintFinding[]): FindingGroup[] {
    const groups = new Map<string, FindingGroup>();
    for (const finding of findings) {
        const source = finding.source;
        const root = finding.sourceLocation;
        const site = finding.sinkLocation;
        // Source rule + exact location distinguishes independent input roots, even
        // when their pattern or enclosing sink scope is the same.
        const key = JSON.stringify([
            source.kind,
            source.pattern,
            source.description,
            source.paramIndex,
            source.paramPropertyPaths,
            root.fileName,
            root.line,
            root.column,
            site.fileName,
            site.line,
            site.column,
            finding.sinkSite,
            finding.sink.name,
            finding.sink.pattern,
            finding.sink.argPositions,
            [...finding.sink.categories].sort(),
            findingReporting(finding.sink).kind,
        ]);
        let group = groups.get(key);
        if (!group) {
            group = { key, findings: [] };
            groups.set(key, group);
        }
        group.findings.push(finding);
    }
    return [...groups.values()];
}

/**
 * Keep one finding per stable handle, preferring command execution over a
 * quoted-argument classification of the same flow. Preserve order otherwise.
 */
export function deduplicateFindings(findings: TaintFinding[], seenHandles: Set<string> = new Set()): TaintFinding[] {
    const preferred = new Map<string, TaintFinding>();
    for (const finding of findings) {
        if (seenHandles.has(finding.handle)) continue;
        const previous = preferred.get(finding.handle);
        if (
            previous == null ||
            (previous.sink.categories.includes("arg_injection") &&
                !previous.sink.categories.includes("rce") &&
                finding.sink.categories.includes("rce"))
        ) {
            preferred.set(finding.handle, finding);
        }
    }
    for (const handle of preferred.keys()) seenHandles.add(handle);
    return [...preferred.values()];
}
