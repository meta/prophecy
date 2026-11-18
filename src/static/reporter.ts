/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { TaintFinding, CodeLocation, FindingKind } from "./spec/types";
import { findingReporting, groupFindingsForPresentation, FindingGroup } from "./findingUtils";
import { Internal } from "./Internal";

const kindNouns: Record<FindingKind, string> = {
    security_candidate: "security candidate",
    file_access: "file-access trace",
    persistence_trace: "persistence trace",
};

function countOf(count: number, noun: string): string {
    return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function severityOf(finding: TaintFinding): string {
    return (finding.sink.severity || "high").toUpperCase();
}

/** One row per severity and sink category, most severe first. */
function reportHeader(findings: TaintFinding[]): string {
    const rows = new Map<string, { severity: string; category: string; count: number }>();
    for (const finding of findings) {
        const severity = severityOf(finding);
        const category = finding.sink.categories.join(", ") || "unknown";
        const key = `${severity}\u0000${category}`;
        const row = rows.get(key) ?? { severity, category, count: 0 };
        row.count++;
        rows.set(key, row);
    }
    const sorted = [...rows.values()].sort(
        (a, b) =>
            severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) ||
            b.count - a.count ||
            a.category.localeCompare(b.category),
    );
    const severityWidth = Math.max(...sorted.map((row) => row.severity.length));
    const categoryWidth = Math.max(...sorted.map((row) => row.category.length));
    return [
        `Found ${countOf(findings.length, "taint flow")}:`,
        ...sorted.map(
            (row) => `  ${row.severity.padEnd(severityWidth)}  ${row.category.padEnd(categoryWidth)}  ${row.count}`,
        ),
        "Findings are candidates for further review, not confirmed security issues.",
        "",
    ].join("\n");
}

function groupTitle(group: FindingGroup, index: number, total: number): string {
    const f = group.findings[0];
    const noun = kindNouns[findingReporting(f.sink).kind];
    return (
        `[${index + 1}/${total}] ${noun[0].toUpperCase()}${noun.slice(1)} ` +
        `(${f.sink.categories.join(", ")}; ${countOf(group.findings.length, "trace")})`
    );
}

/** Format human-facing groups without dropping alternate paths or entry contexts. */
export function formatFindings(findings: TaintFinding[], repoRoot?: string, rev?: string): string {
    if (findings.length === 0) return "No taint flows detected.";
    const groups = groupFindingsForPresentation(findings);
    const lines: string[] = [reportHeader(findings)];
    for (let i = 0; i < groups.length; i++) {
        const group = groups[i];
        lines.push("─".repeat(70), groupTitle(group, i, groups.length));
        for (let j = 0; j < group.findings.length; j++) {
            const f = group.findings[j];
            lines.push(`  Trace ${j + 1}/${group.findings.length}: ${severityOf(f)}: ${f.sink.description}`);
            lines.push(`  Handle: ${f.handle}`, "");
            lines.push(`  Source: ${f.source.description}`);
            lines.push(`    at ${formatLocation(f.sourceLocation, repoRoot, rev)}`, "");
            if (f.propagationChain.length > 0) {
                lines.push("  Propagation:");
                for (const step of f.propagationChain) {
                    lines.push(`    → ${step.description}`);
                    lines.push(`      at ${formatLocation(step.location, repoRoot, rev)}`);
                }
                lines.push("");
            }
            lines.push(`  Sink: ${f.sink.description}`);
            lines.push(`    at ${formatLocation(f.sinkLocation, repoRoot, rev)}`, "");
        }
    }
    lines.push("─".repeat(70));
    return lines.join("\n");
}

/** Keep the raw JSON array complete; reporting metadata is additive. */
export function formatFindingsJSON(findings: TaintFinding[]): string {
    return JSON.stringify(
        findings.map((f) => ({ ...f, reporting: findingReporting(f.sink) })),
        null,
        2,
    );
}

function formatLocation(loc: CodeLocation, repoRoot?: string, rev?: string): string {
    const url = codeLinkUrl(loc, repoRoot, rev);
    let s = url ? `${url} (column ${loc.column})` : `${loc.fileName}:${loc.line}:${loc.column}`;
    if (loc.text) s += `  [${loc.text}]`;
    return s;
}

/** Escape text for use inside a Mermaid node label (double-quoted string). */
function mermaidEscape(text: string): string {
    return text.replace(/"/g, "#quot;").replace(/[[\]]/g, "#").replace(/\r?\n/g, "<br/>");
}

/** Build a code link only when the provider can map the path to the repo. */
function codeLinkUrl(loc: CodeLocation, repoRoot: string | undefined, rev: string | undefined): string | undefined {
    if (!Internal.codeLinkUrl || !repoRoot || !rev) return undefined;
    const normalized = path.resolve(loc.fileName);
    const root = path.resolve(repoRoot);
    if (!normalized.startsWith(root + path.sep)) return undefined;
    const relative = normalized
        .slice(root.length + 1)
        .split(path.sep)
        .join("/");
    return Internal.codeLinkUrl(root, rev, relative, loc.line);
}

/** One chart per presentation group, with a complete subgraph for each raw row. */
export function formatFindingsMermaid(findings: TaintFinding[], repoRoot?: string, rev?: string): string {
    if (findings.length === 0) return "No taint flows detected.";
    const groups = groupFindingsForPresentation(findings);
    const blocks: string[] = [];
    for (let i = 0; i < groups.length; i++) {
        const group = groups[i];
        const lines = [groupTitle(group, i, groups.length), "", "```mermaid", "flowchart TD"];
        const clicks: string[] = [];
        for (let k = 0; k < group.findings.length; k++) {
            const f = group.findings[k];
            const id = `${i}_${k}`;
            lines.push(`    subgraph T${id}["${mermaidEscape(`Trace ${k + 1}: ${f.handle}`)}"]`);
            const node = (nodeId: string, label: string, loc: CodeLocation) => {
                lines.push(
                    `    ${nodeId}["${mermaidEscape(label)}<br/>${mermaidEscape(`${loc.fileName}:${loc.line}:${loc.column}`)}"]`,
                );
                const url = codeLinkUrl(loc, repoRoot, rev);
                if (url) clicks.push(`    click ${nodeId} "${url}" _blank`);
            };
            const srcId = `S${id}`;
            node(srcId, `Source: ${f.source.description}`, f.sourceLocation);
            for (let j = 0; j < f.propagationChain.length; j++) {
                const step = f.propagationChain[j];
                node(`P${id}_${j}`, step.description, step.location);
            }
            const sinkId = `K${id}`;
            node(sinkId, `${severityOf(f)}: Sink: ${f.sink.description}`, f.sinkLocation);
            let previous = srcId;
            for (let j = 0; j < f.propagationChain.length; j++) {
                const next = `P${id}_${j}`;
                lines.push(`    ${previous} --> ${next}`);
                previous = next;
            }
            lines.push(`    ${previous} --> ${sinkId}`, "    end");
        }
        lines.push(...clicks, "```");
        blocks.push(lines.join("\n"));
    }
    return reportHeader(findings) + blocks.join("\n\n");
}
