/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { TaintFinding, CodeLocation } from "./spec/types";
import { findingReporting, findingKindLabels, groupFindingsForPresentation, FindingGroup } from "./findingUtils";
import { Internal } from "./Internal";

function reportHeader(findings: TaintFinding[], groups: FindingGroup[]): string {
    const counts = { security_candidate: 0, file_access: 0, persistence_trace: 0 };
    for (const finding of findings) counts[findingReporting(finding.sink).kind]++;
    return (
        `Found ${findings.length} modeled taint flows in ${groups.length} presentation groups: ` +
        `${counts.security_candidate} modeled security candidates, ${counts.file_access} file-access traces, ` +
        `${counts.persistence_trace} generic persistence traces.\n` +
        "These traces do not establish exploitability, disclosure, privilege crossing, or an attacker boundary.\n"
    );
}

function groupTitle(group: FindingGroup, index: number, total: number): string {
    const f = group.findings[0];
    return (
        `[${index + 1}/${total}] ${findingKindLabels[findingReporting(f.sink).kind]} ` +
        `(${f.sink.categories.join(", ")}; ${group.findings.length} raw findings)`
    );
}

/** Format human-facing groups without dropping alternate paths or entry contexts. */
export function formatFindings(findings: TaintFinding[], repoRoot?: string, rev?: string): string {
    if (findings.length === 0) return "No taint flows detected.";
    const groups = groupFindingsForPresentation(findings);
    const lines: string[] = [reportHeader(findings, groups)];
    for (let i = 0; i < groups.length; i++) {
        const group = groups[i];
        lines.push("─".repeat(70), groupTitle(group, i, groups.length));
        for (let j = 0; j < group.findings.length; j++) {
            const f = group.findings[j];
            lines.push(
                `  Trace ${j + 1}/${group.findings.length}: ${(f.sink.severity || "high").toUpperCase()}: ${f.sink.description}`,
            );
            lines.push(`  Raw finding / entry context: ${f.handle}`);
            lines.push(`  ${findingReporting(f.sink).limitation}`, "");
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
            node(sinkId, `${(f.sink.severity || "high").toUpperCase()}: Sink: ${f.sink.description}`, f.sinkLocation);
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
    return reportHeader(findings, groups) + blocks.join("\n\n");
}
