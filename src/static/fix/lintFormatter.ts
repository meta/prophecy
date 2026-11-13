/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { TaintFinding, LintMessage, FixStrategy } from "../spec/types";
import { FixStrategyProvider, generateFix, generateImportFix } from "./fixGenerator";
import { resolveFixStrategy } from "./fixStrategy";

export function formatFindingsLint(
    findings: TaintFinding[],
    fileContents: Map<string, string>,
    pathBase?: string,
    specOverrides?: FixStrategyProvider,
): string {
    if (findings.length === 0) return "";

    const messages: LintMessage[] = [];
    const requiredImports = new Map<
        string,
        {
            fileName: string;
            strategy: FixStrategy;
            names: Set<string>;
        }
    >();

    for (const finding of findings) {
        const category = finding.sink.categories[0];
        const overrides = typeof specOverrides === "function" ? specOverrides(finding) : specOverrides;
        const strategy = resolveFixStrategy(finding.sink, overrides);
        const fix = finding.fix ?? generateFix(finding, fileContents, overrides);

        const filePath = pathBase
            ? path.relative(pathBase, finding.sinkLocation.fileName)
            : finding.sinkLocation.fileName;

        const msg: LintMessage = {
            path: filePath,
            line: finding.sinkLocation.line,
            char: finding.sinkLocation.column,
            category: category || "taint",
            severity: mapSeverity(finding.sink.severity || "high"),
            name: `${finding.sink.name}: ${finding.sink.description}`,
            description: buildDescription(finding, strategy),
        };

        if (fix) {
            msg.original = fix.original;
            msg.replacement = fix.replacement;
            msg.replacementIsSafe = false;
        }

        messages.push(msg);

        if (fix && strategy?.importPackage && strategy.importName) {
            const importKey = `${finding.sinkLocation.fileName}:${strategy.importPackage}`;
            const required = requiredImports.get(importKey) ?? {
                fileName: finding.sinkLocation.fileName,
                strategy,
                names: new Set<string>(),
            };
            required.names.add(strategy.importName);
            requiredImports.set(importKey, required);
        }
    }

    for (const { fileName, strategy, names } of requiredImports.values()) {
        const content = fileContents.get(fileName);
        if (!content) continue;
        const importFix = generateImportFix(strategy, fileName, content, [...names]);
        if (!importFix) continue;
        messages.push({
            path: pathBase ? path.relative(pathBase, fileName) : fileName,
            line: importFix.line,
            char: importFix.column,
            category: "import",
            severity: "advice",
            name: `Add import: ${[...names].join(", ")}`,
            description: importFix.description,
            original: importFix.original,
            replacement: importFix.replacement,
            replacementIsSafe: false,
        });
    }

    return messages.map((m) => JSON.stringify(serializeForArcLint(m))).join("\n");
}

function serializeForArcLint(msg: LintMessage): Record<string, unknown> {
    const { category, ...rest } = msg;
    return {
        ...rest,
        code: `PROPHECY-${category.toUpperCase()}`,
    };
}

function mapSeverity(sinkSeverity: "critical" | "high" | "medium" | "low"): "error" | "warning" | "advice" {
    switch (sinkSeverity) {
        case "critical":
        case "high":
            return "error";
        case "medium":
            return "warning";
        case "low":
            return "advice";
    }
}

function buildDescription(finding: TaintFinding, strategy?: FixStrategy): string {
    const lines: string[] = [];
    lines.push(`Taint flow: ${finding.source.description} → ${finding.sink.description}`);
    lines.push(`Source: ${finding.sourceLocation.fileName}:${finding.sourceLocation.line}`);

    if (finding.propagationChain.length > 0) {
        const steps = finding.propagationChain.map((s) => s.description).join(" → ");
        lines.push(`Chain: ${steps}`);
    }

    if (strategy) {
        if (strategy.applicability === "unfixable") {
            lines.push(`Manual fix required: ${strategy.description}`);
        } else {
            lines.push(`Suggested fix: ${strategy.description}`);
            if (strategy.saferPattern) {
                lines.push(`Pattern: ${strategy.saferPattern}`);
            }
        }
    }

    return lines.join("\n");
}
