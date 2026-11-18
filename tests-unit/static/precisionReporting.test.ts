/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as crypto from "crypto";
import { analyze } from "../../src/static/analyzer";
import { findingReporting, groupFindingsForPresentation } from "../../src/static/findingUtils";
import { formatFindings, formatFindingsJSON, formatFindingsMermaid } from "../../src/static/reporter";
import {
    generateSappMetadata,
    writeFindingsSappStream,
    writeTraceFramesSappStream,
} from "../../src/static/sappFormatter";
import { formatFindingsLint } from "../../src/static/fix/lintFormatter";
import { NodeFileReadSinks } from "../../src/static/spec/nodeApis";
import { WriteFileSink, WriteFilePathSink } from "../../src/static/spec/sinks";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { SinkSpec, TaintFinding } from "../../src/static/spec/types";

function row(context = "first"): TaintFinding {
    return {
        handle: `input|exec|${context}|/demo/sink.ts|20`,
        sinkSite: "run>call:exec#0",
        source: { kind: "callReturnValue", pattern: "input", description: "Modeled input" },
        sourceLocation: { fileName: "/demo/input.ts", line: 3, column: 1 },
        sink: {
            kind: "callArgument",
            name: "exec",
            pattern: "child_process.exec",
            description: "Command execution",
            categories: ["rce"],
        },
        sinkLocation: { fileName: "/demo/sink.ts", line: 20, column: 5 },
        propagationChain: [
            {
                kind: "argument",
                description: `alternate ${context}`,
                location: { fileName: `/demo/${context}.ts`, line: 10, column: 2 },
            },
        ],
    };
}

function sapp(findings: TaintFinding[]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "reporting-sapp-"));
    try {
        const issues = path.join(directory, "issues.sapp");
        const frames = path.join(directory, "frames.sapp");
        writeFindingsSappStream(issues, findings);
        writeTraceFramesSappStream(frames, findings);
        const read = (file: string): any[] =>
            fs
                .readFileSync(file, "utf8")
                .trim()
                .split("\n")
                .filter(Boolean)
                .map((line) => JSON.parse(line));
        return { issues: read(issues), frames: read(frames) };
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
}

function originalSappHandle(finding: TaintFinding, code: number) {
    const filename = finding.sinkLocation.fileName;
    const scope = finding.sinkSite.slice(0, finding.sinkSite.lastIndexOf(">"));
    const callable = `${filename}::${scope}`;
    const identity = [filename, finding.sinkSite, code, finding.sink.name, finding.source.pattern].join("\u0000");
    return `${callable}:${code}:${finding.sink.name}:${crypto.createHash("md5").update(identity).digest("hex").slice(0, 16)}`;
}

describe("precision reporting", () => {
    it("groups alternate entry contexts without losing either raw row or path", () => {
        const findings = [row(), row("second")];
        const before = JSON.stringify(findings);
        const groups = groupFindingsForPresentation(findings);
        expect(groups).toHaveLength(1);
        expect(groups[0].findings).toEqual(findings);
        const text = formatFindings(findings);
        const mermaid = formatFindingsMermaid(findings);
        for (const output of [text, mermaid]) {
            expect(output).toContain("Found 2 taint flows:\n  HIGH  rce  2\n");
            expect(output).not.toMatch(/vulnerabilit/i);
            expect(output).toContain("not confirmed security issues");
            for (const f of findings) {
                expect(output).toContain(f.handle);
                expect(output).toContain(f.propagationChain[0].location.fileName);
                expect(output).toContain(f.propagationChain[0].description);
            }
        }
        expect(mermaid.match(/```mermaid/g)).toHaveLength(1);
        const json = JSON.parse(formatFindingsJSON(findings));
        expect(json.map(({ reporting: _reporting, ...raw }: TaintFinding) => raw)).toEqual(findings);
        expect(json.every((f: TaintFinding) => f.reporting?.kind === "security_candidate")).toBe(true);
        const { issues, frames } = sapp(findings);
        expect(issues).toHaveLength(2);
        expect(issues.map((issue) => issue.handle)).toEqual(findings.map((f) => originalSappHandle(f, 9001)));
        expect(
            issues.map((issue) => issue.features.find((feature: string) => feature.startsWith("prophecy-handle:"))),
        ).toEqual(findings.map((f) => `prophecy-handle:${f.handle}`));
        expect(frames).toHaveLength(6);
        expect(new Set(frames.map((frame) => frame.caller)).size).toBe(6);
        expect(JSON.stringify(findings)).toBe(before);
    });

    it("keeps independent roots, parameter roots, categories and sink sites separate", () => {
        const first = row();
        const otherLocation = { ...row("other"), sourceLocation: { ...first.sourceLocation, line: 4 } };
        const otherFile = { ...row("file"), sourceLocation: { ...first.sourceLocation, fileName: "/else/input.ts" } };
        const otherParameter = { ...row("parameter"), source: { ...first.source, paramIndex: 1 } };
        const otherCategory = {
            ...row("category"),
            sink: { ...first.sink, categories: ["lfi"] as SinkSpec["categories"] },
        };
        const otherSite = { ...row("site"), sinkLocation: { ...first.sinkLocation, column: 10 } };
        expect(
            groupFindingsForPresentation([first, otherLocation, otherFile, otherParameter, otherCategory, otherSite]),
        ).toHaveLength(6);
    });

    it("keeps separate sink operand contracts at the same call site", () => {
        const first = row();
        const argument = { ...row("argv"), sink: { ...first.sink, name: "exec_args", argPositions: [1] } };
        expect(groupFindingsForPresentation([first, argument])).toHaveLength(2);
    });

    it("distinguishes access, content persistence, and path-write candidates without changing raw severity", () => {
        const findings = [
            { ...row(), sink: NodeFileReadSinks[0] },
            { ...row("content"), sink: WriteFileSink },
            { ...row("path"), sink: WriteFilePathSink },
        ];
        expect(findings.map((f) => findingReporting(f.sink).kind)).toEqual([
            "file_access",
            "persistence_trace",
            "security_candidate",
        ]);
        for (const output of [formatFindings(findings), formatFindingsMermaid(findings)]) {
            expect(output).toContain(
                "Found 3 taint flows:\n  HIGH  file_write      1\n  LOW   file_access     1\n  LOW   file_integrity  1\n",
            );
        }
        const { issues } = sapp(findings);
        expect(issues.map((issue) => issue.code)).toEqual([9013, 9012, 9005]);
        expect(issues.map((issue) => issue.handle)).toEqual(
            findings.map((f, i) => originalSappHandle(f, i === 0 ? 9013 : i === 1 ? 9012 : 9005)),
        );
        for (let i = 0; i < findings.length; i++) {
            expect(issues[i].features).toContain(`prophecy-reporting-kind:${findingReporting(findings[i].sink).kind}`);
            expect(issues[i].description).toContain("not established");
        }
        const rules = generateSappMetadata("demo").sapper.rules;
        expect(rules.find((rule) => rule.code === 9013)?.name).toBe("Prophecy-FileAccess");
        expect(rules.find((rule) => rule.code === 9012)?.name).toBe("Prophecy-FileIntegrity");
        const lint = formatFindingsLint([findings[0]], new Map());
        expect(JSON.parse(lint)).toMatchObject({ code: "PROPHECY-FILE_ACCESS", severity: "advice" });
        expect(findings[1].sink.severity).toBe("low");
    });

    it("supports a presentation-only override without inferring a safety boundary", () => {
        expect(findingReporting({ ...WriteFileSink, reportingKind: "security_candidate" }).kind).toBe(
            "security_candidate",
        );
        expect(findingReporting({ ...WriteFileSink, argPositions: [0, 1], reportingKind: undefined }).kind).toBe(
            "security_candidate",
        );
        expect(
            findingReporting({ ...WriteFileSink, categories: ["file_write", "rce"], reportingKind: undefined }).kind,
        ).toBe("security_candidate");
        expect(
            findingReporting({ ...WriteFileSink, name: "custom_path_at_arg_one", reportingKind: undefined }).kind,
        ).toBe("security_candidate");
        expect(formatFindings([])).toBe("No taint flows detected.");
        expect(formatFindingsMermaid([])).toBe("No taint flows detected.");
        expect(JSON.parse(formatFindingsJSON([]))).toEqual([]);
        expect(sapp([])).toEqual({ issues: [], frames: [] });
    });
});

describe("file-access reporting fixture", () => {
    it("retains all composed-preset read traces and file-content execution flows", async () => {
        const options = {
            projectDir: path.join(__dirname, "fixtures/file-access-reporting"),
            outputFormat: "json" as const,
            requireTypes: true,
        };
        const result = await analyze({ ...options, spec: vscodeExtensionSpec });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(7);
        const access = result.findings.filter((f) => f.sink.categories.includes("file_access"));
        expect(access.map((f) => f.sink.name).sort()).toEqual([
            "createReadStream_path",
            "readFileSync_path",
            "readFile_path",
        ]);
        expect(access.every((f) => f.sink.severity === "low")).toBe(true);
        expect(result.findings.filter((f) => f.sink.name === "exec")).toHaveLength(3);
        expect(result.findings.filter((f) => findingReporting(f.sink).kind === "persistence_trace")).toHaveLength(1);
        expect(JSON.parse(result.formattedOutput)).toHaveLength(7);
        expect(sapp(result.findings).issues).toHaveLength(7);

        const legacy = await analyze({
            ...options,
            spec: {
                ...vscodeExtensionSpec,
                sinks: vscodeExtensionSpec.sinks.map((sink) =>
                    NodeFileReadSinks.some((read) => read.name === sink.name)
                        ? {
                              ...sink,
                              categories: ["lfi"],
                              severity: "high",
                              description: `File read from an attacker-controlled path via ${sink.pattern}`,
                          }
                        : sink,
                ),
            },
        });
        expect(legacy.findings).toHaveLength(7);
        // A category/code change intentionally remints read SAPP handles; the
        // library handles, roots, paths, entry contexts and other findings stay.
        const normalize = (findings: TaintFinding[]) =>
            findings.map((f) =>
                NodeFileReadSinks.some((read) => read.name === f.sink.name)
                    ? { ...f, sink: { ...f.sink, categories: [], severity: undefined, description: "read" } }
                    : f,
            );
        expect(normalize(result.findings)).toEqual(normalize(legacy.findings));
        const before = sapp(legacy.findings).issues;
        const after = sapp(result.findings).issues;
        for (let i = 0; i < result.findings.length; i++) {
            expect(after[i].handle === before[i].handle).toBe(
                !result.findings[i].sink.categories.includes("file_access"),
            );
        }
    });

    it("keeps explicitly configured LFI rules as security candidates", async () => {
        const lfi: SinkSpec = {
            ...NodeFileReadSinks[0],
            name: "custom_read",
            categories: ["lfi"],
            severity: "high",
            description: "Explicit file-inclusion model",
        };
        const result = await analyze({
            source: 'import * as fs from "node:fs"; export function main() { fs.readFile(process.env.INPUT!, () => {}); }',
            fileName: path.join(__dirname, "file-access-custom-input.ts"),
            spec: {
                entryFunctions: ["main"],
                sources: [
                    {
                        kind: "propertyAccess",
                        pattern: "process.env",
                        description: "Modeled input",
                        taintAllProperties: true,
                    },
                ],
                sinks: [lfi],
                sanitizers: [],
            },
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink).toEqual(lfi);
        expect(findingReporting(result.findings[0].sink).kind).toBe("security_candidate");
        expect(sapp(result.findings).issues[0].code).toBe(9007);
    });
});
