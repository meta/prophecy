/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyze, AnalyzerResult } from "../../../src/static/analyzer";
import { analyzeDiffScreening } from "../../../src/static/diff";
import * as fixGenerator from "../../../src/static/fix/fixGenerator";
import { formatFindingsLint } from "../../../src/static/fix/lintFormatter";
import { parseSource } from "../../../src/static/parser";
import { TaintSpec } from "../../../src/static/spec/types";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "Untrusted input" }],
    sinks: [
        {
            kind: "callArgument",
            name: "exec",
            pattern: "child_process.exec",
            argPositions: [0],
            categories: ["rce"],
            severity: "critical",
            description: "Shell command",
        },
    ],
    sanitizers: [],
};
const fileName = path.join(__dirname, "lint-generation.ts");
const unsupported = "exec(`demo ${input()} | other`);";
const supported = "exec(`demo ${input()}`);";

function sourceFor(statements: string[]): string {
    return [
        'import { exec } from "child_process";',
        "declare function input(): string;",
        "export function main() {",
        ...statements,
        "}",
    ].join("\n");
}

function expectComplete(result: AnalyzerResult): void {
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    expect(result.typeEnvironmentWarning).toBeUndefined();
}

async function scan(source: string, selectedSpec = spec, outputFormat: "lint" | "json" = "lint") {
    expect(parseSource(source, fileName).program.getSemanticDiagnostics()).toEqual([]);
    const result = await analyze({ source, fileName, spec: selectedSpec, outputFormat });
    expectComplete(result);
    return result;
}

afterEach(() => jest.restoreAllMocks());

describe("completed fix generation", () => {
    it("does not retry unsupported repairs while formatting an analysis", async () => {
        const generate = jest.spyOn(fixGenerator, "generateFix");
        const source = sourceFor(Array(16).fill(unsupported));
        const result = await scan(source);
        expect(result.findings).toHaveLength(16);
        expect(result.findings.every((finding) => finding.fix === undefined)).toBe(true);
        expect(generate).not.toHaveBeenCalled();
        const before = JSON.stringify(result.findings);
        expect(result.formattedOutput).toBe(formatFindingsLint(result.findings, new Map([[fileName, source]])));
        expect(generate).toHaveBeenCalledTimes(16);
        expect(JSON.stringify(result.findings)).toBe(before);
    });

    it("does not retry unsupported repairs while formatting patch screening", async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-lint-generation-"));
        try {
            fs.symlinkSync(
                path.resolve(__dirname, "../../../node_modules"),
                path.join(directory, "node_modules"),
                "dir",
            );
            fs.writeFileSync(
                path.join(directory, "tsconfig.json"),
                JSON.stringify({
                    compilerOptions: { target: "ES2020", module: "commonjs", types: ["node"] },
                    files: ["entry.ts"],
                }),
            );
            const source = sourceFor(Array(16).fill(unsupported));
            const entry = path.join(directory, "entry.ts");
            fs.writeFileSync(entry, source);
            const patchFile = path.join(directory, "change.patch");
            fs.writeFileSync(patchFile, "--- a/entry.ts\n+++ b/entry.ts\n");
            expect(parseSource(source, entry).program.getSemanticDiagnostics()).toEqual([]);
            const generate = jest.spyOn(fixGenerator, "generateFix");
            const result = await analyzeDiffScreening({ patchFile, repoRoot: directory, spec, outputFormat: "lint" });
            expectComplete(result);
            expect(result.findings).toHaveLength(16);
            expect(generate).not.toHaveBeenCalled();
            expect(result.formattedOutput).toBe(
                formatFindingsLint(result.findings, new Map([[entry, source]]), directory),
            );
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("preserves mixed repair output, imports, and unsafe migration labels", async () => {
        const generate = jest.spyOn(fixGenerator, "generateFix");
        const source = sourceFor([supported, unsupported]);
        const result = await scan(source);
        expect(result.findings).toHaveLength(2);
        expect(result.findings.filter((finding) => finding.fix !== undefined)).toHaveLength(1);
        expect(generate).not.toHaveBeenCalled();
        expect(result.formattedOutput).toBe(formatFindingsLint(result.findings, new Map([[fileName, source]])));
        const messages = result.formattedOutput.split("\n").map((line) => JSON.parse(line));
        expect(messages.filter((message) => message.code === "PROPHECY-IMPORT")).toHaveLength(1);
        const replacements = messages.filter((message) => message.replacement !== undefined);
        expect(replacements).toHaveLength(2);
        expect(replacements.every((message) => message.replacementIsSafe === false)).toBe(true);
    });

    it("uses the new source snapshot on the next analysis of the same filename", async () => {
        const first = await scan(sourceFor([unsupported]));
        const second = await scan(sourceFor([supported]));
        expect(first.findings).toHaveLength(1);
        expect(first.findings[0].fix).toBeUndefined();
        expect(second.findings).toHaveLength(1);
        expect(second.findings[0].fix?.replacement).toContain("execFile");
    });

    it("uses each analysis's strategy overrides without retaining negative results", async () => {
        const source = sourceFor([supported]);
        const first = await scan(source, {
            ...spec,
            fixStrategies: [
                {
                    category: "rce",
                    sinkName: "exec",
                    saferAPI: "",
                    saferPattern: "",
                    applicability: "unfixable",
                    description: "Review this command manually.",
                },
            ],
        });
        const second = await scan(source);
        expect(first.findings).toHaveLength(1);
        expect(first.findings[0].fix).toBeUndefined();
        expect(first.formattedOutput).toContain("Manual fix required: Review this command manually.");
        expect(second.findings[0].fix?.replacement).toContain("execFile");
    });

    it("still generates repairs when the standalone formatter has no completed batch", async () => {
        const source = sourceFor([supported]);
        const result = await scan(source, spec, "json");
        const generate = jest.spyOn(fixGenerator, "generateFix");
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].fix).toBeUndefined();
        const output = formatFindingsLint(result.findings, new Map([[fileName, source]]));
        expect(generate).toHaveBeenCalledTimes(1);
        expect(output).toContain("execFile");
        expect(result.findings[0].fix).toBeUndefined();
    });

    it("retries a standalone formatter's negative result with fresh source and per-finding overrides", async () => {
        const source = sourceFor([unsupported]);
        const result = await scan(source, spec, "json");
        const contents = new Map([[fileName, source]]);
        const generate = jest.spyOn(fixGenerator, "generateFix");
        expect(formatFindingsLint(result.findings, contents)).not.toContain('"replacement"');
        contents.set(fileName, sourceFor([supported]));
        const overrides = jest.fn((): undefined => undefined);
        expect(formatFindingsLint(result.findings, contents, undefined, overrides)).toContain("execFile");
        expect(overrides).toHaveBeenCalledWith(result.findings[0]);
        expect(generate).toHaveBeenCalledTimes(2);
    });
});
