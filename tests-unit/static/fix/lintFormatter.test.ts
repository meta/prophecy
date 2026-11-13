/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { formatFindingsLint } from "../../../src/static/fix/lintFormatter";
import { TaintFinding, SourceSpec } from "../../../src/static/spec/types";

function makeSource(): SourceSpec {
    return {
        kind: "parameter",
        pattern: "handleUri.uri",
        description: "URI handler parameter",
        taintAllProperties: true,
    };
}

function makeFinding(
    sinkName: string,
    categories: string[],
    severity: string,
    fileName: string,
    line: number,
): TaintFinding {
    return {
        handle: `test|${sinkName}|${line}`,
        sinkSite: `activate>call:${sinkName}#${line}`,
        source: makeSource(),
        sourceLocation: { fileName, line: 1, column: 1 },
        sink: {
            kind: "callArgument",
            name: sinkName,
            pattern: `test.${sinkName}`,
            description: `Test: ${sinkName}`,
            severity: severity as any,
            categories: categories as any,
        },
        sinkLocation: { fileName, line, column: 5, text: `${sinkName}(cmd)` },
        propagationChain: [],
    };
}

describe("formatFindingsLint", () => {
    it.each([false, true])("combines helper imports for async and sync replacements (reverse=%s)", (reverse) => {
        const code =
            'import {exec, execSync} from "child_process";\n    exec(`tool ${input}`);\n    execSync(`tool ${input}`);';
        const findings = [
            makeFinding("exec", ["rce"], "critical", "test.ts", 2),
            makeFinding("execSync", ["rce"], "critical", "test.ts", 3),
        ];
        if (reverse) findings.reverse();
        const messages = formatFindingsLint(findings, new Map([["test.ts", code]]))
            .split("\n")
            .map((line) => JSON.parse(line));
        const imports = messages.filter((message) => message.code === "PROPHECY-IMPORT");
        expect(imports).toHaveLength(1);
        expect(imports[0].replacement).toMatch(/\bexecFile\b/);
        expect(imports[0].replacement).toContain("execFileSync");
        const run = jest.fn();
        let fixed = code;
        for (const message of messages) fixed = fixed.replace(message.original, message.replacement);
        const body = fixed.slice(fixed.indexOf(";") + 1);
        new Function("input", "execFile", "execFileSync", body)("a;b", run, run);
        expect(run).toHaveBeenCalledTimes(2);
        expect(run).toHaveBeenLastCalledWith("tool", ["a;b"]);
    });

    it("returns empty string for no findings", () => {
        const output = formatFindingsLint([], new Map());
        expect(output).toBe("");
    });

    it("produces valid JSON Lines output", () => {
        const findings = [makeFinding("exec", ["rce"], "critical", "test.ts", 5)];
        const fileContents = new Map([["test.ts", "exec(cmd);"]]);

        const output = formatFindingsLint(findings, fileContents);
        const lines = output.trim().split("\n");

        expect(lines.length).toBeGreaterThanOrEqual(1);
        for (const line of lines) {
            expect(() => JSON.parse(line)).not.toThrow();
        }
    });

    it("includes required LintMessage fields", () => {
        const findings = [makeFinding("exec", ["rce"], "critical", "test.ts", 5)];
        const fileContents = new Map([["test.ts", "exec(cmd);"]]);

        const output = formatFindingsLint(findings, fileContents);
        const msg = JSON.parse(output.trim().split("\n")[0]);

        expect(msg.path).toBeDefined();
        expect(msg.line).toBe(5);
        expect(msg.char).toBe(5);
        expect(msg.code).toBe("PROPHECY-RCE");
        expect(msg.category).toBeUndefined();
        expect(msg.severity).toBe("error");
        expect(msg.name).toBeDefined();
        expect(msg.description).toBeDefined();
    });

    it("maps severity correctly", () => {
        const tests: Array<[string, string]> = [
            ["critical", "error"],
            ["high", "error"],
            ["medium", "warning"],
            ["low", "advice"],
        ];

        for (const [sinkSeverity, expected] of tests) {
            const findings = [makeFinding("exec", ["rce"], sinkSeverity, "test.ts", 1)];
            const output = formatFindingsLint(findings, new Map([["test.ts", "exec(x);"]]));
            const msg = JSON.parse(output.trim().split("\n")[0]);
            expect(msg.severity).toBe(expected);
        }
    });

    it("unfixable findings omit original/replacement", () => {
        const findings = [makeFinding("executeCommand", ["rce"], "critical", "test.ts", 5)];
        const fileContents = new Map([["test.ts", "vscode.commands.executeCommand(cmd);"]]);

        const output = formatFindingsLint(findings, fileContents);
        const msg = JSON.parse(output.trim().split("\n")[0]);

        expect(msg.original).toBeUndefined();
        expect(msg.replacement).toBeUndefined();
    });

    it("makes paths relative to projectDir", () => {
        const findings = [makeFinding("exec", ["rce"], "critical", "/proj/src/test.ts", 5)];
        const fileContents = new Map([["/proj/src/test.ts", "exec(cmd);"]]);

        const output = formatFindingsLint(findings, fileContents, "/proj");
        const msg = JSON.parse(output.trim().split("\n")[0]);

        expect(msg.path).toBe("src/test.ts");
    });

    it("replacementIsSafe is always false for API migrations", () => {
        const code = ['import { exec } from "child_process";', "exec(cmd);"].join("\n");
        const findings = [makeFinding("exec", ["rce"], "critical", "test.ts", 2)];
        const fileContents = new Map([["test.ts", code]]);

        const output = formatFindingsLint(findings, fileContents);
        const lines = output.trim().split("\n");
        const msgsWithReplacement = lines
            .map((line: string) => JSON.parse(line))
            .filter((msg: any) => msg.replacementIsSafe !== undefined);

        expect(msgsWithReplacement.length).toBeGreaterThanOrEqual(1);
        for (const msg of msgsWithReplacement) {
            expect(msg.replacementIsSafe).toBe(false);
        }
    });
});
