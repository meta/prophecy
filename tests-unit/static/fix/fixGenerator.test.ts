/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { generateFix, generateFixes, generateImportFix } from "../../../src/static/fix/fixGenerator";
import { TaintFinding, SourceSpec, SinkSpec, FixStrategy } from "../../../src/static/spec/types";

function makeSource(): SourceSpec {
    return {
        kind: "parameter",
        pattern: "handleUri.uri",
        description: "URI handler parameter",
        taintAllProperties: true,
    };
}

function makeSink(name: string, pattern: string, categories: string[], argPositions?: number[]): SinkSpec {
    return {
        kind: "callArgument",
        name,
        pattern,
        argPositions: argPositions || [0],
        description: `Sink: ${name}`,
        severity: "critical",
        categories: categories as any,
    };
}

function makeFinding(
    sinkName: string,
    sinkPattern: string,
    categories: string[],
    sinkFileName: string,
    sinkLine: number,
    sinkColumn: number,
    sinkText?: string,
    argPositions?: number[],
): TaintFinding {
    return {
        handle: "test-handle",
        sinkSite: "activate>call:exec#0",
        source: makeSource(),
        sourceLocation: { fileName: sinkFileName, line: 1, column: 1 },
        sink: makeSink(sinkName, sinkPattern, categories, argPositions),
        sinkLocation: { fileName: sinkFileName, line: sinkLine, column: sinkColumn, text: sinkText },
        propagationChain: [],
    };
}

describe("generateFix", () => {
    it.each(["exec", "execSync"])("disables shell options in %s replacements", (name) => {
        const code = `${name}(\`printf \${value}\`, {shell: "/bin/sh", cwd: "/tmp"});`;
        const fix = generateFix(
            makeFinding(name, `child_process.${name}`, ["rce"], "test.ts", 1, 1),
            new Map([["test.ts", code]]),
        );
        expect(fix).toBeDefined();
        const run = jest.fn();
        new Function("value", name === "exec" ? "execFile" : "execFileSync", fix!.replacement)(
            "ok; echo injected",
            run,
        );
        expect(run).toHaveBeenCalledWith("printf", ["ok; echo injected"], { shell: false, cwd: "/tmp" });
    });

    it("preserves dynamic options and callback while disabling the shell", () => {
        const fix = generateFix(
            makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 1, 1),
            new Map([["test.ts", "exec(`tool ${value}`, options, callback);"]]),
        );
        const run = jest.fn();
        const callback = jest.fn();
        const options = { shell: "/bin/sh", timeout: 123 };
        new Function("value", "options", "callback", "execFile", fix!.replacement)("input", options, callback, run);
        expect(run).toHaveBeenCalledWith("tool", ["input"], { shell: false, timeout: 123 }, callback);
        expect(options.shell).toBe("/bin/sh");
    });

    it("preserves execSync options supplied through a variable", () => {
        const fix = generateFix(
            makeFinding("execSync", "child_process.execSync", ["rce"], "test.ts", 1, 1),
            new Map([["test.ts", "execSync(`tool ${value}`, options);"]]),
        );
        const run = jest.fn();
        const options = { shell: "/bin/sh", timeout: 123 };
        new Function("value", "options", "execFileSync", fix!.replacement)("input", options, run);
        expect(run).toHaveBeenCalledWith("tool", ["input"], { shell: false, timeout: 123 });
        expect(options.shell).toBe("/bin/sh");
    });

    it("withholds a fix when the second argument could be options or a callback", () => {
        expect(
            generateFix(
                makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 1, 1),
                new Map([["test.ts", "exec(`tool ${value}`, unknown);"]]),
            ),
        ).toBeUndefined();
    });

    it.each([
        [0, 1],
        [1, 0],
        [3, 1],
        [1, 14],
        [2, 100],
    ])("rejects invalid locations without fixing a different call (%s:%s)", (line, column) => {
        const code = 'exec("one");\nexec("two");';
        const finding = makeFinding("exec", "child_process.exec", ["rce"], "test.ts", line, column);
        expect(generateFix(finding, new Map([["test.ts", code]]))).toBeUndefined();
    });

    function commandFix(command: string) {
        const code = `exec(${command});`;
        return generateFix(
            makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 1, 1),
            new Map([["test.ts", code]]),
        );
    }

    it("preserves quoted template values as one valid argument", () => {
        const fix = commandFix('`echo "${value}"`');
        expect(fix).toBeDefined();
        const execFile = jest.fn();
        new Function("value", "execFile", fix!.replacement)('a "quoted" value', execFile);
        expect(execFile).toHaveBeenCalledWith("echo", ['a "quoted" value']);
    });

    it("keeps an interpolated option value in its original argument", () => {
        const fix = commandFix("`tool --name=${value}`");
        expect(fix).toBeDefined();
        const execFile = jest.fn();
        new Function("value", "execFile", fix!.replacement)("two words", execFile);
        expect(execFile).toHaveBeenCalledWith("tool", ["--name=two words"]);
    });

    it("preserves empty and quoted literal arguments", () => {
        const fix = commandFix(JSON.stringify('tool "" "two words" "a\'quote"'));
        expect(fix).toBeDefined();
        const execFile = jest.fn();
        new Function("execFile", fix!.replacement)(execFile);
        expect(execFile).toHaveBeenCalledWith("tool", ["", "two words", "a'quote"]);
    });

    it.each(["`tool ${value} | other`", "`tool $HOME ${value}`", '`tool "${value}`', "`./${value} arg`"])(
        "omits unsupported shell syntax: %s",
        (command) => {
            expect(commandFix(command)).toBeUndefined();
        },
    );

    it("uses each current file snapshot for multiple fix locations", () => {
        const findings = [
            makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 1, 1),
            makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 2, 1),
        ];
        const contents = new Map([["test.ts", 'exec("one");\nexec("two");']]);
        expect(generateFixes(findings, contents)).toBe(2);
        expect(findings.map((finding) => finding.fix!.replacement)).toEqual([
            'execFile("one", [])',
            'execFile("two", [])',
        ]);
        contents.set("test.ts", 'exec("three");\nexec("four");');
        expect(generateFixes(findings, contents)).toBe(2);
        expect(findings.map((finding) => finding.fix!.replacement)).toEqual([
            'execFile("three", [])',
            'execFile("four", [])',
        ]);
    });

    it("generates execFile replacement for exec(variable)", () => {
        const code = [
            'import { exec } from "child_process";',
            "function handleUri(uri: any) {",
            "    const cmd = uri.query;",
            "    exec(cmd);",
            "}",
        ].join("\n");

        const finding = makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 4, 5, "exec(cmd)");
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.original).toBe("exec(cmd)");
        expect(fix!.replacement).toContain("execFile");
        expect(fix!.replacement).toContain("cmd");
        expect(fix!.applicability).toBe("unsafe");
    });

    it("does not replace a promisified exec with callback-style execFile", () => {
        const code = "const run = promisify(exec);\nawait run(cmd);";
        const finding = {
            ...makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 2, 7),
            promisified: true as const,
        };
        expect(generateFix(finding, new Map([["test.ts", code]]))).toBeUndefined();
    });

    it("generates execFile replacement for exec with template literal", () => {
        const code = [
            'import { exec } from "child_process";',
            "function handleUri(uri: any) {",
            "    const repo = uri.query;",
            "    exec(`git clone ${repo} /tmp/repo`);",
            "}",
        ].join("\n");

        const finding = makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 4, 5);
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.original).toContain("exec(`git clone ${repo} /tmp/repo`)");
        expect(fix!.replacement).toContain("execFile");
        expect(fix!.replacement).toContain('"git"');
        expect(fix!.replacement).toContain('"/tmp/repo"');
    });

    it("generates quote() wrapping for terminal.sendText", () => {
        const code = [
            "function run(cmd: string) {",
            "    const terminal = { sendText: (t: string) => {} };",
            "    terminal.sendText(cmd);",
            "}",
        ].join("\n");

        const finding = makeFinding(
            "sendText",
            "Terminal.sendText",
            ["rce"],
            "test.ts",
            3,
            5,
            "terminal.sendText(cmd)",
        );
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.original).toBe("terminal.sendText(cmd)");
        expect(fix!.replacement).toContain("quote([cmd])");
    });

    it("generates ProcessExecution replacement for ShellExecution", () => {
        const code = ["function run(cmd: string) {", "    const task = new ShellExecution(cmd);", "}"].join("\n");

        const finding = makeFinding(
            "ShellExecution",
            "ShellExecution",
            ["rce"],
            "test.ts",
            2,
            18,
            "new ShellExecution(cmd)",
        );
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.original).toBe("new ShellExecution(cmd)");
        expect(fix!.replacement).toContain("ProcessExecution");
    });

    it("uses vscode namespace alias for ShellExecution replacements", () => {
        const code = [
            'import * as vscode from "vscode";',
            "function run(cmd: string) {",
            "    const task = new vscode.ShellExecution(cmd);",
            "}",
        ].join("\n");

        const finding = makeFinding(
            "ShellExecution",
            "ShellExecution",
            ["rce"],
            "test.ts",
            3,
            18,
            "new vscode.ShellExecution(cmd)",
        );
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain("new vscode.ProcessExecution");
    });

    it("returns undefined for unfixable categories (code_injection)", () => {
        const code = "eval(userInput);";
        const finding = makeFinding("eval", "eval", ["code_injection"], "test.ts", 1, 1);
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);
        expect(fix).toBeUndefined();
    });

    it("returns undefined for unfixable categories (executeCommand)", () => {
        const code = "vscode.commands.executeCommand(cmd, args);";
        const finding = makeFinding("executeCommand", "vscode.commands.executeCommand", ["rce"], "test.ts", 1, 1);
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);
        expect(fix).toBeUndefined();
    });

    it("returns undefined when file content is not available", () => {
        const finding = makeFinding("exec", "child_process.exec", ["rce"], "missing.ts", 1, 1);
        const fix = generateFix(finding, new Map());
        expect(fix).toBeUndefined();
    });

    it("uses namespace alias when module is imported as import * as cp", () => {
        const code = [
            'import * as cp from "child_process";',
            "function handleUri(uri: any) {",
            "    const cmd = uri.query;",
            "    cp.exec(cmd);",
            "}",
        ].join("\n");

        const finding = makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 4, 5, "cp.exec(cmd)");
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain("cp.execFile");
        expect(fix!.replacement).toContain("cmd");
    });

    it("generates exec with string literal splitting", () => {
        const code = ['import { exec } from "child_process";', 'exec("ls -la /tmp");'].join("\n");

        const finding = makeFinding("exec", "child_process.exec", ["rce"], "test.ts", 2, 1);
        const fileContents = new Map([["test.ts", code]]);
        const fix = generateFix(finding, fileContents);

        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain("execFile");
        expect(fix!.replacement).toContain('"ls"');
        expect(fix!.replacement).toContain('"-la"');
        expect(fix!.replacement).toContain('"/tmp"');
    });
});

describe("generateImportFix", () => {
    const execStrategy: FixStrategy = {
        category: "rce",
        sinkName: "exec",
        saferAPI: "child_process.execFile",
        saferPattern: "execFile(program, [args])",
        importPackage: "child_process",
        importName: "execFile",
        applicability: "unsafe",
        description: "test",
    };

    it("collects existing named imports across every declaration", () => {
        const code = 'import { exec } from "child_process";\nimport { execFile } from "child_process";';
        expect(generateImportFix(execStrategy, "test.ts", code)).toBeUndefined();
        const fix = generateImportFix(execStrategy, "test.ts", code, ["execFile", "execFileSync"]);
        expect(fix!.replacement).toBe('import { exec, execFileSync } from "child_process";');
    });

    it.each([
        "exec // keep the explanation\n",
        "exec, // keep the explanation\n",
        "exec /* keep the explanation with } */",
        "/* keep the explanation */",
    ])("preserves comments when merging named bindings: %s", (bindings) => {
        const code = `import {${bindings}} from "child_process";`;
        const fix = generateImportFix(execStrategy, "test.ts", code);
        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain("keep the explanation");
        const source = ts.createSourceFile("test.ts", fix!.replacement, ts.ScriptTarget.Latest, true);
        const declaration = source.statements[0] as ts.ImportDeclaration;
        const names = declaration.importClause!.namedBindings as ts.NamedImports;
        expect(names.elements.map((element) => element.name.text)).toContain("execFile");
        expect(ts.transpileModule(fix!.replacement, { reportDiagnostics: true }).diagnostics).toEqual([]);
    });

    it("generates import for shell-quote when not present", () => {
        const code = ['import * as vscode from "vscode";', "", "function run() {}"].join("\n");

        const strategy: FixStrategy = {
            category: "rce",
            sinkName: "sendText",
            saferAPI: "shell-quote",
            saferPattern: "quote([arg])",
            importPackage: "shell-quote",
            importName: "quote",
            applicability: "unsafe",
            description: "test",
        };

        const fix = generateImportFix(strategy, "test.ts", code);
        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain('import { quote } from "shell-quote"');
    });

    it("returns undefined when the specific named import already exists", () => {
        const code = [
            'import { quote } from "shell-quote";',
            'import * as vscode from "vscode";',
            "",
            "function run() {}",
        ].join("\n");

        const strategy: FixStrategy = {
            category: "rce",
            sinkName: "sendText",
            saferAPI: "shell-quote",
            saferPattern: "quote([arg])",
            importPackage: "shell-quote",
            importName: "quote",
            applicability: "unsafe",
            description: "test",
        };

        const fix = generateImportFix(strategy, "test.ts", code);
        expect(fix).toBeUndefined();
    });

    it("adds named export to existing import when module is imported but name is missing", () => {
        const code = ['import { exec } from "child_process";', "", "function run() {}"].join("\n");

        const strategy: FixStrategy = {
            category: "rce",
            sinkName: "exec",
            saferAPI: "child_process.execFile",
            saferPattern: "execFile(program, [args])",
            importPackage: "child_process",
            importName: "execFile",
            applicability: "unsafe",
            description: "test",
        };

        const fix = generateImportFix(strategy, "test.ts", code);
        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain("exec, execFile");
    });

    it("returns undefined when no import is needed", () => {
        const strategy: FixStrategy = {
            category: "rce",
            sinkName: "exec",
            saferAPI: "child_process.execFile",
            saferPattern: "execFile(program, [args])",
            applicability: "unsafe",
            description: "test",
        };

        const fix = generateImportFix(strategy, "test.ts", "function run() {}");
        expect(fix).toBeUndefined();
    });

    it("adds ProcessExecution to an existing vscode named import", () => {
        const code = ['import { ShellExecution, window } from "vscode";', "", "function run() {}"].join("\n");

        const strategy: FixStrategy = {
            category: "rce",
            sinkName: "ShellExecution",
            saferAPI: "vscode.ProcessExecution",
            saferPattern: "new ProcessExecution(program, [args])",
            importPackage: "vscode",
            importName: "ProcessExecution",
            applicability: "unsafe",
            description: "test",
        };

        const fix = generateImportFix(strategy, "test.ts", code);
        expect(fix).toBeDefined();
        expect(fix!.replacement).toContain("ShellExecution, window, ProcessExecution");
    });

    it("returns undefined for import when module uses namespace import", () => {
        const code = ['import * as cp from "child_process";', "", "function run() {}"].join("\n");

        const strategy: FixStrategy = {
            category: "rce",
            sinkName: "exec",
            saferAPI: "child_process.execFile",
            saferPattern: "execFile(program, [args])",
            importPackage: "child_process",
            importName: "execFile",
            applicability: "unsafe",
            description: "test",
        };

        const fix = generateImportFix(strategy, "test.ts", code);
        expect(fix).toBeUndefined();
    });
});
