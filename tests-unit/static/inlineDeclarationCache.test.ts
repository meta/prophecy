/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as ts from "typescript";
import { analyze } from "../../src/static/analyzer";
import { InlineDeclarationCache } from "../../src/static/inlineDeclarationCache";
import { ParsedProject, parseSource, parseSourceForAnalysis } from "../../src/static/parser";
import { functionFreeSymbols } from "../../src/static/taint/taintTracker";

const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2020,
    module: ts.ModuleKind.CommonJS,
    moduleResolution: ts.ModuleResolutionKind.NodeJs,
    skipLibCheck: true,
    noEmit: true,
};

function variableType(parsed: ParsedProject): string {
    const statement = parsed.sourceFiles[0].statements.find(ts.isVariableStatement)!;
    return parsed.checker.typeToString(
        parsed.checker.getTypeAtLocation(statement.declarationList.declarations[0].name),
    );
}

function diagnosticCodes(parsed: ParsedProject): number[] {
    return parsed.program.getSemanticDiagnostics(parsed.sourceFiles[0]).map((diagnostic) => diagnostic.code);
}

describe("inline declaration reuse", () => {
    let directory: string;
    beforeEach(() => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-declarations-"));
    });
    afterEach(() => {
        fs.rmSync(directory, { recursive: true, force: true });
    });

    it("keeps root snapshots and checkers fresh for repeated filenames", () => {
        const first = parseSourceForAnalysis('const value = "first";', "same.ts");
        const second = parseSourceForAnalysis("const value = 42;", "same.ts");
        expect(second.program).not.toBe(first.program);
        expect(second.checker).not.toBe(first.checker);
        expect(second.sourceFiles[0]).not.toBe(first.sourceFiles[0]);
        expect(variableType(second)).toBe("42");
        expect(variableType(first)).toBe('"first"');
        const firstLib = first.program.getSourceFiles().find((file) => file.fileName.endsWith("lib.es5.d.ts"));
        expect(firstLib).toBeDefined();
        expect(second.program.getSourceFile(firstLib!.fileName)).toBe(firstLib);
    });

    it("does not leak root global augmentations into earlier or subsequent checkers", () => {
        const plain = "export {}; const value = [].demoMarker;";
        const augmented =
            "export {}; declare global { interface Array<T> { demoMarker: string; } } const value = [].demoMarker;";
        const before = parseSourceForAnalysis(plain, "same.ts");
        const during = parseSourceForAnalysis(augmented, "same.ts");
        const after = parseSourceForAnalysis(plain, "same.ts");
        // Query the earlier checker only after binding both later programs.
        expect(diagnosticCodes(before)).toContain(2339);
        expect(diagnosticCodes(during)).not.toContain(2339);
        expect(diagnosticCodes(after)).toContain(2339);
        expect(variableType(during)).toBe("string");
    });

    it("keeps the public parser's declaration objects private to each caller", () => {
        const first = parseSource("const value = 1;");
        const second = parseSource("const value = 2;");
        const firstLib = first.program.getSourceFiles().find((file) => file.fileName.endsWith("lib.es5.d.ts"))!;
        expect(second.program.getSourceFile(firstLib.fileName)).not.toBe(firstLib);
        firstLib.text = "caller mutation";
        const internal = parseSourceForAnalysis("const value = 3;");
        expect(internal.program.getSourceFile(firstLib.fileName)!.text).not.toBe("caller mutation");
    });

    it.each([false, true])("keeps analyzer findings and entry state independent of run order: %s", async (reverse) => {
        const source = (command: string) => `
            import * as vscode from "vscode";
            import {exec} from "child_process";
            export function activate() {
                vscode.window.registerUriHandler({handleUri(uri: vscode.Uri) { exec(${command}); }});
            }`;
        const cases = [
            [source("uri.query"), 1],
            [source('"echo safe"'), 0],
        ] as const;
        const ordered = reverse ? [...cases].reverse() : [...cases];
        for (const [text, count] of [...ordered, ...ordered]) {
            const result = await analyze({ source: text, fileName: "same.ts", outputFormat: "json" });
            expect(result.findings).toHaveLength(count);
            expect(result.entryPointCount).toBe(2);
            expect(result.syntaxErrors).toEqual([]);
            expect(result.skippedEntryPoints).toEqual([]);
        }
    });

    it("re-reads changed and deleted declarations without changing retained snapshots", () => {
        const declaration = path.join(directory, "environment.d.ts");
        const source = `/// <reference path="${declaration}" />\nconst value: Demo = {marker: "text"};`;
        fs.writeFileSync(declaration, "interface Demo { marker: string; }");
        const before = parseSourceForAnalysis(source, "same.ts");
        const stat = fs.statSync(declaration);
        // Same length and timestamp must not hide a type-environment replacement.
        fs.writeFileSync(declaration, "interface Demo { marker: number; }");
        fs.utimesSync(declaration, stat.atime, stat.mtime);
        const changed = parseSourceForAnalysis(source, "same.ts");
        expect(diagnosticCodes(changed)).toContain(2322);
        expect(diagnosticCodes(before)).not.toContain(2322);
        expect(changed.program.getSourceFile(declaration)).not.toBe(before.program.getSourceFile(declaration));
        fs.unlinkSync(declaration);
        expect(diagnosticCodes(parseSourceForAnalysis(source, "same.ts"))).toContain(2304);
        fs.writeFileSync(declaration, "interface Demo { marker: string; }");
        expect(diagnosticCodes(parseSourceForAnalysis(source, "same.ts"))).not.toContain(2304);
    });

    it("resolves module declarations afresh after package metadata changes", () => {
        const packageDir = path.join(directory, "node_modules", "demo");
        fs.mkdirSync(packageDir, { recursive: true });
        fs.writeFileSync(path.join(packageDir, "string.d.ts"), "export const value: string;");
        fs.writeFileSync(path.join(packageDir, "number.d.ts"), "export const value: number;");
        const manifest = path.join(packageDir, "package.json");
        fs.writeFileSync(manifest, JSON.stringify({ name: "demo", types: "string.d.ts" }));
        const source = 'import {value as imported} from "demo"; const value = imported;';
        const fileName = path.join(directory, "root.ts");
        const before = parseSourceForAnalysis(source, fileName);
        fs.writeFileSync(manifest, JSON.stringify({ name: "demo", types: "number.d.ts" }));
        const after = parseSourceForAnalysis(source, fileName);
        expect(variableType(after)).toBe("number");
        expect(variableType(before)).toBe("string");
    });

    it("invalidates exact compiler options, including binding-only options and interleaved hosts", () => {
        const file = path.join(directory, "demo.d.ts");
        fs.writeFileSync(file, "declare const value: string;");
        const cache = new InlineDeclarationCache();
        const firstHost = cache.createCompilerHost({ ...options });
        const first = firstHost.getSourceFile(file, ts.ScriptTarget.ES2020)!;
        expect(cache.createCompilerHost({ ...options }).getSourceFile(file, ts.ScriptTarget.ES2020)).toBe(first);
        const secondHost = cache.createCompilerHost({ ...options, strictNullChecks: true });
        const second = secondHost.getSourceFile(file, ts.ScriptTarget.ES2020);
        expect(second).not.toBe(first);
        expect(firstHost.getSourceFile(file, ts.ScriptTarget.ES2020)).not.toBe(second);
        expect(secondHost.getSourceFile(file, ts.ScriptTarget.ES2020)).not.toBe(first);
        const mutableOptions = { ...options };
        const mutableHost = cache.createCompilerHost(mutableOptions);
        const old = mutableHost.getSourceFile(file, ts.ScriptTarget.ES2020);
        mutableOptions.strictNullChecks = true;
        expect(mutableHost.getSourceFile(file, ts.ScriptTarget.ES2020)).not.toBe(old);
    });

    it.each([
        "export function helper() { return demoInput; }",
        "export declare function helper(value = demoInput): string;",
    ])("does not share checker-derived free symbols from malformed declarations: %s", (declaration) => {
        const file = path.join(directory, "helper.d.ts");
        fs.writeFileSync(file, declaration);
        const source = (type: string) => `import {helper} from "./helper";
            declare global { var demoInput: ${type}; } const value = helper();`;
        const first = parseSourceForAnalysis(source("string"), path.join(directory, "root.ts"));
        const firstFunction = first.program.getSourceFile(file)!.statements.find(ts.isFunctionDeclaration)!;
        const firstSymbol = functionFreeSymbols(first.checker, firstFunction).find(
            (symbol) => symbol.name === "demoInput",
        )!;
        expect(firstSymbol.declarations![0].getSourceFile()).toBe(first.sourceFiles[0]);
        const second = parseSourceForAnalysis(source("number"), path.join(directory, "root.ts"));
        const secondFunction = second.program.getSourceFile(file)!.statements.find(ts.isFunctionDeclaration)!;
        const secondSymbol = functionFreeSymbols(second.checker, secondFunction).find(
            (symbol) => symbol.name === "demoInput",
        )!;
        expect(secondSymbol.declarations![0].getSourceFile() === second.sourceFiles[0]).toBe(true);
        expect(secondSymbol).not.toBe(firstSymbol);
        expect(secondFunction).not.toBe(firstFunction);
    });

    it.each([
        "declare class Demo { method() { return 1; } }",
        "declare class Demo { get value() { return 1; } }",
        "declare namespace Demo { const callback = () => 1; }",
        "declare class Demo { static { const value = 1; } }",
    ])("bypasses declarations containing nested executable nodes: %s", (declaration) => {
        const file = path.join(directory, "executable.d.ts");
        fs.writeFileSync(file, declaration);
        const host = new InlineDeclarationCache().createCompilerHost(options);
        const first = host.getSourceFile(file, ts.ScriptTarget.ES2020)!;
        expect(first.isDeclarationFile).toBe(true);
        expect(host.getSourceFile(file, ts.ScriptTarget.ES2020)).not.toBe(first);
    });

    it("resolves configured type roots afresh when the options change", () => {
        const file = path.join(directory, "root.ts");
        fs.writeFileSync(file, "const value = demoValue;");
        const typeRoots = ["string", "number"].map((kind) => {
            const root = path.join(directory, kind);
            fs.mkdirSync(path.join(root, "demo"), { recursive: true });
            fs.writeFileSync(path.join(root, "demo", "index.d.ts"), `declare const demoValue: ${kind};`);
            return root;
        });
        const cache = new InlineDeclarationCache();
        const parse = (root: string): ParsedProject => {
            const settings = { ...options, types: ["demo"], typeRoots: [root] };
            const program = ts.createProgram([file], settings, cache.createCompilerHost(settings));
            return { program, checker: program.getTypeChecker(), sourceFiles: [program.getSourceFile(file)!] };
        };
        const first = parse(typeRoots[0]);
        const second = parse(typeRoots[1]);
        expect(variableType(second)).toBe("number");
        expect(variableType(first)).toBe("string");
        expect(variableType(parse(typeRoots[0]))).toBe("string");
    });

    it("invalidates per-file parse options and honors a forced fresh AST", () => {
        const file = path.join(directory, "demo.d.ts");
        fs.writeFileSync(file, "declare const value: string;");
        const host = new InlineDeclarationCache().createCompilerHost(options);
        const first = host.getSourceFile(file, ts.ScriptTarget.ES2020);
        const changed = host.getSourceFile(file, ts.ScriptTarget.ESNext);
        expect(changed).not.toBe(first);
        const esm: ts.CreateSourceFileOptions = {
            languageVersion: ts.ScriptTarget.ESNext,
            impliedNodeFormat: ts.ModuleKind.ESNext,
        };
        const cjs: ts.CreateSourceFileOptions = { ...esm, impliedNodeFormat: ts.ModuleKind.CommonJS };
        const moduleFile = host.getSourceFile(file, esm);
        expect(host.getSourceFile(file, cjs)).not.toBe(moduleFile);
        const current = host.getSourceFile(file, cjs);
        expect(host.getSourceFile(file, cjs, undefined, true)).not.toBe(current);
    });

    it("bounds retained declaration count with LRU eviction and never caches implementation files", () => {
        const host = new InlineDeclarationCache(2, 1024).createCompilerHost(options);
        const files = ["a.d.ts", "b.d.ts", "c.d.ts", "implementation.ts"].map((name) => path.join(directory, name));
        for (const file of files) fs.writeFileSync(file, "declare const value: string;");
        const first = host.getSourceFile(files[0], ts.ScriptTarget.ES2020);
        const second = host.getSourceFile(files[1], ts.ScriptTarget.ES2020);
        expect(host.getSourceFile(files[0], ts.ScriptTarget.ES2020)).toBe(first);
        host.getSourceFile(files[2], ts.ScriptTarget.ES2020);
        expect(host.getSourceFile(files[1], ts.ScriptTarget.ES2020)).not.toBe(second);
        const implementation = host.getSourceFile(files[3], ts.ScriptTarget.ES2020);
        expect(host.getSourceFile(files[3], ts.ScriptTarget.ES2020)).not.toBe(implementation);
    });

    it("bounds retained text bytes and bypasses oversized declarations", () => {
        const host = new InlineDeclarationCache(10, 100).createCompilerHost(options);
        const a = path.join(directory, "a.d.ts");
        const b = path.join(directory, "b.d.ts");
        const huge = path.join(directory, "huge.d.ts");
        fs.writeFileSync(a, "declare const first: string;");
        fs.writeFileSync(b, "declare const other: string;");
        fs.writeFileSync(huge, "//" + "x".repeat(100));
        const first = host.getSourceFile(a, ts.ScriptTarget.ES2020);
        host.getSourceFile(b, ts.ScriptTarget.ES2020);
        expect(host.getSourceFile(a, ts.ScriptTarget.ES2020)).not.toBe(first);
        const oversized = host.getSourceFile(huge, ts.ScriptTarget.ES2020);
        expect(host.getSourceFile(huge, ts.ScriptTarget.ES2020)).not.toBe(oversized);
    });
});
