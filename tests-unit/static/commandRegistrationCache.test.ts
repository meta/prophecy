/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as ts from "typescript";
import { parseProject } from "../../src/static/parser";
import { resolveCommandRegistration, resolveStaticString } from "../../src/static/taint/functionResolver";
import { InterproceduralAnalyzer } from "../../src/static/taint/interprocedural";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

const declarations = `declare module "vscode" {
    export namespace commands {
        export function registerCommand(name: string, handler: (...args: any[]) => any): void;
    }
}`;
const imports = `import { commands as api } from "vscode";`;
const fixtures: string[] = [];

function project(files: Record<string, string>, types = declarations) {
    const dir = apiBoundaryFixture(files, types);
    fixtures.push(dir);
    const parsed = parseProject(dir);
    const calls: ts.CallExpression[] = [];
    const visit = (node: ts.Node) => {
        if (ts.isCallExpression(node)) calls.push(node);
        node.forEachChild(visit);
    };
    parsed.sourceFiles.forEach(visit);
    return { ...parsed, calls };
}

function registrations(parsed: ReturnType<typeof project>) {
    return parsed.calls.flatMap((call) => {
        const registration = resolveCommandRegistration(parsed.checker, call);
        if (!registration) return [];
        const command = resolveStaticString(parsed.checker, registration.command);
        return command == null ? [] : [[command, registration.handlerParamOffset]];
    });
}

afterEach(() => {
    for (const dir of fixtures.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("Command registration symbol memoization", () => {
    it("reuses direct and negative symbol facts without skipping variable aliases", () => {
        const parsed = project({
            "main.ts": `${imports}
                const alias = api.registerCommand;
                const local = { run(name, callback) {} };
                api.registerCommand("demo.direct1", x => x);
                api.registerCommand("demo.direct2", x => x);
                alias("demo.alias1", x => x);
                alias("demo.alias2", x => x);
                local.run("demo.local1", x => x);
                local.run("demo.local2", x => x);`,
        });
        const fqn = jest.spyOn(parsed.checker, "getFullyQualifiedName");
        try {
            expect(registrations(parsed)).toEqual([
                ["demo.direct1", 0],
                ["demo.direct2", 0],
                ["demo.alias1", 0],
                ["demo.alias2", 0],
            ]);
            expect(fqn).toHaveBeenCalledTimes(3);
            expect(new Set(fqn.mock.calls.map(([symbol]) => symbol)).size).toBe(3);
        } finally {
            fqn.mockRestore();
        }
    });

    it.each([false, true])("retains reexported aliases through namespace access: %s", (namespace) => {
        const parsed = project({
            "bridge.ts": `${imports} export const register = api.registerCommand;`,
            "main.ts": namespace
                ? `import * as bridge from "./bridge"; bridge.register("demo.reexport", x => x);`
                : `import { register as renamed } from "./bridge"; renamed("demo.reexport", x => x);`,
        });
        expect(registrations(parsed)).toEqual([["demo.reexport", 0]]);
    });

    it("retains named default declarations whose symbol name differs from their FQN", () => {
        // TypeScript prints this named declaration as registerCommand even though
        // the resolved symbol's name is default; a leaf-name gate would lose it.
        const parsed = project(
            {
                "bridge.ts": `${imports} export const register = api.default;`,
                "main.ts": `${imports} import { register as renamed } from "./bridge";
                api.default("demo.default1", x => x);
                api.default("demo.default2", x => x);
                renamed("demo.defaultAlias", x => x);`,
            },
            `declare module "vscode" {
            export namespace commands {
                export default function registerCommand(name: string, handler: (...args: any[]) => any): void;
            }
        }`,
        );
        const direct = parsed.calls.find((call) => call.expression.getText() === "api.default")!;
        const symbol = parsed.checker.getSymbolAtLocation((direct.expression as ts.PropertyAccessExpression).name)!;
        expect(symbol.getName()).toBe("default");
        expect(parsed.checker.getFullyQualifiedName(symbol)).toBe('"vscode".commands.registerCommand');
        expect(registrations(parsed)).toEqual([
            ["demo.default1", 0],
            ["demo.default2", 0],
            ["demo.defaultAlias", 0],
        ]);
    });

    it("preserves reordered wrappers, injected offsets, and private property aliases", () => {
        const parsed = project({
            "main.ts": `${imports}
            function inner(callback, name) {
                api.registerCommand(name, (...args) => callback({}, ...args));
            }
            function outer(name, callback) { inner(callback, name); }
            class Demo {
                private register = (name, callback) => outer(name, callback);
                run() { this.register("demo.private", (_context, value) => value); }
            }
            outer("demo.wrapper", (_context, value) => value);`,
        });
        expect(registrations(parsed)).toEqual([
            ["demo.private", 1],
            ["demo.wrapper", 1],
        ]);
    });

    it("preserves property overrides and current mixed-receiver resolution", () => {
        const parsed = project({
            "main.ts": `${imports}
            const real = { register(name, callback) { api.registerCommand(name, callback); } };
            const copied = { ...real };
            const alias = copied.register;
            const overridden = { ...real, register(name, callback) {} };
            alias("demo.property", x => x);
            overridden.register("demo.override", x => x);
            function mixed<T extends typeof real | typeof overridden>(receiver: T) {
                receiver.register("demo.mixed", x => x);
            }`,
        });
        expect(registrations(parsed)).toEqual([
            ["demo.property", 0],
            ["demo.mixed", 0],
        ]);
    });

    it("keeps unsupported destructuring, cycles, and unrelated names negative", () => {
        const parsed = project({
            "main.ts": `${imports}
            const { registerCommand: destructured } = api;
            const first = second; const second = first;
            function registerCommand(name, callback) {}
            const local = { registerCommand(name, callback) {} };
            destructured("demo.destructured", x => x);
            first("demo.cycle", x => x);
            registerCommand("demo.local", x => x);
            local.registerCommand("demo.property", x => x);`,
        });
        expect(registrations(parsed)).toEqual([]);
    });

    it("retains syntax fallback and repeated command entries with unknown names", () => {
        const parsed = project({
            "main.ts": `declare const vscode: any;
            declare const unknownName: string;
            const handler = (x: string) => x;
            vscode.commands.registerCommand("demo.duplicate", handler);
            vscode.commands.registerCommand("demo.duplicate", handler);
            vscode.commands.registerCommand(unknownName, handler);`,
        });
        const analyzer = new InterproceduralAnalyzer(parsed.checker, vscodeExtensionSpec, 5);
        analyzer.buildVSCodeCommandRegistry(parsed.sourceFiles);
        const entries = analyzer.discoverEntryPoints(parsed.sourceFiles).filter((ep) => ep.kind === "command");
        expect(entries).toHaveLength(3);
        expect(entries.map((ep) => [ep.node.pos, [...ep.taintedParams]])).toEqual([
            [entries[0].node.pos, []],
            [entries[0].node.pos, []],
            [entries[0].node.pos, []],
        ]);
    });

    it("does not reuse symbol facts across checkers sharing a source AST", () => {
        const source = ts.createSourceFile(
            "shared.ts",
            `${imports} api.registerCommand("demo", x => x);`,
            ts.ScriptTarget.ES2020,
            true,
        );
        const build = (types: string) => {
            const host = ts.createCompilerHost({ noLib: true, types: [] });
            host.getSourceFile = (name) =>
                name === "shared.ts" ? source : ts.createSourceFile(name, types, ts.ScriptTarget.ES2020, true);
            return ts.createProgram(["shared.ts", "api.d.ts"], { noLib: true, types: [] }, host).getTypeChecker();
        };
        const call = (source.statements[1] as ts.ExpressionStatement).expression as ts.CallExpression;
        expect(resolveCommandRegistration(build(declarations), call)).toBeDefined();
        expect(
            resolveCommandRegistration(
                build(
                    `declare module "other" { export namespace commands { export function registerCommand(name: string, handler: any): void; } } declare module "vscode" { export { commands } from "other"; }`,
                ),
                call,
            ),
        ).toBeUndefined();
    });
});
