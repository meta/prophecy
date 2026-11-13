/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { InterproceduralAnalyzer } from "../../src/static/taint/interprocedural";
import { InterproceduralCallResult } from "../../src/static/taint/taintTracker";
import { TaintSpec } from "../../src/static/spec/types";
import { vscodeSpecWithEnvSource } from "./testUtils";

const prelude = `
import * as vscode from "vscode";
import * as fs from "fs";
import { exec } from "child_process";
declare const flag: boolean;
declare function opaque(callback: () => void): void;
class Runner {
    command: string;
    constructor(command: string) { this.command = command; }
}
`;

function scan(body: string, maxDepth = 5, spec?: TaintSpec) {
    return analyze({
        source:
            prelude +
            `
export function activate() {
    vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) { ${body} } });
}`,
        fileName: "/src/engine-state.ts",
        maxDepth,
        outputFormat: "json",
        spec,
    });
}

describe("Engine state regressions", () => {
    it("uses completed clean return summaries and preserves actual return taint", async () => {
        expect(
            (
                await scan(`function fixed(x: string) { return "echo safe"; }
            exec(fixed(uri.query));`)
            ).findings,
        ).toHaveLength(0);
        expect(
            (
                await scan(`function identity(x: string) { return x; }
            exec(identity(uri.query));`)
            ).findings,
        ).toHaveLength(1);
    });

    it.each(["opaque", "clean"])(
        "requires every dispatch alternative to resolve before crediting clean returns: %s",
        async (alternative) => {
            const original = InterproceduralAnalyzer.prototype.analyzeFunctionCall;
            const bodies: { text: string; result?: InterproceduralCallResult }[] = [];
            const spy = jest
                .spyOn(InterproceduralAnalyzer.prototype, "analyzeFunctionCall")
                .mockImplementation(function (this: InterproceduralAnalyzer, ...args) {
                    const boundFunction = args[7];
                    if (args[0].expression.getText() !== "dispatch" || !boundFunction) {
                        return original.apply(this, args);
                    }
                    const text = boundFunction.declaration.body!.getText();
                    // Keep dispatch resolution real while making one body unavailable.
                    if (alternative === "opaque" && text === '"echo alternative"') {
                        bodies.push({ text });
                        return undefined;
                    }
                    const result = original.apply(this, args);
                    bodies.push({ text, result });
                    return result;
                });
            try {
                const result = await scan(`
                const fixed = (_input: string) => "echo fixed";
                const other = (_input: string) => "echo alternative";
                const dispatch = flag ? fixed : other;
                exec(dispatch(uri.query));
            `);
                expect(bodies.map((body) => body.text).sort()).toEqual(['"echo alternative"', '"echo fixed"']);
                const resolved = bodies.filter((body) => body.result != null);
                expect(resolved).toHaveLength(alternative === "opaque" ? 1 : 2);
                for (const { result: summary } of resolved) {
                    expect(summary!.returnTaints ?? []).toHaveLength(0);
                    expect(summary!.returnUnknown).toBeFalsy();
                    expect(summary!.truncated).toBeFalsy();
                }
                expect(result.skippedEntryPoints).toHaveLength(0);
                expect(result.findings).toHaveLength(alternative === "opaque" ? 1 : 0);
                if (alternative === "opaque") {
                    expect(result.findings[0].source.pattern).toBe("handleUri.uri");
                    expect(result.findings[0].sink.name).toBe("exec");
                    expect(result.findings[0].sinkLocation.text).toContain("exec(dispatch(uri.query))");
                }
            } finally {
                spy.mockRestore();
            }
        },
    );

    it("credits immutable primitive constants while retaining opaque mutable returns", async () => {
        expect(
            (
                await scan(`function fixed(input: string) { const command = "echo safe"; return command; }
            exec(fixed(uri.query));`)
            ).findings,
        ).toHaveLength(0);
        expect(
            (
                await scan(`function mutate(input: string) { let command = "echo safe";
                const load = () => { command = input; }; load(); return command; }
            exec(mutate(uri.query));`)
            ).findings,
        ).toHaveLength(1);
    });

    it.each(["direct", "wrapper", "cached"])("preserves callback-backed Promise returns: %s", async (mode) => {
        const setup = `function readBody(req: unknown): Promise<string> {
            return new Promise(resolve => {
                const chunks: string[] = [];
                (req as any).on("data", (chunk: string) => chunks.push(chunk));
                (req as any).on("end", () => resolve(chunks.join("")));
            });
        }
        function wrapper(req: unknown) { const result = readBody(req); return result; }`;
        const before = mode === "cached" ? 'readBody("safe");' : "";
        const call = mode === "wrapper" ? "wrapper(uri.query)" : "readBody(uri.query)";
        expect((await scan(`${setup} ${before} exec((await ${call})!);`)).findings).toHaveLength(1);
    });

    it("preserves unmodeled URL getters in returned command strings", async () => {
        expect(
            (
                await scan(`function install(url: string) {
                const origin = new URL(url).origin; return "curl '" + origin + "'";
            }
            exec(install(uri.query));`)
            ).findings,
        ).toHaveLength(1);
    });

    it("preserves byte-encoding and serialization wrapper returns", async () => {
        expect(
            (
                await scan(`function encode(contents: string) {
                return new TextEncoder().encode(JSON.stringify({contents}));
            }
            eval(new TextDecoder().decode(encode(uri.query)));`)
            ).findings,
        ).toHaveLength(1);
    });

    it("does not certify clean catch overwrites as a clean success return", async () => {
        expect(
            (
                await scan(`function command(input: string) {
                let value; try { value = input; } catch { value = "echo safe"; } return value;
            } exec(command(uri.query));`)
            ).findings,
        ).toHaveLength(1);
        expect(
            (
                await scan(`function command(input: string) {
                let url; try { url = new URL(input); } catch { url = new URL("https://safe.test"); }
                return "curl '" + url.origin + "'";
            } exec(command(uri.query));`)
            ).findings,
        ).toHaveLength(1);
    });

    it("does not certify computed-key object returns as clean", async () => {
        expect(
            (
                await scan(`function build(input: string) { return {[input]: [{path: "", section: {}}]}; }
            eval(JSON.stringify(build(uri.query)));`)
            ).findings,
        ).toHaveLength(1);
    });

    it("preserves unresolved Promise.resolve results", async () => {
        expect(
            (
                await scan(`function body(input: string) { return Promise.resolve(input); }
            exec((await body(uri.query))!);`)
            ).findings,
        ).toHaveLength(1);
    });

    it("requires fixed values and modeled mutations before crediting array returns", async () => {
        expect(
            (
                await scan(`function fixed(input: string) { const values: string[] = [];
                for (const value of ["echo safe"]) { if (input !== "disabled") values.push(value); }
                return values; } exec(fixed(uri.query).join(""));`)
            ).findings,
        ).toHaveLength(0);
        expect(
            (
                await scan(`declare function mutate(values: string[], input: string): void;
            function unresolved(input: string) { const values: string[] = []; mutate(values, input); return values; }
            exec(unresolved(uri.query).join(""));`)
            ).findings,
        ).toHaveLength(1);
    });

    it.each([
        ["direct alias push", "const alias = values; alias.push(input);"],
        ["direct alias element write", "const alias = values; alias[0] = input;"],
        ["shorthand alias push", "const holder = {values}; holder.values.push(input);"],
        ["shorthand alias element write", "const holder = {values}; holder.values[0] = input;"],
    ])("retains mutations through array aliases: %s", async (_name, mutation) => {
        const build = `function build(input: string) {
            const values: string[] = []; ${mutation} return values;
        }`;
        const raw = await scan(`${build} exec(build(uri.query).join(""));`);
        expect(raw.skippedEntryPoints).toHaveLength(0);
        expect(raw.findings).toHaveLength(1);
        expect(raw.findings[0].source.pattern).toBe("handleUri.uri");
        expect(raw.findings[0].sink.name).toBe("exec");
        expect(raw.findings[0].sinkLocation.text).toContain('exec(build(uri.query).join(""))');
        const clean = await scan(`${build} exec(build("echo safe").join(""));`);
        expect(clean.skippedEntryPoints).toHaveLength(0);
        expect(clean.findings).toHaveLength(0);
    });

    it.each(["push", "unshift"])("credits a fixed array %s despite unused tainted input", async (method) => {
        const result = await scan(`function fixed(input: string) {
            const values: string[] = []; values.${method}("echo safe"); return values;
        } exec(fixed(uri.query).join(""));`);
        expect(result.skippedEntryPoints).toHaveLength(0);
        expect(result.findings).toHaveLength(0);
    });

    it("distinguishes a shadowed shorthand from the returned array binding", async () => {
        const result = await scan(`function fixed(input: string) {
            const values: string[] = [];
            { const values = "echo other"; const unrelated = {values}; }
            values.push("echo safe"); return values;
        } exec(fixed(uri.query).join(""));`);
        expect(result.skippedEntryPoints).toHaveLength(0);
        expect(result.findings).toHaveLength(0);
    });

    it("retains callee findings while using its clean return", async () => {
        const result = await scan(`function consume(command: string) {
                exec(command); return "echo safe";
            }
            exec(consume(uri.query));`);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toContain("exec(command)");
    });

    it("preserves conservative returns when nested analysis was truncated", async () => {
        const result = await scan(
            `function deeper(x: string) { return "echo safe"; }
            function helper(x: string) { return deeper(x); }
            exec(helper(uri.query));`,
            1,
        );
        expect(result.findings).toHaveLength(1);
    });

    it("retains truncated status when a closure context is reused", async () => {
        const result = await scan(
            `function deeper() { return "echo safe"; }
            function helper(input: string) { const callback = () => deeper(); return "echo safe"; }
            helper("echo safe"); exec(helper(uri.query));`,
            1,
        );
        expect(result.findings).toHaveLength(1);
    });

    it.each(["", "f('echo safe');"])("evaluates omitted defaults after %s", async (before) => {
        const result = await scan(`const f = (x = uri.query) => exec(x); ${before} f();`);
        expect(result.findings).toHaveLength(1);
    });

    it.each(["undefined", "void 0"])("evaluates explicit %s defaults", async (arg) => {
        expect((await scan(`const f = (x = uri.query) => exec(x); f(${arg});`)).findings).toHaveLength(1);
    });

    it.each(["", "undefined", "void 0"])(
        "evaluates defaults in function declarations and constructors: %s",
        async (argument) => {
            expect(
                (
                    await scan(`function consume(command = uri.query) { exec(command); }
            consume(${argument});`)
                ).findings,
            ).toHaveLength(1);
            expect(
                (
                    await scan(`class CommandRunner { constructor(public command = uri.query) {} }
            exec(new CommandRunner(${argument}).command);`)
                ).findings,
            ).toHaveLength(1);
        },
    );

    it("retains both defined arguments and possibly undefined defaults", async () => {
        expect(
            (
                await scan(`const f = (x = uri.query) => exec(x);
            f(flag ? 'echo safe' : undefined);`)
            ).findings,
        ).toHaveLength(1);
    });

    it("keeps dirty defined arguments when a possible default is clean", async () => {
        expect(
            (
                await scan(`const f = (x = "echo safe") => exec(x);
            f(flag ? uri.query : undefined);`)
            ).findings,
        ).toHaveLength(1);
    });

    it("evaluates defaults on registered command bridges", async () => {
        expect(
            (
                await scan(`vscode.commands.registerCommand("demo", (x = uri.query) => exec(x));
            vscode.commands.executeCommand("demo", "echo safe");
            vscode.commands.executeCommand("demo", undefined);`)
            ).findings,
        ).toHaveLength(1);
    });

    it.each([
        `flag ? 0 : (command = "echo safe");`,
        `flag && (command = "echo safe");`,
        `flag || (command = "echo safe");`,
        `flag ?? (command = "echo safe");`,
        `switch (flag) { case true: command = "echo safe"; break; }`,
    ])("joins conditional overwrites: %s", async (statement) => {
        expect((await scan(`let command = uri.query; ${statement} exec(command);`)).findings).toHaveLength(1);
    });

    it("joins switch breaks while excluding returned paths", async () => {
        const result = await scan(`let command = uri.query;
            switch (flag) {
                case true: command = "echo safe"; break;
                default: return;
            }
            exec(command);`);
        expect(result.findings).toHaveLength(0);
    });

    it("retains switch fallthrough and distinguishes nested loop breaks", async () => {
        const result = await scan(`let command = "echo safe";
            switch (flag) {
                case true: command = uri.query;
                default: while (flag) { break; } exec(command); break;
            }`);
        expect(result.findings).toHaveLength(1);
    });

    it.each([false, true])("retains case-selection effects when default is first: %s", async (defaultFirst) => {
        const clauses = [`case (command = uri.query, true): break;`, `default: exec(command); break;`];
        if (defaultFirst) clauses.reverse();
        expect(
            (await scan(`let command = "echo safe"; switch (flag) { ${clauses.join("\n")} }`)).findings,
        ).toHaveLength(1);
    });

    it("preserves instance aliases across conditional branches", async () => {
        const result = await scan(`const runner = new Runner(uri.query); const alias = runner;
            flag ? 0 : (alias.command = "echo safe"); exec(runner.command);`);
        expect(result.findings).toHaveLength(1);
    });

    it.each(["flag ? runner : runner", "runner || runner", "runner ?? runner"])(
        "preserves returned instance aliases through %s",
        async (expression) => {
            const result = await scan(`const runner = new Runner(uri.query);
                const selected = ${expression}; selected.command = "echo safe";
                exec(runner.command);`);
            expect(result.findings).toHaveLength(0);
        },
    );

    it("does not execute object writes from an uncalled closure", async () => {
        expect(
            (
                await scan(`const runner = new Runner("echo safe");
            const never = () => { runner.command = uri.query; }; exec(runner.command);`)
            ).findings,
        ).toHaveLength(0);
        expect(
            (
                await scan(`const runner = new Runner(uri.query);
            const never = () => { runner.command = "echo safe"; }; exec(runner.command);`)
            ).findings,
        ).toHaveLength(1);
    });

    it("applies instance effects when a captured alias is called", async () => {
        const result = await scan(`const runner = new Runner(uri.query); const alias = runner;
            const clear = () => { alias.command = "echo safe"; }; clear(); exec(runner.command);`);
        expect(result.findings).toHaveLength(0);
    });

    it.each([false, true])("joins registered command effects regardless of registration order: %s", async (reverse) => {
        const callbacks = [
            `vscode.commands.registerCommand("demo.load", () => { runner.command = uri.query; });`,
            `vscode.commands.registerCommand("demo.run", () => exec(runner.command));`,
        ];
        if (reverse) callbacks.reverse();
        expect((await scan(`const runner = new Runner("echo safe"); ${callbacks.join("\n")}`)).findings).toHaveLength(
            1,
        );
    });

    it.each([false, true])("retains dirty command state when a registered cleanup may run: %s", async (reverse) => {
        const callbacks = [
            `vscode.commands.registerCommand("demo.clear", () => { runner.command = "echo safe"; });`,
            `vscode.commands.registerCommand("demo.run", () => exec(runner.command));`,
        ];
        if (reverse) callbacks.reverse();
        expect((await scan(`const runner = new Runner(uri.query); ${callbacks.join("\n")}`)).findings).toHaveLength(1);
    });

    it.each([false, true])("preserves captured instance aliases across registered handlers: %s", async (reverse) => {
        const callbacks = [
            `vscode.commands.registerCommand("demo.load", () => { alias.command = uri.query; });`,
            `vscode.commands.registerCommand("demo.run", () => exec(runner.command));`,
        ];
        if (reverse) callbacks.reverse();
        expect(
            (
                await scan(`const runner = new Runner("echo safe"); const alias = runner;
            ${callbacks.join("\n")}`)
            ).findings,
        ).toHaveLength(1);
    });

    it("distinguishes rebinding a captured alias from mutating its original instance", async () => {
        expect(
            (
                await scan(`const runner = new Runner("echo safe"); let alias = runner;
            vscode.commands.registerCommand("demo.replace", () => { alias = new Runner(uri.query); });
            vscode.commands.registerCommand("demo.run", () => exec(runner.command));`)
            ).findings,
        ).toHaveLength(0);
    });

    it.each([false, true])("retains initially clean scalar writers from direct sources: %s", async (reverse) => {
        const callbacks = [
            `vscode.commands.registerCommand("demo.load", () => { command = process.env.SCRIPT!; });`,
            `vscode.commands.registerCommand("demo.run", () => exec(command));`,
        ];
        if (reverse) callbacks.reverse();
        expect(
            (await scan(`let command = "echo safe"; ${callbacks.join("\n")}`, 5, vscodeSpecWithEnvSource)).findings,
        ).toHaveLength(1);
    });

    it("keeps independent command sources attributed to their command entry point", async () => {
        const result = await scan(`vscode.commands.registerCommand("demo.input", async () => {
                exec((await vscode.window.showInputBox())!);
            });
            vscode.commands.registerCommand("demo.noop", () => {});`);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].handle).toContain("Callback handler for registerCommand");
    });

    it("does not apply possible command effects to subsequent caller statements", async () => {
        expect(
            (
                await scan(`const runner = new Runner("echo safe");
            vscode.commands.registerCommand("demo.load", () => { runner.command = uri.query; });
            vscode.commands.registerCommand("demo.noop", () => {}); exec(runner.command);`)
            ).findings,
        ).toHaveLength(0);
    });

    it.each(["&&", "||", "??"])(
        "joins long short-circuit chains without recursive stack growth: %s",
        async (operator) => {
            const chain = [...Array.from({ length: 600 }, () => "flag"), '(command = "echo safe")'].join(
                ` ${operator} `,
            );
            const result = await scan(`let command = uri.query; ${chain}; exec(command);`);
            expect(result.findings).toHaveLength(1);
            expect(result.skippedEntryPoints).toHaveLength(0);
        },
    );

    it("includes instance state in closure memoization", async () => {
        expect(
            (
                await scan(`function visit(runner: Runner) { opaque(() => exec(runner.command)); }
            visit(new Runner("echo safe")); visit(new Runner(uri.query));`)
            ).findings,
        ).toHaveLength(1);
    });

    it("includes lexical this state in closure memoization", async () => {
        expect(
            (
                await scan(`class CallbackRunner extends Runner {
                run() { opaque(() => exec(this.command)); }
            }
            const runner = new CallbackRunner("echo safe"); runner.run();
            runner.command = uri.query; runner.run();`)
            ).findings,
        ).toHaveLength(1);
    });

    it.each([63, 64, 65])("preserves later captured taint across %i uncaptured parameter values", async (count) => {
        const irrelevant = Array.from(
            { length: count },
            (_, i) => `visit("echo safe", fs.readFileSync("/tmp/${i}"));`,
        ).join("\n");
        const result = await scan(`function visit(command: string, unused: unknown) {
                opaque(() => exec(command));
            }
            ${irrelevant} visit(uri.query, "safe");`);
        expect(result.findings).toHaveLength(1);
        expect(result.skippedEntryPoints).toHaveLength(0);
    });

    it("retains findings across matching event and definition analyses", async () => {
        const calls = Array.from({ length: 64 }, (_, i) => `visit(fs.readFileSync("/tmp/${i}"));`).join("\n");
        const result = await scan(`function visit(command: string) {
                vscode.commands.registerCommand("demo.run", () => exec(command));
            } ${calls}`);
        expect(result.skippedEntryPoints).toHaveLength(0);
        expect(result.findings.length).toBeGreaterThan(0);
    });

    it("continues to later sources after more than 64 captured contexts", async () => {
        const calls = Array.from({ length: 65 }, (_, i) => `visit(fs.readFileSync("/tmp/${i}"));`).join("\n");
        const result = await scan(`
            function visit(command: string) { opaque(() => exec(command)); }
            ${calls} visit(uri.query);`);
        expect(result.skippedEntryPoints).toHaveLength(0);
        expect(result.findings.some((finding) => finding.source.pattern === "handleUri.uri")).toBe(true);
        expect(result.findings.some((finding) => finding.source.pattern === "fs.readFileSync")).toBe(true);
    });

    it("continues past distinct captured heaps that the callback does not read", async () => {
        const calls = Array.from(
            { length: 65 },
            (_, i) => `new CallbackRunner(fs.readFileSync("/tmp/${i}")).run();`,
        ).join("\n");
        const result = await scan(`class CallbackRunner {
                constructor(private unused: unknown) {}
                run() { opaque(() => { void this; exec("echo safe"); }); }
            }
            ${calls} exec(uri.query);`);
        expect(result.skippedEntryPoints).toHaveLength(0);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("handleUri.uri");
    });
});
