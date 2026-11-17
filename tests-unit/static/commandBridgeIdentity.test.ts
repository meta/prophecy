/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "External input" }],
    sinks: [
        {
            kind: "callArgument",
            name: "observe",
            pattern: "observe",
            description: "Observed input",
            categories: ["code_injection"],
        },
    ],
    sanitizers: [],
};

async function check(source: string) {
    const result = await analyze({
        source: `import * as vscode from "vscode";
            declare function input(): string; declare function observe(value: unknown): void;
            ${source}`,
        fileName: path.join(__dirname, "command-identity-input.ts"),
        spec,
        maxDepth: 8,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("VS Code invocation bridge identity", () => {
    it.each(["executeCommand", "otherexecuteCommand", "run"])(
        "analyzes the real local %s body despite a colliding command ID",
        async (method) => {
            expect(
                await check(`
            const local = { ${method}(id: string, value: string) { observe(value); } };
            export function main() {
                vscode.commands.registerCommand("demo.command", (value: string) => "fixed");
                local.${method}("demo.command", input());
            }
        `),
            ).toHaveLength(1);
        },
    );

    it("does not invent a command-handler call from an unrelated local method", async () => {
        expect(
            await check(`
            const local = { executeCommand(id: string, value: string) {} };
            export function main() {
                vscode.commands.registerCommand("demo.command", (value: string) => observe(value));
                local.executeCommand("demo.command", input());
            }
        `),
        ).toHaveLength(0);
    });

    it("preserves a local method when no command ID collides", async () => {
        expect(
            await check(`
            const local = { executeCommand(id: string, value: string) { observe(value); } };
            export function main() {
                vscode.commands.registerCommand("other.command", (value: string) => "fixed");
                local.executeCommand("demo.command", input());
            }
        `),
        ).toHaveLength(1);
    });

    it.each([
        ["", "vscode.commands.executeCommand"],
        ["", 'vscode.commands["executeCommand"]'],
        ['import * as api from "vscode";', "api.commands.executeCommand"],
        ['import { commands as registry } from "vscode";', "registry.executeCommand"],
        ["const invoke = vscode.commands.executeCommand;", "invoke"],
        ["const { executeCommand: invoke } = vscode.commands;", "invoke"],
        ['import { invoke } from "./fixtures/command-bridge-identity/commands";', "invoke"],
    ])("bridges real imports, aliases and wrappers: %s %s", async (declaration, callee) => {
        expect(
            await check(`
            ${declaration}
            export function main() {
                vscode.commands.registerCommand("demo.command", (value: string) => observe(value));
                ${callee}("demo.command", input());
                ${callee}("demo.command", "fixed");
            }
        `),
        ).toHaveLength(1);
    });

    it("preserves an imported wrapper around a genuine command invocation", async () => {
        expect(
            await check(`
            import { throughWrapper } from "./fixtures/command-bridge-identity/commands";
            export function main() {
                vscode.commands.registerCommand("demo.command", (value: string) => observe(value));
                throughWrapper(input());
                throughWrapper("fixed");
            }
        `),
        ).toHaveLength(1);
    });

    it("does not route real calls to a different registered handler", async () => {
        expect(
            await check(`
            export function main() {
                vscode.commands.registerCommand("demo.unsafe", (value: string) => observe(value));
                vscode.commands.registerCommand("demo.safe", (value: string) => "fixed");
                vscode.commands.executeCommand("demo.safe", input());
                vscode.commands.executeCommand("demo.unsafe", "fixed");
            }
        `),
        ).toHaveLength(0);
    });
});
