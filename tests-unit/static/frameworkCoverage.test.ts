/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { electronSpec } from "../../src/static/spec/electron";
import { TaintSpec } from "../../src/static/spec/types";
import {
    frameworkCoverageCases,
    frameworkCoverageCleanCases,
    frameworkCoverageFixture,
} from "./frameworkCoverageFixtures";

async function scan(spec: TaintSpec, source: string, files: Record<string, string> = {}) {
    const projectDir = frameworkCoverageFixture({ "main.ts": source, ...files });
    try {
        const { program } = parseProject(projectDir);
        expect(program.getSemanticDiagnostics().map((diagnostic) => diagnostic.messageText)).toEqual([]);
        const result = await analyze({ projectDir, spec, outputFormat: "json", requireTypes: true });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        return result;
    } finally {
        fs.rmSync(projectDir, { recursive: true, force: true });
    }
}

function sinkLines(result: Awaited<ReturnType<typeof scan>>) {
    return [...new Set(result.findings.map((finding) => finding.sinkLocation.line))];
}

describe("frameworkCoverage Electron main process", () => {
    it("discovers IPC and deep-link input boundaries", async () => {
        const result = await scan(electronSpec, frameworkCoverageCases.electron);
        expect(result.entryPointCount).toBe(3);
        expect(sinkLines(result)).toHaveLength(3);
        expect(result.findings.every((finding) => finding.sink.name === "exec")).toBe(true);
    });

    it("keeps event metadata, numeric conversions and unrelated objects clean", async () => {
        const result = await scan(electronSpec, frameworkCoverageCleanCases.electron);
        expect(result.findings).toEqual([]);
        expect(result.entryPointCount).toBe(1);
    });

    it("follows callbacks and payloads across files", async () => {
        const result = await scan(
            electronSpec,
            `
            import {handler} from "./handler";
            import {ipcMain} from "electron";
            ipcMain.handle("run", handler);
        `,
            {
                "handler.ts": `import {run} from "./command";
                export function handler(event: any, value: string) { run(value); }`,
                "command.ts": 'import {exec} from "child_process"; export function run(value: string) {exec(value)}',
            },
        );
        expect(result.findings).toHaveLength(1);
        const finding = result.findings[0];
        expect(path.basename(finding.sourceLocation.fileName)).toBe("handler.ts");
        expect(path.basename(finding.sinkLocation.fileName)).toBe("command.ts");
        expect(finding.propagationChain.some((step) => step.kind === "argument")).toBe(true);
    });

    it.each([
        'ipcMain.handle("open", (_event, url) => shell.openExternal(url));',
        'app.on("open-url", (_event, url) => shell.openExternal(url));',
    ])("reports attacker-controlled external protocol URLs: %s", async (registration) => {
        const result = await scan(
            electronSpec,
            `
            import {ipcMain, app, shell} from "electron";
            ${registration}
        `,
        );
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.name).toBe("electron_openExternal");
        expect(result.findings[0].sink.categories).toEqual(["open_redirect"]);
    });

    it("keeps fixed external URLs and unrelated local shell implementations clean", async () => {
        const result = await scan(
            electronSpec,
            `
            import {ipcMain, shell as electronShell} from "electron";
            ipcMain.handle("open", (_event, url) => {
                electronShell.openExternal("https://example.com/help");
                electronShell.openExternal("https://example.com/help", {workingDirectory: url});
                const shell = {openExternal(value: string) {}};
                shell.openExternal(url);
                const other = {shell};
                other.shell.openExternal(url);
            });
        `,
        );
        expect(result.entryPointCount).toBe(1);
        expect(result.findings).toEqual([]);
    });

    it.each(["handle", "handleOnce", "on", "once", "addListener"])(
        "taints only renderer payload arguments for ipcMain.%s",
        async (method) => {
            const result = await scan(
                electronSpec,
                `
            import {ipcMain as ipc} from "electron";
            import {exec} from "child_process";
            ipc.${method}("run", (event, first, second, ...rest) => {
                exec(first.command);
                exec(second);
                exec(rest[0]);
                exec(String(event.sender.id));
            });`,
            );
            expect(sinkLines(result)).toEqual([5, 6, 7]);
        },
    );

    it("selects open-url through a constant alias without sourcing unrelated app events", async () => {
        const result = await scan(
            electronSpec,
            `
            import {app} from "electron";
            import {exec} from "child_process";
            import {eventName} from "./eventName";
            app.on(eventName, (event, url) => {exec(url); exec(String(event.defaultPrevented));});
            app.on("activate", (event, hasVisibleWindows) => exec(String(hasVisibleWindows)));
        `,
            { "eventName.ts": 'export const eventName = "open-url";' },
        );
        expect(result.findings).toHaveLength(1);
    });
});
