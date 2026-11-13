/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { ExecSink } from "../../src/static/spec/sinks";
import { SourceSpec, TaintSpec } from "../../src/static/spec/types";

const ipc: SourceSpec = {
    kind: "parameter",
    pattern: "ipc.payload",
    description: "IPC payload",
    callbackRegistration: "electron.ipcMain.on",
    callbackMatch: "api",
    callbackArgIndex: 1,
    taintParamsFromIndex: 1,
    taintAllProperties: true,
};
async function check(body: string, source: SourceSpec = ipc) {
    const spec: TaintSpec = { sources: [source], sinks: [ExecSink], sanitizers: [] };
    const result = await analyze({
        source: `import { exec } from "child_process"; ${body}`,
        fileName: "/src/discovery.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("Electron identity-qualified callback discovery", () => {
    it("taints aliased Electron payloads from parameter one but keeps the event clean", async () => {
        const findings = await check(`
            import { ipcMain as main } from "electron";
            main.on("run", (event, command, second) => {
                exec(event.sender);
                exec(command);
                exec(second);
            });`);
        expect(findings.map((f) => f.sinkLocation.text)).toEqual(["exec(command)", "exec(second)"]);
    });
    it("discovers a rest-only IPC callback without tainting event slot or array metadata", async () => {
        const findings = await check(`
            import {ipcMain} from "electron";
            ipcMain.on("run", (...args) => {
                exec(args[0]);
                exec(args[1]);
                exec(args[2]);
                exec(args.length);
            });`);
        expect(findings.map((f) => f.sinkLocation.text)).toEqual(["exec(args[1])", "exec(args[2])"]);
    });
    it("taints payload rest slots after a separately named event parameter", async () => {
        const findings = await check(`
            import {ipcMain} from "electron";
            ipcMain.on("run", (event, ...args) => {
                exec(event);
                exec(args[0]);
                exec(args.length);
            });`);
        expect(findings.map((f) => f.sinkLocation.text)).toEqual(["exec(args[0])"]);
    });
    it("retains rest source indices through array destructuring", async () => {
        const findings = await check(`
            import {ipcMain} from "electron";
            ipcMain.on("run", (...args) => {
                const [event, payload] = args;
                exec(event);
                exec(payload);
            });`);
        expect(findings.map((f) => f.sinkLocation.text)).toEqual(["exec(payload)"]);
    });
    it("does not infer Electron identity from local variable or method names", async () => {
        expect(
            await check(`
            const electron = {ipcMain: {on(channel, handler) {}}};
            electron.ipcMain.on("run", (event, command) => exec(command));
        `),
        ).toHaveLength(0);
    });
    it("filters event-name conditions through static imported-style aliases", async () => {
        const source = {
            ...ipc,
            pattern: "openUrl.url",
            callbackRegistration: "electron.app.on",
            callbackArgumentValues: { 0: ["open-url"] },
        };
        const findings = await check(
            `
            import { app } from "electron";
            const eventName = "open-url";
            app.on(eventName, (event, url) => exec(url));
            app.on("ready", (event, value) => exec(value));
        `,
            source,
        );
        expect(findings).toHaveLength(1);
        expect(findings[0].sinkLocation.text).toBe("exec(url)");
    });
});
