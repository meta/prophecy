/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { electronSpec } from "../../src/static/spec/electron";
import { TaintSpec } from "../../src/static/spec/types";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

// Minimal public Electron callback contracts, not a framework implementation.
// https://www.electronjs.org/docs/latest/api/ipc-main
const declarations = `
declare module "child_process" { export function exec(command: string): void; }
declare module "electron" {
    export interface Event { preventDefault(): void; defaultPrevented: boolean; }
    export interface IpcMainEvent extends Event { sender: { id: number }; }
    export interface IpcMainInvokeEvent extends Event { sender: { id: number }; }
    export interface IpcMain {
        handle(channel: string, listener: (event: IpcMainInvokeEvent, ...args: any[]) => any): void;
        handleOnce(channel: string, listener: (event: IpcMainInvokeEvent, ...args: any[]) => any): void;
        on(channel: string, listener: (event: IpcMainEvent, ...args: any[]) => void): this;
        once(channel: string, listener: (event: IpcMainEvent, ...args: any[]) => void): this;
        addListener(channel: string, listener: (event: IpcMainEvent, ...args: any[]) => void): this;
    }
    export interface App {
        on(event: "open-url", listener: (event: Event, url: string) => void): this;
        on(event: "activate", listener: (event: Event, hasVisibleWindows: boolean) => void): this;
        once(event: "open-url", listener: (event: Event, url: string) => void): this;
        addListener(event: "open-url", listener: (event: Event, url: string) => void): this;
    }
    export interface Shell {
        openExternal(url: string, options?: {activate?: boolean; workingDirectory?: string; logUsage?: boolean}): Promise<void>;
    }
    export const shell: Shell;
    export const ipcMain: IpcMain;
    export const app: App;
}
`;

describe("Electron API identities through local modules", () => {
    it.each<{ name: string; spec: TaintSpec; files: Record<string, string> }>([
        {
            name: "reexported Electron IPC",
            spec: electronSpec,
            files: {
                "server.ts": `export {ipcMain} from "electron";`,
                "main.ts": `import {ipcMain} from "./server"; import {exec} from "child_process";
                    ipcMain.handle("run", (_event, value) => exec(value));`,
            },
        },
    ])("retains $name", async ({ spec, files }) => {
        const projectDir = apiBoundaryFixture(files, declarations);
        try {
            const { program } = parseProject(projectDir);
            expect(program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({ projectDir, spec, outputFormat: "json", maxDepth: 8, requireTypes: true });
            expect(result.syntaxErrors).toEqual([]);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.entryPointCount).toBe(1);
            expect(result.findings).toHaveLength(1);
        } finally {
            fs.rmSync(projectDir, { recursive: true, force: true });
        }
    });
});
