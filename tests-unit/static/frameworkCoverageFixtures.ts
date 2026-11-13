/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// Minimal declaration stubs, not framework implementations. The callback and
// request/response contracts come from the public API references below:
// https://www.electronjs.org/docs/latest/api/ipc-main
// https://www.electronjs.org/docs/latest/api/app#event-open-url-macos
// https://www.electronjs.org/docs/latest/api/shell#shellopenexternalurl-options
const declarations = `
declare module "child_process" {
    export function exec(command: string): void;
}
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

export function frameworkCoverageFixture(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-frameworkCoverage-"));
    fs.writeFileSync(
        path.join(dir, "tsconfig.json"),
        JSON.stringify({
            compilerOptions: {
                target: "es2020",
                module: "commonjs",
                moduleResolution: "node",
                esModuleInterop: true,
                skipLibCheck: true,
                strict: false,
                types: [],
                noEmit: true,
            },
            include: ["*.ts"],
        }),
    );
    fs.writeFileSync(path.join(dir, "api.d.ts"), declarations);
    for (const [name, content] of Object.entries(files)) {
        fs.writeFileSync(path.join(dir, name), content);
    }
    return dir;
}

export const frameworkCoverageCleanCases = {
    electron: `
        import {ipcMain, app} from "electron";
        import {exec} from "child_process";
        ipcMain.handle("metadata", (event, command) => {
            exec(String(event.sender.id));
            exec("tool " + Number(command));
        });
        app.on("activate", (event, hasVisibleWindows) => exec(String(hasVisibleWindows)));
        const local = {on(channel: string, handler: (event: any, payload: string) => void) {}};
        local.on("run", (event, payload) => exec(payload));
    `,
};

export const frameworkCoverageCases = {
    electron: `
        import {ipcMain, app} from "electron";
        import {exec} from "child_process";
        ipcMain.handle("run", (_event, command) => exec(command));
        ipcMain.on("run", (_event, prefix, command) => exec(command));
        app.on("open-url", (_event, url) => exec(url));
    `,
};
