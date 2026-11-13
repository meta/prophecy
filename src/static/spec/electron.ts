/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SourceSpec, TaintSpec } from "./types";
import { NodeSinks } from "./nodeApis";
import { NumberSanitizer, ParseIntSanitizer } from "./sanitizers";

const ipcSources: SourceSpec[] = ["handle", "handleOnce", "on", "once", "addListener"].map((method) => ({
    kind: "parameter",
    pattern: `electron.ipcMain.${method}.payload`,
    description: "Electron renderer IPC payload (attacker-controlled)",
    callbackRegistration: `electron.ipcMain.${method}`,
    callbackMatch: "api",
    callbackArgIndex: 1,
    taintParamsFromIndex: 1,
    taintAllProperties: true,
}));

const deepLinkSources: SourceSpec[] = ["on", "once", "addListener"].map((method) => ({
    kind: "parameter",
    pattern: `electron.app.${method}.openUrl`,
    description: "Electron application deep-link URL (attacker-controlled)",
    callbackRegistration: `electron.app.${method}`,
    callbackMatch: "api",
    callbackArgumentValues: { 0: ["open-url"] },
    callbackArgIndex: 1,
    paramIndex: 1,
    taintAllProperties: true,
}));

/** Main-process boundaries; host event objects are not renderer payloads. */
export const electronSpec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [...ipcSources, ...deepLinkSources],
    sinks: [
        ...NodeSinks,
        {
            kind: "callArgument",
            name: "electron_openExternal",
            pattern: "electron.shell.openExternal",
            argPositions: [0],
            requireAPIIdentity: true,
            description: "External protocol URL opened by the desktop with attacker-controlled input",
            severity: "high",
            categories: ["open_redirect"],
        },
    ],
    sanitizers: [ParseIntSanitizer, NumberSanitizer],
};
