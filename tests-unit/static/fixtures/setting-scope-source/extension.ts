/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: settings reported with the scope package.json declares for them
//
// Only a setting that workspace settings can supply is attacker-controlled via
// .vscode/settings.json. `machine` and `application` settings are still
// reported, labeled with their scope. A value whose key or scope is unknown
// keeps the workspace label.
import * as vscode from "vscode";
import { execFile } from "child_process";

type Server = { enable: boolean; path: string };

function readSetting(key: string): string {
    return vscode.workspace.getConfiguration("demo").get<string>(key, "");
}

export function activate() {
    const config = vscode.workspace.getConfiguration("demo");
    execFile(config.get<string>("serverPath", "demo"), ["machine"]);
    execFile(config.get<string>("toolPath", "tool"), ["application"]);
    execFile(config.get<string>("command", "demo"), ["window"]);
    const all = vscode.workspace.getConfiguration();
    execFile(all.get<string>("demo.serverPath", "demo"), ["full-key"]);

    // An object setting: `enable` can come from the workspace, `path` cannot.
    const server = config.get<Server>("server", { enable: true, path: "demo" });
    execFile(server.path, ["object-property"]);
    const { path: serverPath } = server;
    execFile(serverPath, ["destructured"]);
    execFile(JSON.stringify(server), ["whole-object"]);

    execFile(readSetting("serverPath"), ["dynamic-key"]);
}
