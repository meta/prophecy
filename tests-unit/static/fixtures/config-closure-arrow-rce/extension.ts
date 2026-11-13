/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: workspace config → exec through arrow consts, default
// parameters, renamed object properties, and stored closures
//
// A malicious .vscode/settings.json sets "demo.ctlPath" or "demo.agentPath" to
// an attacker binary that the extension later executes.
//
// Taint flows (source: settings() → getConfiguration("demo").get(...)):
//   control: runCtl(ctlPath) → execFile
//   A:  spawnCtl(ctlPath) → arrow const body → spawn
//   B:  checkRequirements(ctlPath) → probe = defaultProbe → execFile
//   C:  new Pane({agentPath}) → this.host.agentPath → new Client({executable}) → spawn
//   D1: new Changes(() => ({ctlPath})) → const {ctlPath} = this.ctl() → execFile
//   D2: parseMachine(key, ctlPath) → m.ctlPath → execFile
import * as vscode from "vscode";
import { runCtl, spawnCtl, checkRequirements, Pane, Changes } from "./ctl";

function settings() {
    const cfg = vscode.workspace.getConfiguration("demo");
    return {
        ctlPath: cfg.get<string>("ctlPath", "democtl"),
        agentPath: cfg.get<string>("agentPath", "agent"),
    };
}

export function activate(context: vscode.ExtensionContext) {
    const s = settings();
    runCtl(settings().ctlPath, ["list"]);                                   // control
    spawnCtl(settings().ctlPath, ["tail"]);                                 // A
    checkRequirements(s.ctlPath);                                           // B
    new Pane({ agentPath: s.agentPath }).open();                            // C
    new Changes(() => ({ ctlPath: settings().ctlPath })).refresh("node:od-1"); // D1, D2
}
