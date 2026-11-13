/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: workspace setting that names a binary → execFile
//
// Models a malicious project whose .vscode/settings.json overrides an
// extension's binary-path setting, here "demo.toolPath", to point to a malicious
// binary. On activation, the fixture reads the configured path and executes it.
// The static test does not exercise VS Code's workspace-trust behavior.
//
// Taint flow:
//   activate() → config.get("toolPath") → execFile(toolPath)
import * as vscode from "vscode";
import { execFile } from "child_process";

export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration("demo");
    const toolPath = config.get("toolPath", "demo-tool");
    execFile(toolPath, ["check"]);
}
