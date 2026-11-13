/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: repository-defined names → exec through a CLI's output
//
// The extension runs a fixed CLI in the workspace folder to list the tasks a
// project defines. The CLI discovers task definitions in the checkout and
// prints their names unvalidated, so a malicious repository chooses them. Each
// name is then interpolated into another shell command.
//
// Taint flow:
//   activate() → TaskLoader.preload() → listTasks() → execAsync(..., { cwd: workspace folder })
//     → JSON.parse(stdout) → task.name → taskOptions(name) → execAsync(command)
import * as vscode from "vscode";
import { TaskLoader } from "./loader";

export function activate(context: vscode.ExtensionContext) {
    const loader = new TaskLoader();
    void loader.preload();
}
