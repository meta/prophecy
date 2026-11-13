/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: workspace config → exec behind an abstract method (T293409641)
//
// A malicious workspace overrides "demo.toolPath" with shell metacharacters.
// Saved documents are rescanned through scanners typed as an abstract base
// class. Its caching method calls the abstract `scan()`, and one override
// builds a shell command from the setting.
//
// Taint flow:
//   activate() → onDidSaveTextDocument callback → DocumentScanner.scanCached()
//     → this.scan() → ScriptScanner.scan() → runTool() → config.get("demo.toolPath")
//     → runCommand(command) → exec(command)
import * as vscode from "vscode";
import { DocumentScanner } from "./scanner";
import { MarkupScanner, ScriptScanner } from "./scanners";

export function activate(context: vscode.ExtensionContext) {
    const scanners: DocumentScanner[] = [new MarkupScanner(), new ScriptScanner()];
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            for (const scanner of scanners) {
                await scanner.scanCached(document);
            }
        }),
    );
}
