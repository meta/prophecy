/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: workspace config → exec from a code lens provider (T293409641)
//
// A malicious workspace overrides "demo.toolPath" with shell metacharacters.
// Activation only registers a code lens provider per scanner. VS Code calls
// `provideCodeLenses()` when a matching document opens, and the scan it runs
// builds a shell command from the setting five calls later.
//
// Taint flow:
//   provideCodeLenses() → LensProvider.scanFile() → DocumentScanner.scanCached()
//     → this.scan() → ScriptScanner.scan() → runTool() → config.get("demo.toolPath")
//     → runCommand(command) → exec(command)
import * as vscode from "vscode";
import { DocumentScanner, MarkupScanner, ScriptScanner } from "./scanner";

class LensProvider implements vscode.CodeLensProvider {
    constructor(private scanner: DocumentScanner) {}

    provideCodeLenses(document: vscode.TextDocument): Promise<vscode.CodeLens[]> {
        return this.scanFile(document);
    }

    private async scanFile(document: vscode.TextDocument): Promise<vscode.CodeLens[]> {
        const labels = await this.scanner.scanCached(document);
        return labels.map((label) => new vscode.CodeLens(new vscode.Range(0, 0, 0, 0), { title: label, command: "" }));
    }
}

export function activate(context: vscode.ExtensionContext) {
    for (const scanner of [new MarkupScanner(), new ScriptScanner()]) {
        context.subscriptions.push(
            vscode.languages.registerCodeLensProvider(scanner.selector(), new LensProvider(scanner)),
        );
    }
}
