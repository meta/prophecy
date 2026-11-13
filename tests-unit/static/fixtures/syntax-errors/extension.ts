/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: TypeScript file with syntax errors
// The analyzer should not crash on unparseable source.
import * as vscode from "vscode";

export function activate(context: vscode.ExtensionContext) {
    const x = ;
    if ( {
        vscode.window.showInformationMessage("broken"
    }
}

function unclosed(a: string {
    return a
