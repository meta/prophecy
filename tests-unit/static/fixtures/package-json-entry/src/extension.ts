/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: package.json main alongside framework entry points (T255561860)
//
// package.json points to ./src/extension. Framework entry-point discovery still
// scans all parsed source files; main restricts fallback discovery only when
// no framework entry point is found. This fixture has a registered URI handler.
import * as vscode from "vscode";
import { exec } from "child_process";

export function activate(context: vscode.ExtensionContext) {
    vscode.window.registerUriHandler({
        handleUri(uri: vscode.Uri) {
            exec(uri.query);
        },
    });
}
