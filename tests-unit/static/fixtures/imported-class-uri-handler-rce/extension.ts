/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: imported URI handler class instantiated inline at the
// registration site (D95145147).
//
// Taint flow:
//   uriHandler.ts: handleUri(uri) → uri.query → init_commands → debug.startDebugging
//   extension.ts:  registerUriHandler(new DebugSessionUriHandler())
//
// The handler class lives in a separate module, so the `new` expression's
// callee resolves to an import alias. Entry point discovery has to follow the
// alias to reach the class declaration, otherwise the deeplink source is never
// introduced and the whole flow disappears.
import * as vscode from "vscode";
import { DebugSessionUriHandler } from "./uriHandler";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler(new DebugSessionUriHandler())
    );
}
