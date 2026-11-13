/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: Multi-file deeplink RCE
//
// Taint flows across files:
//   extension.ts → uriHandler.ts (class handleUri) → commandRunner.ts (free function) → terminal.ts (sink)
import * as vscode from "vscode";
import { DeeplinkRouter } from "./uriHandler";

export function activate(context: vscode.ExtensionContext) {
    const router = new DeeplinkRouter();
    context.subscriptions.push(
        vscode.window.registerUriHandler(router)
    );
}
