/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import DeepLinkHandler from "./uri/DeepLinkHandler";
import { registerRunTerminalCommand } from "./commands/runTerminalCommand";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(vscode.window.registerUriHandler(new DeepLinkHandler()));
    context.subscriptions.push(registerRunTerminalCommand());
}
