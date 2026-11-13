/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: AI assistant deeplink → command bridge → terminal (D86095152)
//
// Models an assistant deeplink dispatching a task to a registered command
// handler, which interpolates it into a terminal command. The reduced fixture
// forwards the whole URI query rather than parsing individual parameters; it
// does not exercise an AI model or a user-confirmation flow.
//
// Taint flow:
//   uriHandler.ts: handleUri(uri) → executeCommand('assistant.runTask', uri.query)
//   extension.ts:  registerCommand('assistant.runTask', handler) → terminal.sendText(task)
import * as vscode from "vscode";
import { AIAssistantHandler } from "./uriHandler";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler(new AIAssistantHandler())
    );

    // Command handler that receives tainted task param via executeCommand bridge
    context.subscriptions.push(
        vscode.commands.registerCommand("assistant.runTask", (task: string) => {
            const terminal = vscode.window.createTerminal("Assistant");
            terminal.sendText(`demo-cli test ${task}`, true);
        })
    );
}
