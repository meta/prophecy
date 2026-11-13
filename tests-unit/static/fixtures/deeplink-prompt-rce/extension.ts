/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: AI assistant deeplink prompt injection → RCE (D75979307)
//
// Models a deeplink whose prompt reaches an AI agent that can run commands.
// This fixture substitutes a direct exec call; it does not test prompt
// interpretation, model behavior, or user-confirmation checks.
//
// The assertion covers only the explicit TypeScript source-to-sink flow below.
// It is not an end-to-end reproduction of an agent vulnerability.
//
// Taint flow:
//   handleUri(uri) → uri.query (prompt) → startConversation(prompt) → exec(prompt)
import * as vscode from "vscode";
import { exec } from "child_process";

export function activate(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            handleUri(uri: vscode.Uri) {
                const prompt = uri.query;
                startConversation(prompt);
            },
        })
    );
}

function startConversation(prompt: string) {
    // Direct exec stands in for the agent running a command.
    // No model call or generated-code execution is part of this fixture.
    exec(prompt);
}
