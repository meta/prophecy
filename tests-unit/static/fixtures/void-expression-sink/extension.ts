/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: `void expr` discards a result, often a fire-and-forget promise.
// TypeScript represents it as a VoidExpression, not a PrefixUnaryExpression.
// The analyzer must traverse its operand to find calls and sinks, just as it
// does for the awaited control below.
//
// Each handler routes through its own helper so the two findings have distinct
// sink locations and do not collapse into one handle.
import * as vscode from "vscode";
import {exec} from "child_process";

export function activate(context: vscode.ExtensionContext) {
    // Reported only once `void` operands are traversed.
    vscode.commands.registerCommand("ext.voidCall", (cmd: string) => {
        void runViaVoid(cmd);
    });

    // Positive control: await traverses the helper call's operand.
    vscode.commands.registerCommand("ext.awaited", async (cmd: string) => {
        await runViaAwait(cmd);
    });

    vscode.window.registerUriHandler({
        handleUri(uri: vscode.Uri) {
            void vscode.commands.executeCommand("ext.voidCall", uri.query);
            void vscode.commands.executeCommand("ext.awaited", uri.query);
        },
    });
}

async function runViaVoid(cmd: string): Promise<void> {
    exec(cmd);
}

async function runViaAwait(cmd: string): Promise<void> {
    exec(cmd);
}
