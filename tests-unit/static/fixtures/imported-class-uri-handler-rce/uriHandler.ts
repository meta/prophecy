/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// URI handler class declared in its own module, exported for registration
// elsewhere. Discovery must handle this shape: the `new` expression at the
// registration site resolves to an import alias, not to this class.
import * as vscode from "vscode";

export class DebugSessionUriHandler implements vscode.UriHandler {
    async handleUri(uri: vscode.Uri): Promise<void> {
        const params = new URLSearchParams(uri.query);
        const initCommands = JSON.parse(params.get("init_commands") ?? "[]");

        const config: vscode.DebugConfiguration = {
            type: "lldb",
            request: "attach",
            name: "Debug session",
            initCommands: initCommands,
        };

        // VULN: attacker-controlled debugger commands reach startDebugging.
        await vscode.debug.startDebugging(undefined, config);
    }
}
