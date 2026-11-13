/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: handlers declared as function-valued properties
//
// VS Code calls a handler by name on the object it was registered with, so a
// property holding an arrow or function expression is a handler just like a
// method. Each registration below reaches a sink only through such a property.
//
// Taint flows:
//   registerUriHandler(handler) → DeeplinkHandler.handleUri = (uri) => ... → exec(uri.query)
//   registerCodeLensProvider(..., lensProvider) → { provideCodeLenses: () => ... }
//     → config.get("demo.toolPath") → spawn(tool)
//   registerDebugAdapterDescriptorFactory(..., new AdapterFactory())
//     → createDebugAdapterDescriptor = function (session) { ... } → spawn(session.configuration.program)
import { exec, spawn } from "child_process";
import * as vscode from "vscode";

class DeeplinkHandler implements vscode.UriHandler {
    handleUri = (uri: vscode.Uri): void => {
        exec(`demo open ${uri.query}`);
    };
}

const lensProvider: vscode.CodeLensProvider = {
    provideCodeLenses: (): vscode.CodeLens[] => {
        const tool = vscode.workspace.getConfiguration().get<string>("demo.toolPath") ?? "demo";
        spawn(tool, ["--lenses"]);
        return [];
    },
};

class AdapterFactory implements vscode.DebugAdapterDescriptorFactory {
    createDebugAdapterDescriptor = function (session: vscode.DebugSession): vscode.DebugAdapterDescriptor {
        spawn(session.configuration.program, []);
        return new vscode.DebugAdapterServer(4711);
    };
}

export function activate(context: vscode.ExtensionContext) {
    const handler = new DeeplinkHandler();
    context.subscriptions.push(
        vscode.window.registerUriHandler(handler),
        vscode.languages.registerCodeLensProvider({ language: "demo" }, lensProvider),
        vscode.debug.registerDebugAdapterDescriptorFactory("demo", new AdapterFactory()),
    );
}
