/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// tsconfig.json names only a type library that does not exist, so @types/node
// is not in the program, as in a checkout where node_modules was never
// installed. `child_process` then has no declarations, and only the import
// names the module behind `cp.exec`. `runner.exec` is a local function with the
// same name and must not match.

import * as cp from "child_process";
import * as vscode from "vscode";
import * as runner from "./runner";

interface LaunchConfig {
    enabled: boolean;
    command: string;
}

function execShell(command: string): Promise<void> {
    return new Promise((resolve, reject) => {
        cp.exec(command, (error: Error | null) => {
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        });
    });
}

export async function activate() {
    const configuration = vscode.workspace.getConfiguration();
    const launchConfig = configuration.get<LaunchConfig>("extension.startOnStartup");
    if (launchConfig?.enabled) {
        runner.exec(launchConfig.command);
        await execShell(launchConfig.command);
    }
}
