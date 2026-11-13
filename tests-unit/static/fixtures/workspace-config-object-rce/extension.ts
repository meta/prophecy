/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as cp from "child_process";
import * as vscode from "vscode";

interface LaunchConfig {
    enabled: boolean;
    command: string;
}

function execShell(command: string): Promise<void> {
    return new Promise((resolve, reject) => {
        cp.exec(command, (error) => {
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
        await execShell(launchConfig.command);
    }
}
