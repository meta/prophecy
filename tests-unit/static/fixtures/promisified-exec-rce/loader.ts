/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import { execAsync } from "./shell";

export class Loader {
    private command(): string {
        const config = vscode.workspace.getConfiguration("demo");
        const toolPath = config.get<string>("toolPath", "tool");
        return `${toolPath} run --quiet`;
    }

    async load(): Promise<string> {
        const { stdout } = await execAsync(`${this.command()} --list-json`, { cwd: "/tmp" });
        return stdout;
    }
}
