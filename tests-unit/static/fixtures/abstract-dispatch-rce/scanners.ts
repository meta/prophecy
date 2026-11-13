/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import { DocumentScanner } from "./scanner";
import { runTool } from "./tool";

export class MarkupScanner extends DocumentScanner {
    async scan(document: vscode.TextDocument): Promise<string[]> {
        return document.getText().includes("<!--") ? ["comment"] : [];
    }
}

export class ScriptScanner extends DocumentScanner {
    async scan(document: vscode.TextDocument): Promise<string[]> {
        if (!document.getText().includes("label")) return [];
        const output = await runTool("--scan --json");
        return JSON.parse(output) as string[];
    }
}
