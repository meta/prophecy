/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import { runTool } from "./tool";

export abstract class DocumentScanner {
    private cache = new Map<string, string[]>();

    abstract selector(): vscode.DocumentSelector;
    abstract scan(document: vscode.TextDocument): Promise<string[]>;

    async scanCached(document: vscode.TextDocument): Promise<string[]> {
        const key = document.uri.toString();
        const cached = this.cache.get(key);
        if (cached) return cached;
        const result = await this.scan(document);
        this.cache.set(key, result);
        return result;
    }
}

export class MarkupScanner extends DocumentScanner {
    selector(): vscode.DocumentSelector {
        return { language: "html" };
    }

    async scan(document: vscode.TextDocument): Promise<string[]> {
        return document.getText().includes("<!--") ? ["comment"] : [];
    }
}

export class ScriptScanner extends DocumentScanner {
    selector(): vscode.DocumentSelector {
        return { language: "javascript" };
    }

    async scan(document: vscode.TextDocument): Promise<string[]> {
        if (!document.getText().includes("label")) return [];
        const output = await runTool("--scan --json");
        return JSON.parse(output) as string[];
    }
}
