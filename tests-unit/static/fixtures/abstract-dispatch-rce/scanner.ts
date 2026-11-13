/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";

export abstract class DocumentScanner {
    private cache = new Map<string, string[]>();

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
