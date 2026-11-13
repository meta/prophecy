/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { CodeLocation } from "../spec/types";

/**
 * Memoized locations for unchanged AST nodes. Repeated propagation steps
 * reuse the line lookup and source-text slice. Weak keys do not retain nodes
 * after callers release them.
 *
 * Callers must treat the returned object as immutable; every lookup for the
 * same node shares it.
 */
const cache = new WeakMap<ts.Node, CodeLocation>();

export function resolveNodeLocation(node: ts.Node): CodeLocation {
    const cached = cache.get(node);
    if (cached) return cached;
    const sourceFile = node.getSourceFile();
    const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    const location: CodeLocation = {
        fileName: sourceFile.fileName,
        line: line + 1,
        column: character + 1,
        text: node.getText().substring(0, 80),
    };
    cache.set(node, location);
    return location;
}
