/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { parseSource } from "../../src/static/parser";
import { APIIdentityCache } from "../../src/static/taint/apiIdentity";

function identities(source: string) {
    const parsed = parseSource(source, "api-boundary.ts");
    const cache = APIIdentityCache.forChecker(parsed.checker);
    const expressions: ts.Expression[] = [];
    function visit(node: ts.Node): void {
        if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "inspect") {
            expressions.push(node.arguments[0]);
        }
        ts.forEachChild(node, visit);
    }
    visit(parsed.program.getSourceFile("api-boundary.ts")!);
    return { cache, expressions };
}

describe("Electron exact API identities", () => {
    it("matches exact API names, including bare default imports, without last-segment guessing", () => {
        const { cache, expressions } = identities(`
            import run from "execa";
            import {ipcMain} from "electron";
            import axios from "axios";
            const client = axios.create();
            inspect(run); inspect(ipcMain.handle); inspect(client.get);
        `);
        expect(cache.registrationMatches(expressions[1], "electron.ipcMain.handle")).toBe(true);
        expect(cache.registrationMatches(expressions[1], "handle")).toBe(false);
    });
});
