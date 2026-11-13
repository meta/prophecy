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

describe("Shared Node API identities", () => {
    it("retains awaited literal namespaces and compatible fs-extra exports", () => {
        const { cache, expressions } = identities(`
            async function main() {
                const fs = await import("node:fs");
                const pending = import("fs/promises");
                const promised = await pending;
                const extra = await import("fs-extra");
                const {readFile} = await import("fs/promises");
                inspect(fs.promises.readFile); inspect(promised.readFile);
                inspect(extra.readFile); inspect(readFile);
            }
        `);
        expect(expressions.map((expr) => cache.registrationName(expr))).toEqual([
            "fs.readFile",
            "fs.readFile",
            "fs.readFile",
            "fs.readFile",
        ]);
        expect(cache.rawImportedName(expressions[1])).toBe("fs/promises.readFile");
        expect(cache.rawImportedName(expressions[2])).toBe("fs-extra.readFile");
    });

    it("matches exact API names, including bare default imports, without last-segment guessing", () => {
        const { cache, expressions } = identities(`
            import run from "execa";
            import {ipcMain} from "electron";
            import axios from "axios";
            const client = axios.create();
            inspect(run); inspect(ipcMain.handle); inspect(client.get);
        `);
        expect(cache.matchesAPI(expressions[0], "execa")).toBe(true);
        expect(cache.matchesAPI(expressions[0], "run")).toBe(false);
        expect(cache.matchesAPI(expressions[2], "axios.get")).toBe(true);
        expect(cache.matchesAPI(expressions[2], "axios.*")).toBe(true);
        expect(cache.matchesAPI(expressions[2], "axiosXget")).toBe(false);
    });
});
