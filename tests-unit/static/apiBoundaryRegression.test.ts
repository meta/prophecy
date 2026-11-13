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

describe("Identity-scoped API models", () => {
    it("resolves ES and CommonJS module aliases without erasing raw promise-module identity", () => {
        const { cache, expressions } = identities(`
            import { readFile as read } from "node:fs/promises";
            import spawn = require("cross-spawn");
            const axios = require("axios");
            const { exec: run } = require("node:child_process");
            const { promises: { readFile: nested } } = require("fs");
            inspect(read); inspect(spawn); inspect(axios.get); inspect(run); inspect(nested);
        `);
        expect(expressions.map((expr) => cache.registrationName(expr))).toEqual([
            "fs.readFile",
            "cross-spawn",
            "axios.get",
            "child_process.exec",
            "fs.readFile",
        ]);
        expect(cache.rawImportedName(expressions[0])).toBe("node:fs/promises.readFile");
        expect(cache.rawImportedName(expressions[4])).toBe("fs.promises.readFile");
    });

    it("does not expose filesystem APIs on an import Promise or a dynamic module name", () => {
        const { cache, expressions } = identities(`
            async function main(name: string) {
                const pending = import("fs");
                const dynamic = await import(name);
                inspect(pending.readFile); inspect(dynamic.readFile);
            }
        `);
        expect(expressions.map((expr) => cache.matchesAPI(expr, "fs.readFile"))).toEqual([false, false]);
    });

    it("rejects local names, local same-named methods, shadowed require and dynamic module names", () => {
        const { cache, expressions } = identities(`
            const execa = (command: string) => command;
            const axios = {get(value: string) {return value}};
            const fs = {readFile(value: string) {return value}};
            inspect(execa); inspect(axios.get); inspect(fs.readFile);
            function local(require: (name: string) => any) {
                const run = require("execa"); inspect(run);
            }
            declare const name: string;
            const dynamic = require(name); inspect(dynamic);
        `);
        expect(expressions.map((expr) => cache.registrationName(expr))).toEqual([
            undefined,
            undefined,
            undefined,
            undefined,
            undefined,
        ]);
    });
});
