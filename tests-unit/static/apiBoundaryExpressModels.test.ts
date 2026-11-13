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

describe("Express API identities", () => {
    it("uses explicit Express factories and fluent returns rather than matching method suffixes", () => {
        const { cache, expressions } = identities(`
            import express from "express";
            const app = express();
            const router = express.Router();
            inspect(app.use); inspect(router.post); inspect(app.route("/x").get);
            inspect(app.get("setting").get);
        `);
        expect(expressions.map((expr) => cache.registrationName(expr))).toEqual([
            "express.Application.use",
            "express.Router.post",
            "express.Route.get",
            undefined,
        ]);
    });

    it("invalidates only a directly replaced registration method on the same receiver", () => {
        const { cache, expressions } = identities(`
            import express from "express";
            const app = express();
            const other = express();
            inspect(app.get);
            app.get = (_path, _handler) => app;
            inspect(app.get); inspect(app.post); inspect(other.get);
        `);
        expect(cache.registrationMatches(expressions[0], "express.Application.get")).toBe(true);
        expect(cache.registrationMatches(expressions[1], "express.Application.get")).toBe(false);
        expect(cache.registrationMatches(expressions[2], "express.Application.post")).toBe(true);
        expect(cache.registrationMatches(expressions[3], "express.Application.get")).toBe(true);
    });
});
