/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import * as path from "path";
import * as ts from "typescript";
import { analyze } from "../../src/static/analyzer";
import { parseSource } from "../../src/static/parser";
import { expressSpec } from "../../src/static/spec/express";
import { APIIdentityCache } from "../../src/static/taint/apiIdentity";

const projectDir = path.join(__dirname, "fixtures/discovery-typed-express");

describe("static registration receiver mutations", () => {
    it("preserves method capture time in strict and registration identity checks", () => {
        const fileName = path.join(projectDir, "captures.ts");
        const parsed = parseSource(
            `
            /// <reference path="${path.join(projectDir, "apis.d.ts")}" />
            import {Instance} from "express-ws";
            function install(server: Instance): void {
                const before = server.app.get;
                server.app.get = (_path, ..._handlers) => server.app;
                const after = server.app.get;
                before("/before");
                after("/after");
            }
        `,
            fileName,
        );
        const calls = new Map<string, ts.Expression>();
        const visit = (node: ts.Node): void => {
            if (ts.isCallExpression(node)) calls.set(node.expression.getText(), node.expression);
            node.forEachChild(visit);
        };
        visit(parsed.program.getSourceFile(fileName)!);
        const cache = APIIdentityCache.forChecker(parsed.checker);
        const before = calls.get("before")!;
        const after = calls.get("after")!;
        // Query the later read first so cached snapshots cannot redirect earlier captures.
        expect(cache.matchesAPI(after, "express.Application.get")).toBe(false);
        expect(cache.matchesAPI(before, "express.Application.get")).toBe(true);
        expect(cache.registrationMatches(after, "express.Application.get")).toBe(false);
        expect(cache.registrationMatches(before, "express.Application.get")).toBe(true);
        expect(ts.isArrowFunction(cache.registrationReceiver(after) as ts.Node)).toBe(true);
        expect(cache.registrationReceiver(before)).not.toBe(cache.registrationReceiver(after));
    });

    it.each([
        {
            name: "separates request state after replacing a field receiver",
            body: `server.app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
                server.app = separate.app;
                server.app.get("/run", (_req, res) => exec(res.locals.command));`,
            expected: 0,
        },
        {
            name: "does not let the old receiver terminate the replacement's route",
            body: `server.app.use((_req, res) => { res.send("stop"); });
                server.app = separate.app;
                server.app.get("/run", req => exec(req.query.command));`,
            expected: 1,
        },
        {
            name: "uses middleware already registered on the replacement receiver",
            body: `separate.app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
                server.app = separate.app;
                server.app.get("/run", (_req, res) => exec(res.locals.command));`,
            expected: 1,
        },
        {
            name: "preserves termination on the replacement receiver",
            body: `separate.app.use((_req, res) => { res.send("stop"); });
                server.app = separate.app;
                server.app.get("/run", req => exec(req.query.command));`,
            expected: 0,
        },
        {
            name: "keeps an alias captured before field replacement on the old receiver",
            body: `server.app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
                const old = server.app;
                server.app = separate.app;
                old.get("/run", (_req, res) => exec(res.locals.command));`,
            expected: 1,
        },
        {
            name: "keeps the old receiver's termination through its captured alias",
            body: `server.app.use((_req, res) => { res.send("stop"); });
                const old = server.app;
                server.app = separate.app;
                old.get("/run", req => exec(req.query.command));`,
            expected: 0,
        },
        {
            name: "captures the replacement receiver in a later alias",
            body: `server.app.use((_req, res) => { res.send("stop"); });
                server.app = separate.app;
                const fresh = server.app;
                fresh.get("/run", req => exec(req.query.command));`,
            expected: 1,
        },
        {
            name: "shares unchanged field state through chained receiver aliases",
            body: `const first = server.app;
                const second = first;
                second.use((req, res, next) => { res.locals.command = req.query.command; next(); });
                server.app.get("/run", (_req, res) => exec(res.locals.command));`,
            expected: 1,
        },
        {
            name: "recognizes field writes through an alias of the containing object",
            body: `server.app.use((_req, res) => { res.send("stop"); });
                const wrapper = server;
                wrapper.app = separate.app;
                server.app.get("/run", req => exec(req.query.command));`,
            expected: 1,
        },
        {
            name: "recognizes literal bracket field writes and reads",
            body: `server["app"].use((req, res, next) => { res.locals.command = req.query.command; next(); });
                server["app"] = separate.app;
                server.app.get("/run", (_req, res) => exec(res.locals.command));`,
            expected: 0,
        },
        {
            name: "does not discover a directly replaced registration method",
            body: `server.app.get = (_path, ..._handlers) => server.app;
                server.app.get("/run", req => exec(req.query.command));`,
            expected: 0,
        },
        {
            name: "observes method replacement through an earlier object alias",
            body: `const old = server.app;
                server.app.get = (_path, ..._handlers) => server.app;
                old.get("/run", req => exec(req.query.command));`,
            expected: 0,
        },
        {
            name: "observes method replacement through a later object alias",
            body: `server.app.get = (_path, ..._handlers) => server.app;
                const fresh = server.app;
                fresh.get("/run", req => exec(req.query.command));`,
            expected: 0,
        },
        {
            name: "recognizes method writes through an alias and literal brackets",
            body: `const alias = server.app;
                alias["get"] = (_path, ..._handlers) => alias;
                server.app.get("/run", req => exec(req.query.command));`,
            expected: 0,
        },
        {
            name: "does not transfer an old receiver's method replacement to a new receiver",
            body: `const old = server.app;
                old.get = (_path, ..._handlers) => old;
                server.app = separate.app;
                server.app.get("/run", req => exec(req.query.command));`,
            expected: 1,
        },
        {
            name: "does not redirect an old alias when the new receiver's method is replaced",
            body: `const old = server.app;
                server.app = separate.app;
                server.app.get = (_path, ..._handlers) => server.app;
                old.get("/run", req => exec(req.query.command));`,
            expected: 1,
        },
        {
            name: "does not invalidate an earlier registration retroactively",
            body: `server.app.get("/run", req => exec(req.query.command));
                server.app.get = (_path, ..._handlers) => server.app;`,
            expected: 1,
        },
        {
            name: "keeps unrelated receivers' methods independent",
            body: `server.app.get = (_path, ..._handlers) => server.app;
                separate.app.get("/run", req => exec(req.query.command));`,
            expected: 1,
        },
    ])("$name", async ({ body, expected }) => {
        const result = await analyze({
            source: `/// <reference path="${path.join(projectDir, "apis.d.ts")}" />
                import {Instance} from "express-ws";
                import {exec} from "child_process";
                export function install(server: Instance, separate: Instance): void { ${body} }`,
            fileName: path.join(projectDir, "mutation.ts"),
            spec: expressSpec,
            maxDepth: 8,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.syntaxErrors).toEqual([]);
        expect(result.findings.filter((finding) => finding.sink.name === "exec")).toHaveLength(expected);
    });
});
