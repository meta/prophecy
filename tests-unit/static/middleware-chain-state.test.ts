/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { expressSpec } from "../../src/static/spec/express";
import { ExecSink } from "../../src/static/spec/sinks";
import { SourceSpec, TaintSpec } from "../../src/static/spec/types";

const route: SourceSpec = {
    kind: "parameter",
    pattern: "get.req",
    description: "Request input",
    callbackRegistration: "get",
    callbackArgStart: 1,
    taintAllProperties: true,
    paramPropertyPaths: [["query"], ["body"]],
    callbackChain: {
        nextParamIndex: 2,
        sharedParamIndices: [0, 1],
        role: "route",
        pathArgIndex: 0,
        excludedHandlerArities: [4],
        sharedParamProperties: { 1: [["locals"]] },
    },
};
const spec: TaintSpec = {
    sources: [
        route,
        {
            ...route,
            pattern: "use.req",
            callbackRegistration: "use",
            callbackArgStart: 0,
            callbackChain: { ...route.callbackChain!, role: "middleware", pathArgIndex: 0 },
        },
    ],
    sinks: [ExecSink],
    sanitizers: [],
};

async function check(body: string) {
    const result = await analyze({
        source: `import { exec } from "child_process";
            declare function server(): { get(...args: any[]): void; use(...args: any[]): void };
            const app = server(); ${body}`,
        fileName: "/src/middleware.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("ordered middleware shared state", () => {
    it("carries response.locals through next into the next route handler", async () => {
        expect(
            await check(`app.get("/run",
            (req, res, next) => { res.locals.command = req.query.command; next(); },
            (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(1);
    });
    it("carries middleware request writes into an imported-style named handler", async () => {
        expect(
            await check(`
            function consume(req, res) { exec(req.command); }
            app.use((req, res, next) => { req.command = req.query.command; next(); });
            app.get("/run", consume);`),
        ).toHaveLength(1);
    });
    it("does not run a downstream sink when the first handler does not call next", async () => {
        expect(
            await check(`app.get("/run",
            (req, res, next) => { res.locals.command = req.query.command; },
            (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(0);
    });
    it("does not run even a direct request sink without a preceding next", async () => {
        expect(
            await check(`app.get("/run", (req, res, next) => {},
            (req, res) => { exec(req.query.command); });`),
        ).toHaveLength(0);
    });
    it("keeps state written after next out of the downstream handler", async () => {
        expect(
            await check(`app.get("/run",
            (req, res, next) => { next(); res.locals.command = req.query.command; },
            (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(0);
    });
    it("retains state only along the branch that calls next", async () => {
        expect(
            await check(`app.get("/run",
            (req, res, next) => {
                if (req.query.block) { res.locals.command = req.query.command; }
                else { res.locals.command = "fixed"; next(); }
            },
            (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(0);
    });
    it("stops the normal chain for next(error)", async () => {
        expect(
            await check(`app.get("/run", (req, res, next) => { next(new Error("stop")); },
            (req, res) => { exec(req.query.command); });`),
        ).toHaveLength(0);
    });
    it.each(["undefined", "null", "void 0", "false", "0", "-0", "0n", '""'])(
        "continues normally for next(%s)",
        async (argument) => {
            expect(
                await check(`app.get("/run",
            (req, res, next) => { res.locals.command = req.query.command; next(${argument}); },
            (req, res) => { exec(res.locals.command); });`),
            ).toHaveLength(1);
        },
    );
    it("keeps a clean overwrite before next clean", async () => {
        expect(
            await check(`app.get("/run",
            (req, res, next) => { res.locals.command = req.query.command; res.locals.command = "fixed"; next(); },
            (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(0);
    });
    it("does not reintroduce parameter taint after middleware overwrites a request field", async () => {
        expect(
            await check(`app.get("/run",
            (req, res, next) => { req.query = "fixed"; next(); },
            (req, res) => { exec(req.query); });`),
        ).toHaveLength(0);
    });
    it("supports handler arrays and same-receiver middleware aliases", async () => {
        expect(
            await check(`const alias = app;
            const first = (req, res, next) => { res.locals.command = req.query.command; next(); };
            alias.use([first]);
            app.get("/run", [(req, res) => { exec(res.locals.command); }]);`),
        ).toHaveLength(1);
    });
    it("does not share middleware state across server instances", async () => {
        expect(
            await check(`const other = server();
            app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
            other.get("/run", (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(0);
    });
    it("skips error-handler arity on the normal request path", async () => {
        const findings = await check(`app.get("/run",
            (error, req, res, next) => { exec(error.query.command); },
            (req, res) => { exec(req.query.command); });`);
        expect(findings.map((f) => f.sinkLocation.text)).toEqual(["exec(req.query.command)"]);
    });
    it("links middleware-only applications in registration order", async () => {
        expect(
            await check(`
            app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
            app.use((req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(1);
    });
    it("stops a middleware-only application when an earlier handler omits next", async () => {
        expect(
            await check(`app.use((req, res, next) => {});
            app.use((req, res) => { exec(req.query.command); });`),
        ).toHaveLength(0);
    });
    it("registers fluent receiver middleware before the outer route", async () => {
        const result = await analyze({
            source: `import express from "express"; import {exec} from "child_process";
                const app = express();
                app.use((req, res, next) => { res.locals.command = req.query.command; next(); })
                    .get("/run", (req, res) => exec(res.locals.command));`,
            fileName: "/src/express-middleware.ts",
            spec: expressSpec,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });
    it("does not share state between separately allocated inline Routers", async () => {
        const result = await analyze({
            source: `import express from "express"; import {exec} from "child_process";
                express.Router().use((req, res, next) => { res.locals.command = req.query.command; next(); });
                express.Router().get("/run", (req, res) => exec(res.locals.command));`,
            fileName: "/src/express-middleware.ts",
            spec: expressSpec,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });
    it("uses the Express preset for head, options, and route-builder handler positions", async () => {
        const result = await analyze({
            source: `import express from "express"; import {exec} from "child_process";
                const app = express();
                const router = express.Router();
                app.head("/head", req => exec(req.query.command));
                router.options("/options", req => exec(req.body.command));
                app.route("/built").get(req => exec(req.query.command));
                const unrelated = {get(path, callback) {}};
                unrelated.get("/", req => exec(req.query.command));`,
            fileName: "/src/express-middleware.ts",
            spec: expressSpec,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(3);
    });
    it("carries request state through cross-file helpers and handler imports", async () => {
        const result = await analyze({
            projectDir: path.join(__dirname, "fixtures/middleware-dispatch-cross-file"),
            spec: expressSpec,
            maxDepth: 8,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(new Set(result.findings[0].propagationChain.map((step) => step.location.fileName)).size).toBeGreaterThan(
            1,
        );
    });
    it.each([
        [
            "parent shared state",
            `
            app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
            router.get("/run", (req, res) => { exec(res.locals.command); });
            app.use("/api", router);`,
            1,
        ],
        [
            "terminal parent",
            `
            app.use((req, res, next) => {});
            router.get("/run", (req, res) => { exec(req.query.command); });
            app.use("/api", router);`,
            0,
        ],
        [
            "clean overwrite",
            `
            app.use((req, res, next) => { res.locals.command = req.query.command; res.locals.command = "fixed"; next(); });
            router.get("/run", (req, res) => { exec(res.locals.command); });
            app.use("/api", router);`,
            0,
        ],
        [
            "different app",
            `
            const other = express();
            app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
            router.get("/run", (req, res) => { exec(res.locals.command); });
            other.use("/api", router);`,
            0,
        ],
        [
            "combined mount and route prefix",
            `
            app.use("/api/run", (req, res, next) => { res.locals.command = req.query.command; next(); });
            router.get("/run", (req, res) => { exec(res.locals.command); });
            app.use("/api", router);`,
            1,
        ],
        [
            "nonmatching combined path",
            `
            app.use("/api/other", (req, res, next) => { res.locals.command = req.query.command; next(); });
            router.get("/run", (req, res) => { exec(res.locals.command); });
            app.use("/api", router);`,
            0,
        ],
    ] as const)("models a direct static router mount: %s", async (_label, body, expected) => {
        const result = await analyze({
            source: `import express from "express"; import {exec} from "child_process";
                const app = express(); const router = express.Router(); ${body}`,
            fileName: "/src/express-mount.ts",
            spec: expressSpec,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected);
    });
    it("does not share middleware state across disjoint static paths", async () => {
        expect(
            await check(`
            app.use("/private", (req, res, next) => { res.locals.command = req.query.command; next(); });
            app.get("/public", (req, res) => { exec(res.locals.command); });`),
        ).toHaveLength(0);
    });
});
