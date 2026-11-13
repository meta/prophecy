/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { expressSpec } from "../../src/static/spec/express";

async function scan(source: string) {
    const result = await analyze({
        source: `import express from "express"; const app = express();\n${source}`,
        spec: expressSpec,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result;
}

describe("Express request and response contracts", () => {
    it.each(["res", "response", "reply"])("recognizes sinks on response parameter %s", async (name) => {
        const result = await scan(`app.get("/", (request, ${name}) => {
            ${name}.send(request.query.x);
            ${name}.redirect(request.query.x);
            ${name}.render(request.query.view, {title: "Fixed title"});
            ${name}.sendFile(request.query.x);
        });`);
        expect(result.findings.map((finding) => finding.sink.name).sort()).toEqual([
            "http_redirect",
            "render",
            "send",
            "sendFile",
        ]);
    });

    it("preserves the response identity through aliases, branches, and helper parameters", async () => {
        const result = await scan(`
            function send(output: any, value: any) { output.send(value); }
            app.get("/", (request, response) => {
                const reply = response;
                if (request.query.branch) { send(reply, request.query.x); }
                else { reply["redirect"](request.query.x); }
            });`);
        expect(result.findings.map((finding) => finding.sink.name).sort()).toEqual(["http_redirect", "send"]);
    });

    it("does not match an unrelated send method or a reassigned response", async () => {
        const result = await scan(`app.get("/", (request, response) => {
            const logger = {send(value: any) {}};
            logger.send(request.query.x);
            response = logger;
            response.send(request.query.x);
        });`);
        expect(result.findings).toHaveLength(0);
    });

    it.each([
        "request.query.x",
        "302, request.query.x",
        "...[request.query.x]",
        "...[302, request.query.x]",
        "302, ...[request.query.x]",
        "...[302], request.query.x",
        "...([302, request.query.x] as const)",
        "...[...[302], request.query.x]",
        "...[], request.query.x",
        "...request.query.args",
        "...request.query.prefix, request.query.x",
    ])("selects the redirect URL for %s", async (args) => {
        expect((await scan(`app.get("/", (request, response) => response.redirect(${args}));`)).findings).toHaveLength(
            1,
        );
    });

    it.each([
        'request.query.status, "/safe"',
        '...[request.query.status, "/safe"]',
        '...[request.query.status], "/safe"',
        '...[...[request.query.status], "/safe"]',
        '...[], request.query.status, "/safe"',
        '302, ...["/safe"]',
    ])("does not treat redirect status as a URL: %s", async (args) => {
        expect((await scan(`app.get("/", (request, response) => response.redirect(${args}));`)).findings).toHaveLength(
            0,
        );
    });

    it.each([
        "(request, response, next) => next(), (request, response) => response.send(request.query.x)",
        "[(request, response, next) => next(), [(request, response) => response.send(request.query.x)]]",
        "middleware, handler",
        "handlers",
    ])("follows every route callback in %s", async (callbacks) => {
        const result = await scan(`
            const middleware = (request, response, next) => next();
            function handler(request, response) {response.send(request.query.x)}
            const handlers = [middleware, handler];
            app.get("/", ${callbacks});`);
        // One request entry advances through both callbacks via next().
        expect(result.entryPointCount).toBe(1);
        expect(result.findings).toHaveLength(1);
    });
});
