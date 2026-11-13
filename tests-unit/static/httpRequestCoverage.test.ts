/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { expressSpec } from "../../src/static/spec/express";
import { WebRequestPropertyPaths } from "../../src/static/spec/http";
import { TaintSpec } from "../../src/static/spec/types";
import { httpRequestCoverageFixture } from "./httpRequestCoverageFixtures";

async function scan(spec: TaintSpec, source: string, files: Record<string, string> = {}) {
    const projectDir = httpRequestCoverageFixture({ "main.ts": source, ...files });
    try {
        const { program } = parseProject(projectDir);
        expect(program.getSemanticDiagnostics().map((diagnostic) => diagnostic.messageText)).toEqual([]);
        const result = await analyze({ projectDir, spec, outputFormat: "json", requireTypes: true });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        return result;
    } finally {
        fs.rmSync(projectDir, { recursive: true, force: true });
    }
}

function sinkLines(result: Awaited<ReturnType<typeof scan>>) {
    return [...new Set(result.findings.map((finding) => finding.sinkLocation.line))];
}

describe("frameworkCoverage shared HTTP APIs", () => {
    it.each(["http", "https"])("limits %s.createServer sources to request data", async (module) => {
        const result = await scan(
            expressSpec,
            `
            import {createServer} from "${module}";
            import {exec} from "child_process";
            createServer({}, (request, response) => {
                exec(request.url);
                exec(request.headers.command);
                exec(response.statusMessage);
                exec(request.socket.localAddress);
            });
            const other = {createServer(options: object, handler: (request: any, response: any) => void) {}};
            other.createServer({}, (request, response) => exec(request.url));
        `,
        );
        expect(sinkLines(result)).toEqual([5, 6]);
        expect(result.entryPointCount).toBe(1);
    });

    it("tracks custom incoming Request body readers without sourcing local Request or Response bodies", async () => {
        const spec: TaintSpec = {
            ...expressSpec,
            sources: [
                {
                    kind: "parameter",
                    pattern: "serve.request",
                    description: "Incoming web request",
                    callbackRegistration: "serve",
                    callbackArgIndex: 0,
                    paramIndex: 0,
                    paramPropertyPaths: WebRequestPropertyPaths,
                    taintAllProperties: true,
                },
            ],
        };
        const result = await scan(
            spec,
            `
            import {exec} from "child_process";
            declare function serve(handler: (request: Request, response: Response) => Promise<void>): void;
            serve(async (request, response) => {
                exec((await request.json()).command);
                exec(await request.text());
                exec(String((await request.formData()).get("command")));
                exec(await response.text());
                exec(await new Request("https://example.com", {method: "POST", body: "fixed"}).text());
                exec(request.signal.reason);
            });
        `,
        );
        expect(sinkLines(result)).toEqual([5, 6, 7]);
    });
});
