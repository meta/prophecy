/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { expressSpec } from "../../src/static/spec/express";
import { analyzeFixture } from "./testUtils";

describe("request event flow", () => {
    it("delivers incoming request chunks across files without tainting response streams", async () => {
        const result = await analyzeFixture("eventFlowRequest", { spec: expressSpec, maxDepth: 8 });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toBe("exec(command)");
        expect(new Set(result.findings[0].propagationChain.map((step) => step.location.fileName)).size).toBe(2);
    });

    it.each([
        ["http.createServer", 'import * as http from "node:http";', "http.createServer(handler)", 1],
        ["Express route", 'import express from "express"; const app = express();', "app.post('/event', handler)", 1],
        [
            "unrelated local receiver",
            "const http = { createServer: (_handler: any) => {} };",
            "http.createServer(handler)",
            0,
        ],
    ])("scopes request streams to %s", async (_name, setup, registration, expected) => {
        const result = await analyze({
            source: `import { exec } from "child_process";
                ${setup}
                function body(request: any) {
                    request.on('data', chunk => { const command = chunk; exec(command); });
                    request.on('close', metadata => exec(metadata));
                    exec(request.socket);
                    exec(request.server);
                }
                function handler(req: any, res: any) { body(req); }
                ${registration};`,
            fileName: "/src/eventFlow-request.ts",
            spec: expressSpec,
            maxDepth: 8,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected);
        expect(result.findings.every((finding) => finding.sinkLocation.text === "exec(command)")).toBe(true);
    });
});
