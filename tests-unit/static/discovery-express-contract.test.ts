/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { ExecSink } from "../../src/static/spec/sinks";
import { SourceSpec, TaintSpec } from "../../src/static/spec/types";

async function check(body: string, source: SourceSpec) {
    const spec: TaintSpec = { sources: [source], sinks: [ExecSink], sanitizers: [] };
    const result = await analyze({
        source: `import { exec } from "child_process"; ${body}`,
        fileName: "/src/discovery.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("Express field-scoped callback input", () => {
    it("scopes Express input taint to query, not application metadata", async () => {
        const source: SourceSpec = {
            kind: "parameter",
            pattern: "express.input",
            description: "HTTP input",
            callbackRegistration: "express.Application.get",
            callbackMatch: "api",
            callbackArgStart: 1,
            paramPropertyPaths: [["query"]],
            taintAllProperties: true,
        };
        const findings = await check(
            `
            import express from "express";
            const app = express();
            app.get("/", request => {
                exec(request.query.command);
                exec(request.app.command);
            });
        `,
            source,
        );
        expect(findings.map((f) => f.sinkLocation.text)).toEqual(["exec(request.query.command)"]);
    });
});
