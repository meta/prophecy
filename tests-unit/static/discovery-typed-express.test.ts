/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { expressSpec } from "../../src/static/spec/express";
import { InterproceduralAnalyzer } from "../../src/static/taint/interprocedural";

const projectDir = path.join(__dirname, "fixtures/discovery-typed-express");
describe("typed Express field registration discovery", () => {
    it("discovers static and dynamic-path routes through a package intersection alias", () => {
        const { checker, sourceFiles } = parseProject(projectDir);
        const analyzer = new InterproceduralAnalyzer(checker, expressSpec);
        const entries = analyzer.discoverEntryPoints(sourceFiles);
        expect(entries.map((entry) => entry.description).sort()).toEqual([
            "Callback handler for get",
            "Callback handler for get",
            "Callback handler for post",
        ]);
    });
    it("shares typed-field middleware state without merging separate wrappers or mock receivers", async () => {
        const result = await analyze({ projectDir, spec: expressSpec, maxDepth: 8, outputFormat: "text" });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(2);
        expect(result.findings.map((finding) => finding.sinkLocation.text).sort()).toEqual([
            "exec(req.body.command)",
            "exec(response.locals.command)",
        ]);
    });
});
