/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { NodeFileSources } from "../../src/static/spec/nodeApis";
import { vscodeSpecWithEnvSource } from "./testUtils";

describe("nodeApiCoverage file-stream transport", () => {
    it("evaluates inline stream receivers before matching their data listeners", async () => {
        const result = await analyze({
            source: `import { createReadStream } from 'node:fs'; import { exec } from 'child_process';
                export function activate() {
                    const state = { command: 'fixed' };
                    createReadStream('/fixed', {fd: 0}).on('data', chunk => exec(chunk.toString()));
                    createReadStream('/fixed').on('data', chunk => { state.command = chunk.toString(); });
                    exec(state.command);
                }`,
            fileName: "/src/eventFlow-inline.ts",
            maxDepth: 8,
            outputFormat: "text",
            spec: { ...vscodeSpecWithEnvSource, sources: [...vscodeSpecWithEnvSource.sources, ...NodeFileSources] },
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.filter((finding) => finding.sink.name === "exec")).toHaveLength(1);
    });
});
