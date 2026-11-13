/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";

const source = `
    import * as vscode from "vscode";
    import { exec } from "child_process";
    function first() { exec(vscode.env.clipboard.readText()); }
    function second() { exec(vscode.env.clipboard.readText()); }
`;

describe("fallback entry point selection", () => {
    it("partitions fallback functions into disjoint shards", async () => {
        const all = await analyze({ source });
        const first = await analyze({ source, shardCount: 2, shardIndex: 0 });
        const second = await analyze({ source, shardCount: 2, shardIndex: 1 });
        expect(all.findings.length).toBe(2);
        expect(first.entryPointCount).toBe(1);
        expect(second.entryPointCount).toBe(1);
        const handles = [...first.findings, ...second.findings].map((finding) => finding.handle);
        expect(new Set(handles).size).toBe(handles.length);
        expect(handles.sort()).toEqual(all.findings.map((finding) => finding.handle).sort());
    });

    it("keeps an empty shard empty", async () => {
        const result = await analyze({ source, shardCount: 3, shardIndex: 2 });
        expect(result.entryPointCount).toBe(0);
        expect(result.findings).toEqual([]);
    });

    it("applies filters to fallback functions", async () => {
        const result = await analyze({ source, entryPointFilter: ["nonexistent-file.ts"] });
        expect(result.entryPointCount).toBe(0);
        expect(result.findings).toEqual([]);
    });
});
