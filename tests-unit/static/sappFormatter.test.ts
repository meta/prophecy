/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { writeFindingsSappStream, writeTraceFramesSappStream } from "../../src/static/sappFormatter";
import { CodeLocation, PropagationStep, TaintFinding } from "../../src/static/spec/types";
import { WriteFileContentSink, WriteFilePathSink } from "../../src/static/spec/sinks";

const at = (fileName: string, line: number, column: number, text: string): CodeLocation => ({
    fileName,
    line,
    column,
    text,
});
const step = (location: CodeLocation): PropagationStep => ({
    kind: "assignment",
    location,
    description: `${location.fileName}:${location.line}:${location.column}`,
});

const finding: TaintFinding = {
    handle: "handleUri.uri|exec|activate|b.ts|9",
    sinkSite: "activate>handleUri>exec",
    source: { kind: "parameter", pattern: "handleUri.uri", description: "Deeplink URI" },
    sourceLocation: at("a.ts", 2, 14, "uri"),
    sink: {
        kind: "callArgument",
        name: "exec",
        pattern: "child_process.exec",
        description: "Shell command",
        categories: ["rce"],
    },
    sinkLocation: at("b.ts", 9, 4, "exec(cmd)"),
    propagationChain: [
        step(at("a.ts", 3, 14, "uri.query")),
        step(at("a.ts", 3, 10, "q = uri.query")),
        // Same line number as the steps above, but in another file.
        step(at("b.ts", 3, 8, "run(q)")),
        step(at("b.ts", 7, 20, "q")),
        step(at("b.ts", 7, 10, "`${q} --x`")),
        // Same line as step 2 again, but not consecutive with it.
        step(at("b.ts", 3, 2, "cmd")),
    ],
};

function readNdjson(write: typeof writeTraceFramesSappStream): any[] {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sapp-formatter-"));
    try {
        const output = path.join(directory, "out.sapp");
        write(output, [finding]);
        return fs
            .readFileSync(output, "utf8")
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
}

describe("SAPP source trace frames", () => {
    it("merges consecutive steps on one line of one file into a single frame", () => {
        const sources = readNdjson(writeTraceFramesSappStream).filter((frame) => frame.type === "postcondition");
        expect(sources.map((frame) => [frame.filename, frame.callee_location.line, frame.sources[0].depth])).toEqual([
            ["b.ts", 3, 4],
            ["b.ts", 7, 3],
            ["b.ts", 3, 2],
            ["a.ts", 3, 1],
            ["a.ts", 2, 0],
        ]);
        for (let i = 1; i < sources.length; i++) {
            expect(sources[i].caller).toBe(sources[i - 1].callee);
        }
        expect(sources[sources.length - 1].callee).toBe("handleUri.uri");

        const merged = sources[1];
        expect(merged.callee_location).toEqual({ line: 7, start: 10, end: 21 });
        expect(merged.features).toEqual([
            { name: "prophecy-step-4:assignment: b.ts:7:10", locations: [{ line: 7, start: 10, end: 20 }] },
            { name: "prophecy-step-3:assignment: b.ts:7:20", locations: [{ line: 7, start: 20, end: 21 }] },
        ]);
    });

    it("reports the merged frame count as the issue's source trace length", () => {
        const [issue] = readNdjson(writeFindingsSappStream);
        const forward = issue.traces.find((trace: any) => trace.forward).forward;
        expect(forward.kinds).toEqual([{ kind: "Deeplink URI", trace_len: 5 }]);
        expect(issue.propagation_steps).toHaveLength(6);
    });

    it("assigns distinct warning codes and severity features to path and content writes", () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sapp-formatter-"));
        try {
            const output = path.join(directory, "out.sapp");
            const pathFinding = {
                ...finding,
                sink: WriteFilePathSink,
            };
            const contentFinding = {
                ...finding,
                handle: finding.handle + "-content",
                sink: WriteFileContentSink,
            };
            writeFindingsSappStream(output, [pathFinding, contentFinding]);
            const issues = fs
                .readFileSync(output, "utf8")
                .trim()
                .split("\n")
                .map((line) => JSON.parse(line));
            expect(issues.map((issue) => issue.code)).toEqual([9005, 9012]);
            expect(
                issues.map((issue) =>
                    issue.features.find((feature: string) => feature.startsWith("prophecy-severity:")),
                ),
            ).toEqual(["prophecy-severity:high", "prophecy-severity:low"]);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });
});
