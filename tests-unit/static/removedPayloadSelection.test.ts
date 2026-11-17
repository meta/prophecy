/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    sources: [{ kind: "callReturnValue", pattern: "boundary.input", description: "input", taintAllProperties: true }],
    sinks: [
        {
            kind: "callArgument",
            name: "emit",
            pattern: "boundary.emit",
            argPositions: [0],
            description: "output",
            categories: ["rce"],
        },
    ],
    sanitizers: [],
    entryFunctions: ["main"],
};

describe("removed finding payload selection", () => {
    it.each([
        ["direct input", "boundary.emit(boundary.input());", 1],
        [
            "numeric selector leaves clean selected payload clean",
            `function choose(nodes, count) { return nodes[Math.floor(nodes.length / count)]; }
             boundary.emit(choose([{name: 'safe'}], boundary.input()).name);`,
            0,
        ],
        [
            "numeric selection preserves an input payload",
            `function choose(nodes, count) { return nodes[Math.floor(nodes.length / count)]; }
             boundary.emit(choose([{name: boundary.input()}], 2).name);`,
            1,
        ],
        [
            "revision does not taint a missing checkpoint sibling",
            `function choose(checkpoint, revision) {
                 if (checkpoint) return {checkpointId: checkpoint};
                 return {revisionId: revision};
             }
             boundary.emit(choose(undefined, boundary.input()).checkpointId);`,
            0,
        ],
        [
            "revision payload remains tainted",
            `function choose(checkpoint, revision) {
                 if (checkpoint) return {checkpointId: checkpoint};
                 return {revisionId: revision};
             }
             boundary.emit(choose(undefined, boundary.input()).revisionId);`,
            1,
        ],
        [
            "literal command stays clean beside input arguments",
            `function build(model, prompt) {
                 switch (model.kind) {
                     case 'one': return {cmd: 'tool1', args: [prompt, model.id]};
                     case 'two': return {cmd: 'tool2', args: [prompt]};
                 }
             }
             const result = build({kind: boundary.input(), id: boundary.input()}, boundary.input());
             const {cmd} = result;
             boundary.emit(cmd);`,
            0,
        ],
        [
            "command arguments preserve their input payload",
            `function build(model, prompt) {
                 switch (model.kind) {
                     case 'one': return {cmd: 'tool1', args: [prompt, model.id]};
                     case 'two': return {cmd: 'tool2', args: [prompt]};
                 }
             }
             const result = build({kind: boundary.input(), id: boundary.input()}, boundary.input());
             const {args} = result;
             boundary.emit(args);`,
            1,
        ],
        [
            "lookup selector does not become independent response bytes",
            `function lookup(id) { return {title: 'safe', body: 'safe'}; }
             boundary.emit(lookup(boundary.input()).title);`,
            0,
        ],
    ])("%s", async (_name, body, expected) => {
        const result = await analyze({
            source: `declare namespace boundary { function input(): any; function emit(value: any): void; }
                     export function main() { ${body} }`,
            fileName: "/neutral/payloadSelection.ts",
            spec,
            maxDepth: 5,
            outputFormat: "json",
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected as number);
    });
});
