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

describe("completion values across nested catch and finally", () => {
    it.each([
        [
            "catch retains the thrown object's payload",
            `try { throw {value: boundary.input()}; }
             catch (error) { boundary.emit(error.value); }`,
            1,
        ],
        [
            "nested catch preserves the pending returned object's alias",
            `function read() {
                 const root = {value: 'safe'};
                 try { return root; }
                 finally {
                     try { throw {root}; } catch (error) {}
                     root.value = boundary.input();
                 }
             }
             boundary.emit(read().value);`,
            1,
        ],
        [
            "nested catch preserves a finalizer's clean overwrite",
            `function read() {
                 const root = {value: boundary.input()};
                 try { return root; }
                 finally {
                     try { throw {root}; } catch (error) {}
                     root.value = 'safe';
                 }
             }
             boundary.emit(read().value);`,
            0,
        ],
        [
            "nested catch preserves the pending thrown object's alias",
            `const root = {value: 'safe'};
             try {
                 try { throw root; }
                 finally {
                     try { throw {root}; } catch (error) {}
                     root.value = boundary.input();
                 }
             } catch (error) { boundary.emit(error.value); }`,
            1,
        ],
        [
            "a finalizer's replacement return keeps its payload",
            `function read() {
                 try { return {value: 'safe'}; }
                 finally {
                     try { throw {value: 'safe'}; } catch (error) {}
                     return {value: boundary.input()};
                 }
             }
             boundary.emit(read().value);`,
            1,
        ],
        [
            "an unresolved throw retains the state before a later clear",
            `const root = {value: 'safe'};
             try {
                 root.value = boundary.input();
                 unknown();
                 root.value = 'safe';
             } catch (error) { boundary.emit(root.value); }`,
            1,
        ],
    ])("%s", async (_name, body, expected) => {
        const result = await analyze({
            source: `declare namespace boundary { function input(): any; function emit(value: any): void; }
                     declare function unknown(): void;
                     export function main() { ${body} }`,
            fileName: "/neutral/completionRootLifetime.ts",
            spec,
            maxDepth: 5,
            outputFormat: "json",
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected as number);
    });
});
