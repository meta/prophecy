/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "external input", taintAllProperties: true }],
    sanitizers: [],
    sinks: [
        {
            kind: "callArgument",
            name: "html",
            pattern: "renderHtml",
            argPositions: [0],
            categories: ["xss"],
            description: "HTML syntax",
        },
        {
            kind: "callArgument",
            name: "persist",
            pattern: "persist",
            argPositions: [0],
            categories: ["file_integrity"],
            description: "Persisted content",
        },
    ],
};

describe("Serialization provenance", () => {
    it.each([
        ["direct serialized aggregate", "renderHtml(JSON.stringify({value: input()}));", 1],
        ["serialized nested value", "renderHtml(JSON.stringify({value: {text: input()}}).trim());", 1],
        [
            "serialized text replacement",
            "const value=JSON.stringify({value: input()}).replace(/</g, '\\\\u003c'); renderHtml('<script>const data='+value+'</script>');",
            1,
        ],
        [
            "decoded modified text",
            "const value=JSON.stringify({value: input()}).replace(/</g, '\\\\u003c'); renderHtml(JSON.parse(value).value);",
            1,
        ],
        [
            "captured native serializer",
            "const serialize=JSON.stringify; renderHtml(serialize({value: input()}).trim());",
            1,
        ],
        ["constant serialized text", "renderHtml(JSON.stringify({value: 'fixed'}).trim());", 0],
        [
            "local serializer preserves aggregate scope",
            "const JSON={stringify(value:any){return value;}}; const value=JSON.stringify({unsafe: input(),safe:'fixed'}); renderHtml(value.safe);",
            0,
        ],
        ["serialized content persistence", "persist(JSON.stringify({value: input()}).trim());", 1],
        ["constant content persistence", "persist(JSON.stringify({value: 'fixed'}).trim());", 0],
    ])("retains %s", async (_name, body, expected) => {
        const result = await analyze({
            source: `declare function input(): string; declare function renderHtml(value: unknown): void; declare function persist(value: string): void; export function main() { ${body} }`,
            fileName: "/neutral/serialization.ts",
            spec,
            outputFormat: "json",
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected as number);
    });
});
