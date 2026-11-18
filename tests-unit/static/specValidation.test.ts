/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { builtinSpecs } from "../../src/static/spec/presets";
import { validateSpec } from "../../src/static/spec/validate";

const source = {
    kind: "parameter",
    pattern: "onPush.event",
    callbackRegistration: "onPush",
    description: "Push event payload",
};
const sink = {
    kind: "callArgument",
    name: "exec",
    pattern: "child_process.exec",
    categories: ["rce"],
    description: "Command execution",
};
const sanitizer = { kind: "callReturnValue", pattern: "parseInt", categories: ["rce"], description: "Integer parsing" };
const spec = { sources: [source], sinks: [sink], sanitizers: [sanitizer] };

describe("custom spec validation", () => {
    it.each(Object.entries(builtinSpecs))("accepts the %s preset as JSON", (_name, preset) => {
        expect(validateSpec(JSON.parse(JSON.stringify(preset)))).toEqual([]);
    });

    it("accepts a minimal spec", () => {
        expect(validateSpec(spec)).toEqual([]);
    });

    it("rejects a misspelled field instead of ignoring it", () => {
        const { callbackRegistration, ...rest } = source;
        const typo = { ...rest, callbackRegistraton: callbackRegistration };
        expect(validateSpec({ ...spec, sources: [typo] })).toEqual(["sources[0].callbackRegistraton: unknown field"]);
    });

    it("rejects missing required arrays and fields", () => {
        const { sanitizers: _sanitizers, ...noSanitizers } = spec;
        const { name: _name, ...unnamed } = sink;
        expect(validateSpec({ ...noSanitizers, sinks: [unnamed] })).toEqual([
            "sinks[0].name: missing required field",
            "sanitizers: missing required field",
        ]);
    });

    it("rejects unknown enum values and wrong types", () => {
        const bad = { ...sink, categories: ["rce", "sqli"], severity: "urgent", argPositions: "0" };
        expect(validateSpec({ ...spec, sinks: [bad] })).toEqual([
            "sinks[0].argPositions: expected an array",
            'sinks[0].severity: expected one of "critical", "high", "medium", "low", got "urgent"',
            expect.stringMatching(/^sinks\[0\]\.categories\[1\]: expected one of "rce", .*, got "sqli"$/),
        ]);
    });

    it("checks nested objects", () => {
        const chain = {
            ...source,
            callbackChain: { nextParamIndex: 2, sharedParamIndices: [0, 1], role: "route", path: 0 },
        };
        expect(validateSpec({ ...spec, sources: [chain] })).toEqual(["sources[0].callbackChain.path: unknown field"]);
    });

    it("requires a sanitizer scope", () => {
        const { categories: _categories, ...unscoped } = sanitizer;
        expect(validateSpec({ ...spec, sanitizers: [unscoped] })).toEqual([
            'sanitizers[0]: requires "categories" or "sinkNames"',
        ]);
    });

    it("rejects a spec that is not an object", () => {
        expect(validateSpec([spec])).toEqual(["the spec must be a JSON object"]);
    });
});
