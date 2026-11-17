/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { parseSource } from "../../src/static/parser";
import { createInstanceState, InstanceState, mergeInstanceStates } from "../../src/static/taint/taintTracker";
import { createTaint, initTaintValueHashing } from "../../src/static/taint/taintValue";

const parsed = parseSource("class Heap { left: any; right: any; next: any; deep: any; shallow: any; value: any; }");
const declaration = parsed.sourceFiles[0].statements[0] as ts.ClassDeclaration;
const type = parsed.checker.getDeclaredTypeOfSymbol(parsed.checker.getSymbolAtLocation(declaration.name!)!);
const symbol = (name: string): ts.Symbol => type.getProperty(name)!;

function value(): InstanceState {
    const state = createInstanceState();
    state.fields.set(symbol("value"), [
        createTaint(
            { kind: "callReturnValue", pattern: "boundary.input", description: "input" },
            { fileName: "/neutral/heap.ts", line: 1, column: 1, text: "input()" },
        ),
    ]);
    return state;
}

function pair(left?: InstanceState, right?: InstanceState): InstanceState {
    const state = createInstanceState();
    if (left) state.fieldInstances.set(symbol("left"), left);
    if (right) state.fieldInstances.set(symbol("right"), right);
    return state;
}

function child(state: InstanceState, name: string): InstanceState {
    const result = state.fieldInstances.get(symbol(name));
    expect(result).toBeDefined();
    return result!;
}

describe("instance graph joins", () => {
    beforeAll(async () => {
        await initTaintValueHashing();
    });

    it("a clear reaches both fields that alias in every alternative", () => {
        const first = value();
        const second = value();
        const joined = mergeInstanceStates([pair(first, first), pair(second, second)])!;
        child(joined, "left").fields.clear();
        expect(child(joined, "right").fields.size).toBe(0);
    });

    it("a write reaches both fields that alias in every alternative", () => {
        const first = createInstanceState();
        const second = createInstanceState();
        const joined = mergeInstanceStates([pair(first, first), pair(second, second)])!;
        const taints = value().fields.get(symbol("value"))!;
        child(joined, "left").fields.set(symbol("value"), taints);
        expect(child(joined, "right").fields.get(symbol("value"))).toEqual(taints);
    });

    it("missing slots do not align values from different alternatives", () => {
        const first = value();
        const second = value();
        const joined = mergeInstanceStates([pair(first), pair(second, first), pair(undefined, second)])!;
        child(joined, "left").fields.clear();
        expect(child(joined, "right").fields.get(symbol("value"))?.length).toBeGreaterThan(0);
    });

    it("duplicate inputs do not align their descendants after filtering", () => {
        const first = createInstanceState();
        const second = createInstanceState();
        first.fieldInstances.set(symbol("next"), value());
        second.fieldInstances.set(symbol("next"), value());
        const joined = mergeInstanceStates([pair(first, first), pair(first, second), pair(second, second)])!;
        child(child(joined, "left"), "next").fields.clear();
        expect(child(child(joined, "right"), "next").fields.get(symbol("value"))?.length).toBeGreaterThan(0);
    });

    it("a deep visit does not truncate a later shallow visit", () => {
        const first = createInstanceState();
        const second = createInstanceState();
        first.fieldInstances.set(symbol("next"), value());
        second.fieldInstances.set(symbol("next"), value());
        const root = (shared: InstanceState): InstanceState => {
            let deep = shared;
            for (let index = 0; index < 8; index++) {
                const parent = createInstanceState();
                parent.fieldInstances.set(symbol("next"), deep);
                deep = parent;
            }
            const result = createInstanceState();
            result.fieldInstances.set(symbol("deep"), deep);
            result.fieldInstances.set(symbol("shallow"), shared);
            return result;
        };
        const joined = mergeInstanceStates([root(first), root(second)])!;
        expect(child(child(joined, "shallow"), "next").fields.get(symbol("value"))?.length).toBeGreaterThan(0);
    });

    it("filtered closure groups retain independent captured values", () => {
        const functions = parseSource(
            "function write() {} function read() {} function other() {}",
        ).sourceFiles[0].statements.filter(ts.isFunctionDeclaration);
        const first = value();
        const second = value();
        const closure = (declaration: ts.FunctionDeclaration, target: InstanceState): InstanceState => {
            const result = createInstanceState();
            result.functions.push({
                declaration,
                captured: new Map(),
                capturedInstances: new Map([[symbol("value"), target]]),
            });
            return result;
        };
        const joined = mergeInstanceStates([
            pair(closure(functions[0], first), closure(functions[2], first)),
            pair(closure(functions[0], second), closure(functions[1], first)),
            pair(closure(functions[2], second), closure(functions[1], second)),
        ])!;
        const written = child(joined, "left").functions.find((fn) => fn.declaration === functions[0])!;
        const read = child(joined, "right").functions.find((fn) => fn.declaration === functions[1])!;
        written.capturedInstances.get(symbol("value"))!.fields.clear();
        expect(read.capturedInstances.get(symbol("value"))!.fields.get(symbol("value"))?.length).toBeGreaterThan(0);
    });

    it("cyclic inputs retain their shallow value", () => {
        const first = value();
        const second = value();
        first.fieldInstances.set(symbol("next"), first);
        second.fieldInstances.set(symbol("next"), second);
        const joined = mergeInstanceStates([pair(first, first), pair(second, second)])!;
        expect(child(child(joined, "left"), "next").fields.get(symbol("value"))?.length).toBeGreaterThan(0);
    });

    it("a join result cannot mutate a later independent join", () => {
        const first = value();
        const second = value();
        const inputs = [pair(first, first), pair(second, second)];
        const joined = mergeInstanceStates(inputs)!;
        child(joined, "left").fields.clear();
        const later = mergeInstanceStates(inputs)!;
        expect(child(later, "left").fields.get(symbol("value"))?.length).toBeGreaterThan(0);
    });
});
