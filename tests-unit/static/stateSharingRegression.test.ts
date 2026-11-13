/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { CopyOnWriteMap } from "../../src/static/taint/copyOnWriteMap";
import {
    createInstanceState,
    forkTaintState,
    InstanceState,
    TaintState,
    TaintTracker,
} from "../../src/static/taint/taintTracker";
import { createTaint, initTaintValueHashing } from "../../src/static/taint/taintValue";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

interface Snapshot {
    taints: TaintState;
    instanceBindings: Map<ts.Symbol, InstanceState>;
    moduleInstances: Map<ts.Symbol, InstanceState>;
    expressionInstances: Map<ts.Expression, InstanceState>;
    currentThisInstance?: InstanceState;
    cleanBindings: Set<ts.Symbol>;
}

function symbol(name: string): ts.Symbol {
    return { getName: () => name } as ts.Symbol;
}
function taint(name: string) {
    return createTaint(
        { kind: "parameter", pattern: name, description: name },
        { fileName: "/src/state.ts", line: 1, column: 1 },
    );
}
function tracker() {
    return new TaintTracker({} as ts.TypeChecker, vscodeExtensionSpec) as unknown as {
        cloneLoopAnalysisState(source: Snapshot): Snapshot;
        mergeLoopAnalysisStates(a: Snapshot, b: Snapshot): Snapshot;
        mergeLoopStates(a: TaintState, b: TaintState): TaintState;
    };
}

beforeAll(initTaintValueHashing);

describe("state sharing ownership", () => {
    it("shares unchanged storage and detaches on set, delete, clear and restore", () => {
        const state = new CopyOnWriteMap([
            ["first", 1],
            ["second", 2],
        ]);
        const branch = state.fork();
        expect(branch.storageIdentity).toBe(state.storageIdentity);
        branch.set("first", 3).set("third", 4);
        state.delete("second");
        expect([...state]).toEqual([["first", 1]]);
        expect([...branch]).toEqual([
            ["first", 3],
            ["second", 2],
            ["third", 4],
        ]);
        state.replaceWith(branch);
        expect(state.storageIdentity).toBe(branch.storageIdentity);
        branch.clear();
        expect([...state]).toHaveLength(3);
        expect(branch.size).toBe(0);
    });

    it("owns producer arrays without freezing or retaining them", () => {
        const key = symbol("value");
        const first = taint("first");
        const second = taint("second");
        const producer = [first];
        const state = forkTaintState(new Map([[key, producer]]));
        const branch = state.fork();
        producer.push(second);
        expect(Object.isFrozen(producer)).toBe(false);
        expect(state.get(key)).toEqual([first]);
        expect(branch.get(key)).toBe(state.get(key));
        expect(Object.isFrozen(branch.get(key))).toBe(true);
        const replacement = [second];
        state.set(key, replacement);
        replacement.push(first);
        expect(state.get(key)).toEqual([second]);
        expect(branch.get(key)).toEqual([first]);
        // An arbitrary sharing map is still an external producer boundary.
        const external = [first];
        const protectedState = forkTaintState(new CopyOnWriteMap([[key, external]]));
        external.push(second);
        expect(protectedState.get(key)).toEqual([first]);
    });

    it.each(["before", "after"])("keeps native iterators live and their forks isolated: %s", (order) => {
        const state = new CopyOnWriteMap([
            ["first", 1],
            ["second", 2],
        ]);
        const early = order === "before" ? state.fork() : undefined;
        const iterator = state.entries();
        expect(iterator.next().value).toEqual(["first", 1]);
        const branch = early ?? state.fork();
        state.delete("second");
        state.set("third", 3);
        expect([...iterator]).toEqual([["third", 3]]);
        expect([...branch]).toEqual([
            ["first", 1],
            ["second", 2],
        ]);
    });

    it("preserves forEach additions and delete/reinsert ordering during a fork", () => {
        const state = new CopyOnWriteMap([
            ["first", 1],
            ["second", 2],
        ]);
        const visited: string[] = [];
        let branch: CopyOnWriteMap<string, number> | undefined;
        state.forEach((value, key, map) => {
            visited.push(key);
            expect(map).toBe(state);
            if (key === "first") {
                branch = state.fork();
                state.delete("second");
                state.set("third", 3).set("second", value + 1);
            }
        });
        expect(visited).toEqual(["first", "third", "second"]);
        expect([...(branch ?? [])]).toEqual([
            ["first", 1],
            ["second", 2],
        ]);
    });

    it("keeps a returned iterator finished after a fork and writes", () => {
        const state = new CopyOnWriteMap([
            ["first", 1],
            ["second", 2],
        ]);
        const iterator = state.entries();
        expect(iterator.next().value).toEqual(["first", 1]);
        iterator.return?.();
        const branch = state.fork();
        state.set("third", 3);
        expect(iterator.next().done).toBe(true);
        expect([...branch]).toEqual([
            ["first", 1],
            ["second", 2],
        ]);
    });

    it("preserves signed numeric values and rejects invalid empty-map callbacks", () => {
        const state = new CopyOnWriteMap([["value", -0]]);
        const branch = state.fork();
        state.set("value", 0);
        expect(Object.is(state.get("value"), 0)).toBe(true);
        expect(Object.is(branch.get("value"), -0)).toBe(true);
        const empty = new CopyOnWriteMap<string, number>();
        const invalid = empty.forEach as unknown as (callback: unknown) => void;
        expect(() => invalid.call(empty, null)).toThrow(TypeError);
    });

    it("preserves the destination value ownership policy during restore", () => {
        const producer = [1];
        const source = new CopyOnWriteMap<string, readonly number[]>([["first", producer]]);
        const destination = new CopyOnWriteMap<string, readonly number[]>(undefined, (values) =>
            Object.freeze([...values]),
        );
        destination.replaceWith(source);
        producer.push(2);
        expect(destination.get("first")).toEqual([1]);
        expect(Object.isFrozen(destination.get("first"))).toBe(true);
        expect(Object.isFrozen(producer)).toBe(false);
    });

    it("keeps cyclic nested aliases and lexical-this closures separate in both write orders", () => {
        const key = symbol("command");
        const rootSymbol = symbol("root");
        const alias = symbol("alias");
        const childSymbol = symbol("child");
        const first = taint("first");
        const root = createInstanceState();
        const child = createInstanceState();
        child.fields.set(key, [first]);
        root.fieldInstances.set(childSymbol, child);
        root.elementInstances.set("0", child);
        child.fieldInstances.set(rootSymbol, root);
        const declaration = ts.createSourceFile(
            "closure.ts",
            "const fn = () => this.command;",
            ts.ScriptTarget.ES2020,
            true,
        ).statements[0] as ts.VariableStatement;
        const fn = declaration.declarationList.declarations[0].initializer as ts.ArrowFunction;
        root.functions.push({
            declaration: fn,
            captured: forkTaintState(new Map([[key, [first]]])),
            capturedInstances: new Map([[alias, child]]),
            thisInstance: child,
        });
        const source: Snapshot = {
            taints: forkTaintState(new Map()),
            instanceBindings: new Map([
                [rootSymbol, root],
                [alias, child],
            ]),
            expressionInstances: new Map(),
            currentThisInstance: child,
            cleanBindings: new Set(),
            moduleInstances: new Map([
                [rootSymbol, root],
                [alias, child],
            ]),
        };
        const fork = tracker().cloneLoopAnalysisState(source);
        const clonedRoot = fork.instanceBindings.get(rootSymbol)!;
        const clonedChild = fork.instanceBindings.get(alias)!;
        expect(clonedRoot).not.toBe(root);
        expect(clonedChild).not.toBe(child);
        expect(clonedRoot.fieldInstances.get(childSymbol)).toBe(clonedChild);
        expect(clonedRoot.elementInstances.get("0")).toBe(clonedChild);
        expect(clonedChild.fieldInstances.get(rootSymbol)).toBe(clonedRoot);
        expect(fork.currentThisInstance).toBe(clonedChild);
        expect(fork.moduleInstances.get(rootSymbol)).toBe(clonedRoot);
        expect(fork.moduleInstances.get(alias)).toBe(clonedChild);
        expect(clonedRoot.functions[0].thisInstance).toBe(clonedChild);
        expect(clonedRoot.functions[0].capturedInstances.get(alias)).toBe(clonedChild);
        child.fields.set(key, [taint("second")]);
        expect(clonedChild.fields.get(key)).toEqual([first]);
        clonedChild.fields.delete(key);
        expect(child.fields.get(key)).toHaveLength(1);
        clonedRoot.functions[0].captured.clear();
        expect(root.functions[0].captured.get(key)).toEqual([first]);
    });

    it("normalizes duplicate taints before sharing a join and invalidates that proof after writes", () => {
        const key = symbol("value");
        const first = taint("first");
        const state = forkTaintState(new Map([[key, [first, first]]]));
        const analyzer = tracker();
        const normalized = analyzer.mergeLoopStates(state, state);
        expect(normalized.get(key)).toEqual([first]);
        const branch = forkTaintState(normalized);
        const merged = analyzer.mergeLoopStates(normalized, branch);
        expect((merged as CopyOnWriteMap<ts.Symbol, readonly unknown[]>).storageIdentity).toBe(branch.storageIdentity);
        branch.set(key, [first, first, taint("second")]);
        expect(analyzer.mergeLoopStates(normalized, branch).get(key)).toHaveLength(2);
        expect(normalized.get(key)).toEqual([first]);
    });
});
