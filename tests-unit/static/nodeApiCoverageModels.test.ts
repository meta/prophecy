/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { parseSource } from "../../src/static/parser";
import { createTaint, initTaintValueHashing } from "../../src/static/taint/taintValue";
import { createInstanceState, mergeInstanceStates } from "../../src/static/taint/taintTracker";
import {
    captureAxiosDefaults,
    axiosInheritedDestinationTaints,
    hasKnownFileDescriptor,
} from "../../src/static/taint/nodeApiModels";

function expression(source: string) {
    const project = parseSource(source);
    const last = project.sourceFiles[0].statements[project.sourceFiles[0].statements.length - 1];
    if (!ts.isExpressionStatement(last)) throw new Error("Expected final expression");
    return { checker: project.checker, value: last.expression };
}

function taint(field: string) {
    return {
        ...createTaint(
            { kind: "propertyAccess", pattern: "input", description: "input" },
            { fileName: "input.ts", line: 1, column: 1 },
        ),
        aggregatePropertyPath: field.split("."),
    };
}

beforeAll(initTaintValueHashing);

describe("nodeApiCoverage pure model helpers", () => {
    it("keeps only Axios-inherited destination fields, not URL, data or proxy credentials", () => {
        const { checker } = expression("({})");
        const base = taint("baseURL");
        const instance = captureAxiosDefaults(
            undefined,
            [base, taint("url"), taint("data"), taint("proxy.auth.username")],
            checker,
            createInstanceState,
        );
        expect(axiosInheritedDestinationTaints(instance, undefined, checker)).toEqual([base]);
    });

    it.each(["({baseURL:'fixed'})", "const fixed='fixed'; ({baseURL:fixed})"])(
        "masks baseURL for a defined override: %s",
        (source) => {
            const { checker, value } = expression(source);
            const base = taint("baseURL");
            const instance = captureAxiosDefaults(undefined, [base], checker, createInstanceState);
            expect(axiosInheritedDestinationTaints(instance, value, checker)).toEqual([]);
            expect(axiosInheritedDestinationTaints(instance, undefined, checker)).toEqual([base]);
        },
    );

    it.each(["({baseURL:undefined})", "({baseURL:'fixed',...unknown})"])(
        "preserves baseURL under an uncertain override: %s",
        (source) => {
            const { checker, value } = expression(source);
            const base = taint("baseURL");
            const instance = captureAxiosDefaults(undefined, [base], checker, createInstanceState);
            expect(axiosInheritedDestinationTaints(instance, value, checker)).toEqual([base]);
        },
    );

    it("does not retain a spread default overwritten by a constant at construction", () => {
        const { checker, value } = expression("({...unknown,baseURL:'fixed'})");
        const instance = captureAxiosDefaults(value, [taint("baseURL")], checker, createInstanceState);
        expect(axiosInheritedDestinationTaints(instance, undefined, checker)).toEqual([]);
    });

    it("deep-merges proxy fields rather than replacing the map", () => {
        const { checker, value } = expression("({proxy:{host:'fixed'}})");
        const host = taint("proxy.host"),
            port = taint("proxy.port");
        const instance = captureAxiosDefaults(undefined, [host, port], checker, createInstanceState);
        expect(axiosInheritedDestinationTaints(instance, value, checker)).toEqual([port]);
    });

    it("stores per-client defaults in the graph used by branch merging", () => {
        const { checker, value } = expression("({baseURL:'fixed'})");
        const base = taint("baseURL");
        const parent = captureAxiosDefaults(undefined, [base], checker, createInstanceState);
        const child = captureAxiosDefaults(value, undefined, checker, createInstanceState, parent);
        expect(axiosInheritedDestinationTaints(child, undefined, checker)).toEqual([]);
        expect(axiosInheritedDestinationTaints(parent, undefined, checker)).toEqual([base]);
        const merged = mergeInstanceStates([parent, child])!;
        expect(axiosInheritedDestinationTaints(merged, undefined, checker)).toEqual([base]);
    });

    it.each([
        ["({fd:0})", true],
        ["const fd=3; ({fd})", true],
        ["const fd=3; ({fd:fd})", true],
        ["({fd:null})", false],
        ["({fd:undefined})", false],
        ["({fd:unknown})", false],
        ["({fd:-1})", false],
        ["({fd:0,...unknown})", false],
        ["({...unknown,fd:0})", true],
        ["const options={fd:0}; options.fd=undefined; options", false],
    ])("proves a descriptor only for %s", (source, expected) => {
        const { checker, value } = expression(source as string);
        expect(hasKnownFileDescriptor(value, "fd", checker)).toBe(expected);
    });
});
