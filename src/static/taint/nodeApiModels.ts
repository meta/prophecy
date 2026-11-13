/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import type { InstanceState } from "./taintTracker";
import { TaintValue } from "./taintValue";
import { unwrapExpression } from "./functionResolver";

const DEFAULTS_SLOT = "$axiosDefaults";
const DESTINATIONS = ["baseURL", "socketPath", "proxy.host", "proxy.port", "proxy.protocol"];

type NewInstance = () => InstanceState;
/** May resolve aliases only when their object has not escaped or been mutated. */
export type StableObjectLiteral = (expression: ts.Expression) => ts.ObjectLiteralExpression | undefined;

const directObject: StableObjectLiteral = (expression) => {
    const value = unwrapExpression(expression);
    return ts.isObjectLiteralExpression(value) ? value : undefined;
};

/** Resolve only immutable scalar aliases; object aliases require a use-site proof. */
function scalarValue(expression: ts.Expression, checker: ts.TypeChecker, seen = new Set<ts.Symbol>()): ts.Expression {
    const value = unwrapExpression(expression);
    if (!ts.isIdentifier(value)) return value;
    const symbol = checker.getSymbolAtLocation(value);
    if (!symbol || seen.has(symbol)) return value;
    const declaration = symbol.valueDeclaration;
    if (
        !declaration ||
        !ts.isVariableDeclaration(declaration) ||
        !declaration.initializer ||
        !ts.isVariableDeclarationList(declaration.parent) ||
        (declaration.parent.flags & ts.NodeFlags.Const) === 0
    )
        return value;
    seen.add(symbol);
    const initializer = scalarValue(declaration.initializer, checker, seen);
    return ts.isStringLiteralLike(initializer) ||
        ts.isNumericLiteral(initializer) ||
        [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(initializer.kind)
        ? initializer
        : value;
}

/** Last property wins; unknown spreads/computed keys may overwrite earlier facts. */
function propertyValue(
    object: ts.ObjectLiteralExpression,
    name: string,
    checker: ts.TypeChecker,
    resolveObject: StableObjectLiteral,
    seen = new Set<ts.ObjectLiteralExpression>(),
): ts.Expression | undefined {
    if (seen.has(object)) return undefined;
    seen.add(object);
    let result: ts.Expression | undefined;
    for (const property of object.properties) {
        if (ts.isSpreadAssignment(property)) {
            const spread = resolveObject(property.expression);
            if (!spread) result = undefined;
            else {
                // A known spread with no matching key cannot erase an earlier key.
                const value = propertyValue(spread, name, checker, resolveObject, new Set(seen));
                if (value) result = value;
                else if (
                    spread.properties.some(
                        (p) => ts.isSpreadAssignment(p) || (p.name != null && ts.isComputedPropertyName(p.name)),
                    )
                )
                    result = undefined;
            }
            continue;
        }
        if (!property.name) continue;
        const key =
            ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : undefined;
        if (key == null) {
            result = undefined;
            continue;
        }
        if (key !== name) continue;
        if (ts.isShorthandPropertyAssignment(property)) {
            const symbol = checker.getShorthandAssignmentValueSymbol(property);
            const declaration = symbol?.valueDeclaration;
            result =
                declaration &&
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer &&
                ts.isVariableDeclarationList(declaration.parent) &&
                (declaration.parent.flags & ts.NodeFlags.Const) !== 0
                    ? scalarValue(declaration.initializer, checker)
                    : undefined;
        } else {
            result = ts.isPropertyAssignment(property) ? property.initializer : undefined;
        }
    }
    return result && scalarValue(result, checker);
}

function definitelyDefined(value: ts.Expression): boolean {
    return (
        ts.isStringLiteralLike(value) ||
        ts.isNumericLiteral(value) ||
        ts.isObjectLiteralExpression(value) ||
        ts.isArrayLiteralExpression(value) ||
        ts.isArrowFunction(value) ||
        ts.isFunctionExpression(value) ||
        [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(value.kind)
    );
}

function overridesDestination(
    config: ts.Expression | undefined,
    destination: string,
    checker: ts.TypeChecker,
    resolveObject: StableObjectLiteral,
): boolean {
    // Proxy objects are deep-merged: only their explicitly replaced children
    // mask defaults. A scalar false/null replaces the entire map.
    const value = destinationValue(config, destination, checker, resolveObject);
    return value != null && definitelyDefined(value);
}

function destinationValue(
    config: ts.Expression | undefined,
    destination: string,
    checker: ts.TypeChecker,
    resolveObject: StableObjectLiteral,
): ts.Expression | undefined {
    const object = config && resolveObject(config);
    if (!object) return undefined;
    const [field, child] = destination.split(".");
    const value = propertyValue(object, field, checker, resolveObject);
    if (!value || !child) return value;
    const nested = resolveObject(value);
    return nested ? propertyValue(nested, child, checker, resolveObject) : value;
}

function definitelyConstant(value: ts.Expression | undefined): boolean {
    return (
        value != null &&
        (ts.isStringLiteralLike(value) ||
            ts.isNumericLiteral(value) ||
            [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(value.kind))
    );
}

function taintsForDestination(taints: readonly TaintValue[], destination: string): TaintValue[] {
    const expected = destination.split(".");
    return taints.filter((taint) => {
        const actual = taint.aggregatePropertyPath;
        if (!actual?.length) return true;
        return expected.every((part, index) => actual[index] == null || actual[index] === part);
    });
}

/**
 * Axios 1.13.1 mergeConfig: url/method/data are config2-only, not inherited.
 * baseURL/socketPath use defaultToConfig2; proxy uses a deep object merge.
 * Keep defaults on the ordinary instance graph so call/branch snapshots own them.
 */
export function captureAxiosDefaults(
    config: ts.Expression | undefined,
    taints: readonly TaintValue[] | undefined,
    checker: ts.TypeChecker,
    newInstance: NewInstance,
    parent?: InstanceState,
    resolveObject: StableObjectLiteral = directObject,
): InstanceState {
    const instance = newInstance();
    instance.apiTypes = ["axios"];
    const defaults = newInstance();
    const inherited = parent?.elementInstances.get(DEFAULTS_SLOT);
    for (const destination of DESTINATIONS) {
        const oldTaints = overridesDestination(config, destination, checker, resolveObject)
            ? []
            : (inherited?.elementInstances.get(destination)?.valueTaints ?? []);
        // A later literal field can replace taint introduced by an earlier
        // spread/property in the same construction expression.
        const newTaints = definitelyConstant(destinationValue(config, destination, checker, resolveObject))
            ? []
            : taintsForDestination(taints ?? [], destination);
        const values = [...oldTaints, ...newTaints];
        if (values.length > 0) {
            const value = newInstance();
            value.valueTaints = [...new Set(values)];
            defaults.elementInstances.set(destination, value);
        }
    }
    instance.elementInstances.set(DEFAULTS_SLOT, defaults);
    return instance;
}

/** Request overrides mask defaults for this call only, never mutate the client. */
export function axiosInheritedDestinationTaints(
    instance: InstanceState,
    config: ts.Expression | undefined,
    checker: ts.TypeChecker,
    resolveObject: StableObjectLiteral = directObject,
): TaintValue[] {
    const defaults = instance.elementInstances.get(DEFAULTS_SLOT);
    if (!defaults) return [];
    return [
        ...new Set(
            DESTINATIONS.flatMap((destination) =>
                overridesDestination(config, destination, checker, resolveObject)
                    ? []
                    : (defaults.elementInstances.get(destination)?.valueTaints ?? []),
            ),
        ),
    ];
}

/** Request argument layout; creation and non-request helpers have no entry. */
export function axiosRequestConfigIndex(method: string, args: readonly ts.Expression[]): number | undefined {
    if (["get", "delete", "head", "options"].includes(method)) return 1;
    if (["post", "put", "patch", "postForm", "putForm", "patchForm"].includes(method)) return 2;
    if (method === "" || method === "request") {
        const first = args[0] && unwrapExpression(args[0]);
        return first && ts.isObjectLiteralExpression(first) ? 0 : args.length > 1 ? 1 : 0;
    }
    return undefined;
}

/**
 * fs stream constructors ignore path when options.fd names an existing file
 * descriptor. Prove a nonnegative integer, including 0; null/undefined/unknown
 * are not proof. FileHandle and openSync results remain conservative here.
 */
export function hasKnownFileDescriptor(
    options: ts.Expression | undefined,
    property: string,
    checker: ts.TypeChecker,
    resolveObject: StableObjectLiteral = directObject,
): boolean {
    const object = options && resolveObject(options);
    if (!object) return false;
    const descriptor = propertyValue(object, property, checker, resolveObject);
    if (!descriptor || !ts.isNumericLiteral(descriptor)) return false;
    const value = Number(descriptor.text);
    return Number.isSafeInteger(value) && value >= 0;
}
