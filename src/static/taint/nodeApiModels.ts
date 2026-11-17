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
import { APIIdentityCache } from "./apiIdentity";

function provesRuntimeShape(
    expression: ts.Expression,
    checker: ts.TypeChecker,
    shape: (value: ts.Expression) => boolean,
    mutable: boolean,
    fields: readonly string[] = [],
    seen = new Set<ts.Symbol>(),
    depth = 8,
): boolean {
    if (depth === 0) return false;
    const value = unwrapExpression(expression);
    const cache = APIIdentityCache.forChecker(checker);
    const follow = (next: ts.Expression, path = fields, nextSeen = new Set(seen)): boolean =>
        provesRuntimeShape(next, checker, shape, mutable, path, nextSeen, depth - 1);
    if (ts.isAwaitExpression(value)) return follow(value.expression);
    if (ts.isConditionalExpression(value)) return follow(value.whenTrue) && follow(value.whenFalse);
    if (ts.isPropertyAccessExpression(value)) {
        return !cache.hasPropertyWrite(value) && follow(value.expression, [value.name.text, ...fields]);
    }
    if (ts.isElementAccessExpression(value) && ts.isStringLiteralLike(value.argumentExpression)) {
        return !cache.hasPropertyWrite(value) && follow(value.expression, [value.argumentExpression.text, ...fields]);
    }
    if (fields.length === 0 && shape(value)) return true;
    const fromSymbol = (symbol: ts.Symbol | undefined, path = fields): boolean => {
        if (!symbol) return false;
        if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
        if (seen.has(symbol)) return false;
        const nextSeen = new Set(seen).add(symbol);
        const declaration = symbol.valueDeclaration;
        if (!declaration || !ts.isVariableDeclaration(declaration)) return false;
        if (!mutable && (ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.Const) === 0) return false;
        const scope = ts.findAncestor(declaration, ts.isFunctionLike) ?? declaration.getSourceFile();
        const values: ts.Expression[] = declaration.initializer ? [declaration.initializer] : [];
        let unknown = false;
        const exposesSymbol = (expression: ts.Expression): boolean => {
            const node = unwrapExpression(expression);
            if (ts.isIdentifier(node)) return checker.getSymbolAtLocation(node) === symbol;
            if (ts.isObjectLiteralExpression(node))
                return node.properties.some((property) =>
                    ts.isPropertyAssignment(property)
                        ? exposesSymbol(property.initializer)
                        : ts.isShorthandPropertyAssignment(property)
                          ? checker.getShorthandAssignmentValueSymbol(property) === symbol
                          : ts.isSpreadAssignment(property)
                            ? exposesSymbol(property.expression)
                            : false,
                );
            if (ts.isArrayLiteralExpression(node))
                return node.elements.some((element) =>
                    ts.isSpreadElement(element) ? exposesSymbol(element.expression) : exposesSymbol(element),
                );
            if (ts.isConditionalExpression(node)) return exposesSymbol(node.whenTrue) || exposesSymbol(node.whenFalse);
            return false;
        };
        const visit = (node: ts.Node): void => {
            if (
                ts.isBinaryExpression(node) &&
                node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
                node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
                ts.isIdentifier(node.left) &&
                checker.getSymbolAtLocation(node.left) === symbol
            ) {
                if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken) values.push(node.right);
                else unknown = true;
            }
            if (ts.isCallExpression(node) && cache.builtinName(node.expression) === "eval") unknown = true;
            if (!mutable && ts.isCallExpression(node) && node.arguments.some(exposesSymbol)) unknown = true;
            ts.forEachChild(node, visit);
        };
        visit(scope);
        return !unknown && values.length > 0 && values.every((next) => follow(next, path, new Set(nextSeen)));
    };
    if (ts.isIdentifier(value)) return fromSymbol(checker.getSymbolAtLocation(value));
    if (ts.isObjectLiteralExpression(value) && fields.length > 0) {
        for (let index = value.properties.length - 1; index >= 0; index--) {
            const property = value.properties[index];
            if (ts.isSpreadAssignment(property)) return false;
            if (!property.name) return false;
            const name =
                ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)
                    ? property.name.text
                    : undefined;
            if (name == null) return false;
            if (name !== fields[0]) continue;
            if (ts.isPropertyAssignment(property)) return follow(property.initializer, fields.slice(1));
            if (ts.isShorthandPropertyAssignment(property))
                return fromSymbol(checker.getShorthandAssignmentValueSymbol(property), fields.slice(1));
            return false;
        }
    }
    if (ts.isCallExpression(value)) {
        const callee = unwrapExpression(value.expression);
        let symbol = checker.getSymbolAtLocation(ts.isPropertyAccessExpression(callee) ? callee.name : callee);
        if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
        const declaration = symbol?.valueDeclaration;
        const fn =
            declaration && ts.isFunctionDeclaration(declaration)
                ? declaration
                : declaration &&
                    ts.isVariableDeclaration(declaration) &&
                    declaration.initializer &&
                    (ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.Const) !== 0 &&
                    (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))
                  ? declaration.initializer
                  : undefined;
        if (!fn?.body || fn.getSourceFile().isDeclarationFile || !symbol || seen.has(symbol)) return false;
        const nextSeen = new Set(seen).add(symbol);
        if (!ts.isBlock(fn.body)) return follow(fn.body, fields, nextSeen);
        const returns: ts.Expression[] = [];
        let unknown = false;
        const visit = (node: ts.Node): void => {
            if (ts.isFunctionLike(node) && node !== fn) return;
            if (ts.isReturnStatement(node)) {
                if (node.expression) returns.push(node.expression);
                else unknown = true;
            }
            ts.forEachChild(node, visit);
        };
        visit(fn.body);
        return !unknown && returns.length > 0 && returns.every((next) => follow(next, fields, new Set(nextSeen)));
    }
    return false;
}

/** Type assertions and opaque object types cannot establish a JSON runtime body. */
export function isConstructedJsonBody(expression: ts.Expression, checker: ts.TypeChecker): boolean {
    return provesRuntimeShape(
        expression,
        checker,
        (value) => ts.isObjectLiteralExpression(value) || ts.isArrayLiteralExpression(value),
        true,
    );
}

const responseHandling = new WeakMap<ts.TypeChecker, WeakMap<ts.CallExpression, boolean>>();

/** Header setters and response escapes prevent assuming the default JSON content type. */
export function hasCustomResponseHandling(call: ts.CallExpression, checker: ts.TypeChecker): boolean {
    let results = responseHandling.get(checker);
    if (!results) {
        results = new WeakMap();
        responseHandling.set(checker, results);
    }
    const cached = results.get(call);
    if (cached != null) return cached;
    const callee = unwrapExpression(call.expression);
    const scope = ts.findAncestor(call, ts.isFunctionLike);
    if (!ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(unwrapExpression(callee.expression)) || !scope) {
        results.set(call, true);
        return true;
    }
    const cache = APIIdentityCache.forChecker(checker);
    const registration = scope.parent;
    if (!ts.isCallExpression(registration) || registration.arguments.indexOf(scope as ts.Expression) !== 1) {
        results.set(call, true);
        return true;
    }
    const registered = unwrapExpression(registration.expression);
    if (!ts.isPropertyAccessExpression(registered) || !cache.registrationName(registered)?.startsWith("express.")) {
        results.set(call, true);
        return true;
    }
    const application = cache.registrationReceiver(registered.expression);
    if (
        !("kind" in application) ||
        !ts.isCallExpression(application as ts.Node) ||
        !["express", "express.Router"].includes(
            cache.registrationName((application as ts.CallExpression).expression) ?? "",
        )
    ) {
        results.set(call, true);
        return true;
    }
    if ("getSourceFile" in application && application.getSourceFile() !== call.getSourceFile()) {
        results.set(call, true);
        return true;
    }
    const symbol = checker.getSymbolAtLocation(unwrapExpression(callee.expression));
    const declaration = symbol?.valueDeclaration;
    if (
        declaration &&
        ts.isVariableDeclaration(declaration) &&
        ((ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.Const) === 0 ||
            !declaration.initializer ||
            !ts.isIdentifier(unwrapExpression(declaration.initializer)))
    ) {
        results.set(call, true);
        return true;
    }
    if (ts.isFunctionDeclaration(scope) || ts.isMethodDeclaration(scope)) {
        results.set(call, true);
        return true;
    }
    const receiver = cache.registrationReceiver(callee.expression);
    const containsReceiver = (node: ts.Node): boolean => {
        let found = false;
        const visit = (value: ts.Node): void => {
            if (found) return;
            if (
                (ts.isIdentifier(value) || value.kind === ts.SyntaxKind.ThisKeyword) &&
                cache.registrationReceiver(value as ts.Expression) === receiver
            ) {
                found = true;
                return;
            }
            ts.forEachChild(value, visit);
        };
        visit(node);
        return found;
    };
    let custom = false;
    const visitFile = (node: ts.Node): void => {
        if (custom) return;
        if (ts.isCallExpression(node)) {
            const member = unwrapExpression(node.expression);
            if (ts.isPropertyAccessExpression(member)) {
                const method = member.name.text;
                const api = cache.registrationName(member);
                const header = node.arguments[0] && unwrapExpression(node.arguments[0]);
                if (
                    method === "use" ||
                    ["type", "contentType", "setHeader", "writeHead", "header"].includes(method) ||
                    (["set", "append"].includes(method) &&
                        (api?.startsWith("express.Response.") ||
                            (header && ts.isStringLiteralLike(header) && header.text.toLowerCase() === "content-type")))
                )
                    custom = true;
            }
        }
        ts.forEachChild(node, visitFile);
    };
    visitFile(call.getSourceFile());
    const visit = (node: ts.Node): void => {
        if (custom) return;
        if (ts.isCallExpression(node) && node !== call) {
            const member = unwrapExpression(node.expression);
            if (ts.isPropertyAccessExpression(member) && cache.registrationReceiver(member.expression) === receiver) {
                if (!["send", "sendStatus", "json", "end", "status"].includes(member.name.text)) custom = true;
            } else if (node.arguments.some(containsReceiver)) {
                custom = true;
            }
        } else if (
            ts.isBinaryExpression(node) &&
            node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
            node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
        ) {
            custom = containsReceiver(node.left) || containsReceiver(node.right);
        } else if (ts.isVariableDeclaration(node) && node.initializer && containsReceiver(node.initializer)) {
            custom =
                !ts.isIdentifier(unwrapExpression(node.initializer)) ||
                (ts.getCombinedNodeFlags(node) & ts.NodeFlags.Const) === 0;
        } else if (ts.isPropertyAssignment(node)) {
            custom = containsReceiver(node.initializer);
        } else if (ts.isReturnStatement(node) && node.expression && node.expression !== call) {
            custom = containsReceiver(node.expression);
        }
        ts.forEachChild(node, visit);
    };
    visit(scope);
    results.set(call, custom);
    return custom;
}

/** Only the native getter supplies a numeric cardinality, not a same-named data field. */
export function isBuiltinCollectionCardinality(
    expression: ts.PropertyAccessExpression,
    checker: ts.TypeChecker,
): boolean {
    if (expression.name.text !== "size") return false;
    const types = checker.getNonNullableType(checker.getTypeAtLocation(expression.expression));
    const members = types.isUnion() ? types.types : [types];
    const cache = APIIdentityCache.forChecker(checker);
    if (
        !provesRuntimeShape(
            expression.expression,
            checker,
            (value) => ts.isNewExpression(value) && ["Map", "Set"].includes(cache.builtinName(value.expression) ?? ""),
            false,
        )
    )
        return false;
    const receiver = cache.registrationReceiver(expression.expression);
    const scope = ts.findAncestor(expression, ts.isFunctionLike) ?? expression.getSourceFile();
    const exposesReceiver = (value: ts.Expression): boolean => {
        const node = unwrapExpression(value);
        if (cache.registrationReceiver(node) === receiver) return true;
        if (ts.isObjectLiteralExpression(node))
            return node.properties.some((property) =>
                ts.isPropertyAssignment(property)
                    ? exposesReceiver(property.initializer)
                    : ts.isShorthandPropertyAssignment(property)
                      ? exposesReceiver(property.name)
                      : ts.isSpreadAssignment(property)
                        ? exposesReceiver(property.expression)
                        : false,
            );
        if (ts.isArrayLiteralExpression(node))
            return node.elements.some((element) =>
                ts.isSpreadElement(element) ? exposesReceiver(element.expression) : exposesReceiver(element),
            );
        if (ts.isConditionalExpression(node)) return exposesReceiver(node.whenTrue) || exposesReceiver(node.whenFalse);
        return false;
    };
    let escaped = false;
    const visit = (node: ts.Node): void => {
        if (escaped) return;
        if (ts.isCallExpression(node)) {
            if (node.arguments.some(exposesReceiver)) escaped = true;
            const callee = unwrapExpression(node.expression);
            if (
                ts.isPropertyAccessExpression(callee) &&
                cache.registrationReceiver(callee.expression) === receiver &&
                (!["get", "has", "set", "add", "delete", "clear", "keys", "values", "entries"].includes(
                    callee.name.text,
                ) ||
                    !["Map", "Set"].some((type) => cache.matchesAPI(callee, `${type}.${callee.name.text}`)))
            )
                escaped = true;
        }
        ts.forEachChild(node, visit);
    };
    visit(scope);
    if (escaped) return false;
    return members.every((member) => {
        const declarations = member.getProperty("size")?.declarations;
        if (!declarations?.length) return false;
        return declarations.every((declaration) => {
            const owner = declaration.parent;
            if (
                !declaration.getSourceFile().hasNoDefaultLib ||
                !ts.isInterfaceDeclaration(owner) ||
                !["Map", "ReadonlyMap", "Set", "ReadonlySet"].includes(owner.name.text)
            )
                return false;
            const constructor = owner.name.text.endsWith("Map") ? "Map" : "Set";
            return (
                cache.matchesAPI(expression, `${owner.name.text}.size`) &&
                !cache.hasBuiltinWrite(constructor, expression) &&
                !cache.hasBuiltinWrite(`${constructor}.prototype.size`, expression)
            );
        });
    });
}

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
