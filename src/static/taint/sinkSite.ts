/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";

/**
 * Location-free identity for the syntactic site a finding sinks at, e.g.
 * `FleetWatcher>start>call:spawn#0` or
 * `activate>registerCommand("ext.run")>call:terminal.sendText#1`.
 *
 * Made of the named scopes enclosing the sink, an argument-free rendering of
 * the sink expression, and the sink's ordinal among identical sites in its
 * innermost named scope. Lines and columns are deliberately absent. Adding,
 * removing, or moving an identical site earlier in that scope can change the
 * ordinal; renaming a scope or callee can also change the identity.
 */
export function sinkSiteIdentity(sinkNode: ts.Node): string {
    const cached = identityCache.get(sinkNode);
    if (cached !== undefined) return cached;

    const scopes: string[] = [];
    let innermostScope: ts.Node = sinkNode.getSourceFile();
    let foundInnermost = false;
    for (let node = sinkNode.parent; node != null; node = node.parent) {
        const name = scopeName(node);
        if (name === undefined) continue;
        scopes.push(name);
        if (!foundInnermost) {
            innermostScope = node;
            foundInnermost = true;
        }
    }
    scopes.reverse();

    const key = siteKey(sinkNode);
    const ordinal = sitesInScope(innermostScope, key).indexOf(sinkNode);
    const identity = `${scopes.length > 0 ? scopes.join(">") : "<module>"}>${key}#${ordinal}`;
    identityCache.set(sinkNode, identity);
    return identity;
}

const identityCache = new WeakMap<ts.Node, string>();
const scopeSitesCache = new WeakMap<ts.Node, Map<string, ts.Node[]>>();

/**
 * Name for a node that opens a named scope, or undefined for nodes that
 * don't. Anonymous callbacks are transparent unless they are passed alongside
 * a string literal, which covers `registerCommand("id", () => ...)` and
 * similar registration APIs.
 */
function scopeName(node: ts.Node): string | undefined {
    if (ts.isClassLike(node) || ts.isFunctionDeclaration(node)) {
        return node.name?.text;
    }
    if (ts.isConstructorDeclaration(node)) return "constructor";
    if (ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) {
        return node.name.getText();
    }
    if (!ts.isArrowFunction(node) && !ts.isFunctionExpression(node)) return undefined;

    if (ts.isFunctionExpression(node) && node.name) return node.name.text;
    const parent = node.parent;
    if (
        (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent)) &&
        parent.initializer === node
    ) {
        return parent.name.getText();
    }
    if (ts.isCallExpression(parent) && parent.arguments.includes(node)) {
        const label = parent.arguments.find(ts.isStringLiteralLike);
        if (label) return `${expressionName(parent.expression)}(${JSON.stringify(label.text)})`;
    }
    return undefined;
}

function siteKey(node: ts.Node): string {
    if (ts.isCallExpression(node)) return `call:${expressionName(node.expression)}`;
    if (ts.isNewExpression(node)) return `new:${expressionName(node.expression)}`;
    if (isAssignmentTarget(node)) return `assign:${expressionName(node as ts.Expression)}`;
    return `${ts.SyntaxKind[node.kind]}:${expressionName(node as ts.Expression)}`;
}

function isAssignmentTarget(node: ts.Node): boolean {
    return (
        ts.isBinaryExpression(node.parent) &&
        node.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        node.parent.left === node
    );
}

/**
 * Render a callee without any call arguments, so that
 * `vscode.window.createTerminal({ name }).sendText` stays the same when the
 * options object changes.
 */
function expressionName(expr: ts.Expression): string {
    if (ts.isIdentifier(expr) || ts.isPrivateIdentifier(expr)) return expr.text;
    if (expr.kind === ts.SyntaxKind.ThisKeyword) return "this";
    if (ts.isPropertyAccessExpression(expr)) {
        return `${expressionName(expr.expression)}.${expr.name.text}`;
    }
    if (ts.isElementAccessExpression(expr)) return `${expressionName(expr.expression)}[]`;
    if (ts.isCallExpression(expr)) return `${expressionName(expr.expression)}()`;
    if (
        ts.isParenthesizedExpression(expr) ||
        ts.isNonNullExpression(expr) ||
        ts.isAsExpression(expr) ||
        ts.isAwaitExpression(expr)
    ) {
        return expressionName(expr.expression);
    }
    return ts.SyntaxKind[expr.kind];
}

/**
 * Sites in `scope` sharing `key`, in source order. Nested named scopes are
 * skipped because their sites are numbered within those scopes.
 *
 * Iterative because real code nests thousands deep (long `+` chains building
 * webview HTML), which overflows the stack if walked recursively.
 */
function sitesInScope(scope: ts.Node, key: string): ts.Node[] {
    let byKey = scopeSitesCache.get(scope);
    if (!byKey) {
        byKey = new Map<string, ts.Node[]>();
        const pending: ts.Node[] = [scope];
        while (pending.length > 0) {
            const node = pending.pop()!;
            if (node !== scope && scopeName(node) !== undefined) continue;
            if (
                ts.isCallExpression(node) ||
                ts.isNewExpression(node) ||
                (node.parent != null && isAssignmentTarget(node))
            ) {
                const nodeKey = siteKey(node);
                const sites = byKey.get(nodeKey);
                if (sites) sites.push(node);
                else byKey.set(nodeKey, [node]);
            }
            const children: ts.Node[] = [];
            ts.forEachChild(node, (child) => {
                children.push(child);
            });
            for (let i = children.length - 1; i >= 0; i--) pending.push(children[i]);
        }
        scopeSitesCache.set(scope, byKey);
    }
    return byKey.get(key) ?? [];
}
