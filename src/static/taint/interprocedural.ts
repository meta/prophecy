/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { TaintSpec, SourceSpec, CodeLocation, TaintFinding, SettingScope } from "../spec/types";
import { SettingScopes } from "../settingScopes";
import { TaintValue, createTaint, propagate } from "./taintValue";
import {
    TaintTracker,
    TaintState,
    InstanceState,
    CallArgument,
    ParameterBinding,
    AnalysisResult,
    InterproceduralContext,
    InterproceduralCallResult,
    FunctionValue,
    createInstanceState,
    expandCallArguments,
    forkTaintState,
    forkInstanceStates,
    joinCallResults,
    mergeInstanceStates,
    mergeReturnInstances,
    AnalysisCoverageLimitError,
    functionFreeSymbols,
} from "./taintTracker";
import {
    getCallChainName,
    memberFunction,
    parameterSymbol,
    resolveCommandRegistration,
    resolveFunctionReference,
    resolveStaticString,
    superClassExpression,
    unwrapExpression,
} from "./functionResolver";
import { resolveNodeLocation } from "./nodeLocation";
import { AnalysisMetrics, createAnalysisMetrics } from "../metrics";
import { callbackArgIndices, callbackParamIndices } from "../spec/sourceUtils";
import { APIIdentityCache } from "./apiIdentity";

// Limit retained call results by entry count, not bytes: findings, field state,
// and propagation chains can make individual entries large. This is not a heap
// bound. The cache is also cleared between entry points.
// PROPHECY_CACHE_ENTRIES overrides the default when it parses as a positive integer.
const MAX_CALL_RESULT_CACHE_ENTRIES = (() => {
    const env = process.env.PROPHECY_CACHE_ENTRIES;
    if (env) {
        const n = Number.parseInt(env, 10);
        if (Number.isFinite(n) && n > 0) return n;
    }
    return 1500;
})();

// Cooperative per-entry-point deadline, checked on interprocedural descent.
// Work between checkpoints can exceed it, so this is not a hard per-handler
// or whole-scan time bound. Expiry skips the current entry point.
// PROPHECY_EP_BUDGET_MS overrides the default; 0 disables the deadline.
const DEFAULT_ENTRY_POINT_BUDGET_MS = (() => {
    const env = process.env.PROPHECY_EP_BUDGET_MS;
    if (env) {
        const n = Number.parseInt(env, 10);
        if (Number.isFinite(n) && n >= 0) return n;
    }
    return 90_000;
})();

// A call to a body-less method is analyzed in every implementation the program
// declares, up to this many. Widely implemented interfaces keep unresolved-call
// passthrough instead of analyzing every implementation at each call site.
const MAX_OVERRIDE_CANDIDATES = 8;

/**
 * Two streaming 32-bit FNV-style states form a compact non-cryptographic
 * digest. This folds oversized argument-key lists without joining them into
 * one string. Digest collisions are not checked.
 */
class FnvHash {
    private h1 = 0x811c9dc5;
    private h2 = 0x01000193;

    add(part: string): this {
        for (let i = 0; i < part.length; i++) {
            const c = part.charCodeAt(i);
            this.h1 = Math.imul(this.h1 ^ c, 0x01000193);
            this.h2 = Math.imul(this.h2 ^ c, 0x85ebca6b);
        }
        // Mix a separator so ["ab","c"] and ["a","bc"] differ.
        this.h1 = Math.imul(this.h1 ^ 0x7c, 0x01000193);
        this.h2 = Math.imul(this.h2 ^ 0x7c, 0x85ebca6b);
        return this;
    }

    digest(): string {
        return (this.h1 >>> 0).toString(16) + (this.h2 >>> 0).toString(16);
    }
}

/**
 * Identifies a deadline skip without relying on an error-message match.
 */
class EntryPointTimeBudgetExceededError extends AnalysisCoverageLimitError {
    constructor(budgetMs: number) {
        super(`entry point analysis exceeded time budget (${budgetMs}ms)`);
        this.name = "EntryPointTimeBudgetExceededError";
    }
}

/**
 * Entry point discovered in a VS Code extension.
 */
export interface EntryPoint {
    kind: "uriHandler" | "command" | "eventHandler" | "activate" | "webviewMessage";
    /** The function/method node to analyze. */
    node: ts.FunctionLikeDeclaration;
    /** Tainted parameters (index → source spec). */
    taintedParams: Map<number, SourceSpec>;
    parameterTypes?: Record<number, string>;
    /** A host-ordered middleware chain, sharing request-scoped argument instances. */
    handlerChain?: RegisteredHandler[];
    /** Human-readable description. */
    description: string;
}

/**
 * An entry point that was abandoned mid-analysis (native-stack overflow on a
 * deeply nested expression, the time budget, or fixed-point saturation) and
 * therefore not fully analyzed. Surfaced in the scan output so the handlers
 * prophecy currently can't analyze are visible rather than silently dropped.
 */
export interface SkippedEntryPoint {
    /** Human-readable entry-point description (e.g. "Callback handler for onDidReceiveMessage"). */
    description: string;
    /** `file:line` of the handler, or "unknown location" if it couldn't be resolved. */
    location: string;
    /** Why analysis was abandoned (error message). */
    reason: string;
    /**
     * True when the failure was NOT one of the known coverage limits
     * (native-stack overflow, time budget, or convergence limit) — i.e. an
     * unexpected error that may indicate an analyzer bug rather than an
     * intractable handler. Surfaced distinctly so it isn't lost among the
     * routine limit skips. See `PROPHECY_STRICT` to fail hard on these.
     */
    unexpected: boolean;
}

/** Syntax preserves undefined alternatives even when strictNullChecks is disabled. */
function argumentDefaultKind(
    checker: ts.TypeChecker,
    expression: ts.Expression,
    seen: Set<ts.Symbol> = new Set(),
): "always" | "maybe" | undefined {
    const arg = unwrapExpression(expression);
    if (ts.isVoidExpression(arg)) return "always";
    if (ts.isConditionalExpression(arg)) {
        const left = argumentDefaultKind(checker, arg.whenTrue, new Set(seen));
        const right = argumentDefaultKind(checker, arg.whenFalse, new Set(seen));
        return left === "always" && right === "always" ? "always" : left || right ? "maybe" : undefined;
    }
    const type = checker.getTypeAtLocation(arg);
    const members = type.isUnion() ? type.types : [type];
    if (members.some((member) => (member.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) !== 0)) return "maybe";
    if (members.some((member) => (member.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void)) !== 0)) {
        return members.every((member) => (member.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void)) !== 0)
            ? "always"
            : "maybe";
    }
    if (ts.isIdentifier(arg)) {
        const symbol = checker.getSymbolAtLocation(arg);
        if (symbol && !seen.has(symbol)) {
            seen.add(symbol);
            for (const declaration of symbol.declarations ?? []) {
                if (ts.isVariableDeclaration(declaration) || ts.isParameter(declaration)) {
                    const annotation = declaration.type;
                    if (
                        annotation &&
                        ts.isUnionTypeNode(annotation) &&
                        annotation.types.some((member) => member.kind === ts.SyntaxKind.UndefinedKeyword)
                    )
                        return "maybe";
                    if (declaration.initializer) {
                        const kind = argumentDefaultKind(checker, declaration.initializer, seen);
                        if (kind) return "maybe";
                    }
                }
            }
        }
    }
    return undefined;
}

interface RegisteredHandler {
    node: ts.FunctionLikeDeclaration;
    source: SourceSpec;
}

interface HandlerRegistration {
    call: ts.CallExpression;
    handlers: RegisteredHandler[];
    receiver: ts.Node | ts.Symbol;
    scope: ts.Node;
    path?: string;
    dynamicPath: boolean;
}

interface HandlerMount {
    call: ts.CallExpression;
    receiver: ts.Node | ts.Symbol;
    child: ts.Node | ts.Symbol;
    scope: ts.Node;
    path: string;
}

interface CachedCallResult {
    returnTaints: TaintValue[] | undefined;
    returnUnknown?: boolean;
    returnInstanceUnknown?: boolean;
    canReturn?: boolean;
    mayThrow?: boolean;
    throwTaints?: TaintValue[];
    throwInstances?: InstanceState[];
    findings: TaintFinding[];
    fieldState: TaintState;
    clearedFieldSymbols: ts.Symbol[];
    /** Call depth the result was computed at. */
    depth: number;
    /** Some call inside was not followed because of the depth limit. */
    truncated: boolean;
}

/** Bind runtime argument positions; an unknown spread can supply any remaining parameter. */
function bindCallArguments(
    checker: ts.TypeChecker,
    declaration: ts.FunctionLikeDeclaration,
    expressions: readonly ts.Expression[],
    taints: (TaintValue[] | undefined)[],
    instances: (InstanceState | undefined)[],
): {
    taints: (TaintValue[] | undefined)[];
    instances: (InstanceState | undefined)[];
    defaults: { parameter: ts.ParameterDeclaration; conditional: boolean }[];
} {
    const expanded = expandCallArguments(expressions, taints, instances);
    const unknownIndex = expanded.findIndex((argument) => argument.unknownSpread);
    const boundTaints: (TaintValue[] | undefined)[] = [];
    const boundInstances: (InstanceState | undefined)[] = [];
    const defaults: { parameter: ts.ParameterDeclaration; conditional: boolean }[] = [];
    declaration.parameters.forEach((parameter, index) => {
        const uncertain = unknownIndex >= 0 && index >= unknownIndex;
        const rest = parameter.dotDotDotToken != null;
        const candidates = uncertain
            ? expanded.slice(unknownIndex)
            : rest
              ? expanded.slice(index)
              : expanded.slice(index, index + 1);
        const joinedTaints = candidates.flatMap((argument) => argument.taints ?? []);
        boundTaints.push(joinedTaints.length ? [...new Set(joinedTaints)] : undefined);
        if (rest) {
            const container = createInstanceState();
            candidates.forEach((argument, offset) => {
                if (!argument.instance) return;
                // Unknown spread lengths make every remaining rest index uncertain.
                // Merge into the wildcard instead of assigning a guessed offset.
                const key = uncertain || argument.unknownSpread ? "*" : String(offset);
                const prior = container.elementInstances.get(key);
                container.elementInstances.set(
                    key,
                    prior ? mergeInstanceStates([prior, argument.instance])! : argument.instance,
                );
            });
            boundInstances.push(container);
        } else {
            boundInstances.push(
                mergeInstanceStates(candidates.flatMap((argument) => (argument.instance ? [argument.instance] : []))),
            );
        }
        if (parameter.initializer) {
            const expression = expanded[index]?.expression;
            const kind = uncertain
                ? "maybe"
                : expression == null || ts.isOmittedExpression(expression)
                  ? "always"
                  : argumentDefaultKind(checker, expression);
            if (kind) defaults.push({ parameter, conditional: kind === "maybe" });
        }
    });
    return { taints: boundTaints, instances: boundInstances, defaults };
}

/**
 * Interprocedural taint analysis engine.
 * Discovers entry points in VS Code extensions, follows taint across function boundaries.
 */
export class InterproceduralAnalyzer implements InterproceduralContext {
    private checker: ts.TypeChecker;
    private spec: TaintSpec;
    private maxDepth: number;
    /** Cache of call results keyed by function identity and argument taint provenance. */
    private callResultCache: Map<string, CachedCallResult> = new Map();
    /** Number of cache hits during analysis. */
    cacheHits: number = 0;
    /** Registry mapping command names to their handlers and argument conventions. */
    private commandRegistry: Map<string, { handler: ts.FunctionLikeDeclaration; handlerParamOffset: number }> =
        new Map();
    /** Name of the entry point currently being analyzed. */
    private currentEntryPointName: string = "unknown";
    private metrics: AnalysisMetrics;
    /** Per-entry-point wall-clock budget in ms (0 disables). */
    private entryPointBudgetMs: number;
    /** Absolute deadline (Date.now() ms) for the current entry point; Infinity when disabled. */
    private epDeadlineMs: number = Infinity;
    /**
     * Closure-analysis cache shared by every TaintTracker this analyzer builds.
     * A fresh tracker per interprocedural call would otherwise re-analyze the
     * same closure once per call-site context.
     */
    private closureCache: Map<ts.Node, Map<string, boolean>> = new Map();
    /** Classes and interfaces keyed by each class or interface they directly extend or implement. */
    private subtypes: Map<ts.Symbol, (ts.ClassLikeDeclaration | ts.InterfaceDeclaration)[]> = new Map();
    private settingScopes: SettingScopes | undefined;
    private overrideCandidateCache: WeakMap<ts.Declaration, ts.FunctionLikeDeclaration[]> = new WeakMap();
    private handlerRegistrations: HandlerRegistration[] = [];
    private handlerMounts: HandlerMount[] = [];
    private continuations = new Map<string, { handlers: RegisteredHandler[]; index: number }>();
    private moduleInstances = new Map<ts.Symbol, InstanceState>();
    private usedModuleInstances = false;
    private indexedArrayFromBuiltins = false;
    private arrayFromBuiltinOverride = false;

    arrayFromBuiltinsUnmodified(): boolean {
        return this.indexedArrayFromBuiltins && !this.arrayFromBuiltinOverride;
    }

    getModuleInstanceState(): Map<ts.Symbol, InstanceState> {
        return this.moduleInstances;
    }

    setModuleInstanceState(state: Map<ts.Symbol, InstanceState>): void {
        this.moduleInstances = state;
        this.usedModuleInstances ||= state.size > 0;
    }

    /** Lazy host allocations are shared across calls, but never across entry points. */
    getModuleInstance(symbol: ts.Symbol, create: () => InstanceState): InstanceState {
        this.usedModuleInstances = true;
        let instance = this.moduleInstances.get(symbol);
        if (!instance) {
            instance = create();
            this.moduleInstances.set(symbol, instance);
        }
        return instance;
    }

    constructor(
        checker: ts.TypeChecker,
        spec: TaintSpec,
        maxDepth: number = 5,
        metrics: AnalysisMetrics = createAnalysisMetrics(),
        entryPointBudgetMs: number = DEFAULT_ENTRY_POINT_BUDGET_MS,
    ) {
        this.checker = checker;
        this.spec = spec;
        this.maxDepth = maxDepth;
        this.metrics = metrics;
        this.entryPointBudgetMs = entryPointBudgetMs;
    }

    /**
     * Cooperative per-entry-point deadline check. Called from the
     * interprocedural hot path; throws once the current entry point has
     * exceeded its wall-clock budget so `analyzeEntryPoints` can skip it.
     * See DEFAULT_ENTRY_POINT_BUDGET_MS.
     */
    private checkEntryPointBudget(): void {
        if (Date.now() > this.epDeadlineMs) {
            throw new EntryPointTimeBudgetExceededError(this.entryPointBudgetMs);
        }
    }

    getMetrics(): AnalysisMetrics {
        return this.metrics;
    }

    /**
     * Discover entry points in VS Code extension source files.
     */
    discoverEntryPoints(sourceFiles: ts.SourceFile[]): EntryPoint[] {
        const entryPoints: EntryPoint[] = [];
        this.handlerRegistrations = [];
        this.handlerMounts = [];

        for (const file of sourceFiles) {
            this.walkTree(file, (node) => this.inspectNodeForEntryPoints(node, entryPoints));
        }
        const fileOrder = new Map(sourceFiles.map((file, index) => [file, index]));
        // The receiver/arguments of a fluent registration run before the outer
        // call. AST preorder instead visits app.use(...).get(...)'s get first.
        this.handlerRegistrations.sort(
            (left, right) =>
                fileOrder.get(left.call.getSourceFile())! - fileOrder.get(right.call.getSourceFile())! ||
                left.call.end - right.call.end,
        );
        this.buildHandlerChainEntryPoints(entryPoints);
        return entryPoints;
    }

    /**
     * Build the command registry from all source files. Must be called with
     * ALL project source files (not just the main entry file) so that
     * the executeCommand → registerCommand bridge works across modules.
     */
    buildVSCodeCommandRegistry(sourceFiles: ts.SourceFile[]): void {
        for (const file of sourceFiles) {
            this.walkTree(file, (node) => this.inspectNodeForCommandRegistration(node));
        }
    }

    /** Index the setting scopes declared by the extension manifests above `sourceFiles`. */
    indexSettingScopes(sourceFiles: ts.SourceFile[]): void {
        this.settingScopes = SettingScopes.fromSourceFiles(sourceFiles);
    }

    settingScope(key: string): SettingScope | undefined {
        return this.settingScopes?.scopeOf(key);
    }

    /**
     * Index the class hierarchy used for abstract and interface dispatch.
     * Include all project source files so implementations in other modules
     * participate.
     */
    indexSubtypes(sourceFiles: ts.SourceFile[]): void {
        this.indexedArrayFromBuiltins = true;
        for (const file of sourceFiles) {
            this.walkTree(file, (node) => {
                if (!this.arrayFromBuiltinOverride && this.affectsArrayFromBuiltins(node))
                    this.arrayFromBuiltinOverride = true;
                if (!ts.isClassLike(node) && !ts.isInterfaceDeclaration(node)) return;
                for (const clause of node.heritageClauses ?? []) {
                    for (const type of clause.types) {
                        let base = this.checker.getSymbolAtLocation(type.expression);
                        if (base && base.flags & ts.SymbolFlags.Alias) base = this.checker.getAliasedSymbol(base);
                        if (!base) continue;
                        const subtypes = this.subtypes.get(base);
                        if (subtypes) subtypes.push(node);
                        else this.subtypes.set(base, [node]);
                    }
                }
            });
        }
    }

    private arrayFromErasedTypeUse(node: ts.Node): boolean {
        for (let parent = node.parent; parent; parent = parent.parent) {
            if (ts.isExpressionWithTypeArguments(parent)) {
                const heritage = parent.parent;
                return (
                    ts.isHeritageClause(heritage) &&
                    (ts.isInterfaceDeclaration(heritage.parent) || heritage.token === ts.SyntaxKind.ImplementsKeyword)
                );
            }
            if (ts.isTypeNode(parent)) return true;
            if (ts.isExpression(parent) || ts.isStatement(parent)) return false;
        }
        return false;
    }

    /** Indexed source syntax is a conservative veto, including writes in another module or later branch. */
    private affectsArrayFromBuiltins(node: ts.Node): boolean {
        const identity = APIIdentityCache.forChecker(this.checker);
        const name = (expression: ts.Expression, seen = new Set<ts.Symbol>()): string | undefined => {
            const value = unwrapExpression(expression);
            if (ts.isIdentifier(value) && ["globalThis", "global", "window", "self"].includes(value.text)) {
                const declarations = this.checker.getSymbolAtLocation(value)?.declarations;
                if (
                    (value.text === "globalThis" && !declarations?.length) ||
                    (declarations?.length &&
                        declarations.every(
                            (declaration) =>
                                declaration.getSourceFile().isDeclarationFile &&
                                (declaration.getSourceFile().hasNoDefaultLib ||
                                    (ts.isVariableDeclaration(declaration) && !declaration.initializer)),
                        ))
                )
                    return "globalThis";
            }
            if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
                const base = name(value.expression, seen);
                const key = ts.isPropertyAccessExpression(value)
                    ? value.name.text
                    : ts.isStringLiteralLike(value.argumentExpression)
                      ? value.argumentExpression.text
                      : resolveStaticString(this.checker, value.argumentExpression);
                if (base && key) return base === "globalThis" ? key : `${base}.${key}`;
            }
            if (ts.isIdentifier(value)) {
                let symbol = this.checker.getSymbolAtLocation(value);
                if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = this.checker.getAliasedSymbol(symbol);
                const declaration = symbol?.valueDeclaration;
                if (
                    symbol &&
                    !seen.has(symbol) &&
                    declaration &&
                    ts.isVariableDeclaration(declaration) &&
                    declaration.initializer
                ) {
                    seen.add(symbol);
                    return name(declaration.initializer, seen);
                }
            }
            const imported = identity.importedName(value);
            return imported && !imported.startsWith(".") ? imported : undefined;
        };
        const member = (
            expression: ts.Expression,
        ): { receiver: string | undefined; key: string | undefined } | undefined => {
            const value = unwrapExpression(expression);
            if (ts.isPropertyAccessExpression(value)) return { receiver: name(value.expression), key: value.name.text };
            if (ts.isElementAccessExpression(value)) {
                const key = unwrapExpression(value.argumentExpression);
                return {
                    receiver: name(value.expression),
                    key:
                        ts.isStringLiteralLike(key) || ts.isNumericLiteral(key)
                            ? key.text
                            : resolveStaticString(this.checker, key),
                };
            }
            return undefined;
        };
        const prototype = (receiver: string | undefined): boolean =>
            receiver === "Object.prototype" || receiver === "Array.prototype";
        const indexed = (key: string | undefined): boolean =>
            key == null || /^(0|[1-9]\d*)$/.test(key) || key === "__proto__";
        const replaced = (expression: ts.Expression): boolean => {
            const value = name(expression);
            if (value === "Array" || value === "Object.prototype" || value === "Array.prototype") return true;
            const property = member(expression);
            return (
                property != null &&
                ((property.receiver === "Array" && (property.key == null || property.key === "from")) ||
                    (prototype(property.receiver) && indexed(property.key)))
            );
        };
        if (ts.isElementAccessExpression(node) || ts.isPropertyAccessExpression(node)) {
            const property = member(node)!;
            // Exposure can lose its constructor name through literals, containers or assignments.
            if (
                ["__proto__", "prototype", "constructor"].includes(property.key ?? "") ||
                (prototype(property.receiver) && indexed(property.key)) ||
                (property.key == null && ["Array", "Object", "Reflect", "globalThis"].includes(property.receiver ?? ""))
            )
                return true;
        }
        if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
            const property = node.propertyName ?? node.name;
            const key =
                ts.isIdentifier(property) || ts.isStringLiteralLike(property)
                    ? property.text
                    : ts.isComputedPropertyName(property)
                      ? resolveStaticString(this.checker, property.expression)
                      : undefined;
            if (["__proto__", "prototype", "constructor"].includes(key ?? "")) return true;
        }
        if (ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node)) {
            const property = node.name;
            const key =
                ts.isIdentifier(property) || ts.isStringLiteralLike(property)
                    ? property.text
                    : ts.isComputedPropertyName(property)
                      ? resolveStaticString(this.checker, property.expression)
                      : undefined;
            const assignment = ts.findAncestor(
                node,
                (ancestor) =>
                    ts.isBinaryExpression(ancestor) &&
                    ancestor.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
                    ancestor.left.pos <= node.pos &&
                    ancestor.left.end >= node.end,
            );
            if (assignment && ["__proto__", "prototype", "constructor"].includes(key ?? "")) return true;
        }
        if (
            ts.isExpression(node) &&
            !this.arrayFromErasedTypeUse(node) &&
            ["Array", "Object", "Reflect", "globalThis"].includes(name(node) ?? "")
        ) {
            const parent = node.parent;
            const declaration = ts.isIdentifier(node)
                ? this.checker.getSymbolAtLocation(node)?.valueDeclaration
                : undefined;
            const declarationName = declaration && "name" in declaration ? declaration.name : undefined;
            const staticReceiver =
                (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
                parent.expression === node &&
                member(parent)?.key != null;
            const propertyName = ts.isPropertyAccessExpression(parent) && parent.name === node;
            const constAlias =
                ts.isVariableDeclaration(parent) &&
                parent.initializer === node &&
                ts.isIdentifier(parent.name) &&
                (parent.parent.flags & ts.NodeFlags.Const) !== 0 &&
                !(
                    ts.isVariableStatement(parent.parent.parent) &&
                    parent.parent.parent.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
                );
            const wrapped = ts.isExpression(parent) && unwrapExpression(parent) === node;
            if (declarationName !== node && !propertyName && !staticReceiver && !constAlias && !wrapped) return true;
        }
        if (ts.isShorthandPropertyAssignment(node)) {
            const symbol = this.checker.getShorthandAssignmentValueSymbol(node);
            if (
                symbol &&
                ["Array", "Object", "Reflect", "globalThis"].includes(symbol.name) &&
                symbol.declarations?.some((declaration) => declaration.getSourceFile().hasNoDefaultLib)
            )
                return true;
            const declaration = symbol?.valueDeclaration;
            if (
                declaration &&
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer &&
                ["Array", "Object", "Reflect", "globalThis"].includes(name(declaration.initializer) ?? "")
            )
                return true;
        }
        if (
            ts.isCallExpression(node) &&
            [
                "Object.getPrototypeOf",
                "Reflect.getPrototypeOf",
                "Reflect.get",
                "Object.getOwnPropertyDescriptor",
                "Object.getOwnPropertyDescriptors",
                "Object.prototype.__lookupGetter__",
                "Object.prototype.__lookupSetter__",
            ].includes(name(node.expression) ?? "")
        )
            return true;
        if (
            (ts.isBinaryExpression(node) &&
                node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
                node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
                replaced(node.left)) ||
            (ts.isDeleteExpression(node) && replaced(node.expression))
        )
            return true;
        return (
            ts.isCallExpression(node) &&
            node.arguments.some((argument) =>
                ["Array", "Object", "Object.prototype", "Array.prototype", "globalThis"].includes(name(argument) ?? ""),
            )
        );
    }

    /**
     * Iterative pre-order traversal avoids one stack frame per AST level.
     * Reverse child insertion preserves source order.
     */
    private walkTree(root: ts.Node, visit: (node: ts.Node) => void): void {
        const stack: ts.Node[] = [root];
        while (stack.length > 0) {
            const node = stack.pop()!;
            visit(node);
            const children: ts.Node[] = [];
            ts.forEachChild(node, (child) => {
                children.push(child);
            });
            for (let i = children.length - 1; i >= 0; i--) {
                stack.push(children[i]);
            }
        }
    }

    /**
     * Analyze entry points independently, collecting findings, warnings, and
     * failures. Per-entry-point return and field state are not retained here.
     *
     * Progress callbacks receive a one-based index and total. `onStartIteration`
     * runs before analysis; `onIteration` runs after success or a handled skip,
     * with the cumulative finding count. Callers control display throttling.
     */
    analyzeEntryPoints(
        entryPoints: EntryPoint[],
        onIteration?: (index: number, total: number, findingsSoFar: number) => void,
        onStartIteration?: (index: number, total: number, entryPoint: EntryPoint) => void,
    ): { findings: TaintFinding[]; warnings: string[]; skippedEntryPoints: SkippedEntryPoint[] } {
        const allFindings: TaintFinding[] = [];
        const allWarnings: string[] = [];
        const skippedEntryPoints: SkippedEntryPoint[] = [];

        for (let i = 0; i < entryPoints.length; i++) {
            if (onStartIteration) {
                onStartIteration(i + 1, entryPoints.length, entryPoints[i]);
            }
            try {
                const result = this.analyzeEntryPoint(entryPoints[i]);
                allFindings.push(...result.findings);
                allWarnings.push(...result.warnings);
            } catch (err) {
                // Record coverage limits separately from unexpected failures.
                // Match only stack-overflow RangeErrors: invalid array/string
                // lengths must not be classified as routine coverage limits.
                // PROPHECY_STRICT=1 rethrows unexpected failures.
                const expected =
                    (err instanceof RangeError && err.message.includes("call stack")) ||
                    err instanceof EntryPointTimeBudgetExceededError ||
                    err instanceof AnalysisCoverageLimitError;
                if (!expected && process.env.PROPHECY_STRICT === "1") {
                    throw err;
                }
                if (err instanceof AnalysisCoverageLimitError) {
                    allFindings.push(...err.findings);
                }
                skippedEntryPoints.push(this.describeSkippedEntryPoint(entryPoints[i], err, !expected));
            } finally {
                // Always clear the per-EP cache, even on a thrown EP, so a
                // partially-populated cache can't leak into the next one.
                this.clearCallResultCache();
            }
            if (onIteration) {
                onIteration(i + 1, entryPoints.length, allFindings.length);
            }
        }

        return { findings: allFindings, warnings: allWarnings, skippedEntryPoints };
    }

    /**
     * `file:line` for an entry point, or "unknown location". Public so callers
     * can filter entry points by location (see `--entry-point-filter`).
     */
    describeEntryPointLocation(entryPoint: EntryPoint): string {
        try {
            const sf = entryPoint.node.getSourceFile();
            const { line } = sf.getLineAndCharacterOfPosition(entryPoint.node.getStart());
            return `${sf.fileName}:${line + 1}`;
        } catch {
            return "unknown location";
        }
    }

    /**
     * Describe a skipped entry point after an analysis failure. Location
     * resolution is shallow enough to run after a stack overflow unwinds.
     */
    private describeSkippedEntryPoint(entryPoint: EntryPoint, err: unknown, unexpected: boolean): SkippedEntryPoint {
        // Location resolution is best-effort; never let it mask the skip.
        const location = this.describeEntryPointLocation(entryPoint);
        return {
            description: entryPoint.description,
            location,
            reason: err instanceof Error ? err.message : String(err),
            unexpected,
        };
    }

    /**
     * Analyze a single entry point.
     */
    analyzeEntryPoint(entryPoint: EntryPoint): AnalysisResult {
        this.currentEntryPointName = entryPoint.description;
        this.epDeadlineMs = this.entryPointBudgetMs > 0 ? Date.now() + this.entryPointBudgetMs : Infinity;
        this.continuations.clear();
        this.moduleInstances.clear();
        this.usedModuleInstances = false;
        if (entryPoint.handlerChain) {
            return this.analyzeHandlerChain(entryPoint.handlerChain, 0, new Map(), new Map(), 0);
        }
        const initialState: TaintState = new Map();
        const initialInstances = new Map<ts.Symbol, InstanceState>();
        const destructuredParameters: ParameterBinding[] = [];

        // Set up tainted parameters
        const params = entryPoint.node.parameters;
        for (const [index, apiType] of Object.entries(entryPoint.parameterTypes ?? {})) {
            const param = params[Number(index)];
            const symbol = param && parameterSymbol(this.checker, param);
            if (symbol) {
                const instance = createInstanceState();
                instance.apiTypes = [apiType];
                initialInstances.set(symbol, instance);
            }
        }
        for (const [paramIndex, sourceSpec] of entryPoint.taintedParams) {
            if (paramIndex < params.length) {
                const param = params[paramIndex];
                const sym = parameterSymbol(this.checker, param);
                const taints = this.parameterTaints(sourceSpec, param);
                if (param.dotDotDotToken) {
                    const instance = createInstanceState();
                    instance.apiTypes = ["Array"];
                    const first = sourceSpec.taintParamsFromIndex ?? (sourceSpec.taintAllParams ? 0 : undefined);
                    if (first != null) {
                        instance.valueTaints = taints;
                        instance.taintedElementsFromIndex = Math.max(0, first - paramIndex);
                    } else {
                        const payload = createInstanceState();
                        payload.valueTaints = taints;
                        instance.elementInstances.set(`$taint:${(sourceSpec.paramIndex ?? 0) - paramIndex}`, payload);
                    }
                    if (sym) initialInstances.set(sym, instance);
                    else destructuredParameters.push({ parameter: param, instance });
                    continue;
                }
                if (sym) {
                    initialState.set(sym, taints);
                } else {
                    destructuredParameters.push({ parameter: param, taints });
                }
            }
        }

        const body = entryPoint.node.body;
        if (!body) {
            return {
                findings: [],
                finalState: new Map(),
                returnTaints: [],
                returnInstances: [],
                warnings: [],
            };
        }

        const tracker = new TaintTracker(
            this.checker,
            this.spec,
            this,
            0,
            this.maxDepth,
            entryPoint.description,
            this.metrics,
            this.closureCache,
            initialInstances,
        );

        return tracker.analyzeFunction(body, initialState, [], destructuredParameters);
    }

    /**
     * InterproceduralContext implementation: resolve and analyze a function call.
     */
    analyzeFunctionCall(
        callExpr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
        checker: ts.TypeChecker,
        depth: number,
        callerState: TaintState,
        receiverInstance?: InstanceState,
        argInstances: (InstanceState | undefined)[] = [],
        boundFunction?: FunctionValue,
        runtimeArguments?: CallArgument[],
    ): InterproceduralCallResult | undefined {
        if (depth >= this.maxDepth) {
            this.noteDepthLimit();
            return undefined;
        }
        // Every interprocedural descent passes through here, so this is the
        // cooperative checkpoint for the per-entry-point time budget.
        this.checkEntryPointBudget();

        const inheritedFieldState = this.extractInstanceFieldState(callerState);

        // Check for executeCommand bridge: follow taint into registered command handler
        const callName = getCallChainName(callExpr.expression);
        if (!boundFunction && callName.endsWith("executeCommand") && callExpr.arguments.length >= 1) {
            const cmdNameArg = callExpr.arguments[0];
            const commandName = resolveStaticString(this.checker, cmdNameArg);
            if (commandName != null) {
                const registration = this.commandRegistry.get(commandName);
                if (registration?.handler.body) {
                    const { handler, handlerParamOffset } = registration;
                    const params = handler.parameters;
                    const enclosingState = new Map(inheritedFieldState);
                    for (const symbol of functionFreeSymbols(checker, handler)) {
                        const taints = callerState.get(symbol);
                        if (taints?.length) enclosingState.set(symbol, taints);
                    }
                    const bound = bindCallArguments(
                        checker,
                        handler,
                        [...params.slice(0, handlerParamOffset).map(() => cmdNameArg), ...callExpr.arguments.slice(1)],
                        [...params.slice(0, handlerParamOffset).map((): undefined => undefined), ...argTaints.slice(1)],
                        [
                            ...params.slice(0, handlerParamOffset).map((): undefined => undefined),
                            ...argInstances.slice(1),
                        ],
                    );
                    const defaults = bound.defaults;
                    const defaultsKey = defaults
                        .map(
                            ({ parameter, conditional }) =>
                                `${params.indexOf(parameter)}:${conditional ? "maybe" : "always"}`,
                        )
                        .join(",");
                    const handlerArgTaints = bound.taints;
                    const handlerArgInstances = bound.instances;
                    const cacheKey = this.getCallCacheKey(
                        handler,
                        handlerArgTaints,
                        enclosingState,
                        `${this.functionArgumentsCacheKey(handlerArgInstances)}#defaults:${defaultsKey}`,
                    );
                    const useCache =
                        !this.usedModuleInstances &&
                        handlerArgInstances.every((instance) => this.isCacheableArgumentInstance(instance));
                    const cached = useCache ? this.cachedCallResult(cacheKey, depth) : undefined;
                    if (cached) {
                        this.cacheHits++;
                        return {
                            returnTaints: cached.returnTaints,
                            returnUnknown: cached.returnUnknown,
                            returnInstanceUnknown: cached.returnInstanceUnknown,
                            canReturn: cached.canReturn,
                            mayThrow: cached.mayThrow,
                            throwTaints: cached.throwTaints,
                            throwInstances: cached.throwInstances,
                            findings: cached.findings,
                            fieldState: cached.fieldState,
                            clearedFieldSymbols: cached.clearedFieldSymbols,
                            truncated: cached.truncated,
                        };
                    }

                    // Map executeCommand(name, arg1, arg2, ...) to the handler,
                    // after any leading parameters injected by a wrapper.
                    const initialState: TaintState = new Map(enclosingState);
                    const initialInstances = new Map<ts.Symbol, InstanceState>();
                    const destructuredParameters: ParameterBinding[] = [];
                    for (let i = handlerParamOffset; i < params.length; i++) {
                        const param = params[i];
                        const taints = handlerArgTaints[i]?.map((taint) =>
                            propagate(
                                taint,
                                {
                                    kind: "argument",
                                    location: this.nodeLocation(callExpr),
                                    description: `passed via executeCommand('${commandName}') to command handler parameter '${param.name.getText()}'`,
                                },
                                this.metrics,
                            ),
                        );
                        const instance = handlerArgInstances[i];
                        const symbol = parameterSymbol(checker, param);
                        if (symbol) {
                            if (taints) initialState.set(symbol, taints);
                            if (instance) initialInstances.set(symbol, instance);
                        } else {
                            destructuredParameters.push({ parameter: param, taints, instance });
                        }
                    }

                    const tracker = new TaintTracker(
                        checker,
                        this.spec,
                        this,
                        depth + 1,
                        this.maxDepth,
                        this.currentEntryPointName,
                        this.metrics,
                        this.closureCache,
                        initialInstances,
                    );

                    const { result, truncated } = this.trackDepthLimit(() =>
                        tracker.analyzeFunction(handler.body!, initialState, defaults, destructuredParameters),
                    );
                    const returnTaints = result.returnTaints.length > 0 ? result.returnTaints : undefined;
                    const instanceState = mergeReturnInstances(result.returnInstances, result.returnInstanceUnknown);
                    const fieldState = this.extractInstanceFieldState(result.finalState);
                    const clearedFieldSymbols = this.clearedFieldSymbols(inheritedFieldState, fieldState);
                    if (useCache && !this.usedModuleInstances && !instanceState && !result.throwInstances?.length) {
                        this.setCachedCallResult(cacheKey, {
                            returnTaints,
                            returnUnknown: result.returnUnknown,
                            returnInstanceUnknown: result.returnInstanceUnknown,
                            canReturn: result.canReturn,
                            mayThrow: result.mayThrow,
                            throwTaints: result.throwTaints,
                            throwInstances: result.throwInstances,
                            findings: result.findings,
                            fieldState,
                            clearedFieldSymbols,
                            depth,
                            truncated,
                        });
                    }

                    return {
                        returnTaints,
                        returnUnknown: result.returnUnknown,
                        returnInstanceUnknown: result.returnInstanceUnknown,
                        canReturn: result.canReturn,
                        mayThrow: result.mayThrow,
                        throwTaints: result.throwTaints,
                        throwInstances: result.throwInstances,
                        findings: result.findings,
                        fieldState,
                        clearedFieldSymbols,
                        instanceState,
                        truncated,
                    };
                }
            }
        }

        const funcDecl = boundFunction?.declaration ?? this.resolveCallTarget(callExpr);
        const concrete = boundFunction ? undefined : this.concreteDispatchTargets(callExpr, receiverInstance);
        const exhaustive = concrete != null && !receiverInstance?.classDeclarationsUnknown;
        const overrides = boundFunction
            ? []
            : exhaustive
              ? concrete!
              : [...new Set([...(concrete || []), ...this.overrideCandidates(callExpr)])];
        if (overrides.length > 0) {
            const joined =
                overrides.length === 1
                    ? this.analyzeFunctionCall(
                          callExpr,
                          argTaints,
                          checker,
                          depth,
                          callerState,
                          receiverInstance,
                          argInstances,
                          {
                              declaration: overrides[0],
                              captured: new Map(),
                              capturedInstances: new Map(),
                              thisInstance: receiverInstance,
                          },
                          runtimeArguments,
                      )
                    : this.analyzeDispatchAlternatives(
                          callExpr,
                          overrides,
                          argTaints,
                          checker,
                          depth,
                          callerState,
                          receiverInstance,
                          argInstances,
                          runtimeArguments,
                      );
            // Only an exhaustive allocation set rules out other implementations.
            return joined && { ...joined, returnUnknown: joined.returnUnknown || !exhaustive };
        }
        if (!funcDecl?.body) return undefined;

        // A function value's captured variables are only visible to its body,
        // so they join the inherited state for both analysis and cache key.
        const enclosingState: TaintState = boundFunction
            ? new Map([...inheritedFieldState, ...boundFunction.captured])
            : inheritedFieldState;
        for (const symbol of functionFreeSymbols(checker, funcDecl)) {
            const taints = callerState.get(symbol);
            if (taints?.length && !enclosingState.has(symbol)) enclosingState.set(symbol, taints);
        }
        const calleeReceiver =
            boundFunction && ts.isArrowFunction(funcDecl) ? boundFunction.thisInstance : receiverInstance;

        const params = funcDecl.parameters;
        const bound = bindCallArguments(
            checker,
            funcDecl,
            runtimeArguments?.map((argument) => argument.expression) ?? callExpr.arguments,
            runtimeArguments?.map((argument) => argument.taints) ?? argTaints,
            runtimeArguments?.map((argument) => argument.instance) ?? argInstances,
        );
        argTaints = bound.taints;
        argInstances = bound.instances;
        const defaults = bound.defaults;
        const defaultsKey = defaults
            .map(({ parameter, conditional }) => `${params.indexOf(parameter)}:${conditional ? "maybe" : "always"}`)
            .join(",");
        const funcArgTaints = params.map((_, i) => argTaints[i]);
        const cacheKey = this.getCallCacheKey(
            funcDecl,
            funcArgTaints,
            enclosingState,
            `${this.functionArgumentsCacheKey(argInstances)}#defaults:${defaultsKey}`,
        );
        const useCache =
            !this.usedModuleInstances &&
            calleeReceiver == null &&
            (boundFunction == null || boundFunction.capturedInstances.size === 0) &&
            argInstances.every((instance) => this.isCacheableArgumentInstance(instance));
        const cached = useCache ? this.cachedCallResult(cacheKey, depth) : undefined;
        if (cached) {
            this.cacheHits++;
            return {
                returnTaints: cached.returnTaints,
                returnUnknown: cached.returnUnknown,
                returnInstanceUnknown: cached.returnInstanceUnknown,
                canReturn: cached.canReturn,
                mayThrow: cached.mayThrow,
                throwTaints: cached.throwTaints,
                throwInstances: cached.throwInstances,
                findings: cached.findings,
                fieldState: cached.fieldState,
                clearedFieldSymbols: cached.clearedFieldSymbols,
                truncated: cached.truncated,
            };
        }

        const initialState: TaintState = new Map(enclosingState);
        const initialInstances = new Map<ts.Symbol, InstanceState>(boundFunction?.capturedInstances);
        const destructuredParameters: ParameterBinding[] = [];

        for (let i = 0; i < params.length && i < argTaints.length; i++) {
            const param = params[i];
            const taints = argTaints[i]?.map((taint) =>
                propagate(
                    taint,
                    {
                        kind: "argument",
                        location: this.nodeLocation(callExpr),
                        description: `passed as argument '${param.name.getText()}' to ${callExpr.expression.getText()}()`,
                    },
                    this.metrics,
                ),
            );
            const instance = argInstances[i];
            const symbol = parameterSymbol(checker, param);
            if (symbol) {
                if (taints) initialState.set(symbol, taints);
                if (instance) initialInstances.set(symbol, instance);
            } else {
                destructuredParameters.push({ parameter: param, taints, instance });
            }
        }

        if (ts.isConstructorDeclaration(funcDecl) && receiverInstance) {
            const classType = checker.getTypeAtLocation(funcDecl.parent);
            for (let i = 0; i < params.length; i++) {
                const param = params[i];
                if (!ts.isIdentifier(param.name) || !ts.isParameterPropertyDeclaration(param, funcDecl)) {
                    continue;
                }

                const fieldSym = classType.getProperty(param.name.text);
                if (!fieldSym) continue;

                const paramSym = parameterSymbol(checker, param);
                const propertySym = checker.getSymbolAtLocation(param.name);
                const steppedTaints = paramSym ? initialState.get(paramSym) : undefined;
                if (steppedTaints) {
                    if (propertySym) initialState.set(propertySym, steppedTaints);
                    initialState.set(fieldSym, steppedTaints);
                    receiverInstance.fields.set(fieldSym, steppedTaints);
                } else {
                    initialState.delete(fieldSym);
                    receiverInstance.fields.delete(fieldSym);
                }

                const instance = argInstances[i];
                if (instance) {
                    receiverInstance.fieldInstances.set(fieldSym, instance);
                } else {
                    receiverInstance.fieldInstances.delete(fieldSym);
                }
            }
        }

        const tracker = new TaintTracker(
            checker,
            this.spec,
            this,
            depth + 1,
            this.maxDepth,
            this.currentEntryPointName,
            this.metrics,
            this.closureCache,
            initialInstances,
            calleeReceiver,
        );

        const { result, truncated } = this.trackDepthLimit(() =>
            tracker.analyzeFunction(funcDecl.body!, initialState, defaults, destructuredParameters),
        );
        const returnTaints = result.returnTaints.length > 0 ? result.returnTaints : undefined;
        const instanceState = mergeReturnInstances(result.returnInstances, result.returnInstanceUnknown);
        const fieldState = this.extractInstanceFieldState(result.finalState);
        const clearedFieldSymbols = this.clearedFieldSymbols(inheritedFieldState, fieldState);
        if (useCache && !this.usedModuleInstances && !instanceState && !result.throwInstances?.length) {
            this.setCachedCallResult(cacheKey, {
                returnTaints,
                returnUnknown: result.returnUnknown,
                returnInstanceUnknown: result.returnInstanceUnknown,
                canReturn: result.canReturn,
                mayThrow: result.mayThrow,
                throwTaints: result.throwTaints,
                throwInstances: result.throwInstances,
                findings: result.findings,
                fieldState,
                clearedFieldSymbols,
                depth,
                truncated,
            });
        }

        return {
            returnTaints,
            returnUnknown: result.returnUnknown,
            returnInstanceUnknown: result.returnInstanceUnknown,
            canReturn: result.canReturn,
            mayThrow: result.mayThrow,
            throwTaints: result.throwTaints,
            throwInstances: result.throwInstances,
            findings: result.findings,
            fieldState,
            clearedFieldSymbols,
            instanceState,
            truncated,
        };
    }

    private analyzeDispatchAlternatives(
        call: ts.CallExpression,
        declarations: ts.FunctionLikeDeclaration[],
        taints: (TaintValue[] | undefined)[],
        checker: ts.TypeChecker,
        depth: number,
        state: TaintState,
        receiver: InstanceState | undefined,
        args: (InstanceState | undefined)[],
        runtimeArguments?: CallArgument[],
    ): InterproceduralCallResult | undefined {
        const modules = [...this.moduleInstances];
        const runtimeInstances = runtimeArguments?.map((argument) => argument.instance) ?? [];
        const roots = [receiver, ...args, ...runtimeInstances, ...modules.map(([, instance]) => instance)];
        const effects = new Map<InstanceState, InstanceState[]>();
        const origins = new Map<InstanceState, InstanceState>();
        const moduleExits: Map<ts.Symbol, InstanceState>[] = [];
        const results: (InterproceduralCallResult | undefined)[] = [];
        const member = this.dispatchMember(call);
        try {
            for (const declaration of declarations) {
                const copies = new Map<InstanceState, InstanceState>();
                const forked = forkInstanceStates(roots, copies);
                const branchReceiver = forked[0];
                if (branchReceiver?.classDeclarations && member) {
                    branchReceiver.classDeclarations = branchReceiver.classDeclarations.filter(
                        (candidate) => this.methodImplementation(candidate, member.name) === declaration,
                    );
                }
                const branchArgs = forked.slice(1, 1 + args.length);
                const branchRuntime = runtimeArguments?.map((argument, index) => ({
                    ...argument,
                    instance: forked[1 + args.length + index],
                }));
                this.setModuleInstanceState(
                    new Map(
                        modules.map(([symbol], index) => [
                            symbol,
                            forked[1 + args.length + runtimeInstances.length + index]!,
                        ]),
                    ),
                );
                const result = this.analyzeFunctionCall(
                    call,
                    taints,
                    checker,
                    depth,
                    forkTaintState(state),
                    branchReceiver,
                    branchArgs,
                    { declaration, captured: new Map(), capturedInstances: new Map(), thisInstance: branchReceiver },
                    branchRuntime,
                );
                if (branchReceiver && result) {
                    for (const symbol of result.clearedFieldSymbols) branchReceiver.fields.delete(symbol);
                    for (const [symbol, values] of result.fieldState) branchReceiver.fields.set(symbol, values);
                }
                results.push(result);
                moduleExits.push(this.moduleInstances);
                for (const [original, copy] of copies) {
                    origins.set(copy, original);
                    const alternatives = effects.get(original) ?? [];
                    alternatives.push(copy);
                    effects.set(original, alternatives);
                }
            }
        } finally {
            this.setModuleInstanceState(new Map(modules));
        }
        const join = this.joinDispatchHeap(effects, origins);
        for (const alternatives of effects.values()) join(alternatives);
        const joinedModules = new Map<ts.Symbol, InstanceState>();
        for (const symbol of new Set(moduleExits.flatMap((exit) => [...exit.keys()]))) {
            const instance = join(moduleExits.flatMap((exit) => (exit.has(symbol) ? [exit.get(symbol)!] : [])));
            if (instance) joinedModules.set(symbol, instance);
        }
        this.setModuleInstanceState(joinedModules);
        return joinCallResults(
            results.map(
                (result) =>
                    result && {
                        ...result,
                        instanceState: result.instanceState && join([result.instanceState]),
                        throwInstances: result.throwInstances?.map((instance) => join([instance])!),
                    },
            ),
        );
    }

    /** Commit the joined heap only after every alternative has run in isolation. */
    private joinDispatchHeap(
        effects: Map<InstanceState, InstanceState[]>,
        origins: Map<InstanceState, InstanceState>,
    ): (instances: InstanceState[]) => InstanceState | undefined {
        const ids = new Map<InstanceState, number>();
        const joined = new Map<string, InstanceState>();
        const join = (instances: InstanceState[]): InstanceState | undefined => {
            const identities = [...new Set(instances.map((instance) => origins.get(instance) ?? instance))];
            if (!identities.length) return undefined;
            const key = identities
                .map((instance) => {
                    if (!ids.has(instance)) ids.set(instance, ids.size);
                    return ids.get(instance)!;
                })
                .sort((a, b) => a - b)
                .join(",");
            const cached = joined.get(key);
            if (cached) return cached;
            const candidates = identities.flatMap((instance) => effects.get(instance) ?? [instance]);
            const target = identities.length === 1 ? identities[0] : createInstanceState();
            joined.set(key, target);
            // Let the shared merger join scalar facts and function captures;
            // nested identity edges are rebuilt with one memo for the whole heap.
            const summary = mergeInstanceStates(
                candidates.map((instance) => ({
                    ...instance,
                    fieldInstances: new Map<ts.Symbol, InstanceState>(),
                    elementInstances: new Map<string, InstanceState>(),
                    functions: instance.functions.map((value): FunctionValue => ({
                        ...value,
                        capturedInstances: new Map<ts.Symbol, InstanceState>(),
                        thisInstance: undefined,
                    })),
                })),
            )!;
            const fieldInstances = new Map<ts.Symbol, InstanceState>();
            for (const symbol of new Set(candidates.flatMap((instance) => [...instance.fieldInstances.keys()]))) {
                fieldInstances.set(
                    symbol,
                    join(
                        candidates.flatMap((instance) =>
                            instance.fieldInstances.has(symbol) ? [instance.fieldInstances.get(symbol)!] : [],
                        ),
                    )!,
                );
            }
            const elementInstances = new Map<string, InstanceState>();
            for (const name of new Set(candidates.flatMap((instance) => [...instance.elementInstances.keys()]))) {
                elementInstances.set(
                    name,
                    join(
                        candidates.flatMap((instance) =>
                            instance.elementInstances.has(name) ? [instance.elementInstances.get(name)!] : [],
                        ),
                    )!,
                );
            }
            const functions = summary.functions.map((value) => {
                const values = candidates
                    .flatMap((instance) => instance.functions)
                    .filter((candidate) => candidate.declaration === value.declaration);
                const capturedInstances = new Map<ts.Symbol, InstanceState>();
                for (const symbol of new Set(values.flatMap((candidate) => [...candidate.capturedInstances.keys()]))) {
                    capturedInstances.set(
                        symbol,
                        join(
                            values.flatMap((candidate) =>
                                candidate.capturedInstances.has(symbol)
                                    ? [candidate.capturedInstances.get(symbol)!]
                                    : [],
                            ),
                        )!,
                    );
                }
                return {
                    ...value,
                    capturedInstances,
                    thisInstance: join(
                        values.flatMap((candidate) => (candidate.thisInstance ? [candidate.thisInstance] : [])),
                    ),
                };
            });
            Object.assign(target, summary, { fieldInstances, elementInstances, functions });
            return target;
        };
        return join;
    }

    /**
     * Resolve a constructor call (`new Foo(args)`) and analyze its body.
     * Returns field state produced by the constructor so callers can observe
     * this.field taint/sanitization performed inside the constructor.
     */
    analyzeConstructorCall(
        newExpr: ts.NewExpression,
        argTaints: (TaintValue[] | undefined)[],
        checker: ts.TypeChecker,
        depth: number,
        callerState: TaintState,
        argInstances: (InstanceState | undefined)[] = [],
    ): InterproceduralCallResult | undefined {
        if (depth >= this.maxDepth) {
            this.noteDepthLimit();
            return undefined;
        }
        this.checkEntryPointBudget();

        const classDecl = this.resolveConstructedClass(newExpr);
        const ctorDecl = this.resolveConstructorTarget(newExpr, classDecl);
        if (!ctorDecl || !ctorDecl.body) {
            if (classDecl && !classDecl.getSourceFile().isDeclarationFile) {
                const instance = createInstanceState();
                instance.classDeclarations = [classDecl];
                return {
                    returnTaints: undefined,
                    findings: [],
                    fieldState: new Map(),
                    clearedFieldSymbols: [],
                    instanceState: instance,
                };
            }
            return undefined;
        }

        const inheritedFieldState = this.extractInstanceFieldState(callerState);
        const params = ctorDecl.parameters;
        const bound = bindCallArguments(checker, ctorDecl, newExpr.arguments ?? [], argTaints, argInstances);
        argTaints = bound.taints;
        argInstances = bound.instances;

        const initialState: TaintState = new Map(inheritedFieldState);
        for (const symbol of functionFreeSymbols(checker, ctorDecl)) {
            const taints = callerState.get(symbol);
            if (taints?.length) initialState.set(symbol, taints);
        }
        const initialInstances = new Map<ts.Symbol, InstanceState>();
        const constructedInstance = createInstanceState();
        if (classDecl) constructedInstance.classDeclarations = [classDecl];
        const destructuredParameters: ParameterBinding[] = [];
        for (let i = 0; i < params.length && i < argTaints.length; i++) {
            const param = params[i];
            let steppedTaints: TaintValue[] | undefined;
            const paramSym = parameterSymbol(checker, param);
            if (argTaints[i]) {
                steppedTaints = argTaints[i]!.map((t) =>
                    propagate(
                        t,
                        {
                            kind: "argument",
                            location: this.nodeLocation(newExpr),
                            description: `passed as argument '${param.name.getText()}' to new ${newExpr.expression.getText()}()`,
                        },
                        this.metrics,
                    ),
                );
                if (paramSym) initialState.set(paramSym, steppedTaints);
            }
            if (!ts.isIdentifier(param.name)) {
                destructuredParameters.push({ parameter: param, taints: steppedTaints, instance: argInstances[i] });
            }
            const isParameterProperty =
                ts.isIdentifier(param.name) && ts.isParameterPropertyDeclaration(param, ctorDecl);
            if (isParameterProperty) {
                const classType = checker.getTypeAtLocation(ctorDecl.parent);
                const fieldSym = classType.getProperty(param.name.text);
                const propertySym = checker.getSymbolAtLocation(param.name);
                if (steppedTaints) {
                    if (propertySym) initialState.set(propertySym, steppedTaints);
                    if (fieldSym) initialState.set(fieldSym, steppedTaints);
                }
                const instance = argInstances[i];
                if (instance && paramSym) {
                    initialInstances.set(paramSym, instance);
                    if (propertySym) {
                        constructedInstance.fieldInstances.set(propertySym, instance);
                    }
                    if (fieldSym) {
                        constructedInstance.fieldInstances.set(fieldSym, instance);
                    }
                }
            } else {
                const instance = argInstances[i];
                if (instance && paramSym) {
                    initialInstances.set(paramSym, instance);
                }
            }
        }

        const tracker = new TaintTracker(
            checker,
            this.spec,
            this,
            depth + 1,
            this.maxDepth,
            this.currentEntryPointName,
            this.metrics,
            this.closureCache,
            initialInstances,
            constructedInstance,
        );

        const { result, truncated } = this.trackDepthLimit(() =>
            tracker.analyzeFunction(ctorDecl.body!, initialState, bound.defaults, destructuredParameters),
        );
        const returnTaints = result.returnTaints.length > 0 ? result.returnTaints : undefined;
        const fieldState = this.extractInstanceFieldState(result.finalState);
        constructedInstance.fields = forkTaintState(fieldState);
        const clearedFieldSymbols = this.clearedFieldSymbols(inheritedFieldState, fieldState);

        return {
            returnTaints,
            returnUnknown: result.returnUnknown,
            returnInstanceUnknown: result.returnInstanceUnknown,
            canReturn: result.canReturn,
            mayThrow: result.mayThrow,
            throwTaints: result.throwTaints,
            throwInstances: result.throwInstances,
            findings: result.findings,
            fieldState,
            clearedFieldSymbols,
            instanceState: constructedInstance,
            truncated,
        };
    }

    /**
     * Resolve a NewExpression to its constructor declaration.
     */
    private resolveConstructorTarget(
        newExpr: ts.NewExpression,
        classDecl: ts.ClassDeclaration | ts.ClassExpression | undefined,
    ): ts.ConstructorDeclaration | undefined {
        const type = this.checker.getTypeAtLocation(newExpr.expression);
        if (!type) return undefined;

        // Look for construct signatures on the type
        const constructSignatures = type.getConstructSignatures();
        if (constructSignatures.length > 0) {
            const decl = constructSignatures[0].getDeclaration();
            if (decl && ts.isConstructorDeclaration(decl)) {
                return decl;
            }
        }

        if (classDecl) {
            for (const member of classDecl.members) {
                if (ts.isConstructorDeclaration(member) && member.body) {
                    return member;
                }
            }
        }
        return undefined;
    }

    private resolveConstructedClass(newExpr: ts.NewExpression): ts.ClassDeclaration | ts.ClassExpression | undefined {
        let symbol = this.checker.getSymbolAtLocation(newExpr.expression);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
            symbol = this.checker.getAliasedSymbol(symbol);
        }
        symbol ??= this.checker.getTypeAtLocation(newExpr.expression)?.getSymbol();
        for (const declaration of symbol?.getDeclarations() ?? []) {
            if (ts.isClassDeclaration(declaration) || ts.isClassExpression(declaration)) {
                return declaration;
            }
        }
        return undefined;
    }

    /**
     * Resolve a call expression to its function declaration.
     */
    private resolveCallTarget(callExpr: ts.CallExpression): ts.FunctionLikeDeclaration | undefined {
        if (callExpr.expression.kind === ts.SyntaxKind.SuperKeyword) {
            const signatureDeclaration = this.checker.getResolvedSignature(callExpr)?.getDeclaration();
            if (signatureDeclaration && ts.isConstructorDeclaration(signatureDeclaration)) {
                return signatureDeclaration;
            }

            const extendsExpression = superClassExpression(callExpr);
            if (!extendsExpression) return undefined;

            const baseType = this.checker.getTypeAtLocation(extendsExpression);
            for (const signature of baseType.getConstructSignatures()) {
                const declaration = signature.getDeclaration();
                if (declaration && ts.isConstructorDeclaration(declaration)) {
                    return declaration;
                }
            }
            return undefined;
        }
        return resolveFunctionReference(this.checker, callExpr.expression);
    }

    hasOverrideCandidates(callExpr: ts.CallExpression): boolean {
        return this.overrideCandidates(callExpr).length > 0;
    }

    /** Explicit `super` calls select the base implementation, never an override. */
    private dispatchMember(callExpr: ts.CallExpression): { receiver: ts.Expression; name: string } | undefined {
        const callee = unwrapExpression(callExpr.expression);
        if (!ts.isPropertyAccessExpression(callee) && !ts.isElementAccessExpression(callee)) return undefined;
        if (callee.expression.kind === ts.SyntaxKind.SuperKeyword) return undefined;
        const name = ts.isPropertyAccessExpression(callee)
            ? callee.name.text
            : ts.isStringLiteralLike(callee.argumentExpression)
              ? callee.argumentExpression.text
              : undefined;
        return name == null ? undefined : { receiver: callee.expression, name };
    }

    private concreteDispatchTargets(
        callExpr: ts.CallExpression,
        receiver?: InstanceState,
    ): ts.FunctionLikeDeclaration[] | undefined {
        const member = this.dispatchMember(callExpr);
        if (!member || !receiver?.classDeclarations?.length) return undefined;
        const implementations = receiver.classDeclarations.map((declaration) =>
            this.methodImplementation(declaration, member.name),
        );
        // A missing method is not evidence for a different class's method.
        return [
            ...new Set(
                implementations.filter(
                    (implementation): implementation is ts.FunctionLikeDeclaration => implementation != null,
                ),
            ),
        ];
    }

    /** Expand an open interface/base-class dispatch within the indexed program. */
    private overrideCandidates(callExpr: ts.CallExpression): ts.FunctionLikeDeclaration[] {
        const member = this.dispatchMember(callExpr);
        if (!member) return [];
        const receiverType = this.checker.getNonNullableType(this.checker.getTypeAtLocation(member.receiver));
        const method = receiverType
            .getProperty(member.name)
            ?.getDeclarations()
            ?.find(
                (declaration) =>
                    ts.isMethodSignature(declaration) ||
                    ts.isMethodDeclaration(declaration) ||
                    ts.isPropertySignature(declaration) ||
                    ts.isPropertyDeclaration(declaration),
            );
        if (!method || method.getSourceFile().isDeclarationFile) return [];
        const cached = this.overrideCandidateCache.get(method);
        if (cached) return cached;

        const candidates = new Set<ts.FunctionLikeDeclaration>();
        const owner = method.parent;
        if (ts.isClassLike(owner)) {
            const implementation = this.methodImplementation(owner, member.name);
            if (implementation) candidates.add(implementation);
        }
        const ownerSymbol =
            (ts.isClassLike(owner) || ts.isInterfaceDeclaration(owner)) && owner.name
                ? this.checker.getSymbolAtLocation(owner.name)
                : undefined;
        const pending = ownerSymbol ? [ownerSymbol] : [];
        const visited = new Set(pending);
        while (pending.length > 0 && candidates.size <= MAX_OVERRIDE_CANDIDATES) {
            for (const subtype of this.subtypes.get(pending.pop()!) ?? []) {
                const implementation = ts.isClassLike(subtype)
                    ? this.methodImplementation(subtype, member.name)
                    : undefined;
                if (implementation) candidates.add(implementation);
                const symbol = subtype.name && this.checker.getSymbolAtLocation(subtype.name);
                if (symbol && !visited.has(symbol)) {
                    visited.add(symbol);
                    pending.push(symbol);
                }
            }
        }
        const result = candidates.size <= MAX_OVERRIDE_CANDIDATES ? [...candidates] : [];
        // An ordinary body with no alternative implementation needs no open-
        // hierarchy join; preserve its precise return summary.
        if (ts.isClassLike(owner) && result.length === 1 && result[0] === this.methodImplementation(owner, member.name))
            result.length = 0;
        this.overrideCandidateCache.set(method, result);
        return result;
    }

    /** The method body instances of `classDecl` run for `name`, declared or inherited. */
    private methodImplementation(
        classDecl: ts.ClassLikeDeclaration,
        name: string,
    ): ts.FunctionLikeDeclaration | undefined {
        const instanceType = ts.isClassDeclaration(classDecl)
            ? this.checker.getTypeAtLocation(classDecl)
            : this.checker.getTypeAtLocation(classDecl).getConstructSignatures()[0]?.getReturnType();
        for (const declaration of instanceType?.getProperty(name)?.getDeclarations() ?? []) {
            if (declaration.getSourceFile().isDeclarationFile) continue;
            if (ts.isMethodDeclaration(declaration) && declaration.body) return declaration;
            if (
                ts.isPropertyDeclaration(declaration) &&
                declaration.initializer &&
                (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))
            ) {
                return declaration.initializer;
            }
        }
        return undefined;
    }

    /**
     * Inspect a single AST node for entry points. The tree is walked
     * iteratively by `walkTree` (which calls this per node), so this method
     * must NOT recurse into children itself.
     */
    private inspectNodeForEntryPoints(node: ts.Node, entryPoints: EntryPoint[]): void {
        if (
            (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) &&
            node.name &&
            this.spec.entryFunctions?.includes(node.name.text)
        ) {
            entryPoints.push({
                kind: "activate",
                node,
                taintedParams: new Map(),
                description: `Entry function: ${node.name.text}()`,
            });
        }

        if (ts.isCallExpression(node)) {
            // Registered commands are code-reachable entry points, but command
            // registration is not itself an attacker boundary. Parameters stay
            // clean unless taint arrives through an explicit invocation bridge
            // such as executeCommand(name, ...taintedArgs).
            this.extractCommandEntryPoint(node, entryPoints);

            const callName = getCallChainName(node.expression);

            // Registrations whose argument is an object/class with a handler
            // METHOD (registerUriHandler, debug providers/factories).
            this.extractMethodHandlerEntryPoints(node, entryPoints);

            // Handler methods the host calls with clean parameters (language
            // feature providers).
            for (const handler of this.spec.handlerEntryPoints ?? []) {
                if (!callName.endsWith(handler.registration) || node.arguments.length <= handler.argIndex) continue;
                for (const method of this.resolveHandlerMethods(node.arguments[handler.argIndex], handler.method)) {
                    entryPoints.push({
                        kind: "eventHandler",
                        node: method,
                        taintedParams: new Map(),
                        description: handler.description,
                    });
                }
            }

            this.extractGenericCallbackEntryPoints(node, entryPoints);

            // Event callbacks: .on/.once/.addListener('message', handler)
            if (this.isMessageEventCallback(callName, node)) {
                this.extractMessageCallbackEntryPoint(node, entryPoints);
            }
        }
    }

    private extractCommandEntryPoint(callExpr: ts.CallExpression, entryPoints: EntryPoint[]): void {
        const registration = resolveCommandRegistration(this.checker, callExpr);
        if (!registration) return;

        const handler = resolveFunctionReference(this.checker, registration.handler);
        if (!handler) return;

        entryPoints.push({
            kind: "command",
            node: handler,
            taintedParams: new Map(),
            description: "Callback handler for registerCommand",
        });
    }

    /**
     * Generic callback entry point extraction driven by the spec.
     * Matches calls against all callbackRegistration patterns in the spec's sources.
     */
    private extractGenericCallbackEntryPoints(callExpr: ts.CallExpression, entryPoints: EntryPoint[]): void {
        for (const source of this.spec.sources) {
            if (!source.callbackRegistration) continue;
            if (source.callbackSource === "call") continue;
            // Skip method-on-object handlers — handled by
            // extractMethodHandlerEntryPoints above.
            if (source.handlerMethod) continue;
            // Skip onMessage — handled by isMessageEventCallback
            if (source.callbackRegistration === "onMessage") continue;

            if (!this.registrationMatches(source, callExpr)) continue;
            if (source.callbackChain) {
                const handlers = callbackArgIndices(source, callExpr.arguments.length).flatMap((index) =>
                    callExpr.arguments[index] ? this.callbackHandlers(callExpr.arguments[index]) : [],
                );
                if (handlers.length === 0) this.recordHandlerMount(source, callExpr);
                this.recordHandlerRegistration(source, callExpr, handlers);
                continue;
            }

            for (const callbackArgIdx of callbackArgIndices(source, callExpr.arguments.length)) {
                if (callExpr.arguments.length <= callbackArgIdx) continue;

                const handler = callExpr.arguments[callbackArgIdx];
                for (const funcDecl of this.callbackHandlers(handler)) {
                    const taintedParams = new Map(
                        callbackParamIndices(
                            source,
                            funcDecl.parameters.length,
                            funcDecl.parameters.findIndex((parameter) => parameter.dotDotDotToken != null),
                        ).map((index): [number, SourceSpec] => [index, source]),
                    );
                    if (taintedParams.size > 0) {
                        entryPoints.push({
                            kind: "eventHandler",
                            node: funcDecl,
                            taintedParams,
                            parameterTypes: source.callbackParameterTypes,
                            description:
                                source.entryPointDescription ?? `Callback handler for ${source.callbackRegistration}`,
                        });
                    }
                }
            }
        }
    }

    /** Associate only statically identical receivers in one registration scope. */
    private registrationReceiver(expression: ts.Expression): ts.Node | ts.Symbol {
        const value = unwrapExpression(expression);
        // Custom callback-chain specs can model fluent APIs beyond the built-in identities.
        if (ts.isCallExpression(value) && ts.isPropertyAccessExpression(value.expression)) {
            const resultName = APIIdentityCache.forChecker(this.checker).registrationName(value);
            const fluent = this.spec.sources.some(
                (source) =>
                    source.callbackChain &&
                    (this.registrationMatches(source, value) ||
                        (source.callbackChain.receiverPathArgIndex != null &&
                            resultName != null &&
                            source.callbackRegistration?.startsWith(`${resultName}.`))),
            );
            if (fluent) return this.registrationReceiver(value.expression.expression);
        }
        return APIIdentityCache.forChecker(this.checker).registrationReceiver(value);
    }

    private recordHandlerMount(source: SourceSpec, call: ts.CallExpression): void {
        const model = source.callbackChain;
        const callee = unwrapExpression(call.expression);
        if (
            !model?.mountReceiverTypes?.length ||
            model.role !== "middleware" ||
            (!ts.isPropertyAccessExpression(callee) && !ts.isElementAccessExpression(callee)) ||
            call.arguments.length < 1 ||
            call.arguments.length > 2
        )
            return;
        const child = call.arguments[call.arguments.length - 1];
        const apiType = APIIdentityCache.forChecker(this.checker).registrationName(child);
        if (!apiType || !model.mountReceiverTypes.includes(apiType)) return;
        const path = call.arguments.length === 1 ? "/" : resolveStaticString(this.checker, call.arguments[0]);
        // Parameterized/regexp mounts require routing predicates, not string concatenation.
        if (path == null || !path.startsWith("/") || /[:*?()+[\]]/.test(path)) return;
        this.handlerMounts.push({
            call,
            receiver: this.registrationReceiver(callee.expression),
            child: this.registrationReceiver(child),
            scope: ts.findAncestor(call, (node) => ts.isFunctionLike(node)) ?? call.getSourceFile(),
            path: path.replace(/\/+$/, ""),
        });
    }

    private recordHandlerRegistration(
        source: SourceSpec,
        call: ts.CallExpression,
        nodes: ts.FunctionLikeDeclaration[],
    ): void {
        const callee = unwrapExpression(call.expression);
        if (!nodes.length || (!ts.isPropertyAccessExpression(callee) && !ts.isElementAccessExpression(callee))) return;
        const model = source.callbackChain!;
        nodes = nodes.filter((node) => !model.excludedHandlerArities?.includes(node.parameters.length));
        if (!nodes.length) return;
        let pathArg = model.pathArgIndex == null ? undefined : call.arguments[model.pathArgIndex];
        if (model.receiverPathArgIndex != null) {
            const receiver = unwrapExpression(callee.expression);
            if (ts.isCallExpression(receiver)) pathArg = receiver.arguments[model.receiverPathArgIndex];
        }
        const path = pathArg && resolveStaticString(this.checker, pathArg);
        const isHandler = pathArg && this.callbackHandlers(pathArg).length > 0;
        const dynamicPath = pathArg != null && path == null && !isHandler;
        this.handlerRegistrations.push({
            call,
            handlers: nodes.map((node) => ({ node, source })),
            receiver: this.registrationReceiver(callee.expression),
            scope: ts.findAncestor(call, (node) => ts.isFunctionLike(node)) ?? call.getSourceFile(),
            path,
            dynamicPath,
        });
    }

    private buildHandlerChainEntryPoints(entryPoints: EntryPoint[]): void {
        const used = new Set<HandlerRegistration>();
        const append = (handlers: RegisteredHandler[]) => {
            const first = handlers[0];
            entryPoints.push({
                kind: "eventHandler",
                node: first.node,
                taintedParams: new Map(
                    callbackParamIndices(first.source, first.node.parameters.length).map(
                        (index): [number, SourceSpec] => [index, first.source],
                    ),
                ),
                handlerChain: handlers,
                description:
                    handlers[handlers.length - 1].source.entryPointDescription ??
                    `Handler chain for ${handlers[handlers.length - 1].source.callbackRegistration}`,
            });
        };
        this.handlerRegistrations.forEach((registration, index) => {
            if (registration.handlers[0].source.callbackChain!.role !== "route") return;
            const middleware = this.handlerRegistrations.slice(0, index).filter((candidate) => {
                if (
                    candidate.receiver !== registration.receiver ||
                    candidate.scope !== registration.scope ||
                    candidate.handlers[0].source.callbackChain!.role !== "middleware"
                )
                    return false;
                if (candidate.dynamicPath || registration.dynamicPath) return false;
                return (
                    candidate.path == null ||
                    candidate.path === "/" ||
                    registration.path === candidate.path ||
                    registration.path?.startsWith(`${candidate.path}/`)
                );
            });
            const mounts =
                registration.path != null && !registration.dynamicPath
                    ? this.handlerMounts.filter(
                          (mount) =>
                              mount.child === registration.receiver &&
                              mount.scope === registration.scope &&
                              mount.receiver !== mount.child,
                      )
                    : [];
            middleware.forEach((candidate) => used.add(candidate));
            if (mounts.length === 0) {
                append([...middleware.flatMap((candidate) => candidate.handlers), ...registration.handlers]);
            } else {
                for (const mount of mounts) {
                    const mountedPath = `${mount.path}${registration.path}`;
                    const parents = this.handlerRegistrations.filter(
                        (candidate) =>
                            candidate.receiver === mount.receiver &&
                            candidate.scope === mount.scope &&
                            candidate.call.end < mount.call.end &&
                            !candidate.dynamicPath &&
                            candidate.handlers[0].source.callbackChain!.role === "middleware" &&
                            (candidate.path == null ||
                                candidate.path === "/" ||
                                candidate.path === mountedPath ||
                                mountedPath.startsWith(`${candidate.path}/`)),
                    );
                    parents.forEach((candidate) => used.add(candidate));
                    append([
                        ...parents.flatMap((candidate) => candidate.handlers),
                        ...middleware.flatMap((candidate) => candidate.handlers),
                        ...registration.handlers,
                    ]);
                }
            }
        });
        for (const registration of this.handlerRegistrations) {
            if (registration.handlers[0].source.callbackChain!.role !== "middleware" || used.has(registration))
                continue;
            // Middleware-only applications have no terminal route registration.
            // Combine their exact static scope/path groups without inventing
            // ordering across modules or dynamic mount paths.
            const group = registration.dynamicPath
                ? [registration]
                : this.handlerRegistrations.filter(
                      (candidate) =>
                          !used.has(candidate) &&
                          !candidate.dynamicPath &&
                          candidate.receiver === registration.receiver &&
                          candidate.scope === registration.scope &&
                          candidate.path === registration.path &&
                          candidate.handlers[0].source.callbackChain!.role === "middleware",
                  );
            group.forEach((candidate) => used.add(candidate));
            append(group.flatMap((candidate) => candidate.handlers));
        }
    }

    private analyzeHandlerChain(
        handlers: RegisteredHandler[],
        index: number,
        shared: Map<number, InstanceState>,
        callerState: TaintState,
        depth: number,
        call?: ts.CallExpression,
    ): AnalysisResult {
        this.checkEntryPointBudget();
        const { node, source } = handlers[index];
        const model = source.callbackChain!;
        const initialState: TaintState = new Map();
        for (const symbol of functionFreeSymbols(this.checker, node)) {
            const taints = callerState.get(symbol);
            if (taints) initialState.set(symbol, taints);
        }
        const instances = new Map<ts.Symbol, InstanceState>();
        const bindings: ParameterBinding[] = [];
        const taintedIndices = callbackParamIndices(source, node.parameters.length);
        for (const paramIndex of model.sharedParamIndices) {
            if (!shared.has(paramIndex)) {
                const instance = createInstanceState();
                const param = node.parameters[paramIndex];
                if (param && taintedIndices.includes(paramIndex))
                    instance.valueTaints = this.parameterTaints(source, param);
                shared.set(paramIndex, instance);
            }
        }
        for (const [paramIndex, paths] of Object.entries(model.sharedParamProperties ?? {})) {
            for (const path of paths) {
                let instance = shared.get(Number(paramIndex));
                for (const name of path) {
                    if (!instance) break;
                    let nested = instance.elementInstances.get(name);
                    if (!nested) {
                        nested = createInstanceState();
                        instance.elementInstances.set(name, nested);
                    }
                    instance = nested;
                }
            }
        }
        const continuation = createInstanceState();
        const token = String(this.continuations.size);
        continuation.hostCallback = token;
        for (const [paramIndex, instance] of shared)
            continuation.elementInstances.set(`$param:${paramIndex}`, instance);
        this.continuations.set(token, { handlers, index: index + 1 });
        node.parameters.forEach((parameter, paramIndex) => {
            const instance = paramIndex === model.nextParamIndex ? continuation : shared.get(paramIndex);
            const apiType = source.callbackParameterTypes?.[paramIndex];
            if (instance && apiType) instance.apiTypes = [apiType];
            let taints = instance?.valueTaints
                ? [...instance.valueTaints]
                : taintedIndices.includes(paramIndex)
                  ? this.parameterTaints(source, parameter)
                  : undefined;
            if (call && taints)
                taints = taints.map((taint) =>
                    propagate(
                        taint,
                        {
                            kind: "argument",
                            location: this.nodeLocation(call),
                            description: `passed through middleware continuation to '${parameter.name.getText()}'`,
                        },
                        this.metrics,
                    ),
                );
            const symbol = parameterSymbol(this.checker, parameter);
            if (symbol) {
                if (instance) instances.set(symbol, instance);
                if (taints) initialState.set(symbol, taints);
            } else {
                bindings.push({ parameter, instance, taints });
            }
        });
        const tracker = new TaintTracker(
            this.checker,
            this.spec,
            this,
            depth,
            this.maxDepth,
            this.currentEntryPointName,
            this.metrics,
            this.closureCache,
            instances,
        );
        return node.body
            ? tracker.analyzeFunction(node.body, initialState, [], bindings)
            : {
                  findings: [],
                  finalState: new Map(),
                  returnTaints: [],
                  returnInstances: [],
                  warnings: [],
              };
    }

    analyzeHostCallback(
        call: ts.CallExpression,
        functionInstance: InstanceState,
        callerState: TaintState,
        depth: number,
    ): InterproceduralCallResult | undefined {
        const continuation =
            functionInstance.hostCallback == null ? undefined : this.continuations.get(functionInstance.hostCallback);
        if (!continuation) return undefined;
        const empty: InterproceduralCallResult = {
            findings: [],
            fieldState: new Map(),
            clearedFieldSymbols: [],
            returnTaints: undefined,
        };
        // Error/route-skipping continuations are not normal handler succession.
        const argument = call.arguments[0];
        const normal = argument == null || this.isFalsyContinuationArgument(argument);
        if (!normal || continuation.index >= continuation.handlers.length) return empty;
        if (depth >= this.maxDepth) {
            this.noteDepthLimit();
            return { ...empty, truncated: true };
        }
        const shared = new Map<number, InstanceState>();
        for (const [key, instance] of functionInstance.elementInstances) {
            if (key.startsWith("$param:")) shared.set(Number(key.slice(7)), instance);
        }
        const { result, truncated } = this.trackDepthLimit(() =>
            this.analyzeHandlerChain(continuation.handlers, continuation.index, shared, callerState, depth + 1, call),
        );
        return {
            ...empty,
            findings: result.findings,
            truncated,
            canReturn: result.canReturn,
            mayThrow: result.mayThrow,
            throwTaints: result.throwTaints,
            throwInstances: result.throwInstances,
        };
    }

    private isFalsyContinuationArgument(argument: ts.Expression): boolean {
        const value = unwrapExpression(argument);
        if (
            value.kind === ts.SyntaxKind.NullKeyword ||
            value.kind === ts.SyntaxKind.FalseKeyword ||
            ts.isVoidExpression(value) ||
            argumentDefaultKind(this.checker, value) === "always"
        )
            return true;
        if (ts.isStringLiteralLike(value)) return value.text === "";
        if (ts.isBigIntLiteral(value)) return Number(value.text.slice(0, -1)) === 0;
        if (ts.isPrefixUnaryExpression(value) && ts.isNumericLiteral(value.operand)) {
            return (
                (value.operator === ts.SyntaxKind.MinusToken || value.operator === ts.SyntaxKind.PlusToken) &&
                Number(value.operand.text) === 0
            );
        }
        const type = this.checker.getTypeAtLocation(value);
        if (type.isNumberLiteral()) return type.value === 0;
        if (type.isStringLiteral()) return type.value === "";
        return (type.flags & ts.TypeFlags.BooleanLiteral) !== 0 && this.checker.typeToString(type) === "false";
    }

    private parameterTaints(source: SourceSpec, param: ts.ParameterDeclaration): TaintValue[] {
        const taint = createTaint(source, this.nodeLocation(param), this.metrics);
        return source.paramPropertyPaths
            ? source.paramPropertyPaths.map((path) => ({
                  ...taint,
                  sourceCacheKey: `${taint.sourceCacheKey}#path:${JSON.stringify(path)}`,
                  aggregatePropertyPath: path,
                  cacheKey: `${taint.cacheKey}#path:${JSON.stringify(path)}`,
              }))
            : [taint];
    }

    private registrationMatches(source: SourceSpec, call: ts.CallExpression): boolean {
        if (!source.callbackRegistration) return false;
        const matches =
            source.callbackMatch === "api"
                ? APIIdentityCache.forChecker(this.checker).registrationMatches(
                      call.expression,
                      source.callbackRegistration,
                  )
                : getCallChainName(call.expression).endsWith(source.callbackRegistration);
        return (
            matches &&
            Object.entries(source.callbackArgumentValues ?? {}).every(([index, values]) => {
                const arg = call.arguments[Number(index)];
                const value = arg && resolveStaticString(this.checker, arg);
                return value != null && values.includes(value);
            })
        );
    }

    private callbackHandlers(expression: ts.Expression, seen = new Set<ts.Node>()): ts.FunctionLikeDeclaration[] {
        const value = unwrapExpression(expression);
        if (seen.has(value)) return [];
        seen.add(value);
        const handler = resolveFunctionReference(this.checker, value);
        if (handler) return [handler];
        if (ts.isArrayLiteralExpression(value)) {
            return value.elements.flatMap((element) =>
                this.callbackHandlers(ts.isSpreadElement(element) ? element.expression : element, seen),
            );
        }
        if (ts.isIdentifier(value)) {
            let symbol = this.checker.getSymbolAtLocation(value);
            if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = this.checker.getAliasedSymbol(symbol);
            const declaration = symbol?.valueDeclaration;
            if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
                return this.callbackHandlers(declaration.initializer, seen);
            }
        }
        return [];
    }

    /**
     * Extract a handler METHOD from a registration call whose argument is an
     * object or class instance rather than a bare function — e.g.
     *   vscode.window.registerUriHandler({ handleUri(uri) {...} })
     *   vscode.debug.registerDebugAdapterDescriptorFactory(type, new Factory())
     *
     * Spec-driven via `SourceSpec.handlerMethod`. Four shapes appear in real
     * code and all four have to be resolved: an object literal; a variable
     * holding one; a variable holding `new SomeClass()`; and `new SomeClass()`
     * passed inline. Class references are alias-resolved, since the class is
     * usually imported from another module.
     */
    private extractMethodHandlerEntryPoints(callExpr: ts.CallExpression, entryPoints: EntryPoint[]): void {
        for (const source of this.spec.sources) {
            if (!source.callbackRegistration || !source.handlerMethod) continue;
            if (!this.registrationMatches(source, callExpr)) continue;

            const argIdx = source.callbackArgIndex ?? 0;
            if (callExpr.arguments.length <= argIdx) continue;
            const arg = callExpr.arguments[argIdx];

            for (const method of this.resolveHandlerMethods(arg, source.handlerMethod)) {
                const indices = callbackParamIndices(
                    source,
                    method.parameters.length,
                    method.parameters.findIndex((parameter) => parameter.dotDotDotToken != null),
                );
                if (!indices.length) continue;
                entryPoints.push({
                    kind: "uriHandler",
                    node: method,
                    taintedParams: new Map(indices.map((index): [number, SourceSpec] => [index, source])),
                    parameterTypes: source.callbackParameterTypes,
                    description:
                        source.entryPointDescription ??
                        `Handler method ${source.handlerMethod} (${source.callbackRegistration})`,
                });
            }
        }
    }

    /**
     * Find the functions `arg` resolves to that the host calls as `methodName`:
     * methods, and properties initialized with a function.
     */
    private resolveHandlerMethods(
        arg: ts.Expression,
        methodName: string,
        seen = new Set<ts.Node>(),
    ): ts.FunctionLikeDeclaration[] {
        arg = unwrapExpression(arg);
        if (seen.has(arg)) return [];
        seen.add(arg);
        const found: ts.FunctionLikeDeclaration[] = [];

        const fromMembers = (members: readonly (ts.ClassElement | ts.ObjectLiteralElementLike)[]) => {
            for (const member of members) {
                if (
                    !member.name ||
                    (!ts.isIdentifier(member.name) && !ts.isStringLiteralLike(member.name)) ||
                    member.name.text !== methodName
                )
                    continue;
                const handler = memberFunction(member);
                if (handler) found.push(handler);
                else if (ts.isPropertyAssignment(member) || ts.isPropertyDeclaration(member)) {
                    if (member.initializer) found.push(...this.callbackHandlers(member.initializer));
                } else if (ts.isShorthandPropertyAssignment(member)) {
                    let symbol = this.checker.getShorthandAssignmentValueSymbol(member);
                    if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = this.checker.getAliasedSymbol(symbol);
                    for (const declaration of symbol?.declarations ?? []) {
                        if (ts.isFunctionDeclaration(declaration)) found.push(declaration);
                        if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
                            found.push(...this.callbackHandlers(declaration.initializer));
                        }
                    }
                }
            }
        };
        const fromObjectLiteral = (obj: ts.ObjectLiteralExpression) => fromMembers(obj.properties);
        const fromClassDecl = (decl: ts.ClassDeclaration) => fromMembers(decl.members);

        // Resolve a class reference through import aliases before looking for
        // members — the class is typically declared in another module.
        const fromClassReference = (ref: ts.Expression) => {
            let sym = this.checker.getSymbolAtLocation(ref);
            if (sym && sym.flags & ts.SymbolFlags.Alias) {
                sym = this.checker.getAliasedSymbol(sym);
            }
            for (const decl of sym?.getDeclarations() ?? []) {
                if (ts.isClassDeclaration(decl)) fromClassDecl(decl);
            }
        };

        // Case 1: object literal passed inline.
        if (ts.isObjectLiteralExpression(arg)) {
            fromObjectLiteral(arg);
        }

        // Case 2: `new SomeClass()` passed inline.
        if (ts.isNewExpression(arg)) {
            fromClassReference(arg.expression);
        }

        // Case 3: a variable — holding an object literal, a `new SomeClass()`,
        // or naming a class directly.
        if (ts.isIdentifier(arg)) {
            let sym = this.checker.getSymbolAtLocation(arg);
            if (sym && sym.flags & ts.SymbolFlags.Alias) sym = this.checker.getAliasedSymbol(sym);
            for (const decl of sym?.getDeclarations() ?? []) {
                if (ts.isVariableDeclaration(decl) && decl.initializer) {
                    found.push(...this.resolveHandlerMethods(decl.initializer, methodName, seen));
                }
                if (ts.isClassDeclaration(decl)) fromClassDecl(decl);
            }
        }

        return found;
    }

    private static readonly EVENT_LISTENER_METHODS = new Set(["on", "once", "addListener"]);

    /**
     * Check if a call is .on('message', callback), .once('message', callback),
     * or .addListener('message', callback).
     */
    private isMessageEventCallback(callName: string, callExpr: ts.CallExpression): boolean {
        const lastSegment = callName.split(".").pop() || "";
        if (!InterproceduralAnalyzer.EVENT_LISTENER_METHODS.has(lastSegment)) return false;
        if (callExpr.arguments.length < 2) return false;
        const firstArg = callExpr.arguments[0];
        return (
            resolveStaticString(this.checker, firstArg) === "message" &&
            APIIdentityCache.forChecker(this.checker).registrationMatches(
                callExpr.expression,
                `ws.WebSocket.${lastSegment}`,
            )
        );
    }

    /**
     * Extract message event callback handler.
     * Pattern: ws.on('message', (data) => { ... })
     *          ws.once('message', (data) => { ... })
     *          ws.addListener('message', (data) => { ... })
     */
    private extractMessageCallbackEntryPoint(callExpr: ts.CallExpression, entryPoints: EntryPoint[]): void {
        if (callExpr.arguments.length < 2) return;
        const handler = callExpr.arguments[1];

        let funcDecl: ts.FunctionLikeDeclaration | undefined;
        if (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler)) {
            funcDecl = handler;
        } else if (ts.isIdentifier(handler) || ts.isPropertyAccessExpression(handler)) {
            funcDecl = resolveFunctionReference(this.checker, handler);
        }

        if (funcDecl) {
            const source = this.findSourceSpec("onMessage");
            if (source && funcDecl.parameters.length > 0) {
                entryPoints.push({
                    kind: "eventHandler",
                    node: funcDecl,
                    taintedParams: new Map([[0, source]]),
                    description: "WebSocket/EventEmitter message handler",
                });
            }
        }
    }

    /**
     * Find a source spec by its callbackRegistration field.
     */
    private findSourceSpec(registration: string): SourceSpec | undefined {
        return this.spec.sources.find((s) => s.callbackRegistration === registration);
    }

    /** Set while a callee analysis skips a call because of the depth limit. */
    private depthLimitReached = false;

    noteDepthLimit(): void {
        this.depthLimitReached = true;
    }

    /**
     * Run a callee analysis and report whether the depth limit cut off any
     * call inside it. A truncation also truncates every enclosing analysis.
     */
    trackDepthLimit<T>(analyze: () => T): { result: T; truncated: boolean } {
        const enclosing = this.depthLimitReached;
        this.depthLimitReached = false;
        try {
            const result = analyze();
            return { result, truncated: this.depthLimitReached };
        } finally {
            this.depthLimitReached ||= enclosing;
        }
    }

    /**
     * A result truncated by the depth limit is reused only at the same or a
     * greater depth. Reusing it from a shallower call would hide flows that
     * the shallower call has the depth budget to follow.
     */
    private cachedCallResult(cacheKey: string, depth: number): CachedCallResult | undefined {
        const cached = this.callResultCache.get(cacheKey);
        if (!cached || (cached.truncated && depth < cached.depth)) return undefined;
        if (cached.truncated) this.noteDepthLimit();
        return cached;
    }

    private setCachedCallResult(cacheKey: string, result: CachedCallResult): void {
        if (this.callResultCache.size >= MAX_CALL_RESULT_CACHE_ENTRIES && !this.callResultCache.has(cacheKey)) {
            const oldestKey = this.callResultCache.keys().next().value;
            if (oldestKey !== undefined) {
                this.callResultCache.delete(oldestKey);
                this.metrics.performance.callResultCacheEvictions++;
            }
        }
        this.callResultCache.set(cacheKey, result);
        this.metrics.performance.callResultCacheStores++;
        this.metrics.performance.maxCallResultCacheEntries = Math.max(
            this.metrics.performance.maxCallResultCacheEntries,
            this.callResultCache.size,
        );
    }

    private clearCallResultCache(): void {
        // Memoized findings include the current entry-point attribution.
        // Retaining them across entries would make results depend on visit
        // order and shard count. Sharding must not change findings.
        this.closureCache.clear();
        if (this.callResultCache.size === 0) return;
        this.callResultCache.clear();
        this.metrics.performance.callResultCacheClears++;
    }

    /**
     * Cache function-valued arguments only when they have no field/element
     * state, captured instances, or bound receiver. The key includes their
     * declarations and captured taint state.
     */
    private isCacheableArgumentInstance(instance: InstanceState | undefined): boolean {
        return (
            instance == null ||
            (instance.functions.length > 0 &&
                !instance.valueTaints?.length &&
                !instance.apiTypes?.length &&
                !instance.classDeclarations?.length &&
                !instance.classDeclarationsUnknown &&
                !instance.hostCallback &&
                instance.fields.size === 0 &&
                instance.fieldInstances.size === 0 &&
                instance.elementInstances.size === 0 &&
                instance.functions.every((value) => value.capturedInstances.size === 0 && value.thisInstance == null))
        );
    }

    private functionArgumentsCacheKey(argInstances: (InstanceState | undefined)[]): string {
        const parts: string[] = [];
        argInstances.forEach((instance, i) => {
            if (!instance || instance.functions.length === 0) return;
            const values = instance.functions.map(
                (value) => `${this.funcDeclCacheKey(value.declaration)}{${this.stateCacheKey(value.captured)}}`,
            );
            parts.push(`${i}=${values.sort().join(";")}`);
        });
        return parts.join(",");
    }

    private getCallCacheKey(
        funcDecl: ts.FunctionLikeDeclaration,
        argTaints: (TaintValue[] | undefined)[],
        inheritedFieldState: TaintState,
        functionArgumentsKey: string = "",
    ): string {
        this.metrics.performance.callCacheKeyBuilds++;
        // Reuse declaration and taint keys rather than walking propagation
        // chains. State and function-argument keys are materialized here;
        // only the per-argument taint joins below have a size preflight.
        const fnKey = this.funcDeclCacheKey(funcDecl);
        const epKey = this.currentEntryPointName ?? "";
        const stateKey = functionArgumentsKey
            ? `${this.stateCacheKey(inheritedFieldState)}#${functionArgumentsKey}`
            : this.stateCacheKey(inheritedFieldState);

        // Estimate argument-key size before joining taints: a single argument
        // can retain enough values to exceed the engine's string-length limit.
        const sortedPerArg: (string[] | undefined)[] = [];
        let totalChars = fnKey.length + epKey.length + stateKey.length;
        for (let i = 0; i < argTaints.length; i++) {
            const taints = argTaints[i];
            if (!taints || taints.length === 0) {
                sortedPerArg.push(undefined);
                continue;
            }
            const sortedKeys = taints.map((t) => t.cacheKey).sort();
            for (const k of sortedKeys) totalChars += k.length + 1;
            sortedPerArg.push(sortedKeys);
        }

        // Join compact keys directly; hash oversized argument lists without
        // constructing their joined string. Taint keys already contain hashes.
        if (totalChars > InterproceduralAnalyzer.MAX_EXACT_CACHE_KEY_CHARS) {
            let h = new FnvHash();
            h.add(fnKey).add(epKey);
            for (let i = 0; i < sortedPerArg.length; i++) {
                const sortedKeys = sortedPerArg[i];
                if (!sortedKeys) continue;
                h.add(String(i));
                for (const k of sortedKeys) h.add(k);
            }
            h.add(stateKey);
            return `#${h.digest()}`;
        }

        const parts: string[] = [fnKey, epKey];
        for (let i = 0; i < sortedPerArg.length; i++) {
            const sortedKeys = sortedPerArg[i];
            if (!sortedKeys) continue;
            parts.push(`${i}:${sortedKeys.join("&")}`);
        }
        parts.push(stateKey);
        return parts.join("|");
    }

    /**
     * Character-count threshold for hashing argument-key lists instead of
     * joining them. It does not bound the state keys built before this check.
     */
    private static readonly MAX_EXACT_CACHE_KEY_CHARS = 1 << 16;

    private funcDeclKeyCache: WeakMap<ts.FunctionLikeDeclaration, string> = new WeakMap();
    private funcDeclCacheKey(funcDecl: ts.FunctionLikeDeclaration): string {
        const cached = this.funcDeclKeyCache.get(funcDecl);
        if (cached !== undefined) return cached;
        const sf = funcDecl.getSourceFile();
        const key = `${sf.fileName}:${funcDecl.getStart()}`;
        this.funcDeclKeyCache.set(funcDecl, key);
        return key;
    }

    private extractInstanceFieldState(state: TaintState): TaintState {
        const fieldState: TaintState = new Map();
        for (const [sym, taints] of state) {
            if (this.isInstanceFieldSymbol(sym) && taints.length > 0) {
                fieldState.set(sym, taints);
            }
        }
        return fieldState;
    }

    private isInstanceFieldSymbol(sym: ts.Symbol): boolean {
        const declarations = sym.getDeclarations();
        return !!declarations?.some(
            (decl) =>
                ts.isPropertyDeclaration(decl) ||
                ts.isPropertySignature(decl) ||
                ts.isGetAccessor(decl) ||
                ts.isSetAccessor(decl) ||
                (ts.isParameter(decl) &&
                    ts.isConstructorDeclaration(decl.parent) &&
                    ts.isParameterPropertyDeclaration(decl, decl.parent)),
        );
    }

    private clearedFieldSymbols(before: TaintState, after: TaintState): ts.Symbol[] {
        const cleared: ts.Symbol[] = [];
        for (const sym of before.keys()) {
            if (!after.has(sym)) {
                cleared.push(sym);
            }
        }
        return cleared;
    }

    private stateCacheKey(state: TaintState): string {
        const parts: string[] = [];
        for (const [sym, taints] of state) {
            const taintKey = taints
                .map((t) => t.cacheKey)
                .sort()
                .join("&");
            parts.push(`${this.symbolCacheKey(sym)}=${taintKey}`);
        }
        return parts.sort().join(",");
    }

    private symbolCacheKey(sym: ts.Symbol): string {
        const declarations = sym.getDeclarations();
        if (declarations && declarations.length > 0) {
            const declaration = declarations[0];
            const sf = declaration.getSourceFile();
            return `${sf.fileName}:${declaration.getStart()}:${sym.getName()}`;
        }
        return sym.getName();
    }

    private nodeLocation(node: ts.Node): CodeLocation {
        return resolveNodeLocation(node);
    }

    /**
     * Inspect a single AST node for a `registerCommand(name, handler)` call.
     * The tree is walked iteratively by `walkTree`, so this must NOT recurse
     * into children itself.
     */
    private inspectNodeForCommandRegistration(node: ts.Node): void {
        if (ts.isCallExpression(node)) {
            const registration = resolveCommandRegistration(this.checker, node);
            if (!registration) return;
            const commandName = resolveStaticString(this.checker, registration.command);
            if (commandName != null) {
                const handler = resolveFunctionReference(this.checker, registration.handler);
                if (handler) {
                    this.commandRegistry.set(commandName, {
                        handler,
                        handlerParamOffset: registration.handlerParamOffset,
                    });
                }
            }
        }
    }
}
