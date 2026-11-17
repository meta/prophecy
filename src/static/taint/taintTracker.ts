/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { CopyOnWriteMap } from "./copyOnWriteMap";
import { APIIdentityCache, canonicalModuleApiName } from "./apiIdentity";
import {
    TaintSpec,
    SourceSpec,
    SinkSpec,
    SanitizerSpec,
    CodeLocation,
    TaintFinding,
    SettingScope,
} from "../spec/types";
import {
    TaintValue,
    PropagationStep,
    createTaint,
    materializePropagationChain,
    propagate,
    withSanitizers,
} from "./taintValue";
import { getLocationString } from "../parser";
import {
    getCallChainName,
    parameterSymbol,
    resolveCommandRegistration,
    resolveFunctionReference,
    resolveStaticString,
    superClassExpression,
    unwrapExpression,
} from "./functionResolver";
import { resolveNodeLocation } from "./nodeLocation";
import { sinkSiteIdentity } from "./sinkSite";
import { AnalysisMetrics, createAnalysisMetrics, recordPatternMatch } from "../metrics";
import { callbackArgIndices } from "../spec/sourceUtils";
import {
    captureAxiosDefaults,
    axiosInheritedDestinationTaints,
    axiosRequestConfigIndex,
    hasKnownFileDescriptor,
} from "./nodeApiModels";

/**
 * Taint state: maps TypeScript symbols (variables, parameters) to their taint values.
 * A variable can carry multiple taints (from different sources).
 */
export type TaintState = Map<ts.Symbol, readonly TaintValue[]>;

// State lists are owned on insertion; callers can retain mutable producer arrays.
function ownTaintList(taints: readonly TaintValue[]): readonly TaintValue[] {
    return Object.isFrozen(taints) ? taints : Object.freeze([...taints]);
}

export function forkTaintState(source: TaintState): CopyOnWriteMap<ts.Symbol, readonly TaintValue[]> {
    return source instanceof CopyOnWriteMap && source.hasValueOwner(ownTaintList)
        ? source.fork()
        : new CopyOnWriteMap(source, ownTaintList);
}

function createTaintState(): CopyOnWriteMap<ts.Symbol, readonly TaintValue[]> {
    return new CopyOnWriteMap(undefined, ownTaintList);
}

// A semantic taint fact can cross several assignments before reaching a sink.
// Bound pathological loops while allowing substantially deeper propagation
// than the analyzer's interprocedural depth limit.
const MAX_LOOP_ITERATIONS = 16;

// Binding metadata is boxed in reserved slots so container iteration cannot consume it.
const BINDING_PROPERTY = "$property:";
const BINDING_OBJECT_SHAPE = "$properties";
const BINDING_ARRAY_SHAPE = "$elements";
const BINDING_VALUE_STATE = "$defined";
const BINDING_DEFINED = ts.factory.createNumericLiteral(0);
const BINDING_UNDEFINED = ts.factory.createVoidZero();

function isBindingPayload(key: string): boolean {
    return key.startsWith(BINDING_PROPERTY) || key.startsWith("$taint:");
}

function missingBindingPayload(owner: InstanceState, key: string): InstanceState {
    const value = createInstanceState();
    const shape = key.startsWith(BINDING_PROPERTY) ? BINDING_OBJECT_SHAPE : BINDING_ARRAY_SHAPE;
    if (owner.elementInstances.has(shape)) value.valueExpression = BINDING_UNDEFINED;
    if (key.startsWith("$taint:")) {
        const defined = createInstanceState();
        defined.valueExpression = value.valueExpression;
        value.elementInstances.set(BINDING_VALUE_STATE, defined);
    }
    if (key.startsWith(BINDING_PROPERTY)) {
        const name = key.slice(BINDING_PROPERTY.length);
        value.valueTaints = ownTaintList(
            [...owner.fields].filter(([property]) => property.getName() === name).flatMap(([, taints]) => taints),
        );
        const instance = [...owner.fieldInstances].find(([property]) => property.getName() === name)?.[1];
        if (instance) value.elementInstances.set("$value", instance);
    }
    return value;
}

type ShellInsertionContext = "commandStart" | "unsafe" | { command: string };

export interface InstanceState {
    /** API identities supplied by a host callback, such as an Express response. */
    apiTypes?: readonly string[];
    /** Concrete runtime classes, independent of the receiver's declared type. */
    classDeclarations?: readonly ts.ClassLikeDeclaration[];
    /** Some possible object values have no tracked concrete class identity. */
    classDeclarationsUnknown?: boolean;
    /** Opaque continuation identity owned by the interprocedural context. */
    hostCallback?: string;
    /** Taint carried by a boxed host payload, not by its surrounding handle. */
    valueTaints?: readonly TaintValue[];
    /** Original scalar expression used for callback default-argument binding. */
    valueExpression?: ts.Expression;
    /** Host rest arguments may have a clean prefix before attacker payloads. */
    taintedElementsFromIndex?: number;
    fields: TaintState;
    fieldInstances: Map<ts.Symbol, InstanceState>;
    elementInstances: Map<string, InstanceState>;
    /**
     * Function bodies this value may be when called. A closure stored in a
     * field or passed as an argument is otherwise unresolvable by symbol:
     * `this.getConfig()` names a property, not a declaration.
     */
    functions: FunctionValue[];
}

export interface CallArgument {
    expression: ts.Expression;
    taints?: TaintValue[];
    instance?: InstanceState;
    unknownSpread?: boolean;
}

/** Expand literal spreads without evaluating arguments a second time. */
export function expandCallArguments(
    expressions: readonly ts.Expression[],
    taints: (TaintValue[] | undefined)[],
    instances: (InstanceState | undefined)[] = [],
): CallArgument[] {
    const expanded: CallArgument[] = [];
    const expand = (
        expression: ts.Expression,
        values: TaintValue[] | undefined,
        instance: InstanceState | undefined,
    ): void => {
        if (!ts.isSpreadElement(expression)) {
            expanded.push({ expression, taints: values, instance });
            return;
        }
        const array = unwrapExpression(expression.expression);
        if (ts.isArrayLiteralExpression(array)) {
            const containerId = `${array.getSourceFile().fileName}:${array.getStart()}`;
            array.elements.forEach((element, index) => {
                const selected = values?.filter((taint) => {
                    for (let node = taint.chain; node; node = node.previous) {
                        if (node.step.kind === "mutation") return true;
                        if (node.step.arrayElement?.containerId === containerId) {
                            return node.step.arrayElement.index === index;
                        }
                    }
                    return true;
                });
                expand(element, selected?.length ? selected : undefined, instance?.elementInstances.get(String(index)));
            });
        } else {
            expanded.push({
                expression,
                taints: values,
                instance:
                    instance &&
                    mergeInstanceStates(
                        [...instance.elementInstances]
                            .filter(([key]) => !key.startsWith("$"))
                            .map(([, value]) => value),
                    ),
                unknownSpread: true,
            });
        }
    };
    expressions.forEach((expression, index) => expand(expression, taints[index], instances[index]));
    return expanded;
}

export interface ParameterBinding {
    parameter: ts.ParameterDeclaration;
    taints?: TaintValue[];
    instance?: InstanceState;
}

/** A function flowing as a value, with the state it captured where defined. */
export interface FunctionValue {
    declaration: ts.FunctionLikeDeclaration;
    captured: TaintState;
    capturedInstances: Map<ts.Symbol, InstanceState>;
    /** Lexical `this` of an arrow function. */
    thisInstance?: InstanceState;
}

interface LoopAnalysisState {
    taints: TaintState;
    instanceBindings: Map<ts.Symbol, InstanceState>;
    moduleInstances: Map<ts.Symbol, InstanceState>;
    currentThisInstance?: InstanceState;
    expressionInstances: Map<ts.Expression, InstanceState>;
    cleanBindings: Set<ts.Symbol>;
}

export function createInstanceState(): InstanceState {
    return {
        fields: createTaintState(),
        fieldInstances: new Map(),
        elementInstances: new Map(),
        functions: [],
    };
}

export function createFunctionInstance(value: FunctionValue): InstanceState {
    const instance = createInstanceState();
    instance.functions.push(value);
    return instance;
}

/** Fork several roots together so aliases and cycles stay shared within an alternative. */
export function forkInstanceStates(
    roots: readonly (InstanceState | undefined)[],
    copies = new Map<InstanceState, InstanceState>(),
): (InstanceState | undefined)[] {
    const clone = (instance: InstanceState): InstanceState => {
        const existing = copies.get(instance);
        if (existing) return existing;
        const copy = {
            ...instance,
            fields: forkTaintState(instance.fields),
            fieldInstances: new Map<ts.Symbol, InstanceState>(),
            elementInstances: new Map<string, InstanceState>(),
            functions: [] as FunctionValue[],
        };
        copies.set(instance, copy);
        for (const [key, value] of instance.fieldInstances) copy.fieldInstances.set(key, clone(value));
        for (const [key, value] of instance.elementInstances) copy.elementInstances.set(key, clone(value));
        copy.functions = instance.functions.map((fn) => ({
            ...fn,
            captured: forkTaintState(fn.captured),
            capturedInstances: new Map([...fn.capturedInstances].map(([symbol, value]) => [symbol, clone(value)])),
            thisInstance: fn.thisInstance && clone(fn.thisInstance),
        }));
        return copy;
    };
    return roots.map((root) => root && clone(root));
}

type InstanceMerger = (instances: InstanceState[]) => InstanceState | undefined;

/**
 * Union by declaration. Values of one declaration reached on different paths
 * keep the captured taint of every path. Captured instances are merged with
 * `mergeInstances` when given; past the merge depth bound the first is kept.
 */
function unionFunctionValues(lists: FunctionValue[][], mergeInstances?: InstanceMerger): FunctionValue[] {
    const byDeclaration = new Map<ts.Node, FunctionValue[]>();
    for (const list of lists) {
        for (const value of list) {
            const values = byDeclaration.get(value.declaration) ?? [];
            if (!values.includes(value)) values.push(value);
            byDeclaration.set(value.declaration, values);
        }
    }
    return [...byDeclaration.values()].map((values) =>
        values.length === 1 ? values[0] : mergeFunctionValues(values, mergeInstances),
    );
}

function mergeFunctionValues(values: FunctionValue[], mergeInstances?: InstanceMerger): FunctionValue {
    const captured: TaintState = createTaintState();
    const instancesBySymbol = new Map<ts.Symbol, InstanceState[]>();
    for (const value of values) {
        for (const [sym, taints] of value.captured) {
            captured.set(sym, [...new Set([...(captured.get(sym) ?? []), ...taints])]);
        }
        for (const [sym, instance] of value.capturedInstances) {
            instancesBySymbol.set(sym, [...(instancesBySymbol.get(sym) ?? []), instance]);
        }
    }
    const merge = (instances: InstanceState[]) => (mergeInstances ? mergeInstances(instances) : instances[0]);
    const capturedInstances = new Map<ts.Symbol, InstanceState>();
    for (const [sym, instances] of instancesBySymbol) {
        const instance = merge(instances);
        if (instance) capturedInstances.set(sym, instance);
    }
    const thisInstances = values
        .map((value) => value.thisInstance)
        .filter((instance): instance is InstanceState => instance != null);
    return {
        declaration: values[0].declaration,
        captured,
        capturedInstances,
        thisInstance: thisInstances.length > 0 ? merge(thisInstances) : undefined,
    };
}

const MAX_INSTANCE_MERGE_DEPTH = 8;

export function mergeInstanceStates(instances: InstanceState[]): InstanceState | undefined {
    return mergeInstanceStatesAtDepth(instances, 0);
}

/** Missing object alternatives must not turn surviving allocations into an exhaustive class set. */
export function mergeReturnInstances(
    instances: InstanceState[],
    unknown: boolean | undefined,
): InstanceState | undefined {
    const merged = mergeInstanceStates(instances);
    // Keep uncertainty on the joined value, not on an original instance retained by another alias.
    return merged?.classDeclarations?.length && unknown ? { ...merged, classDeclarationsUnknown: true } : merged;
}

function mergeInstanceStatesAtDepth(instances: InstanceState[], depth: number): InstanceState | undefined {
    const unique = [...new Set(instances)];
    if (unique.length === 0) return undefined;
    if (unique.length === 1) return unique[0];

    const merged = createInstanceState();
    merged.apiTypes = [...new Set(unique.flatMap((instance) => instance.apiTypes ?? []))].sort();
    merged.classDeclarations = [...new Set(unique.flatMap((instance) => instance.classDeclarations ?? []))];
    merged.classDeclarationsUnknown =
        unique.some((instance) => instance.classDeclarationsUnknown) ||
        (merged.classDeclarations.length > 0 && unique.some((instance) => !instance.classDeclarations?.length)) ||
        undefined;
    merged.hostCallback = unique.every((instance) => instance.hostCallback === unique[0].hostCallback)
        ? unique[0].hostCallback
        : undefined;
    merged.valueTaints = [...new Set(unique.flatMap((instance) => instance.valueTaints ?? []))];
    merged.valueExpression = unique.every((instance) => instance.valueExpression === unique[0].valueExpression)
        ? unique[0].valueExpression
        : undefined;
    const ranges = unique.flatMap((instance) =>
        instance.taintedElementsFromIndex == null ? [] : [instance.taintedElementsFromIndex],
    );
    if (ranges.length) merged.taintedElementsFromIndex = Math.min(...ranges);
    for (const instance of unique) {
        for (const [symbol, taints] of instance.fields) {
            const existing = merged.fields.get(symbol) ?? [];
            merged.fields.set(symbol, [...new Set([...existing, ...taints])]);
        }
    }
    merged.functions = unionFunctionValues(
        unique.map((instance) => instance.functions),
        depth < MAX_INSTANCE_MERGE_DEPTH ? (nested) => mergeInstanceStatesAtDepth(nested, depth + 1) : undefined,
    );

    if (depth >= MAX_INSTANCE_MERGE_DEPTH) return merged;

    const nestedFields = new Map<ts.Symbol, InstanceState[]>();
    const nestedElements = new Map<string, InstanceState[]>();
    for (const instance of unique) {
        for (const [symbol, nested] of instance.fieldInstances) {
            const candidates = nestedFields.get(symbol) ?? [];
            candidates.push(nested);
            nestedFields.set(symbol, candidates);
        }
        for (const [key, nested] of instance.elementInstances) {
            const candidates = nestedElements.get(key) ?? [];
            candidates.push(nested);
            nestedElements.set(key, candidates);
        }
    }
    for (const [symbol, candidates] of nestedFields) {
        const nested = mergeInstanceStatesAtDepth(candidates, depth + 1);
        if (nested) merged.fieldInstances.set(symbol, nested);
    }
    for (const [key, candidates] of nestedElements) {
        if ([BINDING_OBJECT_SHAPE, BINDING_ARRAY_SHAPE].includes(key) && candidates.length !== unique.length) continue;
        const values = isBindingPayload(key)
            ? unique.map((owner) => owner.elementInstances.get(key) ?? missingBindingPayload(owner, key))
            : candidates;
        const nested = mergeInstanceStatesAtDepth(values, depth + 1);
        if (nested) merged.elementInstances.set(key, nested);
    }
    return merged;
}

/**
 * Result of analyzing a function body.
 */
export interface AnalysisResult {
    findings: TaintFinding[];
    /** Taint state at the end of the function (for interprocedural use). */
    finalState: TaintState;
    /** If the function returns a tainted value, this contains those taints. */
    returnTaints: TaintValue[];
    /** Instance identities returned by the function. */
    returnInstances: InstanceState[];
    warnings: string[];
    /** At least one empty return summary is not proven clean. */
    returnUnknown?: boolean;
    /** A potentially returned object has no tracked instance, independently of taint. */
    returnInstanceUnknown?: boolean;
    canReturn?: boolean;
    mayThrow?: boolean;
    throwTaints?: TaintValue[];
    throwInstances?: InstanceState[];
}

/**
 * Result of an interprocedural call analysis.
 */
export interface InterproceduralCallResult {
    returnTaints: TaintValue[] | undefined;
    findings: TaintFinding[];
    fieldState: TaintState;
    clearedFieldSymbols: ts.Symbol[];
    instanceState?: InstanceState;
    /** A nested call was not followed, so an empty return is not proof of cleanliness. */
    truncated?: boolean;
    returnUnknown?: boolean;
    /** A potentially returned object has no tracked instance, independently of taint. */
    returnInstanceUnknown?: boolean;
    canReturn?: boolean;
    mayThrow?: boolean;
    throwTaints?: TaintValue[];
    throwInstances?: InstanceState[];
}

/** Join the results of the possible bodies of one call. */
export function joinCallResults(
    results: (InterproceduralCallResult | undefined)[],
): InterproceduralCallResult | undefined {
    const resolved = results.filter((result): result is InterproceduralCallResult => result != null);
    if (resolved.length === 0) return undefined;
    const returnInstanceUnknown =
        resolved.length !== results.length || resolved.some((result) => result.returnInstanceUnknown) || undefined;
    const instanceState = mergeReturnInstances(
        resolved.flatMap((result) => (result.instanceState ? [result.instanceState] : [])),
        returnInstanceUnknown,
    );
    if (resolved.length === 1)
        return {
            ...resolved[0],
            instanceState,
            returnInstanceUnknown,
            truncated: resolved[0].truncated || resolved.length !== results.length,
            returnUnknown: resolved[0].returnUnknown || resolved.length !== results.length,
        };

    const returnTaints = resolved.flatMap((result) => result.returnTaints ?? []);
    const fieldState: TaintState = new Map();
    for (const result of resolved) {
        for (const [sym, taints] of result.fieldState) {
            fieldState.set(sym, [...(fieldState.get(sym) ?? []), ...taints]);
        }
    }
    return {
        returnTaints: returnTaints.length > 0 ? returnTaints : undefined,
        canReturn: resolved.length !== results.length || resolved.some((result) => result.canReturn !== false),
        mayThrow: resolved.some((result) => result.mayThrow),
        throwTaints: resolved.flatMap((result) => result.throwTaints ?? []),
        throwInstances: resolved.flatMap((result) => result.throwInstances ?? []),
        truncated: resolved.length !== results.length || resolved.some((result) => result.truncated),
        returnUnknown: resolved.length !== results.length || resolved.some((result) => result.returnUnknown),
        findings: resolved.flatMap((result) => result.findings),
        fieldState,
        clearedFieldSymbols: resolved[0].clearedFieldSymbols.filter((sym) =>
            resolved.every((result) => result.clearedFieldSymbols.includes(sym)),
        ),
        instanceState,
        returnInstanceUnknown,
    };
}

/**
 * Context for resolving calls across function boundaries.
 */
export interface InterproceduralContext {
    /** Resolve a function call to its declaration and analyze it. */
    analyzeFunctionCall(
        callExpr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
        checker: ts.TypeChecker,
        depth: number,
        callerState: TaintState,
        receiverInstance?: InstanceState,
        argInstances?: (InstanceState | undefined)[],
        /** The function value being called, when known; overrides symbol resolution. */
        boundFunction?: FunctionValue,
        runtimeArguments?: CallArgument[],
    ): InterproceduralCallResult | undefined;

    getModuleInstance?(symbol: ts.Symbol, create: () => InstanceState): InstanceState;
    getModuleInstanceState?(): Map<ts.Symbol, InstanceState>;
    setModuleInstanceState?(state: Map<ts.Symbol, InstanceState>): void;
    /** Whether indexed program syntax preserves the Array.from constructor and array-like prototype contract. */
    arrayFromBuiltinsUnmodified?(): boolean;

    analyzeHostCallback?(
        callExpr: ts.CallExpression,
        functionInstance: InstanceState,
        callerState: TaintState,
        depth: number,
    ): InterproceduralCallResult | undefined;

    /** Resolve a constructor call and analyze its body. */
    analyzeConstructorCall(
        newExpr: ts.NewExpression,
        argTaints: (TaintValue[] | undefined)[],
        checker: ts.TypeChecker,
        depth: number,
        callerState: TaintState,
        argInstances?: (InstanceState | undefined)[],
    ): InterproceduralCallResult | undefined;

    /** A program-visible Array prototype access can replace or escape native methods. */
    hasArrayPrototypeAccess?(): boolean;

    /** Whether a call to an abstract or interface method has implementations to analyze. */
    hasOverrideCandidates(callExpr: ts.CallExpression): boolean;

    /** Declared scope of a setting, from the extension manifests in the program. */
    settingScope(key: string): SettingScope | undefined;

    /** Record that a call was not followed because of the depth limit. */
    noteDepthLimit(): void;
    trackDepthLimit<T>(analyze: () => T): { result: T; truncated: boolean };
}

/** Symbols referenced by a function but declared in an enclosing scope. */
export function functionFreeSymbols(checker: ts.TypeChecker, fn: ts.FunctionLikeDeclaration): ts.Symbol[] {
    const cached = freeSymbolCache.get(fn);
    if (cached) return cached;

    const symbols = new Set<ts.Symbol>();
    const stack: ts.Node[] = [...fn.parameters, ...(fn.body ? [fn.body] : [])];
    for (const param of fn.parameters) {
        if (param.initializer) stack.push(param.initializer);
    }
    while (stack.length > 0) {
        const node = stack.pop()!;
        if (ts.isIdentifier(node)) {
            const sym =
                ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node
                    ? checker.getShorthandAssignmentValueSymbol(node.parent)
                    : checker.getSymbolAtLocation(node);
            if (sym && !isDeclaredWithin(sym, fn)) symbols.add(sym);
            continue;
        }
        node.forEachChild((child) => {
            stack.push(child);
        });
    }
    const result = [...symbols];
    freeSymbolCache.set(fn, result);
    return result;
}

const freeSymbolCache: WeakMap<ts.Node, ts.Symbol[]> = new WeakMap();

function isDeclaredWithin(symbol: ts.Symbol, node: ts.Node): boolean {
    return (
        symbol.declarations?.some(
            (declaration) =>
                declaration.getSourceFile() === node.getSourceFile() &&
                declaration.pos >= node.pos &&
                declaration.end <= node.end,
        ) ?? false
    );
}

/** An explicit coverage limit, carrying findings already discovered on the call stack. */
export class AnalysisCoverageLimitError extends Error {
    readonly findings = new Set<TaintFinding>();

    constructor(message: string) {
        super(message);
        this.name = "AnalysisCoverageLimitError";
    }
}

/** Where a tainted value was inserted into fixed shell text being composed. */
interface ShellInsertion {
    /** Index of the first of `count` inserted taints in the composition's taint list. */
    first: number;
    count: number;
    /** Length of the fixed text (with placeholders) just after the insertion. */
    end: number;
}

interface ModelAPIContext {
    overridden: boolean;
    calleeNames: readonly string[];
    memberNames: readonly string[];
}

/** Forward dataflow within a function, delegating resolved calls to the interprocedural context. */
export class TaintTracker {
    private checker: ts.TypeChecker;
    private spec: TaintSpec;
    private findings: TaintFinding[] = [];
    private interproc: InterproceduralContext | undefined;
    private depth: number;
    private maxDepth: number;
    private entryPointName: string;
    private metrics: AnalysisMetrics;
    private apiIdentity: APIIdentityCache;
    warnings: string[] = [];

    /**
     * Per-instance field state: maps a variable symbol (the LHS of
     * `const a = new Foo(...)`) to that instance's field taint state.
     * This avoids aliasing where two instances of the same class share
     * a single property symbol.
     */
    private instanceFieldState: Map<ts.Symbol, InstanceState>;

    private currentThisInstance: InstanceState | undefined;

    private expressionInstanceState: Map<ts.Expression, InstanceState> = new Map();
    private instanceOrigins = new WeakMap<InstanceState, InstanceState>();
    private normalizedStates = new WeakSet<object>();
    private cleanBindings = new Set<ts.Symbol>();
    private cleanExpressions = new WeakSet<ts.Expression>();
    private nonReturningExpressions = new WeakSet<ts.Expression>();
    private returnUnknown = false;
    private returnInstanceUnknown = false;
    private hasNormalReturn = false;
    private mayThrow = false;
    private throwTaints: TaintValue[] = [];
    private throwInstances: InstanceState[] = [];

    /**
     * Set of variable symbols that are aliases for `this`.
     * Supports patterns like `const self = this;` so that `self.field`
     * resolves the same as `this.field`.
     */
    private thisAliases: Set<ts.Symbol> = new Set();

    /**
     * Shared definition-site closure cache, keyed by function and semantic
     * context. Each value records whether that analysis hit the depth limit;
     * event-effect analysis bypasses cached results.
     */
    private closureCache: Map<ts.Node, Map<string, boolean>>;
    private breakTargets: { kind: "loop" | "switch"; exits: LoopAnalysisState[] }[] = [];
    private registeredCommandClosures = new Map<
        ts.ArrowFunction | ts.FunctionExpression,
        { environment: LoopAnalysisState; origins: Map<ts.Symbol, Set<InstanceState>> }
    >();

    constructor(
        checker: ts.TypeChecker,
        spec: TaintSpec,
        interproc?: InterproceduralContext,
        depth: number = 0,
        maxDepth: number = 5,
        entryPointName: string = "unknown",
        metrics: AnalysisMetrics = createAnalysisMetrics(),
        closureCache: Map<ts.Node, Map<string, boolean>> = new Map(),
        initialInstanceFieldState: Map<ts.Symbol, InstanceState> = new Map(),
        currentThisInstance?: InstanceState,
    ) {
        this.closureCache = closureCache;
        this.checker = checker;
        this.apiIdentity = APIIdentityCache.forChecker(checker);
        this.spec = spec;
        this.interproc = interproc;
        this.depth = depth;
        this.maxDepth = maxDepth;
        this.entryPointName = entryPointName;
        this.metrics = metrics;
        this.instanceFieldState = new Map(initialInstanceFieldState);
        this.currentThisInstance = currentThisInstance;
    }

    /**
     * Analyze a function body, starting with an initial taint state
     * (e.g., tainted parameters).
     */
    analyzeFunction(
        body: ts.Block | ts.Expression,
        initialState: TaintState,
        /** Parameters whose initializer may execute for the supplied arguments. */
        defaultedParameters: readonly {
            parameter: ts.ParameterDeclaration;
            conditional: boolean;
        }[] = [],
        destructuredParameters: readonly ParameterBinding[] = [],
    ): AnalysisResult {
        const state = forkTaintState(initialState);
        const returnTaints: TaintValue[] = [];
        const returnInstances: InstanceState[] = [];

        try {
            for (const binding of destructuredParameters) {
                this.bindDestructuring(binding.parameter.name, binding.taints, binding.instance, state);
            }
            for (const { parameter: param, conditional } of defaultedParameters) {
                const beforeDefault = conditional ? this.captureLoopAnalysisState(state) : undefined;
                const initializer = param.initializer;
                const sym = initializer && parameterSymbol(this.checker, param);
                if (!initializer) continue;
                const taints = this.analyzeExpression(initializer, state);
                if (taints && sym) {
                    state.set(
                        sym,
                        taints.map((t) =>
                            propagate(
                                t,
                                {
                                    kind: "assignment",
                                    location: this.nodeLocation(param),
                                    description: `default value of parameter '${param.name.getText()}'`,
                                },
                                this.metrics,
                            ),
                        ),
                    );
                }
                const instance = this.resolveValueInstance(initializer);
                if (instance && sym) this.instanceFieldState.set(sym, instance);
                if (!ts.isIdentifier(param.name)) this.bindDestructuring(param.name, taints, instance, state);
                if (beforeDefault) {
                    this.restoreLoopAnalysisState(
                        this.mergeLoopAnalysisStates(beforeDefault, this.captureLoopAnalysisState(state)),
                        state,
                    );
                }
                if (ts.isIdentifier(param.name) && ts.isParameterPropertyDeclaration(param, param.parent)) {
                    const property = this.checker.getSymbolAtLocation(param.name);
                    if (property && taints && sym) state.set(property, state.get(sym)!);
                    if (property && instance && this.currentThisInstance) {
                        this.currentThisInstance.fieldInstances.set(property, instance);
                    }
                }
            }

            let fallsThrough = true;
            if (ts.isBlock(body)) {
                fallsThrough = this.analyzeStatementList(body.statements, state, returnTaints, returnInstances);
            } else {
                // Arrow function with expression body
                const exprTaints = this.analyzeExpression(body, state);
                fallsThrough = !this.nonReturningExpressions.has(unwrapExpression(body));
                if (exprTaints) {
                    returnTaints.push(...exprTaints);
                }
                const instance = this.resolveValueInstance(body, state);
                if (instance) returnInstances.push(instance);
                this.returnInstanceUnknown ||= fallsThrough && !instance && !this.hasPrimitiveType(body);
                this.returnUnknown ||= !exprTaints?.length && !this.isProvenClean(body);
            }

            this.analyzeRegisteredCommandEffects();
            return {
                findings: this.findings,
                finalState: state,
                returnTaints,
                returnInstances,
                warnings: this.warnings,
                returnUnknown: this.returnUnknown,
                returnInstanceUnknown: this.returnInstanceUnknown || undefined,
                canReturn: fallsThrough || this.hasNormalReturn,
                mayThrow: this.mayThrow,
                throwTaints: this.throwTaints,
                throwInstances: this.throwInstances,
            };
        } catch (error) {
            if (error instanceof AnalysisCoverageLimitError) {
                for (const finding of this.findings) error.findings.add(finding);
            }
            throw error;
        }
    }

    /**
     * Analyze statements in execution order and report whether control can
     * reach the statement after the list.
     */
    private analyzeStatementList(
        statements: readonly ts.Statement[],
        state: TaintState,
        returnTaints: TaintValue[],
        returnInstances: InstanceState[],
    ): boolean {
        for (const stmt of statements) {
            if (!this.analyzeStatement(stmt, state, returnTaints, returnInstances)) {
                return false;
            }
        }
        return true;
    }

    private analyzeBranchStatement(
        stmt: ts.Statement,
        state: TaintState,
        returnTaints: TaintValue[],
        returnInstances: InstanceState[],
    ): boolean {
        return ts.isBlock(stmt)
            ? this.analyzeStatementList(stmt.statements, state, returnTaints, returnInstances)
            : this.analyzeStatement(stmt, state, returnTaints, returnInstances);
    }

    /** Return whether control can fall through after this statement. */
    private analyzeStatement(
        stmt: ts.Statement,
        state: TaintState,
        returnTaints: TaintValue[],
        returnInstances: InstanceState[],
    ): boolean {
        // Expression results are only needed while evaluating the current statement.
        this.expressionInstanceState.clear();
        if (ts.isVariableStatement(stmt)) {
            for (const decl of stmt.declarationList.declarations) {
                this.analyzeVariableDeclaration(decl, state);
            }
        } else if (ts.isExpressionStatement(stmt)) {
            this.analyzeExpression(stmt.expression, state);
            if (this.nonReturningExpressions.has(unwrapExpression(stmt.expression))) return false;
        } else if (ts.isReturnStatement(stmt)) {
            if (stmt.expression) {
                const taints = this.analyzeExpression(stmt.expression, state);
                if (taints) {
                    returnTaints.push(...taints);
                }
                const instance = this.resolveValueInstance(stmt.expression, state);
                if (instance) returnInstances.push(instance);
                this.returnInstanceUnknown ||=
                    !instance &&
                    !this.hasPrimitiveType(stmt.expression) &&
                    !this.nonReturningExpressions.has(unwrapExpression(stmt.expression));
                this.returnUnknown ||= !taints?.length && !this.isProvenClean(stmt.expression);
            }
            this.hasNormalReturn ||=
                !stmt.expression || !this.nonReturningExpressions.has(unwrapExpression(stmt.expression));
            return false;
        } else if (ts.isThrowStatement(stmt)) {
            this.mayThrow = true;
            if (stmt.expression) {
                this.throwTaints.push(...(this.analyzeExpression(stmt.expression, state) ?? []));
                const instance = this.resolveValueInstance(stmt.expression, state);
                if (instance) this.throwInstances.push(instance);
            }
            return false;
        } else if (ts.isBreakStatement(stmt)) {
            const target = this.breakTargets[this.breakTargets.length - 1];
            if (!stmt.label && target?.kind === "switch") {
                target.exits.push(this.captureLoopAnalysisState(state));
            }
            return false;
        } else if (ts.isContinueStatement(stmt)) {
            return false;
        } else if (ts.isIfStatement(stmt)) {
            this.analyzeExpression(stmt.expression, state);

            // Both branches start from the same taint and instance snapshot.
            // Merge only branches that can fall through so state from
            // terminated paths cannot leak past the if statement.
            const branchEntryState = this.captureLoopAnalysisState(state);

            this.restoreLoopAnalysisState(this.cloneLoopAnalysisState(branchEntryState), state);
            const thenFallsThrough = this.analyzeBranchStatement(
                stmt.thenStatement,
                state,
                returnTaints,
                returnInstances,
            );
            const thenExitState = this.captureLoopAnalysisState(state);

            let elseFallsThrough = true;
            let elseExitState = this.cloneLoopAnalysisState(branchEntryState);
            if (stmt.elseStatement) {
                this.restoreLoopAnalysisState(this.cloneLoopAnalysisState(branchEntryState), state);
                elseFallsThrough = this.analyzeBranchStatement(
                    stmt.elseStatement,
                    state,
                    returnTaints,
                    returnInstances,
                );
                elseExitState = this.captureLoopAnalysisState(state);
            }

            const branchesToMerge: LoopAnalysisState[] = [];
            if (thenFallsThrough) branchesToMerge.push(thenExitState);
            if (elseFallsThrough) branchesToMerge.push(elseExitState);

            if (branchesToMerge.length === 0) return false;

            const mergedState = branchesToMerge
                .slice(1)
                .reduce((merged, branchState) => this.mergeLoopAnalysisStates(merged, branchState), branchesToMerge[0]);
            this.restoreLoopAnalysisState(mergedState, state);
            return true;
        } else if (ts.isForStatement(stmt) || ts.isWhileStatement(stmt) || ts.isDoStatement(stmt)) {
            this.breakTargets.push({ kind: "loop", exits: [] });
            try {
                this.analyzeLoopStatement(stmt, state, returnTaints, returnInstances);
            } finally {
                this.breakTargets.pop();
            }
        } else if (ts.isForOfStatement(stmt) || ts.isForInStatement(stmt)) {
            this.breakTargets.push({ kind: "loop", exits: [] });
            try {
                this.analyzeForEachStatement(stmt, state, returnTaints, returnInstances);
            } finally {
                this.breakTargets.pop();
            }
        } else if (ts.isBlock(stmt)) {
            return this.analyzeStatementList(stmt.statements, state, returnTaints, returnInstances);
        } else if (ts.isTryStatement(stmt)) {
            const before = { mayThrow: this.mayThrow, taints: this.throwTaints, instances: this.throwInstances };
            this.mayThrow = false;
            this.throwTaints = [];
            this.throwInstances = [];
            const tryFallsThrough = this.analyzeStatementList(
                stmt.tryBlock.statements,
                state,
                returnTaints,
                returnInstances,
            );
            const thrown = { mayThrow: this.mayThrow, taints: this.throwTaints, instances: this.throwInstances };
            this.mayThrow = before.mayThrow || (!stmt.catchClause && thrown.mayThrow);
            this.throwTaints = [...before.taints, ...(stmt.catchClause ? [] : thrown.taints)];
            this.throwInstances = [...before.instances, ...(stmt.catchClause ? [] : thrown.instances)];
            if (stmt.catchClause?.variableDeclaration)
                this.bindDestructuring(
                    stmt.catchClause.variableDeclaration.name,
                    thrown.taints,
                    mergeInstanceStates(thrown.instances),
                    state,
                );
            const catchFallsThrough = stmt.catchClause
                ? this.analyzeStatementList(stmt.catchClause.block.statements, state, returnTaints, returnInstances)
                : true;
            const finallyFallsThrough = stmt.finallyBlock
                ? this.analyzeStatementList(stmt.finallyBlock.statements, state, returnTaints, returnInstances)
                : true;
            return finallyFallsThrough && (tryFallsThrough || catchFallsThrough);
        } else if (ts.isSwitchStatement(stmt)) {
            this.analyzeExpression(stmt.expression, state);
            const exits: LoopAnalysisState[] = [];
            const clauses = stmt.caseBlock.clauses;
            const directEntries = new Map<ts.CaseOrDefaultClause, LoopAnalysisState>();
            for (const clause of clauses) {
                if (ts.isCaseClause(clause)) {
                    this.analyzeExpression(clause.expression, state);
                    directEntries.set(clause, this.captureLoopAnalysisState(state));
                }
            }
            const unmatched = this.captureLoopAnalysisState(state);
            if (!clauses.some(ts.isDefaultClause)) exits.push(unmatched);
            this.breakTargets.push({ kind: "switch", exits });
            try {
                // Case selection evaluates preceding case expressions; default
                // selection evaluates every case expression, wherever default sits.
                let fallthrough: LoopAnalysisState | undefined;
                for (const clause of clauses) {
                    const direct = directEntries.get(clause) ?? unmatched;
                    this.restoreLoopAnalysisState(
                        fallthrough
                            ? this.mergeLoopAnalysisStates(direct, fallthrough)
                            : this.cloneLoopAnalysisState(direct),
                        state,
                    );
                    const fallsThrough = this.analyzeStatementList(
                        clause.statements,
                        state,
                        returnTaints,
                        returnInstances,
                    );
                    fallthrough = fallsThrough ? this.captureLoopAnalysisState(state) : undefined;
                }
                if (fallthrough) exits.push(fallthrough);
            } finally {
                this.breakTargets.pop();
            }
            if (exits.length === 0) return false;
            this.restoreLoopAnalysisState(
                exits.slice(1).reduce((merged, exit) => this.mergeLoopAnalysisStates(merged, exit), exits[0]),
                state,
            );
        }

        return true;
    }

    private analyzeLoopStatement(
        stmt: ts.ForStatement | ts.WhileStatement | ts.DoStatement,
        state: TaintState,
        returnTaints: TaintValue[],
        returnInstances: InstanceState[],
    ): void {
        if (ts.isForStatement(stmt)) {
            if (stmt.initializer) {
                if (ts.isVariableDeclarationList(stmt.initializer)) {
                    for (const decl of stmt.initializer.declarations) {
                        this.analyzeVariableDeclaration(decl, state);
                    }
                } else {
                    this.analyzeExpression(stmt.initializer, state);
                }
            }
        }

        const analyzeBody = (iterationState: TaintState): void => {
            this.analyzeLoopBody(stmt.statement, iterationState, returnTaints, returnInstances);
            if (ts.isForStatement(stmt) && stmt.incrementor) {
                this.analyzeExpression(stmt.incrementor, iterationState);
            }
            this.analyzeLoopCondition(stmt, iterationState);
        };

        if (ts.isDoStatement(stmt)) {
            const beforeFirstIteration = this.captureLoopAnalysisState(state);
            analyzeBody(state);
            const firstIterationState = this.captureLoopAnalysisState(state);
            if (!this.loopAnalysisStatesEqual(beforeFirstIteration, firstIterationState)) {
                this.analyzeLoopToFixedPoint(stmt, state, firstIterationState, analyzeBody);
            }
            return;
        }

        this.analyzeLoopCondition(stmt, state);
        const zeroIterationState = this.captureLoopAnalysisState(state);
        this.analyzeLoopToFixedPoint(stmt, state, zeroIterationState, analyzeBody);
    }

    private analyzeLoopCondition(stmt: ts.ForStatement | ts.WhileStatement | ts.DoStatement, state: TaintState): void {
        if (ts.isForStatement(stmt)) {
            if (stmt.condition) this.analyzeExpression(stmt.condition, state);
        } else {
            this.analyzeExpression(stmt.expression, state);
        }
    }

    private analyzeForEachStatement(
        stmt: ts.ForOfStatement | ts.ForInStatement,
        state: TaintState,
        returnTaints: TaintValue[],
        returnInstances: InstanceState[],
    ): void {
        const iterTaints = this.analyzeExpression(stmt.expression, state);
        const iterInstance = this.resolveInstance(stmt.expression);
        const zeroIterationState = this.captureLoopAnalysisState(state);
        this.analyzeLoopToFixedPoint(stmt, state, zeroIterationState, (iterationState) => {
            const currentIterInstance = this.resolveInstance(stmt.expression) ?? iterInstance;
            this.bindForEachVariable(stmt, iterTaints, currentIterInstance, iterationState);
            this.analyzeLoopBody(stmt.statement, iterationState, returnTaints, returnInstances);
        });
    }

    private bindForEachVariable(
        stmt: ts.ForOfStatement | ts.ForInStatement,
        iterTaints: TaintValue[] | undefined,
        iterInstance: InstanceState | undefined,
        state: TaintState,
    ): void {
        const taints =
            iterInstance && ts.isForOfStatement(stmt) && this.hasHostType(iterInstance, "Array")
                ? this.arrayElementTaints(iterInstance, undefined, iterTaints)
                : iterTaints;
        const instance = ts.isForOfStatement(stmt) && iterInstance ? this.getElementInstance(iterInstance) : undefined;
        const stepped = taints?.map((taint) =>
            propagate(
                taint,
                {
                    kind: "arrayIndex",
                    location: this.nodeLocation(stmt.initializer),
                    description: `iterated from ${stmt.expression.getText()}`,
                },
                this.metrics,
            ),
        );
        if (ts.isVariableDeclarationList(stmt.initializer)) {
            for (const decl of stmt.initializer.declarations)
                this.bindDestructuring(decl.name, stepped, instance, state);
        } else {
            this.assignBindingTarget(stmt.initializer, stepped, instance, state);
        }
    }

    private analyzeLoopBody(
        body: ts.Statement,
        state: TaintState,
        returnTaints: TaintValue[],
        returnInstances: InstanceState[],
    ): void {
        this.analyzeBranchStatement(body, state, returnTaints, returnInstances);
    }

    private analyzeLoopToFixedPoint(
        loop: ts.IterationStatement,
        state: TaintState,
        entryState: LoopAnalysisState,
        analyzeIteration: (iterationState: TaintState) => void,
    ): void {
        let loopHeadState = this.cloneLoopAnalysisState(entryState);
        let converged = false;

        for (let iteration = 0; iteration < MAX_LOOP_ITERATIONS; iteration++) {
            const iterationState = this.cloneLoopAnalysisState(loopHeadState);
            this.restoreLoopAnalysisState(iterationState, state);
            analyzeIteration(state);
            const nextLoopHeadState = this.mergeLoopAnalysisStates(entryState, this.captureLoopAnalysisState(state));
            if (this.loopAnalysisStatesEqual(loopHeadState, nextLoopHeadState)) {
                converged = true;
                break;
            }
            loopHeadState = nextLoopHeadState;
        }

        this.restoreLoopAnalysisState(loopHeadState, state);

        if (!converged) {
            this.warnings.push(
                `Loop analysis did not converge after ${MAX_LOOP_ITERATIONS} iterations at ${getLocationString(loop)}`,
            );
        }
    }

    private captureLoopAnalysisState(state: TaintState): LoopAnalysisState {
        return this.cloneLoopAnalysisState({
            taints: state,
            instanceBindings: this.instanceFieldState,
            moduleInstances: this.interproc?.getModuleInstanceState?.() ?? new Map(),
            currentThisInstance: this.currentThisInstance,
            expressionInstances: this.expressionInstanceState,
            cleanBindings: this.cleanBindings,
        });
    }

    private cloneLoopAnalysisState(source: LoopAnalysisState): LoopAnalysisState {
        const clones = new Map<InstanceState, InstanceState>();
        const cloneInstance = (instance: InstanceState): InstanceState => {
            const cached = clones.get(instance);
            if (cached) return cached;

            const clone = createInstanceState();
            clone.apiTypes = instance.apiTypes;
            clone.classDeclarations = instance.classDeclarations;
            clone.classDeclarationsUnknown = instance.classDeclarationsUnknown;
            clone.hostCallback = instance.hostCallback;
            clone.valueTaints = instance.valueTaints;
            clone.valueExpression = instance.valueExpression;
            clone.taintedElementsFromIndex = instance.taintedElementsFromIndex;
            clones.set(instance, clone);
            this.instanceOrigins.set(clone, this.instanceOrigins.get(instance) ?? instance);
            clone.fields = forkTaintState(instance.fields);
            clone.functions = instance.functions.map((value) => ({
                ...value,
                captured: forkTaintState(value.captured),
                capturedInstances: new Map(
                    [...value.capturedInstances].map(([symbol, nested]) => [symbol, cloneInstance(nested)]),
                ),
                thisInstance: value.thisInstance ? cloneInstance(value.thisInstance) : undefined,
            }));
            for (const [symbol, nested] of instance.fieldInstances) {
                clone.fieldInstances.set(symbol, cloneInstance(nested));
            }
            for (const [key, nested] of instance.elementInstances) {
                clone.elementInstances.set(key, cloneInstance(nested));
            }
            return clone;
        };

        return {
            taints: forkTaintState(source.taints),
            instanceBindings: new Map(
                [...source.instanceBindings].map(([symbol, instance]) => [symbol, cloneInstance(instance)]),
            ),
            expressionInstances: new Map(
                [...source.expressionInstances].map(([expression, instance]) => [expression, cloneInstance(instance)]),
            ),
            moduleInstances: new Map(
                [...source.moduleInstances].map(([symbol, instance]) => [symbol, cloneInstance(instance)]),
            ),
            currentThisInstance: source.currentThisInstance ? cloneInstance(source.currentThisInstance) : undefined,
            cleanBindings: new Set(source.cleanBindings),
        };
    }

    private restoreLoopAnalysisState(source: LoopAnalysisState, state: TaintState): void {
        if (state instanceof CopyOnWriteMap && source.taints instanceof CopyOnWriteMap) {
            state.replaceWith(source.taints);
        } else {
            state.clear();
            for (const [symbol, taints] of source.taints) state.set(symbol, taints);
        }
        this.instanceFieldState = source.instanceBindings;
        this.interproc?.setModuleInstanceState?.(source.moduleInstances);
        this.currentThisInstance = source.currentThisInstance;
        this.expressionInstanceState = source.expressionInstances;
        this.cleanBindings = source.cleanBindings;
    }

    private mergeLoopAnalysisStates(a: LoopAnalysisState, b: LoopAnalysisState): LoopAnalysisState {
        const mergedInstances = new Map<InstanceState, Map<InstanceState, InstanceState>>();
        const mergeInstances = (left: InstanceState, right: InstanceState, depth: number = 0): InstanceState => {
            let byRight = mergedInstances.get(left);
            if (!byRight) {
                byRight = new Map();
                mergedInstances.set(left, byRight);
            }
            const cached = byRight.get(right);
            if (cached) return cached;

            const merged = createInstanceState();
            merged.apiTypes = [...new Set([...(left.apiTypes ?? []), ...(right.apiTypes ?? [])])].sort();
            merged.classDeclarations = [
                ...new Set([...(left.classDeclarations ?? []), ...(right.classDeclarations ?? [])]),
            ];
            merged.classDeclarationsUnknown =
                left.classDeclarationsUnknown ||
                right.classDeclarationsUnknown ||
                (merged.classDeclarations.length > 0 &&
                    (!left.classDeclarations?.length || !right.classDeclarations?.length)) ||
                undefined;
            merged.hostCallback = left.hostCallback === right.hostCallback ? left.hostCallback : undefined;
            merged.valueExpression = left.valueExpression === right.valueExpression ? left.valueExpression : undefined;
            const ranges = [left.taintedElementsFromIndex, right.taintedElementsFromIndex].filter(
                (index): index is number => index != null,
            );
            if (ranges.length) merged.taintedElementsFromIndex = Math.min(...ranges);
            merged.valueTaints = [
                ...new Map(
                    [...(left.valueTaints ?? []), ...(right.valueTaints ?? [])].map((taint) => [
                        this.taintFactKey(taint),
                        taint,
                    ]),
                ).values(),
            ];
            byRight.set(right, merged);
            const leftOrigin = this.instanceOrigins.get(left) ?? left;
            const rightOrigin = this.instanceOrigins.get(right) ?? right;
            if (leftOrigin === rightOrigin) this.instanceOrigins.set(merged, leftOrigin);
            merged.fields = this.mergeLoopStates(left.fields, right.fields);
            merged.functions = unionFunctionValues(
                [left.functions, right.functions],
                depth < MAX_INSTANCE_MERGE_DEPTH
                    ? (nested) => nested.reduce((a, b) => mergeInstances(a, b, depth + 1))
                    : undefined,
            );
            if (depth >= MAX_INSTANCE_MERGE_DEPTH) return merged;

            for (const symbol of new Set([...left.fieldInstances.keys(), ...right.fieldInstances.keys()])) {
                const leftNested = left.fieldInstances.get(symbol);
                const rightNested = right.fieldInstances.get(symbol);
                const nested =
                    leftNested && rightNested
                        ? mergeInstances(leftNested, rightNested, depth + 1)
                        : (leftNested ?? rightNested);
                if (nested) merged.fieldInstances.set(symbol, nested);
            }
            for (const key of new Set([...left.elementInstances.keys(), ...right.elementInstances.keys()])) {
                if (
                    [BINDING_OBJECT_SHAPE, BINDING_ARRAY_SHAPE].includes(key) &&
                    (!left.elementInstances.has(key) || !right.elementInstances.has(key))
                )
                    continue;
                const leftNested =
                    left.elementInstances.get(key) ??
                    (isBindingPayload(key) ? missingBindingPayload(left, key) : undefined);
                const rightNested =
                    right.elementInstances.get(key) ??
                    (isBindingPayload(key) ? missingBindingPayload(right, key) : undefined);
                const nested =
                    leftNested && rightNested
                        ? mergeInstances(leftNested, rightNested, depth + 1)
                        : (leftNested ?? rightNested);
                if (nested) merged.elementInstances.set(key, nested);
            }
            return merged;
        };

        const instanceBindings = new Map<ts.Symbol, InstanceState>();
        for (const symbol of new Set([...a.instanceBindings.keys(), ...b.instanceBindings.keys()])) {
            const left = a.instanceBindings.get(symbol);
            const right = b.instanceBindings.get(symbol);
            const instance = left && right ? mergeInstances(left, right) : (left ?? right);
            if (instance)
                instanceBindings.set(
                    symbol,
                    (!left || !right) && instance.valueExpression
                        ? { ...instance, valueExpression: undefined }
                        : instance,
                );
        }

        const moduleInstances = new Map<ts.Symbol, InstanceState>();
        for (const symbol of new Set([...a.moduleInstances.keys(), ...b.moduleInstances.keys()])) {
            const left = a.moduleInstances.get(symbol);
            const right = b.moduleInstances.get(symbol);
            const instance = left && right ? mergeInstances(left, right) : (left ?? right);
            if (instance) moduleInstances.set(symbol, instance);
        }
        let currentThisInstance: InstanceState | undefined;
        if (a.currentThisInstance && b.currentThisInstance) {
            currentThisInstance = mergeInstances(a.currentThisInstance, b.currentThisInstance);
        } else {
            currentThisInstance = a.currentThisInstance ?? b.currentThisInstance;
        }

        const expressionInstances = new Map<ts.Expression, InstanceState>();
        for (const expression of new Set([...a.expressionInstances.keys(), ...b.expressionInstances.keys()])) {
            const left = a.expressionInstances.get(expression);
            const right = b.expressionInstances.get(expression);
            const instance = left && right ? mergeInstances(left, right) : (left ?? right);
            if (instance) expressionInstances.set(expression, instance);
        }
        return {
            taints: this.mergeLoopStates(a.taints, b.taints),
            instanceBindings,
            moduleInstances,
            currentThisInstance,
            expressionInstances,
            cleanBindings: new Set([...a.cleanBindings].filter((symbol) => b.cleanBindings.has(symbol))),
        };
    }

    private loopAnalysisStatesEqual(a: LoopAnalysisState, b: LoopAnalysisState): boolean {
        if (!this.taintStatesEqual(a.taints, b.taints)) return false;
        if (
            a.cleanBindings.size !== b.cleanBindings.size ||
            [...a.cleanBindings].some((symbol) => !b.cleanBindings.has(symbol))
        )
            return false;
        if (a.instanceBindings.size !== b.instanceBindings.size) return false;

        const compared = new Map<InstanceState, InstanceState>();
        const reverseCompared = new Map<InstanceState, InstanceState>();
        const instancesEqual = (left: InstanceState, right: InstanceState): boolean => {
            const priorRight = compared.get(left);
            if (priorRight) return priorRight === right;
            const priorLeft = reverseCompared.get(right);
            if (priorLeft) return priorLeft === left;
            compared.set(left, right);
            reverseCompared.set(right, left);

            if (!this.taintStatesEqual(left.fields, right.fields)) return false;
            if (!this.functionValuesEqual(left.functions, right.functions)) return false;
            if ((left.apiTypes ?? []).join("|") !== (right.apiTypes ?? []).join("|")) return false;
            if (
                left.hostCallback !== right.hostCallback ||
                left.valueExpression !== right.valueExpression ||
                left.taintedElementsFromIndex !== right.taintedElementsFromIndex
            )
                return false;
            if (
                left.classDeclarationsUnknown !== right.classDeclarationsUnknown ||
                (left.classDeclarations?.length ?? 0) !== (right.classDeclarations?.length ?? 0) ||
                left.classDeclarations?.some((declaration) => !right.classDeclarations?.includes(declaration))
            )
                return false;
            const valueKeys = (instance: InstanceState) =>
                [...new Set((instance.valueTaints ?? []).map((taint) => this.taintFactKey(taint)))].sort().join("|");
            if (valueKeys(left) !== valueKeys(right)) return false;
            if (
                left.fieldInstances.size !== right.fieldInstances.size ||
                left.elementInstances.size !== right.elementInstances.size
            ) {
                return false;
            }
            for (const [symbol, leftNested] of left.fieldInstances) {
                const rightNested = right.fieldInstances.get(symbol);
                if (!rightNested || !instancesEqual(leftNested, rightNested)) {
                    return false;
                }
            }
            for (const [key, leftNested] of left.elementInstances) {
                const rightNested = right.elementInstances.get(key);
                if (!rightNested || !instancesEqual(leftNested, rightNested)) {
                    return false;
                }
            }
            return true;
        };

        for (const [symbol, left] of a.instanceBindings) {
            const right = b.instanceBindings.get(symbol);
            if (!right || !instancesEqual(left, right)) return false;
        }

        if (a.moduleInstances.size !== b.moduleInstances.size) return false;
        for (const [symbol, left] of a.moduleInstances) {
            const right = b.moduleInstances.get(symbol);
            if (!right || !instancesEqual(left, right)) return false;
        }
        if (a.currentThisInstance == null || b.currentThisInstance == null) {
            return a.currentThisInstance === b.currentThisInstance;
        }
        return instancesEqual(a.currentThisInstance, b.currentThisInstance);
    }

    private mergeLoopStates(a: TaintState, b: TaintState): TaintState {
        if (
            a instanceof CopyOnWriteMap &&
            b instanceof CopyOnWriteMap &&
            a.storageIdentity === b.storageIdentity &&
            this.normalizedStates.has(a.storageIdentity)
        ) {
            return a.fork();
        }
        const merged = new Map<ts.Symbol, TaintValue[]>();
        for (const source of [a, b]) {
            for (const [symbol, taints] of source) {
                const existing = merged.get(symbol) ?? [];
                const seen = new Set(existing.map((taint) => this.taintFactKey(taint)));
                for (const taint of taints) {
                    const key = this.taintFactKey(taint);
                    if (seen.has(key)) continue;
                    seen.add(key);
                    existing.push(taint);
                    if (existing.length >= TaintTracker.MAX_TAINTS_PER_SYMBOL) break;
                }
                if (existing.length > 0) merged.set(symbol, existing);
            }
        }
        const result = forkTaintState(merged);
        this.normalizedStates.add(result.storageIdentity);
        return result;
    }

    /** Same declarations, each with the same captured taint. */
    private functionValuesEqual(a: FunctionValue[], b: FunctionValue[]): boolean {
        if (a.length !== b.length) return false;
        const byDeclaration = new Map(a.map((value) => [value.declaration, value]));
        return b.every((value) => {
            const other = byDeclaration.get(value.declaration);
            return other != null && this.taintStatesEqual(other.captured, value.captured);
        });
    }

    private taintStatesEqual(a: TaintState, b: TaintState): boolean {
        if (a instanceof CopyOnWriteMap && b instanceof CopyOnWriteMap && a.storageIdentity === b.storageIdentity)
            return true;
        const populatedA = [...a].filter(([, taints]) => taints.length > 0);
        const populatedB = [...b].filter(([, taints]) => taints.length > 0);
        if (populatedA.length !== populatedB.length) return false;

        for (const [symbol, taintsA] of populatedA) {
            const taintsB = b.get(symbol);
            if (!taintsB || taintsA.length !== taintsB.length) return false;
            const keysB = new Set(taintsB.map((taint) => this.taintFactKey(taint)));
            if (taintsA.some((taint) => !keysB.has(this.taintFactKey(taint)))) {
                return false;
            }
        }
        return true;
    }

    private taintFactKey(taint: TaintValue): string {
        const cached = TaintTracker.loopTaintFactKeys.get(taint);
        if (cached != null) return cached;

        const nestedShell = taint.nestedShellCommandLocation;
        // Propagation chains deliberately do not participate: traversing a
        // back-edge adds another chain node but does not create a new fact.
        const key = JSON.stringify([
            taint.sourceCacheKey,
            taint.aggregatePropertyPath ?? [],
            taint.sanitizers?.map(({ spec, contextSatisfied, shellCommand }) => [
                spec.kind,
                spec.pattern,
                spec.categories ?? [],
                spec.sinkNames ?? [],
                spec.requiresShellArgumentContext === true,
                spec.numeric === true,
                spec.shellCommandDenylist ?? [],
                contextSatisfied,
                shellCommand ?? "",
                spec.numeric === true && TaintTracker.isBareNumber(taint),
                spec.requiresShellArgumentContext === true && TaintTracker.wasQuotedElementWise(taint),
            ]) ?? [],
            nestedShell ? [nestedShell.fileName, nestedShell.line, nestedShell.column, nestedShell.text ?? ""] : null,
        ]);
        TaintTracker.loopTaintFactKeys.set(taint, key);
        return key;
    }

    private analyzeVariableDeclaration(decl: ts.VariableDeclaration, state: TaintState): void {
        if (!decl.initializer) return;

        // Detect `const self = this` alias pattern before analyzing the initializer
        if (ts.isIdentifier(decl.name) && decl.initializer.kind === ts.SyntaxKind.ThisKeyword) {
            const sym = this.checker.getSymbolAtLocation(decl.name);
            if (sym) {
                this.thisAliases.add(sym);
                if (this.currentThisInstance) {
                    this.instanceFieldState.set(sym, this.currentThisInstance);
                }
            }
            return;
        }

        const initTaints = this.analyzeExpression(decl.initializer, state);
        const initInstance = this.resolveInstance(decl.initializer);

        if (ts.isIdentifier(decl.name)) {
            const name = decl.name;
            const sym = this.checker.getSymbolAtLocation(name);
            if (sym) {
                if (initTaints) {
                    const stepped = initTaints.map((t) =>
                        propagate(
                            t,
                            {
                                kind: "assignment",
                                location: this.nodeLocation(decl),
                                description: `assigned to '${name.text}'`,
                            },
                            this.metrics,
                        ),
                    );
                    state.set(sym, stepped);
                }
                if (
                    !initTaints?.length &&
                    (decl.parent.flags & ts.NodeFlags.Const) !== 0 &&
                    this.isProvenClean(decl.initializer) &&
                    this.hasPrimitiveType(decl.initializer)
                ) {
                    this.cleanBindings.add(sym);
                } else {
                    this.cleanBindings.delete(sym);
                }
                if (initInstance) {
                    this.instanceFieldState.set(sym, initInstance);
                } else {
                    this.instanceFieldState.delete(sym);
                }
            }
        } else {
            this.bindDestructuring(decl.name, initTaints, initInstance, state);
        }
    }

    private bindingValueExpression(expression: ts.Expression): ts.Expression | undefined {
        const value = unwrapExpression(expression);
        if (ts.isVoidExpression(value) || ts.isOmittedExpression(value)) return BINDING_UNDEFINED;
        if (
            ts.isIdentifier(value) &&
            value.text === "undefined" &&
            this.checker
                .getSymbolAtLocation(value)
                ?.declarations?.every((declaration) => declaration.getSourceFile().isDeclarationFile)
        )
            return BINDING_UNDEFINED;
        if (
            ts.isStringLiteralLike(value) ||
            ts.isNumericLiteral(value) ||
            [ts.SyntaxKind.NullKeyword, ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword].includes(value.kind) ||
            ts.isObjectLiteralExpression(value) ||
            ts.isArrayLiteralExpression(value) ||
            ts.isArrowFunction(value) ||
            ts.isFunctionExpression(value) ||
            ts.isNewExpression(value)
        )
            return BINDING_DEFINED;
        if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
            const key = ts.isPropertyAccessExpression(value)
                ? value.name.text
                : this.elementKey(value.argumentExpression);
            const owner = this.resolveInstance(value.expression);
            if (owner && key != null) return this.bindingProperty(owner, key)?.valueExpression;
        }
        // Type annotations and mutable initializers are not a runtime value snapshot.
        if (this.isProvenClean(value) && this.hasPrimitiveType(value)) {
            const type = this.checker.getTypeAtLocation(value);
            const members = type.isUnion() ? type.types : [type];
            if (
                members.every(
                    (member) =>
                        !(
                            member.flags &
                            (ts.TypeFlags.Undefined | ts.TypeFlags.Void | ts.TypeFlags.Any | ts.TypeFlags.Unknown)
                        ),
                )
            )
                return BINDING_DEFINED;
        }
        return undefined;
    }

    private bindingProperty(owner: InstanceState, key: string): InstanceState | undefined {
        const array = this.hasHostType(owner, "Array");
        const slot = array ? `$taint:${key}` : `${BINDING_PROPERTY}${key}`;
        const stored = owner.elementInstances.get(slot);
        const fieldTaints = array
            ? []
            : [...owner.fields].filter(([field]) => field.getName() === key).flatMap(([, taints]) => taints);
        const payload =
            stored && fieldTaints.length
                ? {
                      ...stored,
                      valueTaints: [...(stored.valueTaints ?? []), ...fieldTaints],
                      valueExpression: stored.valueTaints?.length ? stored.valueExpression : undefined,
                  }
                : stored;
        const wildcard = array ? owner.elementInstances.get("$taint:*") : undefined;
        if (wildcard)
            return { ...mergeInstanceStates([...(payload ? [payload] : []), wildcard])!, valueExpression: undefined };
        const selected =
            payload ??
            (owner.elementInstances.has(array ? BINDING_ARRAY_SHAPE : BINDING_OBJECT_SHAPE)
                ? missingBindingPayload(owner, slot)
                : undefined);
        const defined = selected?.elementInstances.get(BINDING_VALUE_STATE);
        return array && selected && defined ? { ...selected, valueExpression: defined.valueExpression } : selected;
    }

    private bindingProvenance(values: readonly TaintValue[], incoming: readonly TaintValue[]): TaintValue[] {
        if (!values.length || !incoming.length) return values.slice();
        const byFact = new Map<string, TaintValue>();
        for (const taint of incoming) {
            const key = this.taintFactKey(taint);
            const existing = byFact.get(key);
            if (!existing || existing.chainLength < taint.chainLength) byFact.set(key, taint);
        }
        return values.map((taint) => {
            const candidate = byFact.get(this.taintFactKey(taint));
            return candidate && candidate.chainLength >= taint.chainLength ? candidate : taint;
        });
    }

    private selectBindingProperty(
        name: ts.BindingName | ts.ObjectLiteralExpression | ts.ArrayLiteralExpression,
        key: string | undefined,
        taints: TaintValue[] | undefined,
        instance: InstanceState | undefined,
    ): { taints?: TaintValue[]; instance?: InstanceState; defined?: ts.Expression } {
        const array = ts.isArrayBindingPattern(name) || ts.isArrayLiteralExpression(name);
        const payload = instance && key != null ? this.bindingProperty(instance, key) : undefined;
        let selectedTaints = payload ? payload.valueTaints?.slice() : taints;
        let selectedInstance = payload?.elementInstances.get("$value");
        if (key != null && !array) {
            const incoming = taints && TaintTracker.taintsForAggregateProperty(taints, key);
            selectedTaints = payload ? this.bindingProvenance(selectedTaints ?? [], incoming ?? []) : incoming;
            const property = this.checker.getTypeAtLocation(name).getProperty(key);
            selectedInstance ??= property && instance ? this.getInstanceReference(instance, property) : undefined;
            selectedInstance ??= instance?.elementInstances.get(key);
        } else if (instance) {
            selectedInstance ??= this.getElementInstance(instance, key);
            if (this.hasHostType(instance, "Array")) selectedTaints = this.arrayElementTaints(instance, key, taints);
        }
        return { taints: selectedTaints, instance: selectedInstance, defined: payload?.valueExpression };
    }

    private bindingRest(
        array: boolean,
        start: number,
        excluded: Set<string>,
        taints: TaintValue[] | undefined,
        instance: InstanceState | undefined,
    ): { taints?: TaintValue[]; instance?: InstanceState } {
        const rest = createInstanceState();
        if (array) rest.apiTypes = ["Array"];
        if (instance) {
            for (const [property, values] of instance.fields) {
                if (!array && !excluded.has(property.getName())) rest.fields.set(property, values);
            }
            for (const [property, nested] of instance.fieldInstances) {
                if (!array && !excluded.has(property.getName())) rest.fieldInstances.set(property, nested);
            }
            for (const [key, value] of instance.elementInstances) {
                if (!array) {
                    const property = key.startsWith(BINDING_PROPERTY) ? key.slice(BINDING_PROPERTY.length) : key;
                    if (!excluded.has(property)) rest.elementInstances.set(key, value);
                } else {
                    const numeric = key.startsWith("$taint:") ? key.slice(7) : key;
                    if (/^\d+$/.test(numeric)) {
                        if (Number(numeric) >= start)
                            rest.elementInstances.set(
                                `${key.startsWith("$taint:") ? "$taint:" : ""}${Number(numeric) - start}`,
                                value,
                            );
                    } else if (["*", "$taint:*", BINDING_ARRAY_SHAPE].includes(key))
                        rest.elementInstances.set(key, value);
                }
            }
            if (array && instance.taintedElementsFromIndex != null) {
                rest.taintedElementsFromIndex = Math.max(0, instance.taintedElementsFromIndex - start);
                rest.valueTaints = instance.valueTaints;
            }
        }
        const selected =
            array && instance && this.hasHostType(instance, "Array")
                ? this.arrayElementTaints(rest, undefined, taints)
                : taints?.filter(
                      (taint) => !taint.aggregatePropertyPath?.length || !excluded.has(taint.aggregatePropertyPath[0]),
                  );
        return { taints: selected, instance: rest };
    }

    private bindDestructuring(
        name: ts.BindingName,
        taints: TaintValue[] | undefined,
        instance: InstanceState | undefined,
        state: TaintState,
    ): void {
        if (ts.isIdentifier(name)) {
            const symbol = ts.isShorthandPropertyAssignment(name.parent)
                ? this.checker.getShorthandAssignmentValueSymbol(name.parent)
                : this.checker.getSymbolAtLocation(name);
            if (!symbol) return;
            if (taints?.length) state.set(symbol, taints);
            else state.delete(symbol);
            this.cleanBindings.delete(symbol);
            if (instance) this.instanceFieldState.set(symbol, instance);
            else this.instanceFieldState.delete(symbol);
            return;
        }
        const excluded = new Set<string>();
        for (let index = 0; index < name.elements.length; index++) {
            const element = name.elements[index];
            if (!ts.isBindingElement(element)) continue;
            const key = ts.isArrayBindingPattern(name)
                ? String(index)
                : element.propertyName
                  ? this.propertyName(element.propertyName)
                  : ts.isIdentifier(element.name)
                    ? element.name.text
                    : undefined;
            if (element.propertyName && ts.isComputedPropertyName(element.propertyName))
                this.analyzeExpression(element.propertyName.expression, state);
            const selected = element.dotDotDotToken
                ? this.bindingRest(ts.isArrayBindingPattern(name), index, excluded, taints, instance)
                : this.selectBindingProperty(name, key, taints, instance);
            if (key != null) excluded.add(key);
            const value = this.analyzeBindingDefault(element.initializer, selected, state);
            const stepped = value.taints?.map((taint) =>
                propagate(
                    taint,
                    {
                        kind: "destructuring",
                        location: this.nodeLocation(element),
                        description: `destructured '${key ?? "property"}' into '${element.name.getText()}'`,
                    },
                    this.metrics,
                ),
            );
            this.bindDestructuring(element.name, stepped, value.instance, state);
        }
    }

    private analyzeBindingDefault(
        initializer: ts.Expression | undefined,
        selected: { taints?: TaintValue[]; instance?: InstanceState; defined?: ts.Expression },
        state: TaintState,
    ): { taints?: TaintValue[]; instance?: InstanceState } {
        if (!initializer || selected.defined === BINDING_DEFINED) return selected;
        if (selected.instance) this.expressionInstanceState.set(initializer, selected.instance);
        else this.expressionInstanceState.delete(initializer);
        const skipped = selected.defined !== BINDING_UNDEFINED ? this.captureLoopAnalysisState(state) : undefined;
        const defaultTaints = this.analyzeExpression(initializer, state);
        const defaultInstance = this.resolveValueInstance(initializer, state);
        if (defaultInstance) this.expressionInstanceState.set(initializer, defaultInstance);
        else this.expressionInstanceState.delete(initializer);
        if (!skipped) return { taints: defaultTaints, instance: defaultInstance };
        this.restoreLoopAnalysisState(
            this.mergeLoopAnalysisStates(skipped, this.captureLoopAnalysisState(state)),
            state,
        );
        return {
            taints: [...(selected.taints ?? []), ...(defaultTaints ?? [])],
            instance: this.expressionInstanceState.get(initializer),
        };
    }

    private assignBindingTarget(
        target: ts.Expression,
        taints: TaintValue[] | undefined,
        instance: InstanceState | undefined,
        state: TaintState,
    ): void {
        const value = unwrapExpression(target);
        if (ts.isIdentifier(value)) {
            this.bindDestructuring(value, taints, instance, state);
        } else if (ts.isPropertyAccessExpression(value)) {
            this.analyzeExpression(value.expression, state);
            this.assignPropertyTaint(value, taints, state, value);
            this.assignPropertyInstance(value, instance);
            if (taints) this.checkAssignmentSink(value, taints);
        } else if (ts.isElementAccessExpression(value)) {
            this.analyzeExpression(value.expression, state);
            this.analyzeExpression(value.argumentExpression, state);
            this.assignElementInstance(value, instance, taints);
            if (taints) this.checkAssignmentSink(value, taints);
        } else if (ts.isObjectLiteralExpression(value) || ts.isArrayLiteralExpression(value)) {
            const array = ts.isArrayLiteralExpression(value);
            const elements = array ? value.elements : value.properties;
            const excluded = new Set<string>();
            elements.forEach((element, index) => {
                if (ts.isOmittedExpression(element)) return;
                const rest = ts.isSpreadElement(element) || ts.isSpreadAssignment(element);
                const target = rest
                    ? element.expression
                    : ts.isPropertyAssignment(element)
                      ? element.initializer
                      : element;
                const key = array
                    ? String(index)
                    : ts.isPropertyAssignment(element) || ts.isShorthandPropertyAssignment(element)
                      ? this.propertyName(element.name)
                      : undefined;
                const selected = rest
                    ? this.bindingRest(array, index, excluded, taints, instance)
                    : this.selectBindingProperty(value, key, taints, instance);
                if (key != null) excluded.add(key);
                let destination: ts.Expression;
                let initializer: ts.Expression | undefined;
                if (ts.isShorthandPropertyAssignment(target)) {
                    destination = target.name;
                    initializer = target.objectAssignmentInitializer;
                } else if (ts.isBinaryExpression(target) && target.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
                    destination = target.left;
                    initializer = target.right;
                } else {
                    destination = target as ts.Expression;
                }
                const bound = this.analyzeBindingDefault(initializer, selected, state);
                this.assignBindingTarget(destination, bound.taints, bound.instance, state);
            });
        }
    }

    /**
     * Analyze an expression and return its taint value(s), if any.
     * Also checks for sink matches and reports findings.
     */
    private analyzeExpression(expr: ts.Expression, state: TaintState): TaintValue[] | undefined {
        if (ts.isIdentifier(expr)) {
            return this.analyzeIdentifier(expr, state);
        }

        if (ts.isPropertyAccessExpression(expr)) {
            return this.analyzePropertyAccess(expr, state);
        }

        if (ts.isElementAccessExpression(expr)) {
            return this.analyzeElementAccess(expr, state);
        }

        if (ts.isCallExpression(expr)) {
            return this.analyzeCallExpression(expr, state);
        }

        if (ts.isNewExpression(expr)) {
            return this.analyzeNewExpression(expr, state);
        }

        if (ts.isBinaryExpression(expr)) {
            return this.analyzeBinaryExpression(expr, state);
        }

        if (ts.isTemplateExpression(expr)) {
            return this.analyzeTemplateExpression(expr, state);
        }

        if (ts.isConditionalExpression(expr)) {
            return this.analyzeConditionalExpression(expr, state);
        }

        if (ts.isParenthesizedExpression(expr)) {
            return this.analyzeExpression(expr.expression, state);
        }

        if (ts.isPrefixUnaryExpression(expr) || ts.isPostfixUnaryExpression(expr)) {
            return this.analyzeExpression(expr.operand, state);
        }

        if (ts.isSpreadElement(expr)) {
            const innerTaints = this.analyzeExpression(expr.expression, state);
            if (innerTaints) {
                return innerTaints.map((t) =>
                    propagate(
                        t,
                        {
                            kind: "spread",
                            location: this.nodeLocation(expr),
                            description: `spread of ${expr.expression.getText()}`,
                        },
                        this.metrics,
                    ),
                );
            }
        }

        if (ts.isObjectLiteralExpression(expr)) {
            return this.analyzeObjectLiteral(expr, state);
        }

        if (ts.isArrayLiteralExpression(expr)) {
            return this.analyzeArrayLiteral(expr, state);
        }

        if (ts.isAwaitExpression(expr)) {
            const taints = this.analyzeExpression(expr.expression, state);
            const promise = this.resolveInstance(expr.expression);
            if (this.hasHostType(promise, "Promise")) {
                const value = promise!.elementInstances.get("$fulfilled");
                const rejected = promise!.elementInstances.get("$rejected");
                if (rejected) {
                    this.mayThrow = true;
                    this.throwTaints.push(...(rejected.valueTaints ?? []));
                    const instance = rejected.elementInstances.get("$value");
                    if (instance) this.throwInstances.push(instance);
                    if (!value && !this.hasUnknownPromiseSettlement(promise)) this.nonReturningExpressions.add(expr);
                }
                const instance = value?.elementInstances.get("$value");
                if (instance) this.expressionInstanceState.set(expr, instance);
                if (this.hasUnknownPromiseSettlement(promise)) {
                    return [
                        ...(value?.valueTaints ?? []),
                        ...(promise!.elementInstances.get("$unknownReturn")?.valueTaints ?? taints ?? []),
                    ];
                }
                return value?.valueTaints?.slice();
            }
            return taints;
        }

        if (ts.isVoidExpression(expr) || ts.isTypeOfExpression(expr) || ts.isDeleteExpression(expr)) {
            const operand = unwrapExpression(expr.expression);
            if (ts.isDeleteExpression(expr) && ts.isElementAccessExpression(operand)) {
                this.analyzeExpression(operand.expression, state);
                this.analyzeExpression(operand.argumentExpression, state);
            } else if (ts.isDeleteExpression(expr) && ts.isPropertyAccessExpression(operand)) {
                this.analyzeExpression(operand.expression, state);
            } else {
                this.analyzeExpression(operand, state);
            }
            if (ts.isDeleteExpression(expr)) this.deleteBindingProperty(operand, state);
            this.cleanExpressions.add(expr);
            if (this.nonReturningExpressions.has(operand)) this.nonReturningExpressions.add(expr);
            return undefined;
        }

        if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr) || ts.isSatisfiesExpression(expr)) {
            return this.analyzeExpression(expr.expression, state);
        }

        if (ts.isNonNullExpression(expr)) {
            return this.analyzeExpression(expr.expression, state);
        }

        if (ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)) {
            // Analyze captured values even when a later callback invocation
            // cannot be resolved, e.g. `items.map(() => exec(cmd))`.
            this.analyzeClosureBody(expr, state);
            this.expressionInstanceState.set(expr, createFunctionInstance(this.captureFunctionValue(expr, state)));
            return undefined;
        }

        return undefined;
    }

    /**
     * Snapshot what a function expression captures so a later call through a
     * field or parameter (`this.getConfig()`) can analyze the body with it.
     * Definition-site analysis cannot follow the return value to that caller.
     */
    private captureFunctionValue(fn: ts.ArrowFunction | ts.FunctionExpression, state: TaintState): FunctionValue {
        const captured: TaintState = createTaintState();
        const capturedInstances = new Map<ts.Symbol, InstanceState>();
        const capturedAt = this.nodeLocation(fn);
        for (const sym of this.freeSymbols(fn)) {
            const taints = state.get(sym);
            if (taints && taints.length > 0) {
                captured.set(
                    sym,
                    taints.map((t) =>
                        propagate(
                            t,
                            {
                                kind: "closure",
                                location: capturedAt,
                                description: `captured by ${
                                    ts.isArrowFunction(fn) ? "arrow function" : "function expression"
                                } called later`,
                            },
                            this.metrics,
                        ),
                    ),
                );
            }
            const instance = this.instanceFieldState.get(sym);
            if (instance) capturedInstances.set(sym, instance);
        }
        return {
            declaration: fn,
            captured,
            capturedInstances,
            thisInstance: ts.isArrowFunction(fn) ? this.currentThisInstance : undefined,
        };
    }

    private freeSymbols(fn: ts.FunctionLikeDeclaration): ts.Symbol[] {
        return functionFreeSymbols(this.checker, fn);
    }

    /**
     * Speculatively analyze a closure with its defining scope's taint state.
     * A later unresolved invocation need not be visible. This pass does not
     * observe later writes to captured variables; registered-command effects
     * are analyzed separately with `eventEffects` enabled.
     *
     * Taint and instance state are isolated from the live caller. Definition-site
     * contexts are memoized; event-effect analysis instead returns its state
     * for the caller to merge.
     */
    private analyzeClosureBody(
        fn: ts.ArrowFunction | ts.FunctionExpression,
        state: TaintState,
        eventEffects: boolean = false,
    ): LoopAnalysisState | undefined {
        // Filter by syntax, not sink names: `helper(x)` can reach a sink in
        // another function. Calls, construction, and assignments must survive.
        if (!this.bodyCanReachSink(fn)) return undefined;

        // Key by the captured context, including instance fields and lexical
        // this. Unrelated locals must not create duplicate closure contexts.
        const free = this.freeSymbols(fn);
        const relevantState: TaintState = new Map();
        for (const symbol of free) {
            const taints = state.get(symbol);
            if (taints?.length) relevantState.set(symbol, taints);
        }
        const semanticSignature = this.closureSignature(fn, free, relevantState);
        const signature = `${eventEffects ? "event" : "definition"}:${semanticSignature}`;
        let seen = this.closureCache.get(fn);
        if (seen == null) {
            seen = new Map<string, boolean>();
            this.closureCache.set(fn, seen);
        }
        if (seen.has(signature) && !eventEffects) {
            if (seen.get(signature)) this.interproc?.noteDepthLimit();
            return undefined;
        }
        seen.set(signature, false);

        // Mark the closure boundary in reported propagation traces.
        const liveInstances = this.instanceFieldState;
        const liveModules = this.interproc?.getModuleInstanceState?.();
        const liveThis = this.currentThisInstance;
        const liveExpressions = this.expressionInstanceState;
        const liveAliases = this.thisAliases;
        const liveBreakTargets = this.breakTargets;
        const liveClean = this.cleanBindings;
        const liveReturnUnknown = this.returnUnknown;
        const liveReturnInstanceUnknown = this.returnInstanceUnknown;
        const liveCompletion = {
            hasNormalReturn: this.hasNormalReturn,
            mayThrow: this.mayThrow,
            throwTaints: this.throwTaints,
            throwInstances: this.throwInstances,
        };
        this.hasNormalReturn = false;
        this.mayThrow = false;
        this.throwTaints = [];
        this.throwInstances = [];
        const isolated = this.captureClosureEnvironment(fn, state);
        const closureState = isolated.taints;
        const capturedAt = this.nodeLocation(fn);
        for (const [sym, taints] of closureState) {
            closureState.set(
                sym,
                taints.map((t) =>
                    propagate(
                        t,
                        {
                            kind: "closure",
                            location: capturedAt,
                            description: `captured by enclosing ${ts.isArrowFunction(fn) ? "arrow function" : "function expression"}`,
                        },
                        this.metrics,
                    ),
                ),
            );
        }
        this.instanceFieldState = isolated.instanceBindings;
        this.interproc?.setModuleInstanceState?.(isolated.moduleInstances);
        this.currentThisInstance = isolated.currentThisInstance;
        this.expressionInstanceState = isolated.expressionInstances;
        this.thisAliases = new Set(liveAliases);
        this.breakTargets = [];
        this.cleanBindings = isolated.cleanBindings;
        this.returnUnknown = false;
        this.returnInstanceUnknown = false;
        try {
            const analyzeBody = () => {
                const discardedReturnTaints: TaintValue[] = [];
                const discardedReturnInstances: InstanceState[] = [];
                if (ts.isBlock(fn.body)) {
                    this.analyzeStatementList(
                        fn.body.statements,
                        closureState,
                        discardedReturnTaints,
                        discardedReturnInstances,
                    );
                } else {
                    this.analyzeExpression(fn.body, closureState);
                }
                return eventEffects ? this.captureLoopAnalysisState(closureState) : undefined;
            };
            const analyzed = this.interproc
                ? this.interproc.trackDepthLimit(analyzeBody)
                : { result: analyzeBody(), truncated: false };
            seen.set(signature, analyzed.truncated);
            return analyzed.result;
        } catch (error) {
            seen.delete(signature);
            throw error;
        } finally {
            this.instanceFieldState = liveInstances;
            if (liveModules) this.interproc?.setModuleInstanceState?.(liveModules);
            this.currentThisInstance = liveThis;
            this.expressionInstanceState = liveExpressions;
            this.thisAliases = liveAliases;
            this.breakTargets = liveBreakTargets;
            this.cleanBindings = liveClean;
            this.returnUnknown = liveReturnUnknown;
            this.returnInstanceUnknown = liveReturnInstanceUnknown;
            this.hasNormalReturn = liveCompletion.hasNormalReturn;
            this.mayThrow = liveCompletion.mayThrow;
            this.throwTaints = liveCompletion.throwTaints;
            this.throwInstances = liveCompletion.throwInstances;
        }
    }

    private captureClosureEnvironment(
        fn: ts.ArrowFunction | ts.FunctionExpression,
        state: TaintState,
    ): LoopAnalysisState {
        const free = this.freeSymbols(fn);
        return this.cloneLoopAnalysisState({
            taints: new Map(
                free.flatMap((symbol) => {
                    const taints = state.get(symbol);
                    return taints?.length ? [[symbol, taints] as [ts.Symbol, TaintValue[]]] : [];
                }),
            ),
            instanceBindings: new Map(
                free.flatMap((symbol) => {
                    const instance = this.instanceFieldState.get(symbol);
                    return instance ? [[symbol, instance] as [ts.Symbol, InstanceState]] : [];
                }),
            ),
            moduleInstances: this.interproc?.getModuleInstanceState?.() ?? new Map(),
            currentThisInstance: this.capturesLexicalThis(fn) ? this.currentThisInstance : undefined,
            expressionInstances: new Map(),
            cleanBindings: new Set(free.filter((symbol) => this.cleanBindings.has(symbol))),
        });
    }

    /** Command handlers can run in any order; their possible effects stay outside live caller state. */
    private analyzeRegisteredCommandEffects(): void {
        if (this.registeredCommandClosures.size < 2) return;
        const liveInstances = this.instanceFieldState;
        const liveModules = this.interproc?.getModuleInstanceState?.();
        const liveThis = this.currentThisInstance;
        const liveExpressions = this.expressionInstanceState;
        const liveAliases = this.thisAliases;
        const liveClean = this.cleanBindings;
        const registrations = [...this.registeredCommandClosures.values()];
        let eventState = registrations
            .map(({ environment }) => environment)
            .reduce((a, b) => this.mergeLoopAnalysisStates(a, b));
        const byOrigin = new Map<InstanceState, { symbols: Set<ts.Symbol>; instances: InstanceState[] }>();
        const symbolOrigins = new Map<ts.Symbol, Set<InstanceState>>();
        for (const { environment, origins } of registrations) {
            for (const [symbol, instances] of origins) {
                symbolOrigins.set(symbol, new Set([...(symbolOrigins.get(symbol) ?? []), ...instances]));
                for (const original of instances) {
                    const group = byOrigin.get(original) ?? { symbols: new Set(), instances: [] };
                    group.symbols.add(symbol);
                    group.instances.push(environment.instanceBindings.get(symbol)!);
                    byOrigin.set(original, group);
                }
            }
        }
        for (const [original, { symbols, instances }] of byOrigin) {
            const shared = mergeInstanceStates(instances)!;
            this.instanceOrigins.set(shared, original);
            for (const symbol of symbols) {
                if (symbolOrigins.get(symbol)!.size === 1) eventState.instanceBindings.set(symbol, shared);
            }
        }
        try {
            for (let iteration = 0; iteration < MAX_LOOP_ITERATIONS; iteration++) {
                const before = this.cloneLoopAnalysisState(eventState);
                for (const fn of this.registeredCommandClosures.keys()) {
                    if (
                        !this.freeSymbols(fn).some(
                            (symbol) => eventState.taints.has(symbol) || eventState.instanceBindings.has(symbol),
                        ) &&
                        !(this.capturesLexicalThis(fn) && eventState.currentThisInstance) &&
                        !this.hasCapturedWrite(fn)
                    )
                        continue;
                    const state = forkTaintState(eventState.taints);
                    this.restoreLoopAnalysisState(this.cloneLoopAnalysisState(eventState), state);
                    const capturesContext = this.callbackCapturesTaintedContext(fn, state);
                    const findingCount = this.findings.length;
                    try {
                        const effects = this.analyzeClosureBody(fn, state, true);
                        if (effects) {
                            for (const [symbol, instance] of [...effects.instanceBindings]) {
                                const original = eventState.instanceBindings.get(symbol);
                                if (
                                    !original ||
                                    (this.instanceOrigins.get(instance) ?? instance) !==
                                        (this.instanceOrigins.get(original) ?? original)
                                )
                                    continue;
                                for (const [alias, candidate] of eventState.instanceBindings) {
                                    if (candidate === original) effects.instanceBindings.set(alias, instance);
                                }
                            }
                            eventState = this.mergeLoopAnalysisStates(eventState, effects);
                        }
                    } finally {
                        // Independent command sources are analyzed under their own entry point.
                        if (!capturesContext) this.findings.splice(findingCount);
                    }
                }
                if (this.loopAnalysisStatesEqual(before, eventState)) return;
            }
            this.interproc?.noteDepthLimit();
            throw new AnalysisCoverageLimitError(
                `Command event effect limit (${MAX_LOOP_ITERATIONS}) reached; analysis incomplete`,
            );
        } finally {
            this.instanceFieldState = liveInstances;
            if (liveModules) this.interproc?.setModuleInstanceState?.(liveModules);
            this.currentThisInstance = liveThis;
            this.expressionInstanceState = liveExpressions;
            this.thisAliases = liveAliases;
            this.cleanBindings = liveClean;
        }
    }

    /**
     * Methods that store their argument into the receiver. `args.push(userInput)`
     * leaves `args` holding attacker data, but the call's RETURN value (a length,
     * or the container) is what expression analysis normally looks at, so without
     * this the taint is dropped on the floor and a later `spawn(cmd, args)` looks
     * clean.
     */
    private static readonly MUTATING_METHODS = new Set(["push", "unshift", "splice", "add", "set"]);

    private propagateMutatingMethodTaint(
        expr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
        argInstances: (InstanceState | undefined)[],
        state: TaintState,
    ): void {
        if (!ts.isPropertyAccessExpression(expr.expression)) return;
        const method = expr.expression.name.text;
        if (!TaintTracker.MUTATING_METHODS.has(method)) return;

        const receiverInstance = this.resolveInstance(expr.expression.expression);
        if (receiverInstance) {
            this.invalidateBindingMetadata(receiverInstance);
            if (this.hasHostType(receiverInstance, "Array")) {
                this.storeHostValue(
                    receiverInstance,
                    "$taint:*",
                    this.hostValue(argTaints.slice(method === "splice" ? 2 : 0).flatMap((taints) => taints ?? [])),
                );
            }
            let inserted = argInstances;
            if (method === "splice") {
                inserted = argInstances.slice(2);
            } else if (method === "set") {
                inserted = [argInstances[1]];
            } else if (method === "add") {
                inserted = [argInstances[0]];
            }
            const candidates = [
                receiverInstance.elementInstances.get(TaintTracker.UNKNOWN_ELEMENT),
                ...inserted,
            ].filter((instance): instance is InstanceState => instance != null);
            const merged = mergeInstanceStates(candidates);
            if (merged) {
                receiverInstance.elementInstances.set(TaintTracker.UNKNOWN_ELEMENT, merged);
            }
        }

        // Only a plain identifier receiver can be resolved to a state key.
        const receiver = expr.expression.expression;
        if (!ts.isIdentifier(receiver)) return;
        const receiverSym = this.checker.getSymbolAtLocation(receiver);
        if (!receiverSym) return;

        const incoming = argTaints.filter((t): t is TaintValue[] => t != null).flat();
        if (incoming.length === 0) return;

        const propagated = incoming.map((taint) =>
            propagate(
                taint,
                {
                    kind: "mutation",
                    location: this.nodeLocation(expr),
                    description: `${expr.expression.getText()}(...)`,
                    mutationMethod: method,
                },
                this.metrics,
            ),
        );
        state.set(receiverSym, [...(state.get(receiverSym) || []), ...propagated]);
    }

    /**
     * Order-independent identity of live taint facts, including provenance.
     * The closure cache uses it to decide whether a body needs re-analysis in
     * the current context.
     */
    private taintSignature(state: TaintState): string {
        const parts: string[] = [];
        for (const [sym, taints] of state) {
            if (taints.length === 0) continue;
            let id = TaintTracker.symbolIds.get(sym);
            if (id == null) {
                id = ++TaintTracker.nextSymbolId;
                TaintTracker.symbolIds.set(sym, id);
            }
            const taintKeys = [...new Set(taints.map((taint) => this.taintFactKey(taint)))].sort();
            parts.push(`${id}:${taintKeys.join("&")}`);
        }
        return parts.sort().join("|");
    }

    private hasCapturedWrite(fn: ts.ArrowFunction | ts.FunctionExpression): boolean {
        const cached = TaintTracker.capturedWrites.get(fn);
        if (cached != null) return cached;
        const free = new Set(this.freeSymbols(fn));
        const captures = (target: ts.Node): boolean => {
            const pending = [target];
            while (pending.length > 0) {
                const node = pending.pop()!;
                if (ts.isIdentifier(node) && free.has(this.checker.getSymbolAtLocation(node)!)) return true;
                node.forEachChild((child) => {
                    pending.push(child);
                });
            }
            return false;
        };
        const pending: ts.Node[] = [fn.body];
        while (pending.length > 0) {
            const node = pending.pop()!;
            if (
                (ts.isBinaryExpression(node) &&
                    node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
                    node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
                    captures(node.left)) ||
                ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
                    [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator) &&
                    captures(node.operand)) ||
                ((ts.isForOfStatement(node) || ts.isForInStatement(node)) &&
                    !ts.isVariableDeclarationList(node.initializer) &&
                    captures(node.initializer))
            ) {
                TaintTracker.capturedWrites.set(fn, true);
                return true;
            }
            node.forEachChild((child) => {
                pending.push(child);
            });
        }
        TaintTracker.capturedWrites.set(fn, false);
        return false;
    }

    private static capturedWrites = new WeakMap<ts.Node, boolean>();

    private capturesLexicalThis(fn: ts.ArrowFunction | ts.FunctionExpression): boolean {
        if (!ts.isArrowFunction(fn)) return false;
        const cached = TaintTracker.lexicalThisCaptures.get(fn);
        if (cached != null) return cached;
        const pending: ts.Node[] = [fn.body];
        while (pending.length > 0) {
            const node = pending.pop()!;
            if (node.kind === ts.SyntaxKind.ThisKeyword) {
                TaintTracker.lexicalThisCaptures.set(fn, true);
                return true;
            }
            if (ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) {
                continue;
            }
            node.forEachChild((child) => {
                pending.push(child);
            });
        }
        TaintTracker.lexicalThisCaptures.set(fn, false);
        return false;
    }

    private static lexicalThisCaptures: WeakMap<ts.Node, boolean> = new WeakMap();

    private closureSignature(
        fn: ts.ArrowFunction | ts.FunctionExpression,
        free: ts.Symbol[],
        state: TaintState,
    ): string {
        const visited = new Map<InstanceState, number>();
        const parts = [`depth:${this.depth}`, this.taintSignature(state)];
        const visit = (instance: InstanceState): void => {
            const prior = visited.get(instance);
            if (prior != null) {
                parts.push(`ref:${prior}`);
                return;
            }
            const id = visited.size;
            visited.set(instance, id);
            parts.push(`instance:${id}:${this.taintSignature(instance.fields)}`);
            parts.push(`apis:${(instance.apiTypes ?? []).join("|")}`);
            parts.push(`host:${instance.hostCallback ?? ""}:range:${instance.taintedElementsFromIndex ?? ""}`);
            parts.push(
                `values:${(instance.valueTaints ?? [])
                    .map((taint) => this.taintFactKey(taint))
                    .sort()
                    .join("|")}`,
            );
            if (instance.classDeclarationsUnknown) parts.push("class:unknown");
            for (const declaration of instance.classDeclarations ?? []) {
                parts.push(`class:${declaration.getSourceFile().fileName}:${declaration.getStart()}`);
            }
            for (const [symbol, nested] of [...instance.fieldInstances].sort((a, b) =>
                a[0].getName().localeCompare(b[0].getName()),
            )) {
                parts.push(`field:${symbol.getName()}`);
                visit(nested);
            }
            for (const [key, nested] of [...instance.elementInstances].sort((a, b) => a[0].localeCompare(b[0]))) {
                parts.push(`element:${key}`);
                visit(nested);
            }
            for (const value of instance.functions) {
                parts.push(
                    `function:${value.declaration.getSourceFile().fileName}:${value.declaration.getStart()}:${this.taintSignature(value.captured)}`,
                );
                for (const [symbol, nested] of value.capturedInstances) {
                    parts.push(`capture:${symbol.getName()}`);
                    visit(nested);
                }
                if (value.thisInstance) visit(value.thisInstance);
            }
        };
        for (const symbol of free) {
            const instance = this.instanceFieldState.get(symbol);
            if (instance) {
                parts.push(`binding:${symbol.getName()}`);
                visit(instance);
            }
        }
        if (this.capturesLexicalThis(fn) && this.currentThisInstance) {
            parts.push("lexicalThis");
            visit(this.currentThisInstance);
        }
        return parts.join("|");
    }

    private static symbolIds: WeakMap<ts.Symbol, number> = new WeakMap();
    private static nextSymbolId = 0;

    /**
     * Whether a function body contains any construct that could be a sink or
     * lead to one: a call, a `new`, or an assignment. Cached per node — the
     * same closure is visited many times across an analysis.
     */
    private bodyCanReachSink(fn: ts.ArrowFunction | ts.FunctionExpression): boolean {
        const cached = TaintTracker.sinkReachable.get(fn);
        if (cached != null) return cached;

        let found = false;
        // Explicit stack: closure bodies can nest arbitrarily deep and this
        // runs on every function node in the corpus.
        const stack: ts.Node[] = [fn.body];
        while (stack.length > 0 && !found) {
            const node = stack.pop()!;
            if (
                ts.isCallExpression(node) ||
                ts.isNewExpression(node) ||
                ts.isTaggedTemplateExpression(node) ||
                (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken)
            ) {
                found = true;
                break;
            }
            node.forEachChild((child) => {
                stack.push(child);
            });
        }

        TaintTracker.sinkReachable.set(fn, found);
        return found;
    }

    private static sinkReachable: WeakMap<ts.Node, boolean> = new WeakMap();

    private static readonly SHELL_BINARIES = /(^|[\\/])(sh|bash|zsh|dash|ksh|fish|csh|tcsh)(?:\.exe)?$/i;
    private static readonly arrayIds = new WeakMap<ts.ArrayLiteralExpression, string>();

    private static arrayIdentity(array: ts.ArrayLiteralExpression): string {
        let id = this.arrayIds.get(array);
        if (id == null) {
            id = `${array.getSourceFile().fileName}:${array.getStart()}`;
            this.arrayIds.set(array, id);
        }
        return id;
    }

    /** Unknown shapes and mutated argv stay conservative; known positional operands do not become code. */
    private isShellInvocation(expr: ts.CallExpression, taint: TaintValue): boolean {
        for (const arg of [expr.arguments[2], expr.arguments[1]]) {
            if (arg != null && this.enablesShell(arg)) return true;
        }
        const binary = expr.arguments[0] && this.staticShellCommandPath(expr.arguments[0]);
        if (binary == null) return false;
        const name = binary
            .split(/[\\/]/)
            .pop()!
            .toLowerCase()
            .replace(/\.exe$/, "");
        const shell = TaintTracker.SHELL_BINARIES.test(binary);
        const python = /^python(?:[0-9]+(?:\.[0-9]+)*)?$/.test(name);
        const node = name === "node" || name === "nodejs";
        const powershell = name === "powershell" || name === "pwsh";
        if (!shell && !python && !node && !powershell) return false;
        const argv = expr.arguments[1] && this.resolveArrayLiteral(expr.arguments[1]);
        if (!argv || argv.elements.some(ts.isSpreadElement)) return true;
        const argvValue = unwrapExpression(expr.arguments[1]);
        if (ts.isIdentifier(argvValue)) {
            const symbol = this.checker.getSymbolAtLocation(argvValue);
            if (symbol && this.selectionValueEscapesBefore(symbol, expr)) return true;
        }
        const containerId = TaintTracker.arrayIdentity(argv);
        let index: number | undefined;
        for (let step = taint.chain; step; step = step.previous) {
            if (step.step.kind === "mutation") break;
            if (step.step.arrayElement?.containerId === containerId) {
                index = step.step.arrayElement.index;
                break;
            }
        }
        if (index == null) return true;
        let nodeEval = false;
        for (let i = 0; i < argv.elements.length; i++) {
            const token = this.staticStringText(argv.elements[i]);
            if (token == null) return true;
            if (powershell) {
                const flag = token.toLowerCase();
                if (["-command", "-c", "-encodedcommand", "-enc"].includes(flag)) return true;
                if (["-file", "-f"].includes(flag)) return index <= i + 1;
            }
            if ((shell && /^-[A-Za-z]*c[A-Za-z]*$/.test(token)) || (python && (token === "-c" || token === "-m")))
                return index <= i + 1;
            if (node) {
                if (["-e", "--eval", "-p", "--print"].includes(token)) {
                    if (index <= i + 1) return true;
                    i++;
                    nodeEval = true;
                    continue;
                }
                if (["-r", "--require", "--import", "--loader", "--experimental-loader"].includes(token)) {
                    if (index <= i + 1) return true;
                    i++;
                    continue;
                }
                if (/^--(?:eval|print|require|import|loader|experimental-loader)=/.test(token)) {
                    if (index === i) return true;
                    if (/^--(?:eval|print)=/.test(token)) nodeEval = true;
                    continue;
                }
            }
            if (token === "--") return node && nodeEval ? false : index <= i + 1;
            if (token.startsWith("-") || (shell && token.startsWith("+"))) {
                const withValue = shell
                    ? ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]
                    : python
                      ? ["-W", "-X", "--check-hash-based-pycs"]
                      : node
                        ? ["--inspect-port", "--input-type", "--title", "--conditions", "-C"]
                        : [];
                if (withValue.includes(token)) {
                    if (index <= i + 1) return true;
                    i++;
                    continue;
                }
                if (
                    (node &&
                        ![
                            "--inspect",
                            "--inspect-brk",
                            "--no-warnings",
                            "--trace-warnings",
                            "--enable-source-maps",
                        ].includes(token)) ||
                    (powershell &&
                        !["-nologo", "-noprofile", "-noninteractive", "-sta", "-mta"].includes(token.toLowerCase()))
                ) {
                    return true;
                }
                continue;
            }
            // The first positional argument selects a script, unless node is
            // evaluating a fixed expression. Remaining arguments are data.
            return node && nodeEval ? false : index <= i;
        }
        return true;
    }

    /** Whether an options literal has a `shell` property not set to the literal `false`. */
    private enablesShell(options: ts.Expression): boolean {
        const object = this.resolveObjectLiteral(options);
        if (object == null) return false;
        for (const prop of object.properties) {
            if (ts.isShorthandPropertyAssignment(prop) && prop.name.text === "shell") return true;
            if (!ts.isPropertyAssignment(prop) || this.propertyName(prop.name) !== "shell") continue;
            if (unwrapExpression(prop.initializer).kind !== ts.SyntaxKind.FalseKeyword) return true;
        }
        return false;
    }

    private resolveArrayLiteral(
        expr: ts.Expression,
        seen = new Set<ts.Symbol>(),
    ): ts.ArrayLiteralExpression | undefined {
        const value = unwrapExpression(expr);
        if (ts.isArrayLiteralExpression(value)) return value;
        if (!ts.isIdentifier(value)) return undefined;
        const symbol = this.resolveSymbol(value);
        if (!symbol || seen.has(symbol)) return undefined;
        seen.add(symbol);
        const declaration = symbol.valueDeclaration;
        return declaration && ts.isVariableDeclaration(declaration) && declaration.initializer
            ? this.resolveArrayLiteral(declaration.initializer, seen)
            : undefined;
    }

    private resolveObjectLiteral(
        expr: ts.Expression,
        seen: Set<ts.Symbol> = new Set(),
    ): ts.ObjectLiteralExpression | undefined {
        const value = unwrapExpression(expr);
        if (ts.isObjectLiteralExpression(value)) return value;
        if (!ts.isIdentifier(value)) return undefined;

        const symbol = this.resolveSymbol(value);
        if (symbol == null || seen.has(symbol)) return undefined;
        seen.add(symbol);
        const declaration = symbol.valueDeclaration;
        return declaration != null && ts.isVariableDeclaration(declaration) && declaration.initializer != null
            ? this.resolveObjectLiteral(declaration.initializer, seen)
            : undefined;
    }

    private argumentShape(expr: ts.Expression): "array" | "object" | "string" | undefined {
        const value = unwrapExpression(expr);
        if (ts.isStringLiteralLike(value)) return "string";
        if (ts.isArrayLiteralExpression(value)) return "array";
        if (ts.isObjectLiteralExpression(value)) return "object";

        if (ts.isIdentifier(value)) {
            const symbol = this.resolveSymbol(value);
            const declaration = symbol?.valueDeclaration;
            if (declaration != null && ts.isVariableDeclaration(declaration) && declaration.initializer != null) {
                const initializer = unwrapExpression(declaration.initializer);
                if (ts.isArrayLiteralExpression(initializer)) return "array";
                if (ts.isObjectLiteralExpression(initializer)) return "object";
            }
        }

        const type = this.checker.getNonNullableType(this.checker.getTypeAtLocation(value));
        const members = type.isUnion() ? type.types : [type];
        let shape: "array" | "object" | "string" | undefined;
        for (const member of members) {
            const memberShape =
                (member.flags & ts.TypeFlags.StringLike) !== 0
                    ? "string"
                    : this.checker.isArrayType(member) || this.checker.isTupleType(member)
                      ? "array"
                      : (member.flags & ts.TypeFlags.Object) !== 0 &&
                          this.checker.getSignaturesOfType(member, ts.SignatureKind.Call).length === 0
                        ? "object"
                        : undefined;
            if (memberShape == null || (shape != null && shape !== memberShape)) {
                return undefined;
            }
            shape = memberShape;
        }
        return shape;
    }

    private hasArgumentValues(sink: SinkSpec, args: readonly ts.Expression[]): boolean {
        for (const [position, values] of Object.entries(sink.argumentValues ?? {})) {
            const argument = args[Number(position)];
            const value = argument && resolveStaticString(this.checker, argument);
            if (value == null || !values.includes(value)) return false;
        }
        return true;
    }

    private sinkAcceptsArgument(sink: SinkSpec, position: number, argument: ts.Expression): boolean {
        const expected = sink.argumentShapes?.[position];
        if (expected == null) return true;
        const actual = this.argumentShape(argument);
        return actual == null ? sink.rejectUnknownArgumentShapes !== true : actual === expected;
    }

    /**
     * Merge cutoff for distinct semantic taint facts. `mergeLoopStates`
     * deduplicates by `taintFactKey`, then stops reading an input list when
     * this threshold is reached. This is not a global per-symbol bound, and
     * truncation can discard distinct facts, not just alternate traces.
     */
    private static readonly MAX_TAINTS_PER_SYMBOL = 64;

    private static readonly loopTaintFactKeys = new WeakMap<TaintValue, string>();

    private analyzeIdentifier(expr: ts.Identifier, state: TaintState): TaintValue[] | undefined {
        const sym = this.checker.getSymbolAtLocation(expr);
        if (!sym) return undefined;

        const instance = this.resolveInstance(expr);
        return (
            state.get(sym)?.slice() ??
            (instance?.taintedElementsFromIndex != null ? instance.valueTaints?.slice() : undefined)
        );
    }

    private analyzePropertyAccess(expr: ts.PropertyAccessExpression, state: TaintState): TaintValue[] | undefined {
        const objectTaints = this.analyzeExpression(expr.expression, state);

        const sourceTaint = this.checkPropertySource(expr);
        if (sourceTaint) return [sourceTaint];
        const binding = this.resolveInstance(expr.expression)?.elementInstances.get(
            `${BINDING_PROPERTY}${expr.name.text}`,
        );
        if (binding)
            return this.bindingProvenance(
                [...(binding.valueTaints ?? []), ...(this.getInstanceFieldTaint(expr) ?? [])],
                objectTaints ? TaintTracker.taintsForAggregateProperty(objectTaints, expr.name.text) : [],
            );
        const stringField = this.resolveInstance(expr.expression)?.elementInstances.get(expr.name.text);
        if (stringField) return stringField.valueTaints?.slice();
        if (expr.name.text === "length" && this.hasHostType(this.resolveInstance(expr.expression), "Array")) {
            const length = this.resolveInstance(expr.expression)!.elementInstances.get("$sortLength")?.valueTaints;
            return length?.length
                ? length.map((taint) =>
                      propagate(
                          taint,
                          {
                              kind: "propertyAccess",
                              location: this.nodeLocation(expr),
                              description: "accessed property 'length'",
                          },
                          this.metrics,
                      ),
                  )
                : undefined;
        }

        if (objectTaints) {
            const propertyTaints = TaintTracker.taintsForProperty(objectTaints, expr.name.text);
            if (propertyTaints.length > 0) {
                return propertyTaints.map((t) =>
                    propagate(
                        t,
                        {
                            kind: "propertyAccess",
                            location: this.nodeLocation(expr),
                            description: `accessed property '${expr.name.text}'`,
                        },
                        this.metrics,
                    ),
                );
            }
        }

        // Check if direct this.field state carries taint from an earlier write.
        const thisPropSym = this.getThisPropertySymbol(expr);
        if (thisPropSym) {
            return (
                state.get(thisPropSym)?.slice() ??
                (this.currentThisInstance ? this.getInstanceField(this.currentThisInstance, thisPropSym) : undefined)
            );
        }

        // Check for `self.field` where self is a `this` alias.
        const selfPropSym = this.getThisAliasPropertySymbol(expr);
        if (selfPropSym) {
            return state.get(selfPropSym)?.slice();
        }

        // Per-instance field state: if the receiver is a known variable with
        // bound instance field state, look up the property in that instance.
        const instanceFieldTaints = this.getInstanceFieldTaint(expr);
        if (instanceFieldTaints) {
            return instanceFieldTaints;
        }

        // Preserve symbol-based lookup for other property symbols.
        const sym = this.checker.getSymbolAtLocation(expr);
        if (sym) {
            return state.get(sym)?.slice();
        }

        return undefined;
    }

    private analyzeElementAccess(expr: ts.ElementAccessExpression, state: TaintState): TaintValue[] | undefined {
        const objectTaints = this.analyzeExpression(expr.expression, state);
        this.analyzeExpression(expr.argumentExpression, state);
        const source = this.checkPropertySource(expr);
        if (source) return [source];
        const container = this.resolveInstance(expr.expression);
        if (this.hasHostType(container, "Array")) {
            return this.arrayElementTaints(container!, this.elementKey(expr.argumentExpression), objectTaints);
        }
        const key = this.elementKey(expr.argumentExpression);
        const binding = key != null ? container?.elementInstances.get(`${BINDING_PROPERTY}${key}`) : undefined;
        if (binding)
            return this.bindingProvenance(
                [
                    ...(binding.valueTaints ?? []),
                    ...[...container!.fields]
                        .filter(([property]) => property.getName() === key)
                        .flatMap(([, taints]) => taints),
                ],
                objectTaints ? TaintTracker.taintsForAggregateProperty(objectTaints, key!) : [],
            );
        const field = key != null ? container?.elementInstances.get(key) : undefined;
        if (field?.valueTaints) return field.valueTaints.slice();

        if (objectTaints) {
            const propertyName = ts.isStringLiteralLike(expr.argumentExpression)
                ? expr.argumentExpression.text
                : undefined;
            const propertyTaints =
                propertyName == null
                    ? TaintTracker.taintsForDynamicProperty(objectTaints)
                    : TaintTracker.taintsForAggregateProperty(objectTaints, propertyName);
            if (propertyTaints.length === 0) return undefined;
            return propertyTaints.map((t) =>
                propagate(
                    t,
                    {
                        kind: "arrayIndex",
                        location: this.nodeLocation(expr),
                        description: `element access on ${expr.expression.getText()}`,
                    },
                    this.metrics,
                ),
            );
        }

        return undefined;
    }

    private hasPrimitiveType(expression: ts.Expression): boolean {
        const type = this.checker.getTypeAtLocation(expression);
        const members = type.isUnion() ? type.types : [type];
        return members.every(
            (member) =>
                (member.flags &
                    (ts.TypeFlags.StringLike |
                        ts.TypeFlags.NumberLike |
                        ts.TypeFlags.BooleanLike |
                        ts.TypeFlags.BigIntLike |
                        ts.TypeFlags.Null |
                        ts.TypeFlags.Undefined |
                        ts.TypeFlags.Void)) !==
                0,
        );
    }

    private isProvenClean(expression: ts.Expression, seen: Set<ts.Symbol> = new Set()): boolean {
        const expr = unwrapExpression(expression);
        if (this.hasUnknownPromiseSettlement(this.resolveInstance(expr))) return false;
        if (this.cleanExpressions.has(expr)) return true;
        if (
            ts.isStringLiteralLike(expr) ||
            ts.isNumericLiteral(expr) ||
            expr.kind === ts.SyntaxKind.TrueKeyword ||
            expr.kind === ts.SyntaxKind.FalseKeyword ||
            expr.kind === ts.SyntaxKind.NullKeyword ||
            ts.isVoidExpression(expr) ||
            ts.isTypeOfExpression(expr)
        )
            return true;
        if (ts.isAwaitExpression(expr)) return this.isProvenClean(expr.expression, seen);
        if (ts.isIdentifier(expr)) {
            const payload = this.resolveInstance(expr);
            if (
                !payload?.valueTaints?.length &&
                payload?.valueExpression &&
                payload.fields.size === 0 &&
                payload.fieldInstances.size === 0 &&
                payload.elementInstances.size === 0 &&
                payload.functions.length === 0 &&
                (ts.isNumericLiteral(payload.valueExpression) || ts.isVoidExpression(payload.valueExpression))
            )
                return this.isProvenClean(payload.valueExpression, seen);
            const symbol = this.checker.getSymbolAtLocation(expr);
            if (symbol && this.cleanBindings.has(symbol)) return true;
            if (
                expr.text === "undefined" &&
                (symbol?.declarations?.every((declaration) => declaration.getSourceFile().isDeclarationFile) ?? false)
            )
                return true;
            const declaration = symbol?.valueDeclaration;
            if (
                !symbol ||
                seen.has(symbol) ||
                !declaration ||
                !ts.isVariableDeclaration(declaration) ||
                (declaration.parent.flags & ts.NodeFlags.Const) === 0
            )
                return false;
            if (!declaration.initializer) {
                const loop = declaration.parent.parent;
                return (
                    ts.isForOfStatement(loop) &&
                    ts.isArrayLiteralExpression(unwrapExpression(loop.expression)) &&
                    (unwrapExpression(loop.expression) as ts.ArrayLiteralExpression).elements.every((element) =>
                        this.isProvenClean(element, seen),
                    )
                );
            }
            if (!this.hasPrimitiveType(declaration.initializer)) {
                return this.isProvenCleanArrayBinding(symbol, declaration, seen);
            }
            seen.add(symbol);
            try {
                return this.isProvenClean(declaration.initializer, seen);
            } finally {
                seen.delete(symbol);
            }
        }
        if (ts.isConditionalExpression(expr)) {
            return this.isProvenClean(expr.whenTrue, seen) && this.isProvenClean(expr.whenFalse, seen);
        }
        if (ts.isTemplateExpression(expr)) {
            return expr.templateSpans.every((span) => this.isProvenClean(span.expression, seen));
        }
        if (ts.isBinaryExpression(expr)) {
            return expr.operatorToken.kind === ts.SyntaxKind.EqualsToken
                ? this.isProvenClean(expr.right, seen)
                : this.isProvenClean(expr.left, seen) && this.isProvenClean(expr.right, seen);
        }
        // Property getters, constructors, and unresolved calls can return data
        // whose provenance this tracker has not modeled. Empty taint is not a proof.
        return false;
    }

    private isProvenCleanArrayBinding(
        symbol: ts.Symbol,
        declaration: ts.VariableDeclaration,
        seen: Set<ts.Symbol>,
    ): boolean {
        const initializer = declaration.initializer && unwrapExpression(declaration.initializer);
        if (!initializer || !ts.isArrayLiteralExpression(initializer) || seen.has(symbol)) return false;
        seen.add(symbol);
        try {
            if (!initializer.elements.every((element) => this.isProvenClean(element, seen))) return false;
            let scope: ts.Node = declaration;
            while (scope.parent && !ts.isFunctionLike(scope)) scope = scope.parent;
            const pending: ts.Node[] = [scope];
            while (pending.length > 0) {
                const node = pending.pop()!;
                if (
                    ts.isShorthandPropertyAssignment(node) &&
                    this.checker.getShorthandAssignmentValueSymbol(node) === symbol
                )
                    return false;
                if (
                    ts.isIdentifier(node) &&
                    this.checker.getSymbolAtLocation(node) === symbol &&
                    node !== declaration.name
                ) {
                    let reference: ts.Node = node;
                    while (
                        reference.parent &&
                        ts.isExpression(reference.parent) &&
                        unwrapExpression(reference.parent) === node
                    )
                        reference = reference.parent;
                    const parent = reference.parent;
                    if (parent && ts.isReturnStatement(parent)) continue;
                    if (
                        !parent ||
                        !ts.isPropertyAccessExpression(parent) ||
                        parent.expression !== reference ||
                        !ts.isCallExpression(parent.parent) ||
                        parent.parent.expression !== parent ||
                        !["push", "unshift"].includes(parent.name.text) ||
                        !parent.parent.arguments.every((argument) => this.isProvenClean(argument, seen))
                    )
                        return false;
                }
                node.forEachChild((child) => {
                    pending.push(child);
                });
            }
            return true;
        } finally {
            seen.delete(symbol);
        }
    }

    // Reserved slots keep host payloads, listeners and channels in the same
    // graph as user instances, so argument/return transport and branch forks
    // preserve their identities without a process-global event registry.
    private hostValue(
        taints?: readonly TaintValue[],
        instance?: InstanceState,
        expression?: ts.Expression,
    ): InstanceState {
        const value = createInstanceState();
        value.valueTaints = ownTaintList(taints ?? []);
        value.valueExpression = expression;
        if (instance) value.elementInstances.set("$value", instance);
        return value;
    }

    private storeHostValue(owner: InstanceState, key: string, value: InstanceState): void {
        const previous = owner.elementInstances.get(key);
        owner.elementInstances.set(key, previous ? mergeInstanceStates([previous, value])! : value);
    }

    private hasHostType(instance: InstanceState | undefined, type: string): boolean {
        return instance?.apiTypes?.includes(type) === true;
    }

    private standardMethod(callee: ts.PropertyAccessExpression, owners: readonly string[]): boolean {
        const declarations = this.checker.getSymbolAtLocation(callee.name)?.declarations;
        return (
            !!declarations?.length &&
            declarations.every(
                (declaration) =>
                    declaration.getSourceFile().hasNoDefaultLib &&
                    ts.isInterfaceDeclaration(declaration.parent) &&
                    owners.includes(declaration.parent.name.text),
            )
        );
    }

    private hostCallKind(
        expr: ts.CallExpression,
    ): "promiseStatic" | "promise" | "arrayFrom" | "array" | "event" | undefined {
        const callee = expr.expression;
        if (!ts.isPropertyAccessExpression(callee)) return undefined;
        const name = callee.name.text;
        const instance = this.resolveInstance(callee.expression);
        // An own replacement is not the library implementation, even when the
        // receiver retains its original declared type.
        if (instance?.elementInstances.has(name) || (this.resolveInstance(callee)?.functions.length ?? 0) > 0)
            return undefined;
        if (
            ["resolve", "reject", "all"].includes(name) &&
            this.apiIdentity.importedName(callee.expression) === "Promise" &&
            this.standardMethod(callee, ["PromiseConstructor"])
        )
            return "promiseStatic";
        if (
            name === "from" &&
            this.apiIdentity.importedName(callee.expression) === "Array" &&
            this.interproc?.arrayFromBuiltinsUnmodified?.() === true &&
            this.apiIdentity.matchesAPI(callee, "Array.from") &&
            this.standardMethod(callee, ["ArrayConstructor"]) &&
            this.arrayFromLengthOnlyMapper(expr)
        )
            return "arrayFrom";
        if (
            ["then", "catch"].includes(name) &&
            (this.hasHostType(instance, "Promise") || this.standardMethod(callee, ["Promise"]))
        )
            return "promise";
        if (
            name === "sort" &&
            (!this.standardMethod(callee, ["Array"]) ||
                instance?.elementInstances.has("$unknownReturn") ||
                instance?.classDeclarations?.length ||
                (this.interproc?.hasArrayPrototypeAccess?.() ?? true))
        )
            return undefined;
        if (
            ["map", "filter", "flat", "sort"].includes(name) &&
            (this.hasHostType(instance, "Array") || this.standardMethod(callee, ["Array", "ReadonlyArray"]))
        )
            return "array";
        if (
            ["on", "once", "addListener", "emit", "write", "end", "pipe"].includes(name) &&
            instance?.apiTypes?.some((type) =>
                ["events.EventEmitter", "stream.PassThrough", "fs.ReadStream"].includes(type),
            )
        ) {
            return "event";
        }
        if (
            ["on", "once", "addListener"].includes(name) &&
            instance?.apiTypes?.some((type) => ["http.IncomingMessage", "express.Request"].includes(type))
        )
            return "event";
        return undefined;
    }

    private invokeHostCallback(
        call: ts.CallExpression,
        callback: InstanceState | undefined,
        args: CallArgument[],
        state: TaintState,
        receiver?: InstanceState,
        inlineCallback = false,
    ): InterproceduralCallResult | undefined {
        if (!callback?.functions.length || !this.interproc) return undefined;
        // Inline collection bodies share the lexical budget; their nested calls still consume depth.
        const callerDepth = inlineCallback ? this.depth - 1 : this.depth;
        const result = joinCallResults(
            callback.functions.map((fn) =>
                this.interproc!.analyzeFunctionCall(
                    call,
                    args.map((arg) => arg.taints),
                    this.checker,
                    callerDepth,
                    state,
                    receiver,
                    args.map((arg) => arg.instance),
                    fn,
                    args,
                ),
            ),
        );
        if (result) {
            this.findings.push(...result.findings);
            this.applyCallFieldState(result, state);
        }
        return result;
    }

    private invokeDeferredCallback(
        call: ts.CallExpression,
        callback: InstanceState,
        args: CallArgument[],
        state: TaintState,
    ): InterproceduralCallResult | undefined {
        const live: LoopAnalysisState = {
            taints: forkTaintState(state),
            instanceBindings: this.instanceFieldState,
            moduleInstances: this.interproc?.getModuleInstanceState?.() ?? new Map(),
            currentThisInstance: this.currentThisInstance,
            expressionInstances: this.expressionInstanceState,
            cleanBindings: this.cleanBindings,
        };
        const values = createInstanceState();
        values.elementInstances.set("callback", callback);
        args.forEach((arg, index) => {
            if (arg.instance) values.elementInstances.set(String(index), arg.instance);
        });
        const isolated = this.cloneLoopAnalysisState({ ...live, expressionInstances: new Map([[call, values]]) });
        const cloned = isolated.expressionInstances.get(call)!;
        this.restoreLoopAnalysisState(isolated, state);
        try {
            return this.invokeHostCallback(
                call,
                cloned.elementInstances.get("callback"),
                args.map((arg, index) => ({
                    ...arg,
                    instance: cloned.elementInstances.get(String(index)),
                })),
                state,
            );
        } finally {
            this.restoreLoopAnalysisState(live, state);
        }
    }

    private hostArgument(expression: ts.Expression, payload: InstanceState): CallArgument {
        return {
            expression: payload.valueExpression ?? expression,
            taints: payload.valueTaints?.slice(),
            instance: payload.elementInstances.get("$value"),
        };
    }

    /** Unknown settlement carries passthrough provenance, not an observed fulfillment or rejection. */
    private hasUnknownPromiseSettlement(instance: InstanceState | undefined): boolean {
        return (
            this.hasHostType(instance, "Promise") &&
            (instance!.elementInstances.has("$unknownReturn") ||
                (!instance!.elementInstances.has("$fulfilled") && !instance!.elementInstances.has("$rejected")))
        );
    }

    private promiseValue(
        taints?: readonly TaintValue[],
        instance?: InstanceState,
        expression?: ts.Expression,
    ): InstanceState {
        if (this.hasHostType(instance, "Promise")) {
            if (this.hasUnknownPromiseSettlement(instance) && taints?.length) {
                this.storeHostValue(instance!, "$unknownReturn", this.hostValue(taints));
            }
            return instance!;
        }
        const promise = createInstanceState();
        promise.apiTypes = ["Promise"];
        promise.elementInstances.set("$fulfilled", this.hostValue(taints, instance, expression));
        return promise;
    }

    private promiseFromResult(result: InterproceduralCallResult, fallback?: readonly TaintValue[]): InstanceState {
        const returnedInstance = this.hasHostType(result.instanceState, "Promise")
            ? { ...result.instanceState!, elementInstances: new Map(result.instanceState!.elementInstances) }
            : result.instanceState;
        const promise =
            result.canReturn === false
                ? createInstanceState()
                : this.promiseValue(
                      result.returnTaints ?? (result.truncated || result.returnUnknown ? fallback : undefined),
                      returnedInstance,
                  );
        if (
            result.canReturn !== false &&
            result.returnTaints?.length &&
            this.hasHostType(result.instanceState, "Promise") &&
            !this.hasUnknownPromiseSettlement(result.instanceState)
        ) {
            // A scalar return on another branch is a fulfillment alternative,
            // not part of the adopted Promise's state in the caller.
            this.storeHostValue(promise, "$fulfilled", this.hostValue(result.returnTaints));
        }
        promise.apiTypes = ["Promise"];
        if (result.mayThrow)
            this.storeHostValue(
                promise,
                "$rejected",
                this.hostValue(result.throwTaints, mergeInstanceStates(result.throwInstances ?? [])),
            );
        return promise;
    }

    private finishHostCall(
        expr: ts.CallExpression,
        instance: InstanceState,
        taints?: readonly TaintValue[],
    ): { taints?: TaintValue[] } {
        this.expressionInstanceState.set(expr, instance);
        if (!this.hasUnknownPromiseSettlement(instance)) this.cleanExpressions.add(expr);
        const returnedTaints = taints ?? instance.elementInstances.get("$unknownReturn")?.valueTaints;
        return {
            taints: returnedTaints?.length
                ? returnedTaints.map((taint) =>
                      propagate(
                          taint,
                          {
                              kind: "return",
                              location: this.nodeLocation(expr),
                              description: `returned from ${expr.expression.getText()}()`,
                          },
                          this.metrics,
                      ),
                  )
                : undefined,
        };
    }

    private flatHasKnownEmptyShape(expression: ts.Expression, seen = new Set<ts.Symbol>()): boolean {
        const value = unwrapExpression(expression);
        if (ts.isArrayLiteralExpression(value)) return value.elements.length === 0;
        if (ts.isIdentifier(value)) {
            const symbol = this.checker.getSymbolAtLocation(value);
            const declaration = symbol?.valueDeclaration;
            if (
                symbol &&
                !seen.has(symbol) &&
                declaration &&
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer &&
                (declaration.parent.flags & ts.NodeFlags.Const) !== 0
            ) {
                seen.add(symbol);
                return this.flatHasKnownEmptyShape(declaration.initializer, seen);
            }
        }
        const type = this.checker.getTypeAtLocation(value);
        const alternatives = type.isUnion() ? type.types : [type];
        return (
            alternatives.every(
                (alternative) => this.checker.isArrayType(alternative) || this.checker.isTupleType(alternative),
            ) && this.isProvenClean(value)
        );
    }

    private flatElements(
        container: InstanceState | undefined,
        fallback: readonly TaintValue[] | undefined,
        expression: ts.Expression,
    ): CallArgument[] {
        if (container?.taintedElementsFromIndex != null) {
            return [
                {
                    expression,
                    taints: container.valueTaints?.slice() ?? fallback?.slice(),
                    instance: this.getElementInstance(container),
                    unknownSpread: true,
                },
            ];
        }
        const keys = new Set<string>();
        for (const key of container?.elementInstances.keys() ?? []) {
            const index = key.startsWith("$taint:") ? key.slice(7) : key;
            if (index === "*" || /^(0|[1-9]\d*)$/.test(index)) keys.add(index);
        }
        // An empty tracked alternative alone does not prove that an unresolved array is empty.
        if (
            !keys.size &&
            (!this.hasHostType(container, "Array") || fallback?.length || !this.flatHasKnownEmptyShape(expression))
        )
            keys.add("*");
        return [...keys]
            .sort((a, b) => (a === "*" ? 1 : b === "*" ? -1 : Number(a) - Number(b)))
            .flatMap((key) => {
                const payload = container?.elementInstances.get(`$taint:${key}`);
                const valueExpression = payload?.valueExpression ?? expression;
                if (ts.isOmittedExpression(valueExpression)) return [];
                return [
                    {
                        expression: valueExpression,
                        taints: payload?.valueTaints?.slice() ?? fallback?.slice(),
                        instance: container?.elementInstances.get(key),
                        unknownSpread: key === "*",
                    },
                ];
            });
    }

    private analyzeArrayFlat(
        expr: ts.CallExpression,
        receiver: InstanceState | undefined,
        receiverTaints: TaintValue[] | undefined,
        args: CallArgument[],
    ): { taints?: TaintValue[] } {
        const argument = args[0]?.expression && unwrapExpression(args[0].expression);
        const depth =
            argument == null || (this.checker.getTypeAtLocation(argument).flags & ts.TypeFlags.Undefined) !== 0
                ? 1
                : ts.isNumericLiteral(argument) && (argument.text === "0" || argument.text === "1")
                  ? Number(argument.text)
                  : undefined;
        const output = createInstanceState();
        output.apiTypes = ["Array"];
        const taints: TaintValue[] = [];
        let index = 0;
        let unknownPosition = false;
        const append = (value: CallArgument): void => {
            unknownPosition ||= value.unknownSpread === true;
            const key = unknownPosition ? "*" : String(index++);
            if (value.taints) taints.push(...value.taints);
            this.storeHostValue(output, `$taint:${key}`, this.hostValue(value.taints, undefined, value.expression));
            // flat copies array slots, not the objects stored in those slots.
            if (value.instance) this.storeHostValue(output, key, value.instance);
        };
        const expression = (expr.expression as ts.PropertyAccessExpression).expression;
        const elements = this.flatElements(receiver, receiverTaints, expression);
        if (depth === 0) {
            elements.forEach(append);
        } else if (depth === 1) {
            for (const element of elements) {
                if (this.hasHostType(element.instance, "Array")) {
                    unknownPosition ||= element.unknownSpread === true;
                    this.flatElements(element.instance, element.taints, element.expression).forEach(append);
                } else {
                    const unknown = element.instance == null && !this.hasPrimitiveType(element.expression);
                    append({ ...element, unknownSpread: element.unknownSpread || unknown });
                }
            }
        } else {
            // Other depths retain every reachable array layer as an alternative.
            // Visiting each existing array once bounds cycles without declaring the result empty.
            const visited = new Set<InstanceState>();
            const pending = elements.slice();
            while (pending.length) {
                const element = pending.pop()!;
                append({ ...element, unknownSpread: true });
                if (this.hasHostType(element.instance, "Array") && !visited.has(element.instance!)) {
                    visited.add(element.instance!);
                    pending.push(...this.flatElements(element.instance, element.taints, element.expression));
                }
            }
        }
        const result = this.finishHostCall(expr, output, taints);
        if (unknownPosition) this.cleanExpressions.delete(expr);
        return result;
    }

    /** A fresh length-only literal has no own indexed properties or iterator. */
    private arrayFromLengthOnlyMapper(expr: ts.CallExpression): ts.ArrowFunction | ts.FunctionExpression | undefined {
        if (expr.arguments.length < 2 || expr.arguments.length > 3 || expr.arguments.some(ts.isSpreadElement))
            return undefined;
        const input = unwrapExpression(expr.arguments[0]);
        const mapper = unwrapExpression(expr.arguments[1]);
        if (!ts.isObjectLiteralExpression(input) || input.properties.length !== 1) return undefined;
        const property = input.properties[0];
        if (
            (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) ||
            this.propertyName(property.name) !== "length"
        )
            return undefined;
        if (
            (!ts.isArrowFunction(mapper) && !ts.isFunctionExpression(mapper)) ||
            mapper.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword) ||
            (ts.isFunctionExpression(mapper) && mapper.asteriskToken != null)
        )
            return undefined;
        return mapper;
    }

    private analyzeArrayFrom(
        expr: ts.CallExpression,
        state: TaintState,
        args: CallArgument[],
    ): { taints?: TaintValue[] } {
        const input = unwrapExpression(args[0].expression) as ts.ObjectLiteralExpression;
        const length = input.properties[0];
        if (
            ts.isPropertyAssignment(length) &&
            ts.isNumericLiteral(length.initializer) &&
            Number(length.initializer.text) === 0
        ) {
            const empty = createInstanceState();
            empty.apiTypes = ["Array"];
            return this.finishHostCall(expr, empty);
        }
        const element = ts.factory.createVoidZero();
        const index = ts.factory.createNumericLiteral(0);
        const receiver = args[2]?.instance;
        if (receiver && args[2].taints?.length) {
            for (const property of this.checker.getTypeAtLocation(args[2].expression).getProperties()) {
                const name = property.name;
                if (!receiver.elementInstances.has(name))
                    receiver.elementInstances.set(
                        name,
                        this.hostValue(TaintTracker.taintsForAggregateProperty(args[2].taints, name)),
                    );
            }
        }
        const result = this.invokeHostCallback(
            expr,
            args[1].instance,
            [
                { expression: element, instance: this.hostValue([], undefined, element) },
                // This representative scalar proves numeric provenance, not a particular position or array size.
                { expression: index, instance: this.hostValue([], undefined, index) },
            ],
            state,
            receiver,
            true,
        );
        const unknownReceiver =
            args[2] != null &&
            (receiver == null ||
                receiver.classDeclarationsUnknown === true ||
                receiver.elementInstances.has("$unknownReturn") ||
                (this.checker.getTypeAtLocation(args[2].expression).flags &
                    (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) !==
                    0 ||
                args[2].taints?.some((taint) => !taint.aggregatePropertyPath?.length) === true);
        const unknown = unknownReceiver || !result || result.truncated || result.returnUnknown;
        const values = [...(result?.returnTaints ?? []), ...(unknown ? args.flatMap((arg) => arg.taints ?? []) : [])];
        if (unknown) {
            // A partial summary cannot attach input field paths or clean element identities to an unknown result.
            const returned = this.finishHostCall(expr, createInstanceState(), values);
            this.expressionInstanceState.delete(expr);
            this.cleanExpressions.delete(expr);
            return returned;
        }
        const output = createInstanceState();
        output.apiTypes = ["Array"];
        output.elementInstances.set("$taint:*", this.hostValue(values));
        if (result?.instanceState) output.elementInstances.set("*", result.instanceState);
        return this.finishHostCall(expr, output, values);
    }

    private markSortEscape(instance: InstanceState | undefined, seen = new Set<InstanceState>()): void {
        if (!instance || seen.has(instance)) return;
        if (
            instance.fields.size === 0 &&
            instance.fieldInstances.size === 0 &&
            instance.elementInstances.size === 0 &&
            (instance.functions.length > 0 ||
                (instance.valueExpression && this.hasPrimitiveType(instance.valueExpression)))
        )
            return;
        seen.add(instance);
        instance.elementInstances.set("$sortEscape", this.hostValue());
        for (const [key, nested] of instance.elementInstances) {
            if (!key.startsWith("$")) this.markSortEscape(nested, seen);
        }
        for (const nested of instance.fieldInstances.values()) this.markSortEscape(nested, seen);
    }

    private hasSortEscape(instance: InstanceState | undefined, seen = new Set<InstanceState>()): boolean {
        if (!instance || seen.has(instance)) return false;
        seen.add(instance);
        return (
            instance.elementInstances.has("$sortEscape") ||
            [...instance.elementInstances].some(
                ([key, nested]) => !key.startsWith("$") && this.hasSortEscape(nested, seen),
            ) ||
            [...instance.fieldInstances.values()].some((nested) => this.hasSortEscape(nested, seen))
        );
    }

    private static readonly sortComparatorWrites = new WeakMap<ts.Symbol, boolean>();

    private knownSortComparator(expression: ts.Expression, seen = new Set<ts.Symbol>()): boolean {
        const value = unwrapExpression(expression);
        if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) return true;
        if (ts.isConditionalExpression(value)) {
            return (
                this.knownSortComparator(value.whenTrue, new Set(seen)) &&
                this.knownSortComparator(value.whenFalse, new Set(seen))
            );
        }
        if (!ts.isIdentifier(value)) return false;
        const symbol = this.resolveSymbol(value);
        const declaration = symbol?.valueDeclaration;
        if (!symbol || !declaration || seen.has(symbol)) return false;
        seen.add(symbol);
        if (
            ts.isVariableDeclaration(declaration) &&
            declaration.initializer &&
            (ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.Const) !== 0
        ) {
            return this.knownSortComparator(declaration.initializer, seen);
        }
        if (!ts.isFunctionDeclaration(declaration) || !declaration.body) return false;
        let written = TaintTracker.sortComparatorWrites.get(symbol);
        if (written == null) {
            written = false;
            const pending: ts.Node[] = [declaration.getSourceFile()];
            while (pending.length) {
                const node = pending.pop()!;
                if (
                    ts.isBinaryExpression(node) &&
                    node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
                    node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
                    this.resolveSymbol(unwrapExpression(node.left)) === symbol
                ) {
                    written = true;
                    break;
                }
                node.forEachChild((child) => {
                    pending.push(child);
                });
            }
            TaintTracker.sortComparatorWrites.set(symbol, written);
        }
        return !written;
    }

    private uniqueSortTaints(taints: readonly TaintValue[]): TaintValue[] {
        const facts = new Map<string, TaintValue>();
        for (const taint of taints) {
            const key = this.taintFactKey(taint);
            if (!facts.has(key)) facts.set(key, taint);
        }
        return [...facts.values()];
    }

    private analyzeHostCall(
        expr: ts.CallExpression,
        state: TaintState,
        receiverTaints: TaintValue[] | undefined,
        evaluatedArguments: { value?: CallArgument[] },
    ): { taints?: TaintValue[] } | undefined {
        const resolver = this.resolveInstance(expr.expression);
        const target = resolver?.elementInstances.get("$promise");
        if (
            target &&
            (this.hasHostType(resolver, "Promise.resolveCallback") ||
                this.hasHostType(resolver, "Promise.rejectCallback"))
        ) {
            const args = expr.arguments.map((expression) => {
                const taints = this.analyzeExpression(expression, state);
                return { expression, taints, instance: this.resolveValueInstance(expression, state) };
            });
            evaluatedArguments.value = args;
            if (!target.elementInstances.has("$fulfilled") && !target.elementInstances.has("$rejected")) {
                target.elementInstances.delete("$unknownReturn");
                const expression = expr.arguments[0] ?? ts.factory.createVoidZero();
                const instance = args[0]?.instance;
                if (this.hasHostType(resolver, "Promise.rejectCallback")) {
                    target.elementInstances.set("$rejected", this.hostValue(args[0]?.taints, instance, expression));
                } else {
                    const resolved = this.promiseValue(args[0]?.taints, instance, expression);
                    for (const [key, value] of resolved.elementInstances) target.elementInstances.set(key, value);
                }
            }
            this.cleanExpressions.add(expr);
            return {};
        }
        const kind = this.hostCallKind(expr);
        if (!kind) return undefined;
        const callee = expr.expression as ts.PropertyAccessExpression;
        const method = callee.name.text;
        const receiver = this.resolveInstance(callee.expression);
        const args: CallArgument[] = expr.arguments.map((expression) => {
            const value = unwrapExpression(expression);
            if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) {
                return { expression, instance: createFunctionInstance(this.captureFunctionValue(value, state)) };
            }
            const taints = this.analyzeExpression(expression, state);
            return { expression, taints, instance: this.resolveValueInstance(expression, state) };
        });
        evaluatedArguments.value = args;
        if (kind === "arrayFrom") return this.analyzeArrayFrom(expr, state, args);
        if (kind === "array" && method === "flat") {
            return this.analyzeArrayFlat(expr, receiver, receiverTaints, args);
        }
        if (kind === "array" && method === "sort") {
            const callback = args[0]?.instance;
            const comparator = args[0]?.expression && unwrapExpression(args[0].expression);
            if (
                comparator &&
                (!callback?.functions.length || !this.knownSortComparator(comparator)) &&
                (this.checker.getTypeAtLocation(comparator).flags & ts.TypeFlags.Undefined) === 0
            )
                return undefined;
            if (this.hasSortEscape(receiver)) return undefined;
            const output = receiver ?? createInstanceState();
            output.apiTypes = ["Array"];
            let elements = this.flatElements(receiver, receiverTaints, callee.expression);
            const defaultComparator =
                comparator == null || (this.checker.getTypeAtLocation(comparator).flags & ts.TypeFlags.Undefined) !== 0;
            const elementType = this.checker.getTypeAtLocation(callee.expression).getNumberIndexType();
            const types = elementType?.isUnion() ? elementType.types : elementType ? [elementType] : [];
            const primitiveElements =
                types.length > 0 &&
                types.every(
                    (type) =>
                        (type.flags &
                            (ts.TypeFlags.StringLike |
                                ts.TypeFlags.NumberLike |
                                ts.TypeFlags.BooleanLike |
                                ts.TypeFlags.BigIntLike |
                                ts.TypeFlags.Null |
                                ts.TypeFlags.Undefined)) !==
                        0,
                );
            let comparatorIncomplete = false;
            if (callback && (elements.length > 1 || elements.some((element) => element.unknownSpread))) {
                const originalBindings = elements.flatMap((element) =>
                    element.instance
                        ? [
                              {
                                  owner: element.instance,
                                  values: [...element.instance.elementInstances].filter(([key]) =>
                                      key.startsWith(BINDING_PROPERTY),
                                  ),
                              },
                          ]
                        : [],
                );
                const combined: CallArgument = {
                    expression: callee.expression,
                    taints: elements.flatMap((element) => element.taints ?? []),
                    instance: mergeInstanceStates(
                        elements.flatMap((element) => (element.instance ? [element.instance] : [])),
                    ),
                };
                const inline =
                    comparator != null && (ts.isArrowFunction(comparator) || ts.isFunctionExpression(comparator));
                for (const element of elements) {
                    const first = this.invokeHostCallback(
                        expr,
                        callback,
                        [element, combined],
                        state,
                        undefined,
                        inline,
                    );
                    const second = this.invokeHostCallback(
                        expr,
                        callback,
                        [combined, element],
                        state,
                        undefined,
                        inline,
                    );
                    comparatorIncomplete ||= !first || first.truncated === true || !second || second.truncated === true;
                }
                // Comparator writes to the receiver are alternatives to its original contents.
                for (const { owner, values } of originalBindings) {
                    for (const [key, value] of values) this.storeHostValue(owner, key, value);
                }
                elements.push(...this.flatElements(output, receiverTaints, callee.expression));
            }
            if (
                ((defaultComparator && !primitiveElements) ||
                    comparatorIncomplete ||
                    this.hasSortEscape(output) ||
                    elements.some((element) => this.hasSortEscape(element.instance))) &&
                (elements.length > 1 || elements.some((element) => element.unknownSpread))
            ) {
                // Unknown coercions and escaped comparator arguments can reshape element fields.
                const effects = this.uniqueSortTaints(
                    TaintTracker.clearAggregatePropertyPath(elements.flatMap((element) => element.taints ?? [])),
                );
                for (const element of elements) {
                    if (element.instance && elementType) {
                        for (const property of elementType.getProperties()) {
                            element.instance.fields.set(
                                property,
                                this.uniqueSortTaints([
                                    ...(this.getInstanceField(element.instance, property) ?? []),
                                    ...effects,
                                ]),
                            );
                        }
                    }
                }
                for (const [symbol, instance] of this.instanceFieldState) {
                    if (instance === output || elements.some((element) => element.instance === instance)) {
                        state.set(symbol, this.uniqueSortTaints([...(state.get(symbol) ?? []), ...effects]));
                    }
                }
                elements = elements.map((element) => ({ ...element, taints: [...(element.taints ?? []), ...effects] }));
            }
            elements = elements.map((element) => ({ ...element, taints: this.uniqueSortTaints(element.taints ?? []) }));
            const elementsByValue = new Map<InstanceState | ts.Expression, CallArgument>();
            for (const element of elements) {
                const key = element.instance ?? element.expression;
                const previous = elementsByValue.get(key);
                elementsByValue.set(
                    key,
                    previous
                        ? {
                              ...previous,
                              unknownSpread: previous.unknownSpread || element.unknownSpread,
                              taints: this.uniqueSortTaints([...(previous.taints ?? []), ...(element.taints ?? [])]),
                          }
                        : element,
                );
            }
            elements = [...elementsByValue.values()];
            // Sorting invalidates ordered slots, not the objects or field paths stored in them.
            for (const key of output.elementInstances.keys()) {
                if (/^(?:\$taint:)?(?:0|[1-9]\d*)$/.test(key) || key === "*" || key === "$taint:*")
                    output.elementInstances.delete(key);
            }
            output.taintedElementsFromIndex = undefined;
            const taints = this.uniqueSortTaints(elements.flatMap((element) => element.taints ?? []));
            if (elements.length) {
                output.elementInstances.set("$taint:*", this.hostValue(taints));
                const instance = mergeInstanceStates(
                    elements.flatMap((element) => (element.instance ? [element.instance] : [])),
                );
                if (instance) output.elementInstances.set("*", instance);
            }
            // Collection metadata has separate provenance from the element field paths.
            const length = TaintTracker.taintsForProperty(receiverTaints ?? [], "length");
            output.elementInstances.set(
                "$sortLength",
                this.hostValue(
                    length.map((taint) =>
                        propagate(
                            taint,
                            {
                                kind: "return",
                                location: this.nodeLocation(expr),
                                description: `returned from ${expr.expression.getText()}()`,
                            },
                            this.metrics,
                        ),
                    ),
                ),
            );
            return this.finishHostCall(expr, output, taints);
        }
        if (kind === "promiseStatic") {
            let promise: InstanceState;
            if (method === "resolve")
                promise = this.promiseValue(
                    args[0]?.taints,
                    args[0]?.instance,
                    args[0]?.expression ?? ts.factory.createVoidZero(),
                );
            else if (method === "reject") {
                promise = createInstanceState();
                promise.apiTypes = ["Promise"];
                promise.elementInstances.set("$rejected", this.hostValue(args[0]?.taints, args[0]?.instance));
            } else {
                promise = createInstanceState();
                promise.apiTypes = ["Promise"];
                const array = createInstanceState();
                array.apiTypes = ["Array"];
                const fulfilled: TaintValue[] = [];
                let canFulfill = true;
                const input = args[0]?.instance;
                const keys = input
                    ? [
                          ...new Set(
                              [...input.elementInstances.keys()]
                                  .filter((key) => key.startsWith("$taint:"))
                                  .map((key) => key.slice(7)),
                          ),
                      ]
                    : ["*"];
                for (const key of keys) {
                    const elementTaints = input?.elementInstances.get(`$taint:${key}`)?.valueTaints ?? args[0]?.taints;
                    const element = this.promiseValue(elementTaints, input?.elementInstances.get(key));
                    const resolved = element.elementInstances.get("$fulfilled");
                    const rejected = element.elementInstances.get("$rejected");
                    if (rejected) this.storeHostValue(promise, "$rejected", rejected);
                    if (!resolved) canFulfill = false;
                    else {
                        fulfilled.push(...(resolved.valueTaints ?? []));
                        array.elementInstances.set(`$taint:${key}`, this.hostValue(resolved.valueTaints));
                        const value = resolved.elementInstances.get("$value");
                        if (value) array.elementInstances.set(key, value);
                    }
                }
                if (canFulfill) promise.elementInstances.set("$fulfilled", this.hostValue(fulfilled, array));
            }
            return this.finishHostCall(expr, promise);
        }
        if (kind === "promise") {
            const input = this.promiseValue(receiverTaints, receiver);
            const output = createInstanceState();
            output.apiTypes = ["Promise"];
            if (this.hasUnknownPromiseSettlement(input)) {
                output.elementInstances.set(
                    "$unknownReturn",
                    input.elementInstances.get("$unknownReturn") ?? this.hostValue(receiverTaints),
                );
            }
            for (const channel of ["$fulfilled", "$rejected"]) {
                const payload = input.elementInstances.get(channel);
                if (!payload) continue;
                const callback =
                    method === "catch"
                        ? channel === "$rejected"
                            ? args[0]?.instance
                            : undefined
                        : args[channel === "$fulfilled" ? 0 : 1]?.instance;
                if (!callback?.functions.length) {
                    this.storeHostValue(output, channel, payload);
                    continue;
                }
                const result = this.invokeDeferredCallback(
                    expr,
                    callback,
                    [this.hostArgument(callee.expression, payload)],
                    state,
                );
                const returned = result
                    ? this.promiseFromResult(result, payload.valueTaints)
                    : this.promiseValue(payload.valueTaints);
                for (const returnedChannel of ["$fulfilled", "$rejected", "$unknownReturn"]) {
                    const value = returned.elementInstances.get(returnedChannel);
                    if (value) this.storeHostValue(output, returnedChannel, value);
                }
            }
            return this.finishHostCall(expr, output);
        }
        if (kind === "array") {
            const output = createInstanceState();
            output.apiTypes = ["Array"];
            const keys =
                receiver?.taintedElementsFromIndex != null
                    ? ["*"]
                    : this.hasHostType(receiver, "Array")
                      ? [
                            ...new Set(
                                [...receiver!.elementInstances.keys()]
                                    .filter((key) => key.startsWith("$taint:"))
                                    .map((key) => key.slice(7)),
                            ),
                        ]
                      : ["*"];
            // A tracked empty alternative does not describe an unknown source array.
            if (keys.length === 0 && receiverTaints?.length) keys.push("*");
            const taints: TaintValue[] = [];
            const sanitizer = method === "map" ? this.arrayMapSanitizer(expr) : undefined;
            const callbackExpression = args[0] && unwrapExpression(args[0].expression);
            const inlineCallback =
                callbackExpression != null &&
                (ts.isArrowFunction(callbackExpression) || ts.isFunctionExpression(callbackExpression));
            for (const key of keys) {
                const inputTaints =
                    receiver?.elementInstances.get(`$taint:${key}`)?.valueTaints?.slice() ?? receiverTaints;
                const inputInstance = receiver && this.getElementInstance(receiver, key === "*" ? undefined : key);
                const result = this.invokeHostCallback(
                    expr,
                    args[0]?.instance,
                    [
                        {
                            expression:
                                receiver?.elementInstances.get(`$taint:${key}`)?.valueExpression ?? callee.expression,
                            taints: inputTaints,
                            instance: inputInstance,
                        },
                        { expression: callee.expression },
                        { expression: callee.expression, taints: receiverTaints, instance: receiver },
                    ],
                    state,
                    args[1]?.instance,
                    inlineCallback,
                );
                const values =
                    method === "filter"
                        ? inputTaints
                        : sanitizer && inputTaints
                          ? this.applySanitizer(
                                inputTaints,
                                sanitizer,
                                expr,
                                `each element sanitized via ${expr.arguments[0].getText()}`,
                                true,
                            )
                          : (result?.returnTaints ??
                            (result?.truncated || result?.returnUnknown || !result ? inputTaints : undefined));
                const valueInstance = method === "filter" ? inputInstance : result?.instanceState;
                const outputKey = method === "filter" ? "*" : key;
                if (values) taints.push(...values);
                this.storeHostValue(output, `$taint:${outputKey}`, this.hostValue(values));
                if (valueInstance) this.storeHostValue(output, outputKey, valueInstance);
            }
            if (sanitizer) {
                this.expressionInstanceState.set(expr, output);
                this.cleanExpressions.add(expr);
                return { taints: taints.length ? taints : undefined };
            }
            return this.finishHostCall(expr, output, taints);
        }
        if (!receiver) return { taints: undefined };
        const incoming =
            this.hasHostType(receiver, "http.IncomingMessage") || this.hasHostType(receiver, "express.Request");
        if (incoming && receiverTaints?.length) {
            this.storeHostValue(
                receiver,
                "$source",
                this.hostValue(TaintTracker.clearAggregatePropertyPath(receiverTaints)),
            );
        }
        const stream =
            incoming || this.hasHostType(receiver, "stream.PassThrough") || this.hasHostType(receiver, "fs.ReadStream");
        const event =
            ["write", "end"].includes(method) && stream
                ? "data"
                : args[0] && resolveStaticString(this.checker, args[0].expression);
        if (["on", "once", "addListener"].includes(method)) {
            if (event != null && args[1]?.instance?.functions.length) {
                const key = `$listener:${JSON.stringify(event)}:${expr.getSourceFile().fileName}:${expr.getStart()}`;
                const listener = createInstanceState();
                listener.functions = args[1].instance.functions;
                if (method === "once") listener.apiTypes = ["once"];
                this.storeHostValue(receiver, key, listener);
                if (stream && event === "data") {
                    receiver.apiTypes = [...new Set([...(receiver.apiTypes ?? []), "stream.flowing"])];
                    const buffered =
                        receiver.elementInstances.get("$source") ?? receiver.elementInstances.get("$buffer");
                    if (buffered) {
                        receiver.elementInstances.delete("$buffer");
                        if (method === "once") receiver.elementInstances.delete(key);
                        const callbackArgs = [this.hostArgument(callee.expression, buffered)];
                        if (receiver.elementInstances.has("$source"))
                            this.invokeDeferredCallback(expr, listener, callbackArgs, state);
                        else this.invokeHostCallback(expr, listener, callbackArgs, state, receiver);
                    }
                }
            }
            return this.finishHostCall(expr, receiver);
        }
        if (method === "pipe") {
            const destination = args[0]?.instance;
            if (destination && stream && this.hasHostType(destination, "stream.PassThrough")) {
                this.storeHostValue(receiver, "$pipe", destination);
                receiver.apiTypes = [...new Set([...(receiver.apiTypes ?? []), "stream.flowing"])];
                const future = receiver.elementInstances.get("$source");
                if (future) this.storeHostValue(destination, "$source", future);
                const buffered = future ?? receiver.elementInstances.get("$buffer");
                if (buffered) {
                    receiver.elementInstances.delete("$buffer");
                    this.deliverStreamValue(expr, destination, buffered, state);
                }
                return this.finishHostCall(expr, destination);
            }
            return { taints: undefined };
        }
        if (event != null) {
            const delivered = ["write", "end"].includes(method) ? args.slice(0, 1) : args.slice(1);
            if (stream && ["write", "end"].includes(method) && delivered.length) {
                this.deliverStreamValue(
                    expr,
                    receiver,
                    this.hostValue(delivered[0].taints, delivered[0].instance),
                    state,
                );
            } else if (method === "emit") {
                this.deliverEvent(expr, receiver, event, delivered, state);
            }
        }
        this.cleanExpressions.add(expr);
        return { taints: undefined };
    }

    private deliverEvent(
        call: ts.CallExpression,
        receiver: InstanceState,
        event: string,
        args: CallArgument[],
        state: TaintState,
    ): void {
        const prefix = `$listener:${JSON.stringify(event)}:`;
        for (const [key, listener] of [...receiver.elementInstances]) {
            if (!key.startsWith(prefix)) continue;
            if (this.hasHostType(listener, "once")) receiver.elementInstances.delete(key);
            this.invokeHostCallback(call, listener, args, state, receiver);
        }
    }

    private deliverStreamValue(
        call: ts.CallExpression,
        stream: InstanceState,
        payload: InstanceState,
        state: TaintState,
        seen = new Set<InstanceState>(),
    ): void {
        if (seen.has(stream)) return;
        seen.add(stream);
        if (!this.hasHostType(stream, "stream.flowing") && !stream.elementInstances.has("$pipe")) {
            this.storeHostValue(stream, "$buffer", payload);
        }
        this.deliverEvent(call, stream, "data", [this.hostArgument(call, payload)], state);
        const destination = stream.elementInstances.get("$pipe");
        if (destination) this.deliverStreamValue(call, destination, payload, state, seen);
    }

    private analyzeCallExpression(expr: ts.CallExpression, state: TaintState): TaintValue[] | undefined {
        this.metrics.performance.callExpressions++;
        this.cleanExpressions.delete(expr);
        // A call captures its callee and receiver before evaluating arguments.
        // These per-evaluation roots also travel through argument branch snapshots.
        const callee = unwrapExpression(expr.expression);
        this.expressionInstanceState.delete(callee);
        let receiverTaints: TaintValue[] | undefined;
        let receiverBeforeArguments: InstanceState | undefined;
        const member =
            ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee) ? callee : undefined;
        if (member) {
            this.expressionInstanceState.delete(member.expression);
            receiverTaints = this.analyzeExpression(member.expression, state);
            receiverBeforeArguments = this.resolveInstance(member.expression);
            if (receiverBeforeArguments) this.expressionInstanceState.set(member.expression, receiverBeforeArguments);
            if (ts.isElementAccessExpression(member)) this.analyzeExpression(member.argumentExpression, state);
        } else {
            this.analyzeExpression(expr.expression, state);
        }
        const calleeBeforeArguments = this.resolveInstance(callee);
        if (calleeBeforeArguments) this.expressionInstanceState.set(callee, calleeBeforeArguments);
        // A declaration fixes callable identity, but its free bindings are read
        // when it is invoked, after argument side effects have happened.
        const declaredCallee =
            !calleeBeforeArguments && ts.isIdentifier(callee)
                ? resolveFunctionReference(this.checker, callee)
                : undefined;
        // Sanitizer identity belongs to the selected callee, not to bindings after argument effects.
        const sanitizer = this.matchingSanitizer(expr);
        const evaluatedArguments: { value?: CallArgument[] } = {};
        const hostResult = this.analyzeHostCall(expr, state, receiverTaints, evaluatedArguments);
        if (hostResult) return hostResult.taints;

        const callName = getCallChainName(expr.expression);
        const synchronousForEachCallback = this.getSynchronousForEachCallback(expr);
        // registerCommand stores its callback for later; discovery analyzes that
        // callback as its own entry point. Definition-site analysis is still
        // needed when the callback captures taint from the enclosing context.
        const commandCallback = resolveCommandRegistration(this.checker, expr)?.handler;
        if (commandCallback && (ts.isArrowFunction(commandCallback) || ts.isFunctionExpression(commandCallback))) {
            const environment = this.captureClosureEnvironment(commandCallback, state);
            const previous = this.registeredCommandClosures.get(commandCallback);
            const origins = new Map(previous?.origins);
            for (const symbol of environment.instanceBindings.keys()) {
                const instance = this.instanceFieldState.get(symbol)!;
                origins.set(symbol, new Set([...(origins.get(symbol) ?? []), instance]));
            }
            this.registeredCommandClosures.set(commandCallback, {
                environment: previous ? this.mergeLoopAnalysisStates(previous.environment, environment) : environment,
                origins,
            });
        }
        const separatelyAnalyzedCommandCallback =
            commandCallback &&
            (ts.isArrowFunction(commandCallback) || ts.isFunctionExpression(commandCallback)) &&
            !this.callbackCapturesTaintedContext(commandCallback, state)
                ? commandCallback
                : undefined;

        const argTaints: (TaintValue[] | undefined)[] = [];
        const argInstances: (InstanceState | undefined)[] = [];
        for (const [index, arg] of expr.arguments.entries()) {
            const evaluated = evaluatedArguments.value?.[index];
            if (evaluated) {
                // A declined host model still needs definition-site closure
                // coverage, but must not evaluate argument expressions again.
                const value = unwrapExpression(arg);
                if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) this.analyzeClosureBody(value, state);
                argTaints.push(evaluated.taints);
                argInstances.push(evaluated.instance);
                continue;
            }
            argTaints.push(
                arg === synchronousForEachCallback ||
                    (arg === separatelyAnalyzedCommandCallback &&
                        (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)))
                    ? undefined
                    : this.analyzeExpression(arg, state),
            );
            argInstances.push(this.resolveValueInstance(ts.isSpreadElement(arg) ? arg.expression : arg, state));
        }

        if (this.matchesModelAPI(expr.expression, "axios.create")) {
            const receiver = ts.isPropertyAccessExpression(expr.expression)
                ? this.resolveInstance(expr.expression.expression)
                : undefined;
            const instance = captureAxiosDefaults(
                expr.arguments[0],
                argTaints[0],
                this.checker,
                createInstanceState,
                receiver,
            );
            this.expressionInstanceState.set(expr, instance);
            this.cleanExpressions.add(expr);
            return undefined;
        }
        this.checkAxiosDefaults(expr);

        if (synchronousForEachCallback) {
            this.analyzeSynchronousForEachCallback(expr, synchronousForEachCallback, state, receiverTaints);
        }

        if (sanitizer != null) {
            const inputTaints = argTaints.filter((taints): taints is TaintValue[] => taints != null).flat();
            if (inputTaints.length === 0) return undefined;

            return this.applySanitizer(inputTaints, sanitizer, expr, `sanitized via ${expr.expression.getText()}()`);
        }

        const elementSanitizer = this.arrayMapSanitizer(expr);
        if (elementSanitizer != null) {
            if (!receiverTaints || receiverTaints.length === 0) return undefined;
            return this.applySanitizer(
                receiverTaints,
                elementSanitizer,
                expr,
                `each element sanitized via ${expr.arguments[0].getText()}`,
                true,
            );
        }

        this.checkSink(expr, argTaints);

        // Container mutators write their arguments INTO the receiver, so the
        // receiver has to pick up the argument taint.
        this.propagateMutatingMethodTaint(expr, argTaints, argInstances, state);

        // Call-local callback sources, such as fs.readFile(path, cb), need
        // current argument taints to preserve provenance when possible.
        this.analyzeCallCallbackSources(expr, argTaints, state);

        const sourceResult = this.checkCallSource(expr, argTaints);
        if (sourceResult) {
            if (this.apiIdentity.matchesAPI(expr.expression, "fs.createReadStream")) {
                const stream = createInstanceState();
                stream.apiTypes = ["fs.ReadStream"];
                stream.elementInstances.set("$source", this.hostValue(sourceResult.taints));
                this.expressionInstanceState.set(expr, stream);
                this.cleanExpressions.add(expr);
                return undefined;
            }
            if (this.isPromiseReturningCall(expr)) {
                this.expressionInstanceState.set(expr, this.promiseValue(sourceResult.taints));
                this.cleanExpressions.add(expr);
                return undefined;
            }
            return sourceResult.taints;
        }

        if ((callName === "Object.entries" || callName === "Object.values") && argTaints[0]) {
            return TaintTracker.clearAggregatePropertyPath(argTaints[0]).map((taint) =>
                propagate(
                    taint,
                    {
                        kind: "return",
                        location: this.nodeLocation(expr),
                        description: `returned from ${callName}()`,
                    },
                    this.metrics,
                ),
            );
        }
        if (
            callName.endsWith("workspace.openNotebookDocument") &&
            argTaints[0] &&
            this.isUriExpression(expr.arguments[0])
        ) {
            return TaintTracker.prependAggregateProperty(argTaints[0], "uri").map((taint) =>
                propagate(
                    taint,
                    {
                        kind: "return",
                        location: this.nodeLocation(expr),
                        description: `returned from ${callName}()`,
                    },
                    this.metrics,
                ),
            );
        }

        if (
            this.interproc &&
            this.depth >= this.maxDepth &&
            (this.resolveInstance(expr.expression)?.functions.length ||
                resolveFunctionReference(this.checker, expr.expression)?.body ||
                this.interproc.hasOverrideCandidates(expr))
        ) {
            this.interproc.noteDepthLimit();
        }

        const incompleteReturnTaints: TaintValue[] = [];
        // Interprocedural: follow into called function
        if (this.interproc && this.depth < this.maxDepth) {
            // If the call is a method on an instance variable (e.g., `runner.run()`),
            // inject that instance's field state into the caller state so the
            // interprocedural analysis can see it via extractInstanceFieldState.
            const savedFieldEntries: [ts.Symbol, readonly TaintValue[] | undefined][] = [];
            let receiverInstance: InstanceState | undefined;
            if (member && receiverBeforeArguments) {
                receiverInstance = this.expressionInstanceState.get(member.expression) ?? receiverBeforeArguments;
            } else if (callee.kind === ts.SyntaxKind.SuperKeyword) {
                receiverInstance = this.currentThisInstance;
            }
            if (receiverInstance) {
                for (const [sym, taints] of receiverInstance.fields) {
                    savedFieldEntries.push([sym, state.get(sym)]);
                    state.set(sym, taints);
                }
            }

            const calleeInstance = calleeBeforeArguments
                ? (this.expressionInstanceState.get(callee) ?? calleeBeforeArguments)
                : declaredCallee?.body
                  ? createFunctionInstance(this.captureDeclaredFunctionValue(declaredCallee, state))
                  : undefined;
            const boundFunctions = calleeInstance?.functions ?? [];
            const callResult = calleeInstance?.hostCallback
                ? this.interproc.analyzeHostCallback?.(expr, calleeInstance, state, this.depth)
                : boundFunctions.length === 0
                  ? this.interproc.analyzeFunctionCall(
                        expr,
                        argTaints,
                        this.checker,
                        this.depth,
                        state,
                        receiverInstance,
                        argInstances,
                    )
                  : joinCallResults(
                        boundFunctions.map((boundFunction) =>
                            this.interproc!.analyzeFunctionCall(
                                expr,
                                argTaints,
                                this.checker,
                                this.depth,
                                state,
                                receiverInstance,
                                argInstances,
                                boundFunction,
                            ),
                        ),
                    );

            // Restore saved field entries to avoid cross-instance pollution
            for (const [sym, prev] of savedFieldEntries) {
                if (prev === undefined) {
                    state.delete(sym);
                } else {
                    state.set(sym, prev);
                }
            }

            if (callResult) {
                // Route field state updates back to the instance if the call
                // was on a known instance variable.
                if (receiverInstance) {
                    for (const sym of callResult.clearedFieldSymbols) {
                        receiverInstance.fields.delete(sym);
                    }
                    for (const [sym, taints] of callResult.fieldState) {
                        receiverInstance.fields.set(sym, taints);
                    }
                    if (receiverInstance === this.currentThisInstance) {
                        this.applyCallFieldState(callResult, state);
                    }
                } else {
                    this.applyCallFieldState(callResult, state);
                }
                // Collect findings from the callee
                this.findings.push(...callResult.findings);
                const returnUnknown =
                    callResult.returnUnknown || this.hasUnknownPromiseSettlement(callResult.instanceState);
                let returnedInstance = callResult.instanceState;
                if (this.isPromiseReturningCall(expr)) {
                    returnedInstance = this.promiseFromResult(callResult);
                    if (!callResult.truncated && !returnUnknown)
                        return this.finishHostCall(expr, returnedInstance).taints;
                    if (!returnedInstance.elementInstances.has("$unknownReturn")) {
                        returnedInstance.elementInstances.set("$unknownReturn", this.hostValue());
                    }
                } else {
                    if (callResult.mayThrow) {
                        this.mayThrow = true;
                        this.throwTaints.push(...(callResult.throwTaints ?? []));
                        this.throwInstances.push(...(callResult.throwInstances ?? []));
                    }
                    if (callResult.canReturn === false) this.nonReturningExpressions.add(expr);
                }
                if (returnedInstance) {
                    if (
                        this.hasHostType(returnedInstance, "Array") &&
                        (callResult.truncated || returnUnknown || callResult.returnInstanceUnknown)
                    ) {
                        returnedInstance.elementInstances.set("$sortEscape", this.hostValue());
                    }
                    this.expressionInstanceState.set(expr, returnedInstance);
                }
                if (!callResult.truncated && !returnUnknown && !callResult.returnTaints?.length) {
                    this.cleanExpressions.add(expr);
                }
                if (callResult.returnTaints && callResult.returnTaints.length > 0) {
                    const returned = callResult.returnTaints.map((t) =>
                        propagate(
                            t,
                            {
                                kind: "return",
                                location: this.nodeLocation(expr),
                                description: `returned from ${expr.expression.getText()}()`,
                            },
                            this.metrics,
                        ),
                    );
                    if (!callResult.truncated && !returnUnknown) return returned;
                    incompleteReturnTaints.push(...returned);
                }
                if (!callResult.truncated && !returnUnknown) return undefined;
            }
        }

        // Only sort eligibility consumes this escape marker; other host models retain their contracts.
        for (const instance of argInstances) {
            this.markSortEscape(instance);
            if (instance) this.invalidateBindingMetadata(instance);
        }
        if (ts.isPropertyAccessExpression(expr.expression) || ts.isElementAccessExpression(expr.expression)) {
            const instance = this.resolveInstance(expr.expression.expression);
            this.markSortEscape(instance);
            if (instance) this.invalidateBindingMetadata(instance);
        }
        // Unresolved call passthrough: if we can't see inside the function,
        // propagate taint from arguments and receiver to the return value.
        const passthroughTaints: TaintValue[] = [...incompleteReturnTaints];

        // Tainted arguments
        for (const t of argTaints) {
            if (t) passthroughTaints.push(...t);
        }

        // Tainted receiver: for method calls like taintedObj.method() or
        // taintedObj["method"](), the receiver carries taint even when
        // there are no arguments.
        if (ts.isPropertyAccessExpression(expr.expression)) {
            if (receiverTaints) {
                const sortIdentity =
                    expr.expression.name.text === "sort" ? this.modelAPIContext(expr.expression) : undefined;
                const preservesElementPaths =
                    sortIdentity != null &&
                    !sortIdentity.overridden &&
                    (sortIdentity.memberNames.includes("Array.sort") ||
                        this.standardMethod(expr.expression, ["Array"]));
                // Sort permutes elements; their field paths do not refer to the method itself.
                passthroughTaints.push(
                    ...(preservesElementPaths
                        ? receiverTaints
                        : TaintTracker.taintsForAggregateProperty(receiverTaints, expr.expression.name.text, false)),
                );
            }
        } else if (ts.isElementAccessExpression(expr.expression)) {
            if (receiverTaints) {
                const methodName = ts.isStringLiteralLike(expr.expression.argumentExpression)
                    ? expr.expression.argumentExpression.text
                    : undefined;
                passthroughTaints.push(
                    ...(methodName == null
                        ? TaintTracker.taintsForDynamicProperty(receiverTaints)
                        : TaintTracker.taintsForAggregateProperty(receiverTaints, methodName, false)),
                );
            }
        }

        const returnedInstance = this.expressionInstanceState.get(expr);
        if (this.hasUnknownPromiseSettlement(returnedInstance)) {
            this.storeHostValue(returnedInstance!, "$unknownReturn", this.hostValue(passthroughTaints));
        }
        const commandOutput = this.workspaceCommandOutput(expr);
        if (passthroughTaints.length > 0) {
            const shellArgumentContext = this.fixedShellCommandArrayContext(expr, passthroughTaints);
            const keepsShellQuoting =
                shellArgumentContext == null && this.isSpaceJoinOfElementWiseQuoting(expr, passthroughTaints);
            return [
                ...passthroughTaints.map((taint) => {
                    const step: PropagationStep = {
                        kind: "return",
                        location: this.nodeLocation(expr),
                        description: `returned from ${expr.expression.getText()}()`,
                    };
                    if (shellArgumentContext != null) {
                        return this.propagateWithShellArgumentContext(taint, step, shellArgumentContext);
                    }
                    return propagate(
                        keepsShellQuoting ? taint : this.withoutShellArgumentSanitizers(taint),
                        step,
                        this.metrics,
                    );
                }),
                ...commandOutput,
            ];
        }

        return commandOutput.length > 0 ? commandOutput : undefined;
    }

    private callbackCapturesTaintedContext(
        callback: ts.ArrowFunction | ts.FunctionExpression,
        state: TaintState,
    ): boolean {
        const taintedSymbols = new Set<ts.Symbol>();
        for (const [symbol, taints] of state) {
            if (taints.length > 0) taintedSymbols.add(symbol);
        }
        const outerInstances = new Set(this.instanceFieldState.keys());
        const taintedInstances = new Set(
            [...this.instanceFieldState]
                .filter(([, instance]) => this.instanceContainsTaint(instance))
                .map(([symbol]) => symbol),
        );

        if (taintedSymbols.size === 0 && outerInstances.size === 0 && this.currentThisInstance == null) {
            return false;
        }

        const pending: Array<{ node: ts.Node; lexicalThis: boolean }> = [
            {
                node: callback.body,
                lexicalThis: ts.isArrowFunction(callback),
            },
        ];
        const seenNodes = new Set<ts.Node>();
        while (pending.length > 0) {
            const { node, lexicalThis } = pending.pop()!;
            if (seenNodes.has(node)) continue;
            seenNodes.add(node);

            if (
                ts.isFunctionDeclaration(node) ||
                ts.isMethodDeclaration(node) ||
                ts.isConstructorDeclaration(node) ||
                ts.isGetAccessorDeclaration(node) ||
                ts.isSetAccessorDeclaration(node) ||
                ts.isClassDeclaration(node)
            ) {
                continue;
            }

            if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
                const nestedLexicalThis = ts.isArrowFunction(node) ? lexicalThis : false;
                node.forEachChild((child) => {
                    pending.push({ node: child, lexicalThis: nestedLexicalThis });
                });
                continue;
            }

            if (ts.isPropertyAccessExpression(node)) {
                if (this.propertyAccessCapturesTaintedContext(node, state, lexicalThis)) {
                    return true;
                }
                if (
                    !ts.isIdentifier(node.expression) &&
                    node.expression.kind !== ts.SyntaxKind.ThisKeyword &&
                    !ts.isPropertyAccessExpression(node.expression)
                ) {
                    pending.push({ node: node.expression, lexicalThis });
                }
                continue;
            }

            if (ts.isElementAccessExpression(node)) {
                const receiver = this.resolveInstance(node.expression);
                if (receiver && this.instanceContainsTaint(receiver)) return true;
                if (ts.isIdentifier(node.expression)) {
                    const symbol = this.checker.getSymbolAtLocation(node.expression);
                    if (symbol && (taintedSymbols.has(symbol) || outerInstances.has(symbol))) {
                        return true;
                    }
                }
                pending.push({ node: node.argumentExpression, lexicalThis });
                continue;
            }

            if (ts.isIdentifier(node)) {
                const symbol = this.checker.getSymbolAtLocation(node);
                if (symbol && (taintedSymbols.has(symbol) || taintedInstances.has(symbol))) {
                    return true;
                }
            } else if (node.kind === ts.SyntaxKind.ThisKeyword && lexicalThis && this.currentThisInstance != null) {
                return true;
            }

            node.forEachChild((child) => {
                pending.push({ node: child, lexicalThis });
            });
        }
        return false;
    }

    private propertyAccessCapturesTaintedContext(
        expr: ts.PropertyAccessExpression,
        state: TaintState,
        lexicalThis: boolean,
    ): boolean {
        if (expr.expression.kind === ts.SyntaxKind.ThisKeyword) {
            if (!lexicalThis) return false;
            const property = this.getThisPropertySymbol(expr);
            if (!property) return false;
            if (this.currentThisInstance != null && !this.instanceContainsTaint(this.currentThisInstance)) {
                // A prior callback can taint a shared instance after registration.
                return true;
            }
            return (
                (state.get(property)?.length ?? 0) > 0 ||
                (this.currentThisInstance != null &&
                    (this.getInstanceField(this.currentThisInstance, property)?.length ?? 0) > 0)
            );
        }

        if (ts.isIdentifier(expr.expression)) {
            const receiverSymbol = this.checker.getSymbolAtLocation(expr.expression);
            const receiverTaints = receiverSymbol ? state.get(receiverSymbol) : undefined;
            if (receiverTaints && TaintTracker.taintsForProperty(receiverTaints, expr.name.text).length > 0) {
                return true;
            }
            const receiverInstance = receiverSymbol ? this.instanceFieldState.get(receiverSymbol) : undefined;
            if (receiverInstance && !this.instanceContainsTaint(receiverInstance)) {
                return true;
            }
        }

        const fieldTaints = this.getInstanceFieldTaint(expr);
        if (fieldTaints && fieldTaints.length > 0) return true;

        const referencedInstance = this.resolveInstance(expr);
        const isReceiverOfAnotherAccess =
            (ts.isPropertyAccessExpression(expr.parent) && expr.parent.expression === expr) ||
            (ts.isElementAccessExpression(expr.parent) && expr.parent.expression === expr);
        if (referencedInstance && !isReceiverOfAnotherAccess && this.instanceContainsTaint(referencedInstance)) {
            return true;
        }

        if (ts.isCallExpression(expr.parent) && expr.parent.expression === expr) {
            const receiver = this.resolveInstance(expr.expression);
            if (receiver && this.instanceContainsTaint(receiver)) return true;
        }

        const property = this.checker.getSymbolAtLocation(expr);
        return property != null && (state.get(property)?.length ?? 0) > 0;
    }

    private instanceContainsTaint(root: InstanceState, seen: Set<InstanceState> = new Set()): boolean {
        if (seen.has(root)) return false;
        seen.add(root);
        if (root.valueTaints?.length || [...root.fields.values()].some((taints) => taints.length > 0)) {
            return true;
        }
        for (const nested of root.fieldInstances.values()) {
            if (this.instanceContainsTaint(nested, seen)) return true;
        }
        for (const nested of root.elementInstances.values()) {
            if (this.instanceContainsTaint(nested, seen)) return true;
        }
        return false;
    }

    private applyCallFieldState(callResult: InterproceduralCallResult, state: TaintState): void {
        for (const sym of callResult.clearedFieldSymbols) {
            state.delete(sym);
        }
        for (const [sym, taints] of callResult.fieldState) {
            state.set(sym, taints);
        }
    }

    private analyzeCallCallbackSources(
        expr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
        state: TaintState,
    ): void {
        const callName = getCallChainName(expr.expression);

        for (const source of this.spec.sources) {
            if (source.kind !== "parameter") continue;
            if (source.callbackSource !== "call") continue;
            if (!source.callbackRegistration) continue;
            if (
                source.requireAPIIdentity
                    ? !this.matchesModelAPI(expr.expression, source.callbackRegistration)
                    : !this.matchesPatternWithExpr(
                          expr.expression,
                          callName,
                          source.callbackRegistration,
                          "callbackRegistration.parameter",
                      )
            )
                continue;
            if (source.workspaceCwdOptionIndices && !this.runsInWorkspace(expr, source.workspaceCwdOptionIndices)) {
                continue;
            }

            for (const callbackArgIdx of callbackArgIndices(source, expr.arguments.length)) {
                if (expr.arguments.length <= callbackArgIdx) continue;

                const value = this.resolveValueInstance(expr.arguments[callbackArgIdx], state);
                if (this.interproc && value?.functions.length) {
                    for (const fn of value.functions) {
                        const index = source.paramIndex ?? 0;
                        const param = fn.declaration.parameters[index];
                        if (!param) continue;
                        const taints = this.callbackParameterTaints(source, expr, argTaints, param);
                        if (!taints?.length) continue;
                        const args = fn.declaration.parameters.map((_, i) => ({
                            expression: expr.arguments[callbackArgIdx],
                            taints: i === index ? taints : undefined,
                        }));
                        if (this.apiIdentity.matchesAPI(expr.expression, "fs.readFile")) {
                            this.invokeDeferredCallback(expr, createFunctionInstance(fn), args, state);
                        } else {
                            this.invokeHostCallback(expr, createFunctionInstance(fn), args, state);
                        }
                    }
                } else {
                    const callback = resolveFunctionReference(this.checker, expr.arguments[callbackArgIdx]);
                    if (callback?.body) this.analyzeCallCallbackSource(source, callback, expr, argTaints, state);
                }
            }
        }
    }

    private analyzeCallCallbackSource(
        source: SourceSpec,
        callback: ts.FunctionLikeDeclaration,
        callExpr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
        state: TaintState,
    ): void {
        const paramIdx = source.paramIndex ?? 0;
        if (callback.parameters.length <= paramIdx) return;

        const callbackState: TaintState = forkTaintState(state);
        const param = callback.parameters[paramIdx];
        const sym = this.checker.getSymbolAtLocation(param.name);

        const paramTaints = this.callbackParameterTaints(source, callExpr, argTaints, param);
        if (!paramTaints || paramTaints.length === 0) return;

        if (sym) callbackState.set(sym, paramTaints);

        const tracker = new TaintTracker(
            this.checker,
            this.spec,
            this.interproc,
            this.depth + 1,
            this.maxDepth,
            this.entryPointName,
            this.metrics,
            this.closureCache,
        );
        const result = tracker.analyzeFunction(
            callback.body,
            callbackState,
            [],
            sym ? [] : [{ parameter: param, taints: paramTaints }],
        );
        this.findings.push(...result.findings);
        this.warnings.push(...result.warnings);
    }

    private callbackParameterTaints(
        source: SourceSpec,
        callExpr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
        param: ts.ParameterDeclaration,
    ): TaintValue[] | undefined {
        const mode = source.callbackTaint ?? "always";
        const inheritFromArgIndex = source.callbackTaintFromArgIndex;
        const inherited = inheritFromArgIndex !== undefined ? argTaints[inheritFromArgIndex] : undefined;

        if (inherited && (mode === "inheritFromArg" || mode === "preferArgTaint")) {
            return inherited.map((taint) =>
                propagate(
                    taint,
                    {
                        kind: "argument",
                        location: this.nodeLocation(callExpr),
                        description: `provided as callback parameter '${param.name.getText()}' by ${callExpr.expression.getText()}()`,
                    },
                    this.metrics,
                ),
            );
        }

        if (mode === "inheritFromArg") {
            return undefined;
        }

        return [createTaint(source, this.nodeLocation(callExpr), this.metrics)];
    }

    private analyzePromiseExecutor(expr: ts.NewExpression, executor?: InstanceState): InstanceState {
        const promise = createInstanceState();
        promise.apiTypes = ["Promise"];
        // Executors run synchronously: retain direct sinks at the caller's
        // boundary, while the incremented child depth still bounds recursion.
        if (this.depth > this.maxDepth) {
            this.interproc?.noteDepthLimit();
            return promise;
        }
        const outcomes = [promise];
        for (const fn of executor?.functions ?? []) {
            if (!fn.declaration.body) continue;
            const endpoints = ["Promise.resolveCallback", "Promise.rejectCallback"].map((type) => {
                const endpoint = createInstanceState();
                endpoint.apiTypes = [type];
                endpoint.elementInstances.set("$promise", promise);
                return endpoint;
            });
            const tracker = new TaintTracker(
                this.checker,
                this.spec,
                this.interproc,
                this.depth + 1,
                this.maxDepth,
                this.entryPointName,
                this.metrics,
                this.closureCache,
                fn.capturedInstances,
                fn.thisInstance,
            );
            const result = tracker.analyzeFunction(
                fn.declaration.body,
                fn.captured,
                [],
                fn.declaration.parameters
                    .slice(0, 2)
                    .map((parameter, index) => ({ parameter, instance: endpoints[index] })),
            );
            this.findings.push(...result.findings);
            this.warnings.push(...result.warnings);
            for (const param of fn.declaration.parameters.slice(0, 2)) {
                const symbol = parameterSymbol(this.checker, param);
                const outcome = symbol && tracker.instanceFieldState.get(symbol)?.elementInstances.get("$promise");
                if (outcome) outcomes.push(outcome);
            }
            if (
                result.mayThrow &&
                !promise.elementInstances.has("$fulfilled") &&
                !promise.elementInstances.has("$rejected")
            ) {
                promise.elementInstances.set(
                    "$rejected",
                    this.hostValue(result.throwTaints, mergeInstanceStates(result.throwInstances ?? [])),
                );
            }
        }
        const merged = mergeInstanceStates(outcomes)!;
        if (this.hasUnknownPromiseSettlement(merged)) merged.elementInstances.set("$unknownReturn", this.hostValue());
        return merged;
    }

    private analyzeNewExpression(expr: ts.NewExpression, state: TaintState): TaintValue[] | undefined {
        this.cleanExpressions.delete(expr);
        const nativePromise = this.apiIdentity.importedName(expr.expression) === "Promise";
        const argTaints: (TaintValue[] | undefined)[] = [];
        const argInstances: (InstanceState | undefined)[] = [];
        for (const arg of expr.arguments ?? []) {
            const value = unwrapExpression(arg);
            if (nativePromise && (ts.isArrowFunction(value) || ts.isFunctionExpression(value))) {
                argTaints.push(undefined);
                argInstances.push(createFunctionInstance(this.captureFunctionValue(value, state)));
            } else {
                argTaints.push(this.analyzeExpression(arg, state));
                argInstances.push(this.resolveValueInstance(ts.isSpreadElement(arg) ? arg.expression : arg, state));
            }
        }

        this.checkConstructionSink(expr, expr.expression, argTaints);
        if (nativePromise) {
            const promise = this.analyzePromiseExecutor(expr, argInstances[0]);
            this.expressionInstanceState.set(expr, promise);
            if (!this.hasUnknownPromiseSettlement(promise)) this.cleanExpressions.add(expr);
            return undefined;
        }

        const hostType = this.apiIdentity.importedName(expr.expression);
        if (["events.EventEmitter", "events", "stream.PassThrough"].includes(hostType ?? "")) {
            const instance = createInstanceState();
            instance.apiTypes = [hostType === "events" ? "events.EventEmitter" : hostType!];
            this.expressionInstanceState.set(expr, instance);
            this.cleanExpressions.add(expr);
            return undefined;
        }

        // Resolved constructors return per-instance field taint, including
        // sanitizer provenance. Raw assignments retain their source taint.
        if (this.interproc && this.depth >= this.maxDepth) {
            this.interproc.noteDepthLimit();
        }
        if (this.interproc && this.depth < this.maxDepth) {
            const ctorResult = this.interproc.analyzeConstructorCall(
                expr,
                argTaints,
                this.checker,
                this.depth,
                state,
                argInstances,
            );
            if (ctorResult) {
                this.findings.push(...ctorResult.findings);
                if (ctorResult.instanceState) {
                    this.expressionInstanceState.set(expr, ctorResult.instanceState);
                }
                if (!ctorResult.truncated && !ctorResult.returnUnknown) this.cleanExpressions.add(expr);
                if (ctorResult.returnTaints && ctorResult.returnTaints.length > 0) {
                    return ctorResult.returnTaints.map((t) =>
                        propagate(
                            t,
                            {
                                kind: "return",
                                location: this.nodeLocation(expr),
                                description: `returned from new ${expr.expression.getText()}()`,
                            },
                            this.metrics,
                        ),
                    );
                }
                return undefined;
            }
        }

        // Unresolved constructor passthrough: if we cannot model the
        // constructor body, preserve taint from constructor arguments on the
        // returned instance.
        const passthroughTaints: TaintValue[] = [];
        for (const taints of argTaints) {
            if (taints) passthroughTaints.push(...taints);
        }

        if (passthroughTaints.length > 0) {
            return passthroughTaints.map((taint) =>
                propagate(
                    taint,
                    {
                        kind: "return",
                        location: this.nodeLocation(expr),
                        description: `returned from new ${expr.expression.getText()}()`,
                    },
                    this.metrics,
                ),
            );
        }

        return undefined;
    }

    private analyzeBinaryExpression(expr: ts.BinaryExpression, state: TaintState): TaintValue[] | undefined {
        if (
            expr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
            expr.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
            expr.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
        ) {
            const nodes: ts.BinaryExpression[] = [];
            let leftmost: ts.Expression = expr;
            while (ts.isBinaryExpression(leftmost) && leftmost.operatorToken.kind === expr.operatorToken.kind) {
                nodes.push(leftmost);
                leftmost = leftmost.left;
            }
            const taints = [...(this.analyzeExpression(leftmost, state) ?? [])];
            let selectedInstance = this.resolveInstance(leftmost);
            for (const node of nodes.reverse()) {
                if (selectedInstance) this.expressionInstanceState.set(expr, selectedInstance);
                else this.expressionInstanceState.delete(expr);
                const skipped = this.captureLoopAnalysisState(state);
                taints.push(...(this.analyzeExpression(node.right, state) ?? []));
                const rightInstance = this.resolveInstance(node.right);
                if (rightInstance) this.expressionInstanceState.set(expr, rightInstance);
                else this.expressionInstanceState.delete(expr);
                this.restoreLoopAnalysisState(
                    this.mergeLoopAnalysisStates(skipped, this.captureLoopAnalysisState(state)),
                    state,
                );
                selectedInstance = this.expressionInstanceState.get(expr);
            }
            return taints.length > 0
                ? taints.map((taint) =>
                      propagate(
                          taint,
                          {
                              kind: "shortCircuit",
                              location: this.nodeLocation(expr),
                              description: "short-circuit expression",
                          },
                          this.metrics,
                      ),
                  )
                : undefined;
        }
        // Flatten the left spine of a `+` chain to avoid one stack frame per
        // operand. The concatenation analyzer retains operand order and checks
        // shell-insertion context across the flattened sequence.
        const chainKind = this.combiningChainStepKind(expr.operatorToken.kind);
        if (
            chainKind !== undefined &&
            ts.isBinaryExpression(expr.left) &&
            this.combiningChainStepKind(expr.left.operatorToken.kind) === chainKind
        ) {
            return this.analyzeCombiningChain(expr, chainKind, state);
        }

        if (expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
            const rightTaints = this.analyzeExpression(expr.right, state);
            const rightInstance = this.resolveInstance(expr.right);

            // Assignment replaces the previous taint even when the RHS has no
            // tracked provenance. Empty taint alone is not a cleanliness proof;
            // cleanBindings is cleared separately below.
            if (ts.isIdentifier(expr.left)) {
                const sym = this.checker.getSymbolAtLocation(expr.left);
                if (sym) {
                    if (rightTaints) {
                        const stepped = rightTaints.map((t) =>
                            propagate(
                                t,
                                {
                                    kind: "assignment",
                                    location: this.nodeLocation(expr),
                                    description: `assigned to '${expr.left.getText()}'`,
                                },
                                this.metrics,
                            ),
                        );
                        state.set(sym, stepped);
                    } else {
                        // The old value's taint no longer describes this binding.
                        state.delete(sym);
                    }

                    this.cleanBindings.delete(sym);
                    if (rightInstance) {
                        this.instanceFieldState.set(sym, rightInstance);
                    } else {
                        this.instanceFieldState.delete(sym);
                    }

                    // Check if LHS is a sink (assignment sink, e.g., webview.html = tainted)
                    if (rightTaints) this.checkAssignmentSink(expr.left, rightTaints);
                }
            } else if (ts.isObjectLiteralExpression(expr.left) || ts.isArrayLiteralExpression(expr.left)) {
                this.assignBindingTarget(expr.left, rightTaints, rightInstance, state);
            } else if (ts.isPropertyAccessExpression(expr.left)) {
                this.assignPropertyTaint(expr.left, rightTaints, state, expr);
                this.assignPropertyInstance(expr.left, rightInstance);
                // obj.prop = tainted — check for assignment sinks
                if (rightTaints) this.checkAssignmentSink(expr.left, rightTaints);
            } else if (ts.isElementAccessExpression(expr.left)) {
                this.assignElementInstance(expr.left, rightInstance, rightTaints);
                if (rightTaints) this.checkAssignmentSink(expr.left, rightTaints);
            }
            return rightTaints;
        }

        if (expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
            return this.analyzeStringConcatenation([expr.left, expr.right], expr, state);
        }

        const leftTaints = this.analyzeExpression(expr.left, state);
        const rightTaints = this.analyzeExpression(expr.right, state);

        // Handle += assignment
        if (expr.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) {
            const allTaints = [...(leftTaints || []), ...(rightTaints || [])];
            if (allTaints.length > 0) {
                const stepped = allTaints.map((t) =>
                    propagate(
                        t,
                        {
                            kind: "stringConcat",
                            location: this.nodeLocation(expr),
                            description: `concatenated into '${expr.left.getText()}'`,
                        },
                        this.metrics,
                    ),
                );
                if (ts.isIdentifier(expr.left)) {
                    const sym = this.checker.getSymbolAtLocation(expr.left);
                    if (sym) {
                        state.set(sym, stepped);
                    }
                } else if (ts.isPropertyAccessExpression(expr.left)) {
                    this.assignPropertyTaint(expr.left, stepped, state, expr);
                }
            }
            return allTaints.length > 0 ? allTaints : undefined;
        }

        return undefined;
    }

    private combiningChainStepKind(operatorKind: ts.SyntaxKind): PropagationStep["kind"] | undefined {
        return operatorKind === ts.SyntaxKind.PlusToken ? "stringConcat" : undefined;
    }

    /** Analyze a left-associative concatenation without one stack frame per operand. */
    private analyzeCombiningChain(
        expr: ts.BinaryExpression,
        chainKind: PropagationStep["kind"],
        state: TaintState,
    ): TaintValue[] | undefined {
        const rightOperands: ts.Expression[] = [];
        let node: ts.Expression = expr;
        while (ts.isBinaryExpression(node) && this.combiningChainStepKind(node.operatorToken.kind) === chainKind) {
            rightOperands.push(node.right);
            node = node.left;
        }
        return this.analyzeStringConcatenation([node, ...rightOperands.reverse()], expr, state);
    }

    private analyzeStringConcatenation(
        operands: readonly ts.Expression[],
        expr: ts.BinaryExpression,
        state: TaintState,
    ): TaintValue[] | undefined {
        const allTaints: TaintValue[] = [];
        const insertions: ShellInsertion[] = [];
        let staticContext: string | undefined = "";
        for (const operand of operands) {
            const taints = this.analyzeExpression(operand, state);
            if (taints) {
                const insertionContext = staticContext == null ? "unsafe" : this.shellInsertionContext(staticContext);
                const propagated = taints.map((taint) =>
                    this.propagateWithShellArgumentContext(
                        taint,
                        {
                            kind: "stringConcat",
                            location: this.nodeLocation(expr),
                            description: `string concatenation`,
                        },
                        insertionContext,
                    ),
                );
                allTaints.push(...propagated);
                staticContext = this.continueShellContext(staticContext, propagated, taints);
                if (staticContext != null) {
                    insertions.push({
                        first: allTaints.length - propagated.length,
                        count: propagated.length,
                        end: staticContext.length,
                    });
                }
                continue;
            }

            if (staticContext == null) continue;
            const text = this.staticStringText(operand);
            if (text != null) {
                staticContext += text;
            } else {
                const sanitizedCommand = this.staticSanitizedShellCommand(operand);
                staticContext = sanitizedCommand == null ? undefined : staticContext + sanitizedCommand;
            }
        }
        this.applyShellSuffixes(allTaints, insertions, staticContext, expr);
        return allTaints.length > 0 ? allTaints : undefined;
    }

    private analyzeTemplateExpression(expr: ts.TemplateExpression, state: TaintState): TaintValue[] | undefined {
        const allTaints: TaintValue[] = [];
        const insertions: ShellInsertion[] = [];
        let staticContext: string | undefined = expr.head.text;
        for (const span of expr.templateSpans) {
            const taints = this.analyzeExpression(span.expression, state);
            if (taints) {
                const insertionContext = staticContext == null ? "unsafe" : this.shellInsertionContext(staticContext);
                const propagated = taints.map((taint) =>
                    this.propagateWithShellArgumentContext(
                        taint,
                        {
                            kind: "templateLiteral",
                            location: this.nodeLocation(expr),
                            description: `interpolated into template literal`,
                        },
                        insertionContext,
                    ),
                );
                allTaints.push(...propagated);
                staticContext = this.continueShellContext(staticContext, propagated, taints);
                if (staticContext != null) {
                    insertions.push({
                        first: allTaints.length - propagated.length,
                        count: propagated.length,
                        end: staticContext.length,
                    });
                }
            } else {
                if (staticContext == null) continue;
                const text = this.staticStringText(span.expression);
                if (text != null) {
                    staticContext += text;
                } else {
                    const sanitizedCommand = this.staticSanitizedShellCommand(span.expression);
                    if (sanitizedCommand != null) {
                        staticContext += sanitizedCommand;
                    } else if (this.isQuotedArgumentWord(span.expression, staticContext)) {
                        staticContext += TaintTracker.SHELL_ARGUMENT_PLACEHOLDER;
                    } else {
                        staticContext = undefined;
                    }
                }
            }
            if (staticContext != null) staticContext += span.literal.text;
        }
        this.applyShellSuffixes(allTaints, insertions, staticContext, expr);
        return allTaints.length > 0 ? allTaints : undefined;
    }

    /**
     * Withdraw shell-argument credit from quoted values whose fixed text after
     * them still lets them act as code: a redirection writes them to a file, a
     * pipe feeds them to a denied command, or `cd <value>` picks the directory
     * the next command runs in. Unknown text after a value (`staticContext`
     * undefined) proves nothing either way, so those keep their credit.
     */
    private applyShellSuffixes(
        allTaints: TaintValue[],
        insertions: readonly ShellInsertion[],
        staticContext: string | undefined,
        expr: ts.Expression,
    ): void {
        if (staticContext == null) return;
        for (const { first, count, end } of insertions) {
            const suffix = staticContext.slice(end);
            for (let i = first; i < first + count; i++) {
                const taint = allTaints[i];
                const applied = taint.sanitizers?.find(
                    ({ spec, contextSatisfied }) => spec.requiresShellArgumentContext === true && contextSatisfied,
                );
                if (applied == null) continue;
                const reason = this.dangerousShellSuffix(suffix, applied.shellCommand, applied.spec);
                if (reason == null) continue;
                allTaints[i] = withSanitizers(
                    propagate(
                        taint,
                        {
                            kind: "shellCommandComposition",
                            location: this.nodeLocation(expr),
                            description: `quoted argument ${reason}`,
                        },
                        this.metrics,
                    ),
                    taint.sanitizers!.map((sanitizer) =>
                        sanitizer.spec.requiresShellArgumentContext === true
                            ? { ...sanitizer, contextSatisfied: false, shellCommand: undefined }
                            : sanitizer,
                    ),
                );
            }
        }
    }

    /**
     * Why fixed shell text following a quoted value still lets it act as code,
     * or undefined. Scans up to the end of the value's pipeline, respecting quotes.
     */
    private dangerousShellSuffix(
        suffix: string,
        command: string | undefined,
        sanitizer: SanitizerSpec,
    ): string | undefined {
        let quote: "'" | '"' | undefined;
        for (let i = 0; i < suffix.length; i++) {
            const char = suffix[i];
            if (quote != null) {
                if (char === "\\" && quote === '"') i++;
                else if (char === quote) quote = undefined;
                continue;
            }
            if (char === "\\") {
                i++;
            } else if (char === "'" || char === '"') {
                quote = char;
            } else if (char === ">" || (char === "&" && suffix[i + 1] === ">")) {
                const redirect = TaintTracker.parseRedirect(suffix, i);
                if (redirect.writesStdoutToFile) {
                    return "is redirected to a file by fixed text";
                }
                i = redirect.end - 1;
            } else if (char === "|" && suffix[i + 1] !== "|") {
                const next = TaintTracker.firstCommandWord(suffix.slice(i + 1));
                if (next != null && TaintTracker.isDeniedShellCommand(sanitizer, next)) {
                    return `is piped into \`${next}\``;
                }
                // The value keeps flowing through the pipeline; keep scanning.
            } else if (char === ";" || char === "&" || char === "\n" || char === "|") {
                const rest = suffix.slice(i + 1).replace(/^[|&]/, "");
                if ((command === "cd" || command === "pushd") && TaintTracker.firstCommandWord(rest) != null) {
                    return "chooses the directory the following command runs in";
                }
                return undefined;
            }
        }
        return undefined;
    }

    /**
     * Parse the redirection starting at `index` (at `>` or at `&` of `&>`), and
     * whether it sends stdout (which carries the value, e.g. from `echo`) into a
     * file. `2>` and other descriptors, fd duplication (`>&2`, `2>&1`), and
     * `/dev/null` do not. `end` is just past the redirection target.
     */
    private static parseRedirect(text: string, index: number): { writesStdoutToFile: boolean; end: number } {
        const bothStreams = text[index] === "&";
        const operator = bothStreams ? index + 1 : index;
        let fdStart = index;
        while (!bothStreams && fdStart > 0 && /[0-9]/.test(text[fdStart - 1])) fdStart--;
        const fd = text.slice(fdStart, index);
        let next = operator + 1;
        while (text[next] === ">" || text[next] === "|") next++;
        const duplicatesFd = !bothStreams && text[next] === "&";
        if (duplicatesFd) next++;
        while (text[next] === " " || text[next] === "\t") next++;
        let targetEnd = next;
        while (targetEnd < text.length && !/[\s;&|<>]/.test(text[targetEnd])) targetEnd++;
        const target = text.slice(next, targetEnd);
        return {
            writesStdoutToFile: (fd === "" || fd === "1") && !duplicatesFd && target !== "/dev/null",
            end: targetEnd,
        };
    }

    /** First word of a fixed shell command that names the program, lowercased basename. */
    private static firstCommandWord(text: string): string | undefined {
        const word = text
            .trim()
            .split(/\s+/)
            .find((token) => token.length > 0 && !token.startsWith("-") && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(token));
        return word == null ? undefined : word.split("/").pop()!.toLowerCase();
    }

    private propagateWithShellArgumentContext(
        taint: TaintValue,
        step: PropagationStep,
        context: ShellInsertionContext,
    ): TaintValue {
        const nextSanitizers = taint.sanitizers?.map((sanitizer) => {
            if (sanitizer.spec.requiresShellArgumentContext !== true) {
                return sanitizer;
            }
            if (this.shellContextAllowsSanitizer(context, sanitizer.spec)) {
                const shellCommand = (context as { command: string }).command;
                return sanitizer.contextSatisfied && sanitizer.shellCommand === shellCommand
                    ? sanitizer
                    : { ...sanitizer, contextSatisfied: true, shellCommand };
            }
            if (context === "commandStart" && sanitizer.contextSatisfied) {
                return sanitizer;
            }
            return sanitizer.contextSatisfied
                ? { ...sanitizer, contextSatisfied: false, shellCommand: undefined }
                : sanitizer;
        });
        const activatesSanitizer =
            taint.sanitizers?.some(
                (sanitizer, index) =>
                    sanitizer.spec.requiresShellArgumentContext === true &&
                    !sanitizer.contextSatisfied &&
                    nextSanitizers?.[index].contextSatisfied === true,
            ) === true;
        const propagated = propagate(
            taint,
            activatesSanitizer
                ? {
                      ...step,
                      kind: "shellCommandComposition",
                      description: `quoted argument embedded after fixed shell command`,
                  }
                : step,
            this.metrics,
        );
        if (nextSanitizers == null) return propagated;

        return withSanitizers(propagated, nextSanitizers);
    }

    /** Text of a string literal, or of a `const` whose initializer resolves to one. */
    private staticStringText(expr: ts.Expression, seenSymbols: Set<ts.Symbol> = new Set()): string | undefined {
        const value = unwrapExpression(expr);
        if (ts.isStringLiteralLike(value)) return value.text;
        if (!ts.isIdentifier(value)) return undefined;
        const symbol = this.resolveSymbol(value);
        const declaration = symbol?.valueDeclaration;
        if (
            symbol == null ||
            seenSymbols.has(symbol) ||
            declaration == null ||
            !ts.isVariableDeclaration(declaration) ||
            declaration.initializer == null ||
            !ts.isVariableDeclarationList(declaration.parent) ||
            (declaration.parent.flags & ts.NodeFlags.Const) === 0
        ) {
            return undefined;
        }
        seenSymbols.add(symbol);
        return this.staticStringText(declaration.initializer, seenSymbols);
    }

    private static readonly SHELL_ARGUMENT_PLACEHOLDER = "prophecy_quoted_argument";

    /**
     * Static shell text after inserting `taints`. A quoted argument becomes a
     * placeholder word; a numerically sanitized value (`Number()`, `parseInt()`)
     * becomes a numeric word once a complete command word precedes it.
     * `propagated` are the values after this insertion (with updated context);
     * `beforeInsertion` are the same values as analyzed, used to check they are
     * still a bare number. A value with no satisfied sanitizer is reported at the
     * sink on its own, so it also becomes a placeholder word: values quoted after
     * it are reported as quoted arguments rather than as command execution.
     * Anything else makes the rest of the command unknown.
     */
    private continueShellContext(
        staticContext: string | undefined,
        propagated: readonly TaintValue[],
        beforeInsertion: readonly TaintValue[],
    ): string | undefined {
        if (staticContext == null) return undefined;
        if (propagated.every((taint) => this.hasSatisfiedShellArgumentSanitizer(taint))) {
            return staticContext + TaintTracker.SHELL_ARGUMENT_PLACEHOLDER;
        }
        // A number inside the command word would choose which binary runs.
        if (
            beforeInsertion.every((taint) => TaintTracker.isBareNumber(taint)) &&
            typeof this.shellInsertionContext(staticContext) === "object"
        ) {
            return staticContext + "0";
        }
        if (propagated.some((taint) => taint.sanitizers?.some(({ contextSatisfied }) => contextSatisfied) !== true)) {
            return staticContext + TaintTracker.SHELL_ARGUMENT_PLACEHOLDER;
        }
        return undefined;
    }

    /**
     * Still the number produced by a `numeric` sanitizer scoped to rce sinks
     * (`Number`, `parseInt`). Sanitizer provenance survives later string
     * building (`Number(x) + "; sh -c"`), so only moves between variables,
     * parameters, and closures may follow the conversion.
     */
    private static isBareNumber(taint: TaintValue): boolean {
        for (let node = taint.chain; node != null; node = node.previous) {
            if (node.step.kind === "sanitizer") {
                // The nearest sanitizer must be the numeric conversion itself, scoped
                // to rce sinks and not restricted by sink name (the sink is not known
                // at insertion); any other sanitizer means the value was transformed.
                const spec = node.step.sanitizer;
                return spec?.numeric === true && spec.categories?.includes("rce") === true && spec.sinkNames == null;
            }
            if (!TaintTracker.BARE_VALUE_STEPS.has(node.step.kind)) return false;
        }
        return false;
    }

    private static readonly BARE_VALUE_STEPS: ReadonlySet<string> = new Set(["assignment", "argument", "closure"]);

    private hasSatisfiedShellArgumentSanitizer(taint: TaintValue): boolean {
        return (
            taint.sanitizers?.some(
                ({ spec, contextSatisfied }) => spec.requiresShellArgumentContext === true && contextSatisfied,
            ) === true
        );
    }

    /**
     * An untainted shell-quoted value after a command word is one argument
     * word. As the command word it is not: a dynamic quoted command can still
     * name a shell or interpreter.
     */
    private isQuotedArgumentWord(expr: ts.Expression, staticContext: string): boolean {
        const value = unwrapExpression(expr);
        return (
            ts.isCallExpression(value) &&
            this.matchingSanitizer(value)?.requiresShellArgumentContext === true &&
            typeof this.shellInsertionContext(staticContext) === "object"
        );
    }

    private staticSanitizedShellCommand(expr: ts.Expression): string | undefined {
        const value = unwrapExpression(expr);
        if (!ts.isCallExpression(value) || value.arguments.length !== 1) {
            return undefined;
        }
        const sanitizer = this.matchingSanitizer(value);
        const commandPath = this.staticShellCommandPath(value.arguments[0]);
        if (sanitizer?.requiresShellArgumentContext !== true || commandPath == null) {
            return undefined;
        }
        const command = commandPath.split(/[\\/]/).pop()!.toLowerCase();
        return TaintTracker.isDeniedShellCommand(sanitizer, command) ? undefined : command;
    }

    private staticShellCommandPath(expr: ts.Expression, seenSymbols: Set<ts.Symbol> = new Set()): string | undefined {
        const value = unwrapExpression(expr);
        if (ts.isStringLiteralLike(value)) {
            return value.text;
        }
        if (ts.isIdentifier(value)) {
            const symbol = this.resolveSymbol(value);
            if (symbol == null || seenSymbols.has(symbol)) return undefined;
            const declaration = symbol.valueDeclaration;
            if (
                declaration == null ||
                !ts.isVariableDeclaration(declaration) ||
                declaration.initializer == null ||
                !ts.isVariableDeclarationList(declaration.parent) ||
                (declaration.parent.flags & ts.NodeFlags.Const) === 0
            ) {
                return undefined;
            }
            seenSymbols.add(symbol);
            return this.staticShellCommandPath(declaration.initializer, seenSymbols);
        }
        if (
            ts.isCallExpression(value) &&
            getCallChainName(value.expression) === "os.homedir" &&
            value.arguments.length === 0
        ) {
            return "/prophecy_home";
        }
        if (
            ts.isCallExpression(value) &&
            getCallChainName(value.expression) === "path.join" &&
            value.arguments.length > 0
        ) {
            const parts = value.arguments.map((argument) =>
                this.staticShellCommandPath(argument, new Set(seenSymbols)),
            );
            return parts.every((part): part is string => part != null) ? parts.join("/") : undefined;
        }
        return undefined;
    }

    private shellContextAllowsSanitizer(context: ShellInsertionContext, sanitizer: SanitizerSpec): boolean {
        if (typeof context !== "object") return false;
        if (context.command === TaintTracker.SHELL_ARGUMENT_PLACEHOLDER) {
            return true;
        }
        return !TaintTracker.isDeniedShellCommand(sanitizer, context.command);
    }

    private static isDeniedShellCommand(sanitizer: SanitizerSpec, command: string): boolean {
        const name = command.toLowerCase();
        return (
            sanitizer.shellCommandDenylist?.some((denied) => {
                const deniedName = denied.toLowerCase();
                if (!name.startsWith(deniedName)) return false;
                // The same program under a versioned or Windows name: `python3.11`,
                // `node18`, `bash.exe`. Nothing else is stripped.
                return /^([-.]?\d+(\.\d+)*)?(\.exe)?$/.test(name.slice(deniedName.length));
            }) === true
        );
    }

    /**
     * Classify an insertion point using only the fixed shell syntax before it.
     * Open quoting/substitution stays unsafe. The caller separately checks the
     * parsed command against the sanitizer's command denylist.
     */
    private shellInsertionContext(text: string): ShellInsertionContext {
        let quote: "'" | '"' | undefined;
        let escaped = false;
        let token = "";
        let tokenStarted = false;
        let sawCommandSubstitution = false;
        let completeTokens: string[] = [];

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            if (escaped) {
                token += char;
                tokenStarted = true;
                escaped = false;
                continue;
            }
            if (quote === "'") {
                if (char === "'") quote = undefined;
                else token += char;
                continue;
            }
            if (quote === '"') {
                if (char === '"') {
                    quote = undefined;
                } else if (char === "\\") {
                    escaped = true;
                } else {
                    if (
                        char === "`" ||
                        (char === "$" && text[i + 1] === "(") ||
                        (char === "$" && text[i + 1] === "{")
                    ) {
                        sawCommandSubstitution = true;
                    }
                    token += char;
                }
                continue;
            }

            if (char === "\\") {
                escaped = true;
                tokenStarted = true;
            } else if (char === "'" || char === '"') {
                quote = char;
                tokenStarted = true;
            } else if (char === "`" || (char === "$" && text[i + 1] === "(") || (char === "$" && text[i + 1] === "{")) {
                sawCommandSubstitution = true;
                token += char;
                tokenStarted = true;
            } else if (char === ";" || char === "\n" || char === "|" || char === "&") {
                completeTokens = [];
                token = "";
                tokenStarted = false;
            } else if (/\s/.test(char)) {
                if (tokenStarted) completeTokens.push(token);
                token = "";
                tokenStarted = false;
            } else {
                token += char;
                tokenStarted = true;
            }
        }

        if (quote != null || escaped || sawCommandSubstitution) return "unsafe";
        const command = completeTokens.find(
            (candidate) => !candidate.startsWith("-") && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(candidate),
        );
        if (command == null) {
            return tokenStarted ? "unsafe" : "commandStart";
        }
        return { command: command.split("/").pop()!.toLowerCase() };
    }

    private fixedShellCommandArrayContext(
        expr: ts.CallExpression,
        taints: readonly TaintValue[],
    ): ShellInsertionContext | undefined {
        if (
            !ts.isPropertyAccessExpression(expr.expression) ||
            expr.expression.name.text !== "join" ||
            expr.arguments.length !== 1 ||
            this.staticStringText(expr.arguments[0]) !== " " ||
            !ts.isIdentifier(expr.expression.expression)
        ) {
            return undefined;
        }

        const symbol = this.resolveSymbol(expr.expression.expression);
        const declaration = symbol?.valueDeclaration;
        if (declaration == null || !ts.isVariableDeclaration(declaration) || declaration.initializer == null) {
            return undefined;
        }

        const initializer = unwrapExpression(declaration.initializer);
        if (!ts.isArrayLiteralExpression(initializer)) return undefined;
        const parts: string[] = [];
        for (const element of initializer.elements) {
            if (ts.isSpreadElement(element)) return undefined;
            const text = this.staticStringText(element);
            if (text == null) return undefined;
            parts.push(text);
        }
        const context = this.shellInsertionContext(parts.join(" ") + " ");
        if (typeof context !== "object") return undefined;

        return taints.every(
            (taint) =>
                this.wasAppendedWithPush(taint) &&
                taint.sanitizers?.some(
                    ({ spec }) =>
                        spec.requiresShellArgumentContext === true && this.shellContextAllowsSanitizer(context, spec),
                ) === true,
        )
            ? context
            : undefined;
    }

    private wasAppendedWithPush(taint: TaintValue): boolean {
        for (let node = taint.chain; node != null; node = node.previous) {
            if (node.step.kind === "mutation") {
                return node.step.mutationMethod === "push";
            }
        }
        return false;
    }

    private withoutShellArgumentSanitizers(taint: TaintValue): TaintValue {
        const sanitizers = taint.sanitizers?.filter(({ spec }) => spec.requiresShellArgumentContext !== true);
        if (sanitizers?.length === taint.sanitizers?.length) return taint;
        return withSanitizers(taint, sanitizers && sanitizers.length > 0 ? sanitizers : undefined);
    }

    private analyzeConditionalExpression(expr: ts.ConditionalExpression, state: TaintState): TaintValue[] | undefined {
        this.analyzeExpression(expr.condition, state);
        const entry = this.captureLoopAnalysisState(state);
        this.restoreLoopAnalysisState(this.cloneLoopAnalysisState(entry), state);
        const whenTrue = this.analyzeExpression(expr.whenTrue, state);
        const trueInstance = this.resolveInstance(expr.whenTrue);
        if (trueInstance) this.expressionInstanceState.set(expr, trueInstance);
        else this.expressionInstanceState.delete(expr);
        const trueExit = this.captureLoopAnalysisState(state);
        this.restoreLoopAnalysisState(this.cloneLoopAnalysisState(entry), state);
        const whenFalse = this.analyzeExpression(expr.whenFalse, state);
        const falseInstance = this.resolveInstance(expr.whenFalse);
        if (falseInstance) this.expressionInstanceState.set(expr, falseInstance);
        else this.expressionInstanceState.delete(expr);
        this.restoreLoopAnalysisState(
            this.mergeLoopAnalysisStates(trueExit, this.captureLoopAnalysisState(state)),
            state,
        );
        const mergedInstance = this.expressionInstanceState.get(expr);
        const unknownClass =
            (!trueInstance && !this.hasPrimitiveType(expr.whenTrue)) ||
            (!falseInstance && !this.hasPrimitiveType(expr.whenFalse));
        if (mergedInstance && unknownClass) {
            this.expressionInstanceState.set(expr, mergeReturnInstances([mergedInstance], true)!);
        }
        // Conservative: if either branch is tainted, result is tainted
        const allTaints = [...(whenTrue || []), ...(whenFalse || [])];
        if (allTaints.length > 0) {
            return allTaints.map((t) =>
                propagate(
                    t,
                    {
                        kind: "ternary",
                        location: this.nodeLocation(expr),
                        description: `ternary expression`,
                    },
                    this.metrics,
                ),
            );
        }
        return undefined;
    }

    private analyzeObjectLiteral(expr: ts.ObjectLiteralExpression, state: TaintState): TaintValue[] | undefined {
        const allTaints: TaintValue[] = [];
        // Properties hold value snapshots and shallow object/function aliases.
        const container = createInstanceState();
        container.elementInstances.set(BINDING_OBJECT_SHAPE, this.hostValue());
        for (const prop of expr.properties) {
            if (ts.isPropertyAssignment(prop)) {
                if (ts.isComputedPropertyName(prop.name)) this.analyzeExpression(prop.name.expression, state);
                const taints = this.analyzeExpression(prop.initializer, state);
                const name = this.propertyName(prop.name);
                const stamped = taints && this.stampObjectProperty(taints, name, prop);
                if (stamped) allTaints.push(...stamped);
                const instance = this.resolveValueInstance(prop.initializer, state);
                const property = this.checker.getSymbolAtLocation(prop.name);
                if (instance && property) container.fieldInstances.set(property, instance);
                this.recordBindingProperty(
                    container,
                    name,
                    stamped && name != null ? TaintTracker.taintsForAggregateProperty(stamped, name) : stamped,
                    instance,
                    prop.initializer,
                );
            } else if (ts.isSpreadAssignment(prop)) {
                const taints = this.analyzeExpression(prop.expression, state);
                if (taints)
                    allTaints.push(
                        ...taints.map((t) =>
                            propagate(
                                t,
                                {
                                    kind: "spread",
                                    location: this.nodeLocation(prop),
                                    description: "spread into object literal",
                                },
                                this.metrics,
                            ),
                        ),
                    );
                const source = this.resolveInstance(prop.expression);
                if (!source?.elementInstances.has(BINDING_OBJECT_SHAPE))
                    container.elementInstances.delete(BINDING_OBJECT_SHAPE);
                if (source) {
                    for (const [property, instance] of source.fieldInstances)
                        container.fieldInstances.set(property, instance);
                    for (const [key, value] of source.elementInstances) {
                        if (key.startsWith(BINDING_PROPERTY)) container.elementInstances.set(key, value);
                    }
                }
            } else if (ts.isShorthandPropertyAssignment(prop)) {
                // Shorthand names have a property symbol distinct from the binding read.
                const sym =
                    this.checker.getShorthandAssignmentValueSymbol(prop) ?? this.checker.getSymbolAtLocation(prop.name);
                const taints = sym ? state.get(sym)?.slice() : undefined;
                const stamped = taints && this.stampObjectProperty(taints, prop.name.text, prop);
                if (stamped) allTaints.push(...stamped);
                const instance = sym ? this.instanceFieldState.get(sym) : undefined;
                const property = this.checker.getSymbolAtLocation(prop.name);
                if (instance && property) container.fieldInstances.set(property, instance);
                this.recordBindingProperty(
                    container,
                    prop.name.text,
                    stamped && TaintTracker.taintsForAggregateProperty(stamped, prop.name.text),
                    instance,
                    prop.name,
                );
            } else {
                container.elementInstances.delete(BINDING_OBJECT_SHAPE);
            }
        }
        this.expressionInstanceState.set(expr, container);
        return allTaints.length > 0 ? allTaints : undefined;
    }

    private recordBindingProperty(
        owner: InstanceState,
        key: string | undefined,
        taints: readonly TaintValue[] | undefined,
        instance: InstanceState | undefined,
        expression?: ts.Expression,
    ): void {
        if (key == null) {
            this.invalidateBindingMetadata(owner);
            return;
        }
        const array = this.hasHostType(owner, "Array");
        const slot = array ? `$taint:${key}` : `${BINDING_PROPERTY}${key}`;
        const defined = expression && this.bindingValueExpression(expression);
        const payload = this.hostValue(taints, instance, array ? expression : defined);
        if (array) payload.elementInstances.set(BINDING_VALUE_STATE, this.hostValue([], undefined, defined));
        owner.elementInstances.set(slot, payload);
    }

    private invalidateBindingMetadata(owner: InstanceState, seen = new Set<InstanceState>()): void {
        if (seen.has(owner)) return;
        seen.add(owner);
        owner.elementInstances.delete(BINDING_OBJECT_SHAPE);
        owner.elementInstances.delete(BINDING_ARRAY_SHAPE);
        for (const [key, value] of owner.elementInstances) {
            if (isBindingPayload(key)) {
                const payload: InstanceState = {
                    ...value,
                    valueExpression: undefined,
                    elementInstances: new Map(value.elementInstances),
                };
                if (payload.elementInstances.has(BINDING_VALUE_STATE))
                    payload.elementInstances.set(BINDING_VALUE_STATE, this.hostValue());
                owner.elementInstances.set(key, payload);
            } else this.invalidateBindingMetadata(value, seen);
        }
        for (const value of owner.fieldInstances.values()) this.invalidateBindingMetadata(value, seen);
    }

    private deleteBindingProperty(target: ts.Expression, state: TaintState): void {
        if (!ts.isPropertyAccessExpression(target) && !ts.isElementAccessExpression(target)) return;
        const owner = this.resolveInstance(target.expression);
        if (!owner) return;
        const key = ts.isPropertyAccessExpression(target)
            ? target.name.text
            : this.elementKey(target.argumentExpression);
        if (key == null) {
            this.invalidateBindingMetadata(owner);
            return;
        }
        // A class or unknown prototype can expose an inherited value after deletion.
        if (!owner.elementInstances.has(BINDING_OBJECT_SHAPE) && !owner.elementInstances.has(BINDING_ARRAY_SHAPE)) {
            this.invalidateBindingMetadata(owner);
            return;
        }
        for (const symbol of [...owner.fields.keys()]) {
            if (symbol.getName() === key) owner.fields.delete(symbol);
        }
        for (const symbol of [...owner.fieldInstances.keys()]) {
            if (symbol.getName() === key) owner.fieldInstances.delete(symbol);
        }
        owner.elementInstances.delete(key);
        const slot = this.hasHostType(owner, "Array") ? `$taint:${key}` : `${BINDING_PROPERTY}${key}`;
        owner.elementInstances.set(slot, this.hostValue([], undefined, BINDING_UNDEFINED));
        if (ts.isPropertyAccessExpression(target)) {
            const symbol = this.getThisPropertySymbol(target) ?? this.getThisAliasPropertySymbol(target);
            if (symbol) state.delete(symbol);
        }
    }

    /**
     * Record which object-literal property a taint entered through, so
     * property-sensitive sinks (`SinkSpec.objectProperties`) can tell
     * `initCommands` from `name`.
     */
    private stampObjectProperty(
        taints: readonly TaintValue[],
        propertyName: string | undefined,
        node: ts.PropertyAssignment | ts.ShorthandPropertyAssignment,
    ): TaintValue[] {
        if (propertyName == null) return taints.slice();
        const location = this.nodeLocation(node);
        return taints.map((t) => {
            const stepped = propagate(
                t,
                {
                    kind: "objectProperty",
                    location,
                    description: propertyName,
                    objectLiteral: node.parent,
                },
                this.metrics,
            );
            return {
                ...stepped,
                aggregatePropertyPath: [propertyName, ...(t.aggregatePropertyPath ?? [])],
            };
        });
    }

    private propertyName(name: ts.PropertyName): string | undefined {
        if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) return name.text;
        if (ts.isComputedPropertyName(name)) {
            const expression = unwrapExpression(name.expression);
            if (ts.isStringLiteralLike(expression) || ts.isNumericLiteral(expression)) return expression.text;
        }
        return undefined;
    }

    /** Select and consume a known property path for a static property read. */
    private static taintsForProperty(taints: readonly TaintValue[], propertyName: string): TaintValue[] {
        const selected: TaintValue[] = [];
        for (const taint of taints) {
            const path = taint.aggregatePropertyPath;
            if (path == null || path.length === 0) {
                if (taint.source.taintAllProperties === true) {
                    selected.push(TaintTracker.settingPropertyOf(taint, propertyName));
                }
            } else if (path[0] === propertyName) {
                selected.push({
                    ...taint,
                    aggregatePropertyPath: path.length > 1 ? path.slice(1) : undefined,
                });
            }
        }
        return selected;
    }

    /**
     * A dynamic key may select any known property, so consume one path
     * component without filtering by name.
     */
    private static taintsForDynamicProperty(taints: TaintValue[]): TaintValue[] {
        return taints.map((taint) => {
            const path = taint.aggregatePropertyPath;
            return path != null && path.length > 0
                ? {
                      ...taint,
                      aggregatePropertyPath: path.length > 1 ? path.slice(1) : undefined,
                  }
                : taint;
        });
    }

    private static prependAggregateProperty(taints: TaintValue[], propertyName: string): TaintValue[] {
        return taints.map((taint) => ({
            ...taint,
            aggregatePropertyPath: [propertyName, ...(taint.aggregatePropertyPath ?? [])],
        }));
    }

    private static clearAggregatePropertyPath(taints: TaintValue[]): TaintValue[] {
        return taints.map((taint) =>
            taint.aggregatePropertyPath == null ? taint : { ...taint, aggregatePropertyPath: undefined },
        );
    }

    private isUriExpression(expr: ts.Expression): boolean {
        const type = this.checker.getNonNullableType(this.checker.getTypeAtLocation(expr));
        return (type.aliasSymbol ?? type.getSymbol())?.getName() === "Uri";
    }

    /** A property read from the value of a setting is the setting under that key. */
    private static settingPropertyOf(taint: TaintValue, propertyName: string): TaintValue {
        return taint.settingPath == null ? taint : { ...taint, settingPath: [...taint.settingPath, propertyName] };
    }

    /**
     * Select one property from an aggregate value. Unlike an ordinary property
     * read, unscoped aggregate taint remains conservative because the whole
     * value is being decomposed. `readsProperty` is false when the name is a
     * method called on the value rather than a property read from it.
     */
    private static taintsForAggregateProperty(
        taints: TaintValue[],
        propertyName: string,
        readsProperty = true,
    ): TaintValue[] {
        return taints.flatMap((taint) => {
            const path = taint.aggregatePropertyPath;
            if (path == null || path.length === 0) {
                return [readsProperty ? TaintTracker.settingPropertyOf(taint, propertyName) : taint];
            }
            if (path[0] !== propertyName) return [];
            return [
                {
                    ...taint,
                    aggregatePropertyPath: path.length > 1 ? path.slice(1) : undefined,
                },
            ];
        });
    }

    /**
     * The most recent object-literal property this taint passed through, or
     * undefined if it never did. Walks from the chain tail, so a property that
     * wrapped an already-built object can take precedence over its inner fields.
     */
    private static enclosingObjectProperty(taint: TaintValue): string | undefined {
        for (let node = taint.chain; node != null; node = node.previous) {
            if (node.step.kind === "objectProperty") return node.step.description;
        }
        return undefined;
    }

    /**
     * The step where this taint entered the sink's config object: the most
     * recent object-literal property it passed through, skipping wrapper
     * fields outside `objectPropertyUniverse` when the sink has one. Walks the
     * chain from the tail backwards.
     */
    private static sinkObjectPropertyStep(sink: SinkSpec, taint: TaintValue): PropagationStep | undefined {
        for (let node = taint.chain; node != null; node = node.previous) {
            if (node.step.kind !== "objectProperty") continue;
            if (sink.objectPropertyUniverse?.includes(node.step.description) === false) continue;
            return node.step;
        }
        return undefined;
    }

    /**
     * Whether a property-sensitive sink should fire for this taint. Suppresses
     * only on POSITIVE knowledge that the taint arrived via an uninteresting
     * property; an unknown path still reports unless `requireObjectProperty`.
     */
    private static sinkAcceptsTaint(sink: SinkSpec, taint: TaintValue): boolean {
        if (!sink.objectProperties || sink.objectProperties.length === 0) return true;
        const step = TaintTracker.sinkObjectPropertyStep(sink, taint);
        if (step == null) return sink.requireObjectProperty !== true;
        return TaintTracker.sinkAcceptsProperty(sink, step.description, taint);
    }

    /**
     * Whether the options beside the config field that carried this taint
     * enable a shell (`SinkSpec.shellOptionsProperty`). The field's own object
     * literal is checked, so it holds wherever the object was built.
     */
    private sinkOptionsEnableShell(sink: SinkSpec, taint: TaintValue): boolean {
        if (sink.shellOptionsProperty == null) return false;
        const config = TaintTracker.sinkObjectPropertyStep(sink, taint)?.objectLiteral;
        for (const prop of config?.properties ?? []) {
            let options: ts.Expression | undefined;
            if (ts.isPropertyAssignment(prop) && this.propertyName(prop.name) === sink.shellOptionsProperty) {
                options = prop.initializer;
            } else if (ts.isShorthandPropertyAssignment(prop) && prop.name.text === sink.shellOptionsProperty) {
                const declaration = this.checker.getShorthandAssignmentValueSymbol(prop)?.valueDeclaration;
                options =
                    declaration != null && ts.isVariableDeclaration(declaration) ? declaration.initializer : undefined;
            }
            if (options != null) return this.enablesShell(options);
        }
        return false;
    }

    /**
     * Whether taint that entered the sink's object through `property` reports.
     * For a map-valued property with `objectPropertyKeys`, the aggregate path
     * records the key the taint sits under, as in `{env: {PATH: x}}`. With no
     * key below the property, the taint is the whole map and still reports.
     */
    private static sinkAcceptsProperty(sink: SinkSpec, property: string, taint: TaintValue): boolean {
        if (!sink.objectProperties?.includes(property)) return false;
        const keys = sink.objectPropertyKeys?.[property];
        const path = taint.aggregatePropertyPath;
        if (keys == null || path == null) return true;
        const index = path.indexOf(property);
        if (index < 0 || index + 1 >= path.length) return true;
        const key = path[index + 1].toUpperCase();
        return keys.some((pattern) =>
            pattern.endsWith("*") ? key.startsWith(pattern.slice(0, -1).toUpperCase()) : key === pattern.toUpperCase(),
        );
    }

    private analyzeArrayLiteral(expr: ts.ArrayLiteralExpression, state: TaintState): TaintValue[] | undefined {
        const allTaints: TaintValue[] = [];
        const container = createInstanceState();
        container.apiTypes = ["Array"];
        container.elementInstances.set(BINDING_ARRAY_SHAPE, this.hostValue());
        const nestedShellCommandIndices = this.findNestedShellCommandIndices(expr);
        for (let i = 0; i < expr.elements.length; i++) {
            const element = expr.elements[i];
            let taints = this.analyzeExpression(element, state);
            if (taints && nestedShellCommandIndices.has(i)) {
                const location = this.nodeLocation(element);
                taints = taints.map((taint) => ({
                    ...propagate(
                        taint,
                        {
                            kind: "nestedShellCommand",
                            location,
                            description: "used as a command string by find -exec shell -c",
                        },
                        this.metrics,
                    ),
                    nestedShellCommandLocation: location,
                }));
            }
            if (taints)
                allTaints.push(
                    ...taints.map((taint) =>
                        propagate(
                            taint,
                            {
                                kind: "arrayIndex",
                                location: this.nodeLocation(element),
                                description: `stored in array element ${i}`,
                                arrayElement: { containerId: TaintTracker.arrayIdentity(expr), index: i },
                            },
                            this.metrics,
                        ),
                    ),
                );
            const instance = this.resolveValueInstance(element, state);
            this.recordBindingProperty(container, String(i), taints, instance, element);
            if (instance) container.elementInstances.set(String(i), instance);
            if (ts.isSpreadElement(element)) this.invalidateBindingMetadata(container);
        }
        this.expressionInstanceState.set(expr, container);
        return allTaints.length > 0 ? allTaints : undefined;
    }

    private findNestedShellCommandIndices(argv: ts.ArrayLiteralExpression): Set<number> {
        const call = argv.parent;
        if (!ts.isCallExpression(call) || call.arguments[1] !== argv || call.arguments[0] == null) {
            return new Set();
        }

        const binary = this.staticShellCommandPath(call.arguments[0]);
        if (binary == null || !/(^|\/)find$/.test(binary.toLowerCase())) {
            return new Set();
        }

        const indices = new Set<number>();
        for (let i = 0; i + 3 < argv.elements.length; i++) {
            const execFlag = this.staticStringText(argv.elements[i]);
            const shell = this.staticShellCommandPath(argv.elements[i + 1]);
            const shellFlag = this.staticStringText(argv.elements[i + 2]);
            if (
                (execFlag === "-exec" || execFlag === "-execdir") &&
                shell != null &&
                TaintTracker.SHELL_BINARIES.test(shell) &&
                shellFlag != null &&
                /^-[A-Za-z]*c[A-Za-z]*$/.test(shellFlag)
            ) {
                indices.add(i + 3);
            }
        }
        return indices;
    }

    private getSynchronousForEachCallback(
        expr: ts.CallExpression,
    ): ts.ArrowFunction | ts.FunctionExpression | undefined {
        if (!ts.isPropertyAccessExpression(expr.expression) || expr.expression.name.text !== "forEach") {
            return undefined;
        }

        const receiverType = this.checker.getNonNullableType(
            this.checker.getTypeAtLocation(expr.expression.expression),
        );
        if (!this.checker.isArrayType(receiverType) && !this.checker.isTupleType(receiverType)) {
            return undefined;
        }

        const callback = expr.arguments[0];
        return callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) ? callback : undefined;
    }

    private analyzeSynchronousForEachCallback(
        call: ts.CallExpression,
        callback: ts.ArrowFunction | ts.FunctionExpression,
        state: TaintState,
        receiverTaints: TaintValue[] | undefined,
    ): void {
        const receiver = (call.expression as ts.PropertyAccessExpression).expression;

        const callbackState: TaintState = new Map();
        const capturedAt = this.nodeLocation(callback);
        for (const [sym, taints] of state) {
            callbackState.set(
                sym,
                taints.map((taint) =>
                    propagate(
                        taint,
                        {
                            kind: "closure",
                            location: capturedAt,
                            description: `captured by enclosing ${
                                ts.isArrowFunction(callback) ? "arrow function" : "function expression"
                            }`,
                        },
                        this.metrics,
                    ),
                ),
            );
        }
        const initialCallbackState = new Map(callbackState);

        const elementParameter = callback.parameters[0]?.name;
        if (receiverTaints && elementParameter && ts.isIdentifier(elementParameter)) {
            const symbol = this.checker.getSymbolAtLocation(elementParameter);
            if (symbol) {
                callbackState.set(
                    symbol,
                    TaintTracker.taintsForDynamicProperty(receiverTaints).map((taint) =>
                        propagate(
                            taint,
                            {
                                kind: "arrayIndex",
                                location: this.nodeLocation(elementParameter),
                                description: `iterated element of ${receiver.getText()}`,
                            },
                            this.metrics,
                        ),
                    ),
                );
            }
        }

        const discardedReturnTaints: TaintValue[] = [];
        const discardedReturnInstances: InstanceState[] = [];
        if (ts.isBlock(callback.body)) {
            this.analyzeStatementList(
                callback.body.statements,
                callbackState,
                discardedReturnTaints,
                discardedReturnInstances,
            );
        } else {
            this.analyzeExpression(callback.body, callbackState);
        }

        for (const [symbol, taints] of callbackState) {
            if (initialCallbackState.get(symbol) === taints || this.isSymbolDeclaredWithin(symbol, callback)) {
                continue;
            }
            state.set(symbol, [...new Set([...(state.get(symbol) ?? []), ...taints])]);
        }
    }

    private isSymbolDeclaredWithin(symbol: ts.Symbol, node: ts.Node): boolean {
        return (
            symbol.declarations?.some(
                (declaration) =>
                    declaration.getSourceFile() === node.getSourceFile() &&
                    declaration.pos >= node.pos &&
                    declaration.end <= node.end,
            ) ?? false
        );
    }

    private assignElementInstance(
        target: ts.ElementAccessExpression,
        instance: InstanceState | undefined,
        taints?: readonly TaintValue[],
    ): void {
        const container = this.resolveInstance(target.expression);
        const key = this.elementKey(target.argumentExpression);
        if (!container) return;
        this.recordBindingProperty(container, key, taints, instance);
        if (this.hasHostType(container, "Array")) {
            const payload = this.hostValue(taints);
            if (key == null) this.storeHostValue(container, "$taint:*", payload);
            else container.elementInstances.set(`$taint:${key}`, payload);
        }
        if (key == null) return;

        if (instance) {
            container.elementInstances.set(key, instance);
        } else {
            container.elementInstances.delete(key);
        }
    }

    private assignmentReceiver(expression: ts.Expression): InstanceState | undefined {
        const known = this.resolveInstance(expression);
        if (known) return known;
        const symbol = this.resolveSymbol(expression);
        if (
            symbol?.getName() !== "Promise" ||
            !symbol.valueDeclaration?.getSourceFile().hasNoDefaultLib ||
            !this.interproc?.getModuleInstance
        )
            return undefined;
        // Allocate constructor state only for writes, not ordinary Promise calls.
        const instance = this.interproc.getModuleInstance(symbol, () => {
            const value = createInstanceState();
            value.apiTypes = ["PromiseConstructor"];
            return value;
        });
        this.instanceFieldState.set(symbol, instance);
        return instance;
    }

    private assignPropertyTaint(
        target: ts.PropertyAccessExpression,
        taints: TaintValue[] | undefined,
        state: TaintState,
        assignment: ts.Node,
    ): void {
        const directThisProperty = this.getThisPropertySymbol(target) || this.getThisAliasPropertySymbol(target);
        const receiver = this.assignmentReceiver(target.expression);
        const property = directThisProperty ?? (receiver ? this.resolveSymbol(target.name) : undefined);
        if (receiver) {
            const expression =
                ts.isBinaryExpression(assignment) && assignment.operatorToken.kind === ts.SyntaxKind.EqualsToken
                    ? assignment.right
                    : undefined;
            this.recordBindingProperty(
                receiver,
                target.name.text,
                taints,
                expression && this.resolveValueInstance(expression, state),
                expression,
            );
        }
        if (!property) {
            if (receiver) receiver.elementInstances.set(target.name.text, this.hostValue(taints));
            return;
        }

        if (!taints || taints.length === 0) {
            if (directThisProperty) state.delete(property);
            if (receiver) this.deleteInstanceField(receiver, property);
            return;
        }

        const stepped = taints.map((t) =>
            propagate(
                t,
                {
                    kind: "assignment",
                    location: this.nodeLocation(assignment),
                    description: `assigned to '${target.getText()}'`,
                },
                this.metrics,
            ),
        );
        if (directThisProperty) state.set(property, stepped);
        if (receiver) {
            this.deleteInstanceField(receiver, property);
            receiver.fields.set(property, stepped);
        }
    }

    private assignPropertyInstance(target: ts.PropertyAccessExpression, instance: InstanceState | undefined): void {
        const receiver = this.assignmentReceiver(target.expression);
        if (!receiver) return;

        const property = this.resolveSymbol(target.name);
        const slot = `${BINDING_PROPERTY}${target.name.text}`;
        const payload = receiver.elementInstances.get(slot);
        if (payload) {
            const value = { ...payload, elementInstances: new Map(payload.elementInstances) };
            if (instance) value.elementInstances.set("$value", instance);
            else value.elementInstances.delete("$value");
            receiver.elementInstances.set(slot, value);
        }
        if (!property) {
            if (instance) receiver.elementInstances.set(target.name.text, instance);
            return;
        }

        if (instance) {
            this.deleteInstanceReference(receiver, property);
            receiver.fieldInstances.set(property, instance);
        } else {
            this.deleteInstanceReference(receiver, property);
        }
    }

    /**
     * Like `resolveInstance`, but a reference to a declared function (an
     * argument such as `defaultProbe`) also yields a value, so the callee can
     * call it through its parameter.
     */
    private resolveValueInstance(expr: ts.Expression, state?: TaintState): InstanceState | undefined {
        const instance = this.resolveInstance(expr);
        if (instance) return instance;
        const unwrapped = unwrapExpression(expr);
        if (!ts.isIdentifier(unwrapped) && !ts.isPropertyAccessExpression(unwrapped)) {
            return undefined;
        }
        const declaration = resolveFunctionReference(this.checker, unwrapped);
        if (!declaration?.body) return undefined;
        return createFunctionInstance(this.captureDeclaredFunctionValue(declaration, state));
    }

    private captureDeclaredFunctionValue(declaration: ts.FunctionLikeDeclaration, state?: TaintState): FunctionValue {
        return {
            declaration,
            captured: new Map(
                functionFreeSymbols(this.checker, declaration).flatMap((symbol) => {
                    const taints = state?.get(symbol);
                    return taints ? [[symbol, taints] as [ts.Symbol, readonly TaintValue[]]] : [];
                }),
            ),
            capturedInstances: new Map(
                functionFreeSymbols(this.checker, declaration).flatMap((symbol) => {
                    const resolved =
                        symbol.flags & ts.SymbolFlags.Alias ? this.checker.getAliasedSymbol(symbol) : symbol;
                    const instance = this.instanceFieldState.get(resolved) ?? this.moduleHostInstance(resolved);
                    return instance ? [[resolved, instance] as [ts.Symbol, InstanceState]] : [];
                }),
            ),
        };
    }

    private moduleHostInstance(symbol: ts.Symbol): InstanceState | undefined {
        const resolved = symbol.flags & ts.SymbolFlags.Alias ? this.checker.getAliasedSymbol(symbol) : symbol;
        const known = this.interproc?.getModuleInstanceState?.().get(resolved) ?? this.instanceFieldState.get(resolved);
        if (known) return known;
        if (!this.interproc?.getModuleInstance) return undefined;
        const declaration = resolved.valueDeclaration;
        if (
            !declaration ||
            !ts.isVariableDeclaration(declaration) ||
            !declaration.initializer ||
            !ts.isVariableDeclarationList(declaration.parent) ||
            !(declaration.parent.flags & ts.NodeFlags.Const) ||
            !ts.isVariableStatement(declaration.parent.parent) ||
            !ts.isSourceFile(declaration.parent.parent.parent)
        )
            return undefined;
        const initializer = unwrapExpression(declaration.initializer);
        if (!ts.isNewExpression(initializer)) return undefined;
        const api = this.apiIdentity.importedName(initializer.expression);
        if (!["events", "events.EventEmitter", "stream.PassThrough"].includes(api ?? "")) return undefined;
        const instance = this.interproc.getModuleInstance(resolved, () => {
            const value = createInstanceState();
            value.apiTypes = [api === "events" ? "events.EventEmitter" : api!];
            return value;
        });
        this.instanceFieldState.set(resolved, instance);
        return instance;
    }

    private resolveInstance(expr: ts.Expression): InstanceState | undefined {
        const analyzed = this.expressionInstanceState.get(expr);
        if (analyzed) return analyzed;
        const unwrapped = unwrapExpression(expr);
        if (unwrapped !== expr) {
            return this.resolveInstance(unwrapped);
        }
        if (ts.isAwaitExpression(expr)) {
            const instance = this.resolveInstance(expr.expression);
            return this.hasHostType(instance, "Promise")
                ? instance!.elementInstances.get("$fulfilled")?.elementInstances.get("$value")
                : instance;
        }
        if (expr.kind === ts.SyntaxKind.ThisKeyword) {
            return this.currentThisInstance;
        }
        if (ts.isIdentifier(expr)) {
            const sym = this.resolveSymbol(expr);
            return sym
                ? (this.interproc?.getModuleInstanceState?.().get(sym) ??
                      this.instanceFieldState.get(sym) ??
                      this.moduleHostInstance(sym))
                : undefined;
        }
        if (ts.isPropertyAccessExpression(expr)) {
            const receiver = this.resolveInstance(expr.expression);
            const property = this.resolveSymbol(expr.name);
            return (
                receiver?.elementInstances.get(expr.name.text) ??
                (receiver && property ? this.getInstanceReference(receiver, property) : undefined)
            );
        }
        if (ts.isElementAccessExpression(expr)) {
            const container = this.resolveInstance(expr.expression);
            if (!container) return undefined;
            const key = this.elementKey(expr.argumentExpression);
            return this.getElementInstance(container, key);
        }
        return undefined;
    }

    private static readonly UNKNOWN_ELEMENT = "*";

    private elementKey(expr: ts.Expression): string | undefined {
        const value = unwrapExpression(expr);
        if (ts.isStringLiteralLike(value) || ts.isNumericLiteral(value)) {
            return value.text;
        }
        return undefined;
    }

    private arrayElementTaints(
        container: InstanceState,
        key: string | undefined,
        fallback?: readonly TaintValue[],
    ): TaintValue[] | undefined {
        if (container.taintedElementsFromIndex != null) {
            if (key != null && (!/^\d+$/.test(key) || Number(key) < container.taintedElementsFromIndex)) return [];
            return container.valueTaints?.slice();
        }
        const payloads =
            key == null
                ? [...container.elementInstances]
                      .filter(([name]) => name.startsWith("$taint:"))
                      .map(([, value]) => value)
                : [container.elementInstances.get(`$taint:${key}`), container.elementInstances.get("$taint:*")].filter(
                      (value): value is InstanceState => value != null,
                  );
        return payloads.length ? payloads.flatMap((value) => value.valueTaints ?? []) : fallback?.slice();
    }

    private getElementInstance(container: InstanceState, key?: string): InstanceState | undefined {
        const candidates =
            key == null
                ? [...container.elementInstances].filter(([key]) => !key.startsWith("$")).map(([, value]) => value)
                : [
                      container.elementInstances.get(key),
                      container.elementInstances.get(`${BINDING_PROPERTY}${key}`)?.elementInstances.get("$value"),
                      ...[...container.fieldInstances]
                          .filter(([property]) => property.getName() === key)
                          .map(([, value]) => value),
                      container.elementInstances.get(TaintTracker.UNKNOWN_ELEMENT),
                  ].filter((value): value is InstanceState => value != null);
        return mergeInstanceStates(candidates);
    }

    private resolveSymbol(node: ts.Node): ts.Symbol | undefined {
        const sym = this.checker.getSymbolAtLocation(node);
        if (!sym) return undefined;
        return sym.flags & ts.SymbolFlags.Alias ? this.checker.getAliasedSymbol(sym) : sym;
    }

    private getThisPropertySymbol(expr: ts.PropertyAccessExpression): ts.Symbol | undefined {
        if (expr.expression.kind !== ts.SyntaxKind.ThisKeyword) return undefined;

        const sym = this.checker.getSymbolAtLocation(expr.name);
        if (!sym) return undefined;

        if (sym.flags & ts.SymbolFlags.Alias) {
            return this.checker.getAliasedSymbol(sym);
        }
        return sym;
    }

    /**
     * Detect `self.field` where `self` is a known alias for `this`.
     * Returns the property symbol for the field if the receiver is a this-alias.
     */
    private getThisAliasPropertySymbol(expr: ts.PropertyAccessExpression): ts.Symbol | undefined {
        if (!ts.isIdentifier(expr.expression)) return undefined;

        const receiverSym = this.checker.getSymbolAtLocation(expr.expression);
        if (!receiverSym || !this.thisAliases.has(receiverSym)) return undefined;

        const propSym = this.checker.getSymbolAtLocation(expr.name);
        if (!propSym) return undefined;

        if (propSym.flags & ts.SymbolFlags.Alias) {
            return this.checker.getAliasedSymbol(propSym);
        }
        return propSym;
    }

    /**
     * Look up per-instance field taint for `receiver.field` expressions.
     * Returns field taints if the receiver variable has bound instance state.
     */
    private getInstanceFieldTaint(expr: ts.PropertyAccessExpression): TaintValue[] | undefined {
        const instance = this.resolveInstance(expr.expression);
        const property = this.resolveSymbol(expr.name);
        return instance && property ? this.getInstanceField(instance, property) : undefined;
    }

    private getInstanceField(instance: InstanceState, property: ts.Symbol): TaintValue[] | undefined {
        const exact = instance.fields.get(property);
        if (exact) return exact.slice();
        for (const [candidate, taints] of instance.fields) {
            if (candidate.getName() === property.getName()) return taints.slice();
        }
        return undefined;
    }

    private getInstanceReference(instance: InstanceState, property: ts.Symbol): InstanceState | undefined {
        const exact = instance.fieldInstances.get(property);
        if (exact) return exact;
        for (const [candidate, fieldInstance] of instance.fieldInstances) {
            if (candidate.getName() === property.getName()) return fieldInstance;
        }
        return undefined;
    }

    private deleteInstanceField(instance: InstanceState, property: ts.Symbol): void {
        for (const candidate of instance.fields.keys()) {
            if (candidate === property || candidate.getName() === property.getName()) {
                instance.fields.delete(candidate);
            }
        }
    }

    private deleteInstanceReference(instance: InstanceState, property: ts.Symbol): void {
        for (const candidate of instance.fieldInstances.keys()) {
            if (candidate === property || candidate.getName() === property.getName()) {
                instance.fieldInstances.delete(candidate);
            }
        }
    }

    // --- Source checking ---

    /** A selection is bounded only while its literal values have not escaped or mutated. */
    private isKnownSelectionValue(expr: ts.Expression, use: ts.CallExpression, seen = new Set<ts.Symbol>()): boolean {
        const value = unwrapExpression(expr);
        if (
            ts.isStringLiteralLike(value) ||
            ts.isNumericLiteral(value) ||
            value.kind === ts.SyntaxKind.TrueKeyword ||
            value.kind === ts.SyntaxKind.FalseKeyword ||
            value.kind === ts.SyntaxKind.NullKeyword
        )
            return true;
        if (ts.isArrayLiteralExpression(value)) {
            return value.elements.every(
                (element) => !ts.isSpreadElement(element) && this.isKnownSelectionValue(element, use, new Set(seen)),
            );
        }
        if (ts.isObjectLiteralExpression(value)) {
            return value.properties.every(
                (property) =>
                    ts.isPropertyAssignment(property) &&
                    this.propertyName(property.name) != null &&
                    this.isKnownSelectionValue(property.initializer, use, new Set(seen)),
            );
        }
        if (!ts.isIdentifier(value)) return false;
        const symbol = this.checker.getSymbolAtLocation(value);
        if (!symbol || seen.has(symbol)) return false;
        const declaration = symbol.valueDeclaration;
        if (
            !declaration ||
            !ts.isVariableDeclaration(declaration) ||
            !declaration.initializer ||
            !ts.isVariableDeclarationList(declaration.parent) ||
            (declaration.parent.flags & ts.NodeFlags.Const) === 0 ||
            this.selectionValueEscapesBefore(symbol, use)
        )
            return false;
        seen.add(symbol);
        return this.isKnownSelectionValue(declaration.initializer, use, seen);
    }

    private static readonly selectionEscapes = new WeakMap<ts.CallExpression, Map<ts.Symbol, boolean>>();

    private selectionValueEscapesBefore(symbol: ts.Symbol, use: ts.CallExpression): boolean {
        let bySymbol = TaintTracker.selectionEscapes.get(use);
        if (!bySymbol) {
            bySymbol = new Map();
            TaintTracker.selectionEscapes.set(use, bySymbol);
        }
        const cached = bySymbol.get(symbol);
        if (cached != null) return cached;
        const escaped = this.computeSelectionValueEscape(symbol, use);
        bySymbol.set(symbol, escaped);
        return escaped;
    }

    private computeSelectionValueEscape(symbol: ts.Symbol, use: ts.CallExpression): boolean {
        const nodes: ts.Node[] = [];
        const useStart = use.getStart();
        const pending = [{ node: use.getSourceFile() as ts.Node, nestedFunction: false }];
        while (pending.length) {
            const current = pending.pop()!;
            const node = current.node;
            const nestedFunction =
                current.nestedFunction || (ts.isFunctionLike(node) && !(node.pos <= useStart && node.end >= use.end));
            if (node.pos < useStart || nestedFunction) nodes.push(node);
            node.forEachChild((child) => {
                pending.push({ node: child, nestedFunction });
            });
        }
        const aliases = new Set([symbol]);
        const rootSymbol = (expr: ts.Expression): ts.Symbol | undefined => {
            let root = unwrapExpression(expr);
            while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) {
                root = unwrapExpression(root.expression);
            }
            return ts.isIdentifier(root) ? this.checker.getSymbolAtLocation(root) : undefined;
        };
        let changed = true;
        while (changed) {
            changed = false;
            for (const node of nodes) {
                if (!ts.isVariableDeclaration(node) || !node.initializer || !ts.isIdentifier(node.name)) continue;
                const target = this.checker.getSymbolAtLocation(node.name);
                const initializer = unwrapExpression(node.initializer);
                if (
                    target &&
                    !aliases.has(target) &&
                    ts.isIdentifier(initializer) &&
                    aliases.has(rootSymbol(initializer)!)
                ) {
                    aliases.add(target);
                    changed = true;
                }
            }
        }
        for (const node of nodes) {
            if (node === use) continue;
            if (
                ts.isBinaryExpression(node) &&
                node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
                node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
                (aliases.has(rootSymbol(node.left)!) || aliases.has(rootSymbol(node.right)!))
            )
                return true;
            if (
                ts.isVariableDeclaration(node) &&
                node.initializer &&
                !ts.isIdentifier(unwrapExpression(node.initializer)) &&
                aliases.has(rootSymbol(node.initializer)!)
            )
                return true;
            if (ts.isPropertyAssignment(node) && aliases.has(rootSymbol(node.initializer)!)) return true;
            if (
                ts.isShorthandPropertyAssignment(node) &&
                aliases.has(this.checker.getShorthandAssignmentValueSymbol(node)!)
            )
                return true;
            if (ts.isArrayLiteralExpression(node) && node.elements.some((element) => aliases.has(rootSymbol(element)!)))
                return true;
            if (ts.isReturnStatement(node) && node.expression && aliases.has(rootSymbol(node.expression)!)) return true;
            if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
                if (
                    (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) &&
                    aliases.has(rootSymbol(node.expression.expression)!)
                )
                    return true;
                if (node.arguments?.some((argument) => aliases.has(rootSymbol(argument)!))) return true;
            }
        }
        return false;
    }

    private checkPropertySource(
        expr: ts.PropertyAccessExpression | ts.ElementAccessExpression,
    ): TaintValue | undefined {
        const fullName = this.apiIdentity.accessName(expr);
        for (const source of this.spec.sources) {
            // This path handles property-value sources such as
            // `vscode.TextDocument.fileName`.
            // Call-return sources may have property-access-shaped callees
            // (`vscode.window.showInputBox`) but must only taint the enclosing
            // call expression's return value, so they are handled in
            // checkCallSource().
            if (source.kind === "propertyAccess") {
                if (source.requireAPIIdentity) {
                    if (
                        this.matchesModelAPI(expr, source.pattern) ||
                        (source.resolvedPattern && this.matchesModelAPI(expr, source.resolvedPattern))
                    ) {
                        return createTaint(source, this.nodeLocation(expr), this.metrics);
                    }
                    continue;
                }
                if (
                    this.matchesPatternWithExpr(
                        expr,
                        fullName,
                        source.resolvedPattern ?? source.pattern,
                        `source.${source.kind}.propertyAccessCheck`,
                        !(source.resolvedPattern ?? source.pattern).includes("*"),
                    ) ||
                    (source.resolvedPattern != null &&
                        this.apiIdentity.hasExternalRoot(expr) &&
                        this.matchesPatternWithExpr(
                            expr,
                            fullName,
                            source.pattern,
                            `source.${source.kind}.propertyAccessFallback`,
                            !source.pattern.includes("*"),
                        ))
                ) {
                    return createTaint(source, this.nodeLocation(expr), this.metrics);
                }
            }
        }
        return undefined;
    }

    private isPromiseReturningCall(expr: ts.CallExpression): boolean {
        const isNativePromise = (type: ts.Type): boolean => {
            const members = type.isUnion() ? type.types : [type];
            return members.every(
                (member) =>
                    member.getSymbol()?.getName() === "Promise" &&
                    member
                        .getSymbol()
                        ?.declarations?.some((declaration) => declaration.getSourceFile().hasNoDefaultLib),
            );
        };
        const raw = this.apiIdentity.rawImportedName(expr.expression)?.replace(/^node:/, "");
        const modeledFilePromise =
            raw === "fs-extra.readFile" ||
            raw?.startsWith("fs/promises.") ||
            raw?.startsWith("fs.promises.") ||
            raw?.startsWith("fs-extra.promises.");
        if (!modeledFilePromise) {
            return (
                this.promisifiedFunction(expr.expression) != null ||
                isNativePromise(this.checker.getTypeAtLocation(expr))
            );
        }
        // A captured replacement is a callable value, not the imported API that
        // originally occupied this property. Its own declaration decides whether
        // a result is a Promise; boxing a synchronous result hides scalar taint.
        const declarationReturnsPromise = (declaration: ts.FunctionLikeDeclaration): boolean => {
            if ((ts.getCombinedModifierFlags(declaration) & ts.ModifierFlags.Async) !== 0) return true;
            const signature = this.checker.getSignatureFromDeclaration(declaration);
            return signature != null && isNativePromise(this.checker.getReturnTypeOfSignature(signature));
        };
        const functions = this.resolveInstance(expr.expression)?.functions;
        if (functions?.length) return functions.every(({ declaration }) => declarationReturnsPromise(declaration));
        // Unmodeled imported objects may have no instance state. The static
        // value snapshot still records direct replacements and const captures.
        const captured = this.apiIdentity.registrationReceiver(expr.expression);
        const capturedDeclaration = "kind" in captured ? captured : captured.valueDeclaration;
        if (
            capturedDeclaration &&
            (ts.isArrowFunction(capturedDeclaration) ||
                ts.isFunctionExpression(capturedDeclaration) ||
                ts.isFunctionDeclaration(capturedDeclaration) ||
                ts.isMethodDeclaration(capturedDeclaration)) &&
            capturedDeclaration.body
        ) {
            return declarationReturnsPromise(capturedDeclaration);
        }
        const callee = unwrapExpression(expr.expression);
        const member = ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee);
        const name = ts.isPropertyAccessExpression(callee)
            ? callee.name.text
            : ts.isElementAccessExpression(callee) && ts.isStringLiteralLike(callee.argumentExpression)
              ? callee.argumentExpression.text
              : undefined;
        const receiver = member ? this.resolveInstance(callee.expression) : undefined;
        if (name != null && receiver?.elementInstances.has(name)) return false;
        if (
            raw?.startsWith("fs/promises.") ||
            raw?.startsWith("fs.promises.") ||
            raw?.startsWith("fs-extra.promises.") ||
            this.promisifiedFunction(expr.expression)
        )
            return true;
        if (raw === "fs-extra.readFile") {
            if (expr.arguments.some(ts.isSpreadElement)) return false;
            // fs-extra's universalify wrapper returns void with a callback and
            // a Promise without one. Missing declarations must not erase this
            // contract, or make an opaque second argument a proven options value.
            const knownOptions = (argument: ts.Expression, seen = new Set<ts.Symbol>()): boolean => {
                const value = unwrapExpression(argument);
                if (
                    ts.isStringLiteralLike(value) ||
                    ts.isObjectLiteralExpression(value) ||
                    value.kind === ts.SyntaxKind.NullKeyword
                )
                    return true;
                if (ts.isIdentifier(value)) {
                    const symbol = this.checker.getSymbolAtLocation(value);
                    if (symbol && !seen.has(symbol)) {
                        seen.add(symbol);
                        const declaration = symbol.valueDeclaration;
                        if (
                            declaration &&
                            ts.isVariableDeclaration(declaration) &&
                            declaration.initializer &&
                            ts.isVariableDeclarationList(declaration.parent) &&
                            (declaration.parent.flags & ts.NodeFlags.Const) !== 0 &&
                            knownOptions(declaration.initializer, seen)
                        )
                            return true;
                    }
                }
                const type = this.checker.getTypeAtLocation(value);
                const members = type.isUnion() ? type.types : [type];
                return members.every(
                    (member) =>
                        (member.flags & (ts.TypeFlags.StringLike | ts.TypeFlags.Null | ts.TypeFlags.Undefined)) !== 0,
                );
            };
            return expr.arguments.length === 1 || (expr.arguments.length === 2 && knownOptions(expr.arguments[1]));
        }
        return isNativePromise(this.checker.getTypeAtLocation(expr));
    }

    private checkCallSource(
        expr: ts.CallExpression,
        argTaints: (TaintValue[] | undefined)[],
    ): { taints: TaintValue[] | undefined } | undefined {
        const callName = getCallChainName(expr.expression);
        for (const source of this.spec.sources) {
            // Call-return sources taint the value produced by invoking the
            // callee, not a plain read of the callee access path.
            // Command output joins the call's passthrough instead; see
            // workspaceCommandOutput().
            if (source.kind === "callReturnValue" && !source.workspaceCwdOptionIndices) {
                if (source.callReturnKind === "promise" && !this.isPromiseReturningCall(expr)) continue;
                const callee = this.promisifiedFunction(expr.expression) ?? expr.expression;
                if (
                    source.requireAPIIdentity
                        ? this.matchesModelAPI(callee, source.pattern)
                        : this.matchesPatternWithExpr(callee, callName, source.pattern, "source.callReturnValue")
                ) {
                    const selection = source.selectionFromArgIndex;
                    if (selection != null) {
                        const inputTaints = argTaints[selection];
                        if (inputTaints?.length) {
                            const array = this.resolveArrayLiteral(expr.arguments[selection]);
                            const objectChoices = array?.elements.some(ts.isObjectLiteralExpression);
                            return {
                                taints: inputTaints.map((taint) => {
                                    const property =
                                        objectChoices && taint.aggregatePropertyPath == null
                                            ? TaintTracker.enclosingObjectProperty(taint)
                                            : undefined;
                                    const selected =
                                        property == null
                                            ? taint
                                            : TaintTracker.prependAggregateProperty([taint], property)[0];
                                    return propagate(
                                        selected,
                                        {
                                            kind: "return",
                                            location: this.nodeLocation(expr),
                                            description: `selected from argument ${selection} of ${callName}()`,
                                        },
                                        this.metrics,
                                    );
                                }),
                            };
                        }
                        const choices = expr.arguments[selection];
                        if (choices && this.isKnownSelectionValue(choices, expr)) {
                            return { taints: undefined };
                        }
                    }
                    const taint = createTaint(source, this.nodeLocation(expr), this.metrics);
                    const settingKey = source.settingScopeDescriptions && this.settingKey(expr);
                    return { taints: [settingKey ? { ...taint, settingPath: [settingKey] } : taint] };
                }
            }
        }
        return undefined;
    }

    /**
     * The full key a `config.get(key)` call reads, where `config` is
     * `getConfiguration(section)` or a const bound to one, or undefined when
     * the section or key is not a static string.
     */
    private settingKey(call: ts.CallExpression): string | undefined {
        const key = call.arguments[0] && resolveStaticString(this.checker, call.arguments[0]);
        if (key == null || !ts.isPropertyAccessExpression(call.expression)) return undefined;
        let receiver = unwrapExpression(call.expression.expression);
        const seen = new Set<ts.Symbol>();
        while (ts.isIdentifier(receiver)) {
            const symbol = this.resolveSymbol(receiver);
            const declaration = symbol?.valueDeclaration;
            if (
                symbol == null ||
                seen.has(symbol) ||
                declaration == null ||
                !ts.isVariableDeclaration(declaration) ||
                declaration.initializer == null ||
                (ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.Const) === 0
            )
                return undefined;
            seen.add(symbol);
            receiver = unwrapExpression(declaration.initializer);
        }
        if (!ts.isCallExpression(receiver) || !getCallChainName(receiver.expression).endsWith("getConfiguration")) {
            return undefined;
        }
        const sectionArg = receiver.arguments[0];
        const section =
            sectionArg == null ||
            sectionArg.kind === ts.SyntaxKind.NullKeyword ||
            (ts.isIdentifier(sectionArg) && sectionArg.text === "undefined")
                ? ""
                : resolveStaticString(this.checker, sectionArg);
        if (section == null) return undefined;
        return section === "" ? key : `${section}.${key}`;
    }

    /**
     * Taints for the output of a command run in the workspace. They add to the
     * call's passthrough, so the command's own provenance still reaches the
     * output.
     */
    private workspaceCommandOutput(expr: ts.CallExpression): TaintValue[] {
        const taints: TaintValue[] = [];
        if (expr.arguments.length < 2) return taints;
        let promisified: ts.Expression | undefined | null = null;
        for (const source of this.spec.sources) {
            if (source.kind !== "callReturnValue" || !source.workspaceCwdOptionIndices) continue;
            if (source.promisified) promisified ??= this.promisifiedFunction(expr.expression);
            const callee = source.promisified ? promisified : expr.expression;
            if (
                callee &&
                this.matchesPatternWithExpr(
                    callee,
                    getCallChainName(callee),
                    source.pattern,
                    "source.callReturnValue",
                ) &&
                this.runsInWorkspace(expr, source.workspaceCwdOptionIndices)
            ) {
                taints.push(createTaint(source, this.nodeLocation(expr), this.metrics));
            }
        }
        return taints;
    }

    /** Whether the options object at one of `indices` sets `cwd` to a workspace location. */
    private runsInWorkspace(expr: ts.CallExpression, indices: readonly number[]): boolean {
        return indices.some((index) => {
            const options =
                index < expr.arguments.length ? this.resolveObjectLiteral(expr.arguments[index]) : undefined;
            for (const property of options?.properties ?? []) {
                if (ts.isPropertyAssignment(property) && property.name.getText() === "cwd") {
                    return this.isWorkspaceLocation(property.initializer);
                }
                if (ts.isShorthandPropertyAssignment(property) && property.name.text === "cwd") {
                    const declaration = this.checker.getShorthandAssignmentValueSymbol(property)?.valueDeclaration;
                    return (
                        declaration != null &&
                        ts.isVariableDeclaration(declaration) &&
                        declaration.initializer != null &&
                        this.isWorkspaceLocation(declaration.initializer)
                    );
                }
            }
            return false;
        });
    }

    private static readonly WORKSPACE_LOCATIONS = [
        "vscode.workspace.workspaceFolders",
        "vscode.workspace.rootPath",
        "vscode.workspace.getWorkspaceFolder",
        "vscode.WorkspaceFolder.uri",
        "vscode.TextDocument.uri",
        "vscode.TextDocument.fileName",
    ];

    /**
     * Whether `expr` is a path under a workspace folder or an open document's
     * location. Follows variable initializers, the returns of called helpers,
     * and the arguments of library calls such as `path.join`. Values stored in
     * fields are not followed.
     */
    private isWorkspaceLocation(expr: ts.Expression, depth = 0, seen = new Set<ts.Node>()): boolean {
        const value = unwrapExpression(expr);
        if (depth > 3 || seen.has(value)) return false;
        seen.add(value);
        if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
            const name = this.apiIdentity.accessName(value);
            return (
                TaintTracker.WORKSPACE_LOCATIONS.some((pattern) =>
                    this.matchesPatternWithExpr(value, name, pattern, "source.workspaceLocation", true),
                ) || this.isWorkspaceLocation(value.expression, depth, seen)
            );
        }
        if (ts.isIdentifier(value)) {
            const declaration = this.resolveSymbol(value)?.valueDeclaration;
            return (
                declaration != null &&
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer != null &&
                this.isWorkspaceLocation(declaration.initializer, depth, seen)
            );
        }
        if (ts.isCallExpression(value)) {
            if (this.isWorkspaceLocation(value.expression, depth, seen)) return true;
            const callee = resolveFunctionReference(this.checker, value.expression);
            if (!callee?.body)
                return value.arguments.some((argument) => this.isWorkspaceLocation(argument, depth, seen));
            if (!ts.isBlock(callee.body)) return this.isWorkspaceLocation(callee.body, depth + 1, seen);
            const pending: ts.Node[] = [callee.body];
            while (pending.length > 0) {
                const node = pending.pop()!;
                if (
                    ts.isReturnStatement(node) &&
                    node.expression &&
                    this.isWorkspaceLocation(node.expression, depth + 1, seen)
                )
                    return true;
                if (!ts.isFunctionLike(node))
                    node.forEachChild((child) => {
                        pending.push(child);
                    });
            }
            return false;
        }
        if (ts.isConditionalExpression(value)) {
            return (
                this.isWorkspaceLocation(value.whenTrue, depth, seen) ||
                this.isWorkspaceLocation(value.whenFalse, depth, seen)
            );
        }
        if (ts.isBinaryExpression(value)) {
            return (
                this.isWorkspaceLocation(value.left, depth, seen) || this.isWorkspaceLocation(value.right, depth, seen)
            );
        }
        if (ts.isTemplateExpression(value)) {
            return value.templateSpans.some((span) => this.isWorkspaceLocation(span.expression, depth, seen));
        }
        return false;
    }

    // --- Sink checking ---

    private sinkArguments(
        sink: SinkSpec,
        args: readonly ts.Expression[],
        taints: (TaintValue[] | undefined)[],
    ): { args: readonly ts.Expression[]; taints: (TaintValue[] | undefined)[]; unknownSpreadIndex: number } {
        if (!sink.argPositionsByArity || !args.some(ts.isSpreadElement)) {
            return { args, taints, unknownSpreadIndex: -1 };
        }
        const expanded = expandCallArguments(args, taints);
        return {
            args: expanded.map((argument) => argument.expression),
            taints: expanded.map((argument) => argument.taints),
            unknownSpreadIndex: expanded.findIndex((argument) => argument.unknownSpread),
        };
    }

    private sinkArgumentPositions(sink: SinkSpec, args: readonly ts.Expression[], unknownSpreadIndex = -1): number[] {
        if (sink.allArguments) return Array.from({ length: args.length }, (_, index) => index);
        if (unknownSpreadIndex >= 0 && sink.argPositionsByArity) {
            // Unknown spreads can shift the remaining arguments into any overload.
            const candidates = [...(sink.argPositions ?? [0]), ...Object.values(sink.argPositionsByArity).flat()];
            return args.flatMap((_, index) =>
                (
                    index < unknownSpreadIndex
                        ? candidates.includes(index)
                        : candidates.some((position) => position >= unknownSpreadIndex)
                )
                    ? [index]
                    : [],
            );
        }
        const positions = sink.argPositionsByArity?.[args.length] ?? sink.argPositions ?? [0];
        if (!sink.firstNonStringArgPosition) return positions;
        const position = positions.find(
            (index) =>
                index < args.length &&
                (this.checker.getNonNullableType(this.checker.getTypeAtLocation(args[index])).flags &
                    ts.TypeFlags.StringLike) ===
                    0,
        );
        return position == null ? [] : [position];
    }

    private isGlobalBuiltin(expr: ts.Expression, seen = new Set<ts.Symbol>()): boolean {
        const value = unwrapExpression(expr);
        const symbol = this.checker.getSymbolAtLocation(value);
        if (!symbol || seen.has(symbol)) return false;
        seen.add(symbol);
        if (symbol.declarations?.some((decl) => decl.getSourceFile().hasNoDefaultLib)) return true;
        const declaration = symbol.valueDeclaration;
        return (
            declaration != null &&
            ts.isVariableDeclaration(declaration) &&
            declaration.initializer != null &&
            this.isGlobalBuiltin(declaration.initializer, seen)
        );
    }

    /**
     * The function wrapped by `util.promisify`, for a callee such as
     * `promisify(exec)` or a const bound to it in any module. Assume the usual
     * trailing-callback convention and reuse the wrapped function's sink
     * positions; custom promisify implementations are not modeled.
     */
    private promisifiedFunction(callee: ts.Expression, seen = new Set<ts.Symbol>()): ts.Expression | undefined {
        const value = unwrapExpression(callee);
        if (ts.isCallExpression(value)) {
            return value.arguments.length === 1 &&
                this.matchesPatternWithExpr(
                    value.expression,
                    getCallChainName(value.expression),
                    "util.promisify",
                    "sink.promisify",
                )
                ? value.arguments[0]
                : undefined;
        }
        if (!ts.isIdentifier(value)) return undefined;
        let symbol = this.checker.getSymbolAtLocation(value);
        if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = this.checker.getAliasedSymbol(symbol);
        const declaration = symbol?.valueDeclaration;
        if (
            !symbol ||
            seen.has(symbol) ||
            declaration == null ||
            !ts.isVariableDeclaration(declaration) ||
            declaration.initializer == null ||
            (ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.Const) === 0
        )
            return undefined;
        seen.add(symbol);
        return this.promisifiedFunction(declaration.initializer, seen);
    }

    private checkAxiosDefaults(expr: ts.CallExpression): void {
        const callee = unwrapExpression(expr.expression);
        const method = ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
        const instance = this.resolveInstance(ts.isPropertyAccessExpression(callee) ? callee.expression : callee);
        if (!this.hasHostType(instance, "axios")) return;
        const index = axiosRequestConfigIndex(method, expr.arguments);
        if (index == null) return;
        const identityContext = this.modelAPIContext(callee);
        const sinks = this.spec.sinks.filter(
            (sink) => sink.objectProperties && this.matchesModelAPI(callee, sink.pattern, identityContext),
        );
        const sink = sinks.find((candidate) => candidate.argPositions?.includes(index)) ?? sinks[0];
        if (!sink) return;
        for (const taint of axiosInheritedDestinationTaints(instance!, expr.arguments[index], this.checker)) {
            this.reportFinding(taint, sink, expr);
        }
    }

    private checkSink(expr: ts.CallExpression, argTaints: (TaintValue[] | undefined)[]): void {
        if (expr.expression.kind === ts.SyntaxKind.SuperKeyword) {
            const base = superClassExpression(expr);
            if (base != null) this.checkConstructionSink(expr, base, argTaints);
            return;
        }
        const promisified = this.promisifiedFunction(expr.expression);
        const callee = promisified ?? expr.expression;
        const callName = getCallChainName(callee);
        let identityContext: ModelAPIContext | undefined;

        for (const sink of this.spec.sinks) {
            if (sink.kind !== "callArgument") continue;
            identityContext ??= this.modelAPIContext(callee);
            const matches = sink.requireAPIIdentity
                ? this.matchesModelAPI(callee, sink.pattern, identityContext)
                : this.matchesInstanceAPI(callee, sink.pattern, identityContext) ||
                  this.matchesPatternWithExpr(
                      callee,
                      callName,
                      sink.pattern,
                      "sink.callArgument",
                      sink.globalBuiltin === true,
                  );
            if (!matches) continue;

            if (sink.globalBuiltin && !this.isGlobalBuiltin(callee)) continue;
            const { args, taints, unknownSpreadIndex } = this.sinkArguments(sink, expr.arguments, argTaints);
            if (!this.hasArgumentValues(sink, args)) continue;
            const descriptor = sink.pathOverriddenByFileDescriptor;
            if (descriptor && hasKnownFileDescriptor(args[descriptor.argument], descriptor.property, this.checker))
                continue;
            const positions = this.sinkArgumentPositions(sink, args, unknownSpreadIndex);
            // Executable argv operands and shell-enabled arguments carry code.
            for (const pos of positions) {
                if (pos < taints.length && taints[pos]) {
                    if (!this.sinkAcceptsArgument(sink, pos, args[pos])) {
                        continue;
                    }
                    for (const taint of taints[pos]!) {
                        if (!TaintTracker.sinkAcceptsTaint(sink, taint)) continue;
                        const directShellInvocation =
                            sink.categories.includes("arg_injection") &&
                            (this.isShellInvocation(expr, taint) || this.sinkOptionsEnableShell(sink, taint));
                        const nestedShellInvocation =
                            sink.categories.includes("arg_injection") && taint.nestedShellCommandLocation != null;
                        const effectiveSink =
                            directShellInvocation || nestedShellInvocation
                                ? {
                                      ...sink,
                                      severity: "critical" as const,
                                      categories: ["rce" as const],
                                      description: nestedShellInvocation
                                          ? `${sink.description} — argv contains a find -exec shell command, so this is command execution`
                                          : `${sink.description} — taint reaches an executable operand or shell:true enables command interpretation`,
                                  }
                                : sink;
                        this.reportFinding(
                            taint,
                            effectiveSink,
                            expr,
                            nestedShellInvocation ? taint.nestedShellCommandLocation : undefined,
                            promisified != null,
                        );
                    }
                }
            }
        }
    }

    /** Flow-sensitive identity is reusable within one rule-check loop, never across calls or mutations. */
    private modelAPIContext(callee: ts.Expression): ModelAPIContext {
        const value = unwrapExpression(callee);
        const member = ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value);
        const name = ts.isPropertyAccessExpression(value)
            ? value.name.text
            : ts.isElementAccessExpression(value) && ts.isStringLiteralLike(value.argumentExpression)
              ? value.argumentExpression.text
              : undefined;
        const receiver = member ? this.resolveInstance(value.expression) : undefined;
        const instance = this.resolveInstance(callee);
        return {
            overridden:
                ts.isPropertyAccessExpression(value) &&
                (receiver?.elementInstances.has(value.name.text) === true || (instance?.functions.length ?? 0) > 0),
            calleeNames: instance?.apiTypes ?? [],
            memberNames: name == null ? [] : (receiver?.apiTypes ?? []).map((apiType) => `${apiType}.${name}`),
        };
    }

    private matchesModelAPI(callee: ts.Expression, pattern: string, context = this.modelAPIContext(callee)): boolean {
        return (
            !context.overridden &&
            (context.calleeNames.includes(pattern) ||
                context.memberNames.includes(pattern) ||
                this.apiIdentity.matchesAPI(callee, pattern))
        );
    }

    private matchesInstanceAPI(
        callee: ts.Expression,
        pattern: string,
        context = this.modelAPIContext(callee),
    ): boolean {
        return context.memberNames.includes(pattern);
    }

    /**
     * Sinks on a constructor: `new C(...)`, or `super(...)` in a subclass
     * constructor, which passes its arguments to the base class constructor.
     */
    private checkConstructionSink(
        expr: ts.NewExpression | ts.CallExpression,
        constructor: ts.Expression,
        argTaints: (TaintValue[] | undefined)[],
    ): void {
        const name = getCallChainName(constructor);
        let identityContext: ModelAPIContext | undefined;

        for (const sink of this.spec.sinks) {
            if (sink.kind !== "callArgument") continue;
            if (
                !(sink.requireAPIIdentity
                    ? this.matchesModelAPI(
                          constructor,
                          sink.pattern,
                          (identityContext ??= this.modelAPIContext(constructor)),
                      )
                    : this.matchesPatternWithExpr(
                          constructor,
                          name,
                          sink.pattern,
                          "sink.newExpression",
                          !sink.pattern.includes("*"),
                      ))
            )
                continue;
            if (sink.globalBuiltin && !this.isGlobalBuiltin(constructor)) continue;
            const { args, taints, unknownSpreadIndex } = this.sinkArguments(sink, expr.arguments ?? [], argTaints);
            if (!this.hasArgumentValues(sink, args)) continue;

            const positions = this.sinkArgumentPositions(sink, args, unknownSpreadIndex);
            for (const pos of positions) {
                if (pos < taints.length && taints[pos]) {
                    if (!this.sinkAcceptsArgument(sink, pos, args[pos])) continue;
                    for (const taint of taints[pos]!) {
                        if (!TaintTracker.sinkAcceptsTaint(sink, taint)) continue;
                        const effectiveSink =
                            sink.categories.includes("arg_injection") && this.sinkOptionsEnableShell(sink, taint)
                                ? {
                                      ...sink,
                                      severity: "critical" as const,
                                      categories: ["rce" as const],
                                      description: `${sink.description} — shell:true enables command interpretation`,
                                  }
                                : sink;
                        this.reportFinding(taint, effectiveSink, expr);
                    }
                }
            }
        }
    }

    private checkAssignmentSink(lhs: ts.Expression, rhsTaints: TaintValue[]): void {
        const name = getCallChainName(lhs);

        for (const sink of this.spec.sinks) {
            if (sink.kind !== "assignment") continue;
            if (
                !(sink.requireAPIIdentity
                    ? this.matchesModelAPI(lhs, sink.pattern)
                    : this.matchesPatternWithExpr(
                          lhs,
                          name,
                          sink.pattern,
                          "sink.assignment",
                          !sink.pattern.includes("*"),
                      ))
            )
                continue;

            for (const taint of rhsTaints) {
                this.reportFinding(taint, sink, lhs);
            }
        }
    }

    // --- Sanitizer checking ---

    private matchingSanitizer(expr: ts.CallExpression): SanitizerSpec | undefined {
        return this.sanitizerForCallee(expr.expression);
    }

    private sanitizerForCallee(callee: ts.Expression): SanitizerSpec | undefined {
        const callName = getCallChainName(callee);
        for (const sanitizer of this.spec.sanitizers) {
            if (sanitizer.globalBuiltin) {
                const builtin = this.apiIdentity.builtinName(callee);
                if (builtin != null && this.matchesResolved(builtin, sanitizer.pattern)) return sanitizer;
                continue;
            }
            if (this.matchesPatternWithExpr(callee, callName, sanitizer.pattern, `sanitizer.${sanitizer.kind}`)) {
                return sanitizer;
            }
        }
        return undefined;
    }

    /**
     * The sanitizer `values.map(shlex.quote)` or `values.map((value) => shlex.quote(value))`
     * applies to every element of an array.
     */
    private arrayMapSanitizer(expr: ts.CallExpression): SanitizerSpec | undefined {
        if (
            !ts.isPropertyAccessExpression(expr.expression) ||
            expr.expression.name.text !== "map" ||
            expr.arguments.length !== 1
        ) {
            return undefined;
        }
        const receiverType = this.checker.getNonNullableType(
            this.checker.getTypeAtLocation(expr.expression.expression),
        );
        if (!this.checker.isArrayType(receiverType) && !this.checker.isTupleType(receiverType)) {
            return undefined;
        }
        const callback = unwrapExpression(expr.arguments[0]);
        if (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback)) {
            return this.sanitizerForCallee(callback);
        }
        const parameter = callback.parameters[0];
        if (callback.parameters.length !== 1 || !ts.isIdentifier(parameter.name)) return undefined;
        let body: ts.Expression | undefined;
        if (!ts.isBlock(callback.body)) {
            body = callback.body;
        } else if (callback.body.statements.length === 1 && ts.isReturnStatement(callback.body.statements[0])) {
            body = callback.body.statements[0].expression;
        }
        const call = body == null ? undefined : unwrapExpression(body);
        if (call == null || !ts.isCallExpression(call) || call.arguments.length !== 1) return undefined;
        const argument = unwrapExpression(call.arguments[0]);
        const parameterSymbol = this.checker.getSymbolAtLocation(parameter.name);
        if (!ts.isIdentifier(argument) || parameterSymbol == null || this.resolveSymbol(argument) !== parameterSymbol) {
            return undefined;
        }
        return this.sanitizerForCallee(call.expression);
    }

    /**
     * `values.map(shlex.quote).join(" ")`: space-separated quoted words stay
     * quoted arguments, so the join keeps the shell quoting for the context check
     * where the string is inserted. Any other separator, or an element changed
     * after it was quoted, drops it.
     */
    private isSpaceJoinOfElementWiseQuoting(expr: ts.CallExpression, taints: readonly TaintValue[]): boolean {
        return (
            ts.isPropertyAccessExpression(expr.expression) &&
            expr.expression.name.text === "join" &&
            expr.arguments.length === 1 &&
            this.staticStringText(expr.arguments[0]) === " " &&
            taints.every((taint) => TaintTracker.wasQuotedElementWise(taint))
        );
    }

    private static wasQuotedElementWise(taint: TaintValue): boolean {
        for (let node = taint.chain; node != null; node = node.previous) {
            if (node.step.kind === "sanitizer") {
                return node.step.elementWise === true && node.step.sanitizer?.requiresShellArgumentContext === true;
            }
            if (!TaintTracker.BARE_VALUE_STEPS.has(node.step.kind)) return false;
        }
        return false;
    }

    private applySanitizer(
        taints: readonly TaintValue[],
        sanitizer: SanitizerSpec,
        expr: ts.CallExpression,
        description: string,
        elementWise = false,
    ): TaintValue[] {
        return taints.map((taint) => {
            const sanitized = propagate(
                taint,
                {
                    kind: "sanitizer",
                    location: this.nodeLocation(expr),
                    description,
                    sanitizer,
                    ...(elementWise ? { elementWise: true as const } : {}),
                },
                this.metrics,
            );
            return withSanitizers(sanitized, [
                ...(taint.sanitizers ?? []),
                {
                    spec: sanitizer,
                    contextSatisfied: sanitizer.requiresShellArgumentContext !== true,
                },
            ]);
        });
    }

    // --- Finding reporting ---

    private static readonly scopedSources = new WeakMap<SourceSpec, Map<string, SourceSpec>>();

    /**
     * The source to report, labeled for the declared scope of the setting the
     * taint holds (`SourceSpec.settingScopeDescriptions`).
     */
    private findingSource(taint: TaintValue): SourceSpec {
        const source = taint.source;
        const scope = taint.settingPath && this.interproc?.settingScope(taint.settingPath.join("."));
        const description = scope ? source.settingScopeDescriptions?.[scope] : undefined;
        if (description == null) return source;
        let bySource = TaintTracker.scopedSources.get(source);
        if (!bySource) {
            bySource = new Map();
            TaintTracker.scopedSources.set(source, bySource);
        }
        let scoped = bySource.get(description);
        if (!scoped) {
            scoped = { ...source, description };
            bySource.set(description, scoped);
        }
        return scoped;
    }

    private computeHandle(source: SourceSpec, sink: SinkSpec, sinkLocation: CodeLocation): string {
        const parts = [
            source.pattern,
            sink.name,
            this.entryPointName,
            sinkLocation.fileName,
            String(sinkLocation.line),
        ];
        return parts.join("|");
    }

    private reportFinding(
        taint: TaintValue,
        sink: SinkSpec,
        sinkNode: ts.Node,
        sinkLocationOverride?: CodeLocation,
        promisified = false,
    ): void {
        const covering =
            taint.sanitizers?.filter(
                ({ spec, contextSatisfied }) =>
                    contextSatisfied &&
                    (spec.categories != null || spec.sinkNames != null) &&
                    (spec.categories == null ||
                        (sink.categories.length > 0 &&
                            sink.categories.every((category) => spec.categories!.includes(category)))) &&
                    (spec.sinkNames == null || spec.sinkNames.includes(sink.name)),
            ) ?? [];
        // Shell quoting only stops the value from becoming shell syntax; it is still
        // an argument the command acts on (and fixed text around it may redirect or
        // pipe it). Report it as argument injection instead of dropping it.
        const quotedArgumentOf = covering.every(({ spec }) => spec.requiresShellArgumentContext === true)
            ? covering[0]
            : undefined;
        if (covering.length > 0 && quotedArgumentOf == null) {
            return;
        }
        // A real command name, or undefined when the command is itself a quoted
        // value (the placeholder) or unknown.
        const quotedCommand =
            quotedArgumentOf?.shellCommand != null &&
            quotedArgumentOf.shellCommand !== TaintTracker.SHELL_ARGUMENT_PLACEHOLDER
                ? quotedArgumentOf.shellCommand
                : undefined;
        if (quotedArgumentOf != null) {
            const target = quotedCommand != null ? `\`${quotedCommand}\`` : "a quoted command";
            sink = {
                ...sink,
                severity: "high",
                categories: ["arg_injection"],
                description: `${sink.description} — shell-quoted argument to ${target}; the command decides what the value can do`,
            };
        }
        const sinkLocation = sinkLocationOverride ?? this.nodeLocation(sinkNode);
        this.findings.push({
            handle: this.computeHandle(taint.source, sink, sinkLocation),
            sinkSite: sinkSiteIdentity(sinkNode),
            ...(quotedCommand != null ? { quotedArgumentOf: quotedCommand } : {}),
            ...(promisified ? { promisified: true as const } : {}),
            source: this.findingSource(taint),
            sourceLocation: taint.sourceLocation,
            sink,
            sinkLocation,
            propagationChain: materializePropagationChain(taint).map((step) => ({
                kind: step.kind,
                location: step.location,
                description: step.description,
            })),
        });
    }

    // --- Utilities ---

    /**
     * Resolve the fully-qualified name for a call expression using the type checker.
     * Uses TypeScript's getFullyQualifiedName API which returns names like:
     *   "child_process".exec, "vscode".Terminal.sendText, RegExp.exec
     *
     * The quoted prefix indicates an external module. We strip quotes and return
     * a dot-separated name suitable for pattern matching.
     *
     * Returns undefined when the symbol cannot be resolved.
     */
    private resolveFullyQualifiedName(expr: ts.Expression): string | undefined {
        if (this.apiIdentity.resolvedNames.has(expr)) {
            this.metrics.performance.typeResolutionCacheHits++;
            return this.apiIdentity.resolvedNames.get(expr);
        }
        this.metrics.performance.typeResolutionCacheMisses++;

        let symbol: ts.Symbol | undefined;

        if (ts.isIdentifier(expr)) {
            symbol = this.checker.getSymbolAtLocation(expr);
        } else if (ts.isPropertyAccessExpression(expr)) {
            symbol = this.checker.getSymbolAtLocation(expr.name);
        } else if (ts.isElementAccessExpression(expr) && ts.isStringLiteralLike(expr.argumentExpression)) {
            symbol = this.checker.getTypeAtLocation(expr.expression).getProperty(expr.argumentExpression.text);
        }

        if (!symbol) {
            this.apiIdentity.resolvedNames.set(expr, undefined);
            return undefined;
        }

        if (symbol.flags & ts.SymbolFlags.Alias) {
            symbol = this.checker.getAliasedSymbol(symbol);
        }

        const fqn = this.checker.getFullyQualifiedName(symbol);
        if (!fqn || fqn === "__type" || fqn === "__function" || fqn === "unknown") {
            this.apiIdentity.resolvedNames.set(expr, undefined);
            return undefined;
        }

        // Strip quotes from module names: "child_process".exec → child_process.exec
        const resolved = canonicalModuleApiName(fqn.replace(/"/g, ""));
        this.apiIdentity.resolvedNames.set(expr, resolved);
        return resolved;
    }

    /**
     * Try the type-resolved name and qualified access path. When no name
     * resolves, use import identity or heuristic matching. Strict matching of
     * exact qualified patterns also checks external declaration/root identity.
     */
    private matchesPatternWithExpr(
        expr: ts.Expression,
        callName: string,
        pattern: string,
        context: string = "call",
        strictAPIIdentity = false,
    ): boolean {
        if (strictAPIIdentity) callName = this.apiIdentity.importedName(expr) ?? this.apiIdentity.accessName(expr);
        this.metrics.patternMatching.typeResolutionAttempts++;
        const resolved = this.resolveFullyQualifiedName(expr);
        if (resolved) {
            this.metrics.patternMatching.typeResolutionSuccesses++;
            let match = this.apiIdentity.getMatch(expr, pattern, strictAPIIdentity, callName);
            if (!match) {
                const compiled = this.apiIdentity.pattern(pattern);
                const matchedByType =
                    strictAPIIdentity && compiled.qualified && !compiled.hasWildcard
                        ? resolved.replace(/^global\./, "").toLowerCase() === compiled.lower &&
                          this.apiIdentity.isExternalSymbol(expr)
                        : this.matchesResolved(resolved, pattern);
                const accessPath =
                    !matchedByType &&
                    (!strictAPIIdentity || this.apiIdentity.hasExternalRoot(expr)) &&
                    (this.matchesResolvedAccessPath(callName, pattern) || (strictAPIIdentity && callName === pattern));
                match = { name: callName, matched: matchedByType || accessPath, accessPath };
                this.apiIdentity.setMatch(expr, pattern, strictAPIIdentity, match);
            }
            const { matched, accessPath } = match;
            recordPatternMatch(this.metrics, {
                context,
                strategy: accessPath ? "resolvedAccessPath" : "typeResolved",
                name: callName,
                pattern,
                matched,
                resolvedName: resolved,
            });
            if (matched) {
                this.metrics.patternMatching.typeResolvedMatches++;
                return true;
            }
            return false;
        }
        if (strictAPIIdentity) {
            const matched =
                this.apiIdentity.hasExternalRoot(expr) &&
                (this.matchesResolvedAccessPath(callName, pattern) || callName === pattern);
            this.metrics.patternMatching.heuristicFallbackAttempts++;
            if (matched) this.metrics.patternMatching.heuristicFallbackMatches++;
            recordPatternMatch(this.metrics, {
                context,
                strategy: "heuristicFallback",
                name: callName,
                pattern,
                matched,
            });
            return matched;
        }
        // The import still names the module when its declarations are missing
        // (a checkout without node_modules has no @types/node), so `cp.exec`
        // from `import * as cp from "child_process"` is `child_process.exec`.
        // The heuristic below refuses two unresolved qualified names.
        const imported = this.apiIdentity.importedName(expr);
        if (imported != null && imported !== callName && this.matchesResolvedAccessPath(imported, pattern)) {
            recordPatternMatch(this.metrics, {
                context,
                strategy: "importedName",
                name: callName,
                pattern,
                matched: true,
                resolvedName: imported,
            });
            return true;
        }
        return this.matchesPatternFallback(callName, pattern, context);
    }

    /**
     * Case-insensitive exact or dotted-suffix matching for a resolved name.
     */
    private matchesResolved(resolvedName: string, pattern: string): boolean {
        const rLC = resolvedName.toLowerCase();
        const compiled = this.apiIdentity.pattern(pattern);
        if (rLC === compiled.lower) return true;
        if (rLC.endsWith(compiled.suffix)) return true;
        return false;
    }

    /**
     * Some APIs resolve to the declaring interface rather than the public access
     * path used at the call site. For example, `vscode.workspace.fs.readFile`
     * resolves to `vscode.FileSystem.readFile`. Allow qualified exact, suffix,
     * and wildcard access-path matches, but not last-segment guessing.
     */
    private matchesResolvedAccessPath(callName: string, pattern: string): boolean {
        const compiled = this.apiIdentity.pattern(pattern);
        if (!callName.includes(".") || !compiled.qualified) return false;
        const nLC = callName.toLowerCase();
        if (nLC === compiled.lower || nLC.endsWith(compiled.suffix)) return true;
        if (compiled.hasWildcard) return this.apiIdentity.wildcard(pattern).test(nLC);

        return false;
    }

    /**
     * Heuristic matching: case-insensitive exact or dotted-suffix matches,
     * then segment wildcards. Last-segment matches require an unqualified side.
     * Warn only when unmatched qualified names share their last segment.
     */
    private matchesPattern(name: string, pattern: string, context: string): boolean {
        this.metrics.patternMatching.heuristicOnlyAttempts++;
        const matched = this.matchesPatternRaw(name, pattern);
        if (matched) {
            this.metrics.patternMatching.heuristicOnlyMatches++;
        }
        recordPatternMatch(this.metrics, {
            context,
            strategy: "heuristicOnly",
            name,
            pattern,
            matched,
        });
        return matched;
    }

    private matchesPatternFallback(name: string, pattern: string, context: string): boolean {
        this.metrics.patternMatching.heuristicFallbackAttempts++;
        const matched = this.matchesPatternRaw(name, pattern);
        if (matched) {
            this.metrics.patternMatching.heuristicFallbackMatches++;
        }
        recordPatternMatch(this.metrics, {
            context,
            strategy: "heuristicFallback",
            name,
            pattern,
            matched,
        });
        return matched;
    }

    private matchesPatternRaw(name: string, pattern: string): boolean {
        const nLC = name.toLowerCase();
        const compiled = this.apiIdentity.pattern(pattern);
        const qualified = name.includes(".");

        if (nLC === compiled.lower) return true;
        if (nLC.endsWith(compiled.suffix)) return true;
        if (!qualified && compiled.lower.endsWith("." + nLC)) return true;
        if (compiled.hasWildcard) return this.apiIdentity.wildcard(pattern).test(nLC);
        if (nLC.slice(nLC.lastIndexOf(".") + 1) !== compiled.lastSegment) return false;

        // One side is unqualified — allow the match (import aliasing)
        if (!qualified || !compiled.qualified) return true;

        // Both qualified, type resolution failed — don't guess, warn instead
        this.warnings.push(
            `Could not resolve type for '${name}' — unable to determine if it matches pattern '${pattern}'. ` +
                `Install @types packages or use fully qualified imports for accurate analysis.`,
        );
        return false;
    }

    private nodeLocation(node: ts.Node): CodeLocation {
        return resolveNodeLocation(node);
    }
}
