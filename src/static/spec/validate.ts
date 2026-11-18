/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {
    FixStrategy,
    HandlerEntryPointSpec,
    SanitizerSpec,
    SettingScope,
    SinkCategory,
    SinkSpec,
    SourceSpec,
    TaintSpec,
} from "./types";

type FieldType =
    | "string"
    | "number"
    | "boolean"
    | "record"
    | { oneOf: readonly (string | number | boolean)[] }
    | { array: FieldType }
    | { object: Record<string, Rule> };

interface Rule {
    type: FieldType;
    required?: boolean;
}

type OptionalRule = Rule & { required?: false };
type RequiredRule = Rule & { required: true };

/**
 * One rule per field of `T`. The compiler rejects a schema that omits a field,
 * names a field `T` lacks, or disagrees with `T` about whether it is required.
 */
type Schema<T> = {
    [K in keyof T]-?: {} extends Pick<T, K> ? OptionalRule : RequiredRule;
};

const sinkCategories: Record<SinkCategory, true> = {
    rce: true,
    code_injection: true,
    xss: true,
    ssrf: true,
    file_write: true,
    file_integrity: true,
    open_redirect: true,
    lfi: true,
    file_access: true,
    ssti: true,
    workspace_edit: true,
    arg_injection: true,
    prompt_injection: true,
};

const settingScopes: Record<SettingScope, true> = {
    application: true,
    machine: true,
    window: true,
    resource: true,
    "language-overridable": true,
    "machine-overridable": true,
};

const string: OptionalRule = { type: "string" };
const number: OptionalRule = { type: "number" };
const boolean: OptionalRule = { type: "boolean" };
const record: OptionalRule = { type: "record" };
const onlyTrue: OptionalRule = { type: { oneOf: [true] } };
const strings: OptionalRule = { type: { array: "string" } };
const numbers: OptionalRule = { type: { array: "number" } };
const categories: OptionalRule = { type: { array: { oneOf: Object.keys(sinkCategories) } } };
const oneOf = (...values: string[]): OptionalRule => ({ type: { oneOf: values } });
const required = (rule: OptionalRule): RequiredRule => ({ ...rule, required: true });

type CallbackChain = NonNullable<SourceSpec["callbackChain"]>;

const callbackChainSchema: Schema<CallbackChain> = {
    nextParamIndex: required(number),
    sharedParamIndices: required(numbers),
    excludedHandlerArities: numbers,
    mountReceiverTypes: strings,
    role: required(oneOf("middleware", "route")),
    pathArgIndex: number,
    receiverPathArgIndex: number,
    sharedParamProperties: record,
};

const sourceSchema: Schema<SourceSpec> = {
    kind: required(oneOf("callReturnValue", "parameter", "propertyAccess")),
    pattern: required(string),
    resolvedPattern: string,
    description: required(string),
    taintAllProperties: boolean,
    callbackRegistration: string,
    callbackMatch: oneOf("api"),
    callbackArgumentValues: record,
    requireAPIIdentity: boolean,
    paramPropertyPaths: { type: { array: { array: "string" } } },
    paramIndex: number,
    handlerMethod: string,
    entryPointDescription: string,
    taintAllParams: boolean,
    taintParamsFromIndex: number,
    callbackArgIndex: number,
    callbackArgIndices: numbers,
    callbackArgStart: number,
    callbackParameterTypes: record,
    callbackChain: { type: { object: callbackChainSchema } },
    callbackSource: oneOf("entryPoint", "call"),
    callbackTaint: oneOf("always", "inheritFromArg", "preferArgTaint"),
    callbackTaintFromArgIndex: number,
    selectionFromArgIndex: number,
    workspaceCwdOptionIndices: numbers,
    workspaceDefaultCwd: onlyTrue,
    promisified: onlyTrue,
    callReturnKind: oneOf("promise"),
    settingScopeDescriptions: {
        type: { object: Object.fromEntries(Object.keys(settingScopes).map((scope) => [scope, string])) },
    },
};

const sinkSchema: Schema<SinkSpec> = {
    reportingKind: oneOf("security_candidate", "file_access", "persistence_trace"),
    kind: required(oneOf("callArgument", "assignment")),
    name: required(string),
    pattern: required(string),
    argPositions: numbers,
    argPositionsByArity: record,
    firstNonStringArgPosition: boolean,
    allArguments: boolean,
    globalBuiltin: boolean,
    requireAPIIdentity: boolean,
    argumentShapes: record,
    rejectUnknownArgumentShapes: boolean,
    jsonResponseBody: onlyTrue,
    pathOverriddenByFileDescriptor: {
        type: { object: { argument: required(number), property: required(string) } },
    },
    argumentValues: record,
    description: required(string),
    severity: oneOf("critical", "high", "medium", "low"),
    objectProperties: strings,
    objectPropertyUniverse: strings,
    objectPropertyKeys: record,
    requireObjectProperty: boolean,
    shellOptionsProperty: string,
    categories: required(categories),
};

// The type requires `categories` or `sinkNames`; `validateSpec` checks that.
const sanitizerSchema: Schema<Omit<SanitizerSpec, "categories" | "sinkNames">> &
    Record<"categories" | "sinkNames", OptionalRule> = {
    kind: required(oneOf("callReturnValue", "callWrapping")),
    pattern: required(string),
    globalBuiltin: boolean,
    description: required(string),
    categories,
    sinkNames: strings,
    numeric: boolean,
    requiresShellArgumentContext: boolean,
    shellCommandDenylist: strings,
};

const handlerEntryPointSchema: Schema<HandlerEntryPointSpec> = {
    registration: required(string),
    argIndex: required(number),
    method: required(string),
    description: required(string),
};

const fixStrategySchema: Schema<FixStrategy> = {
    category: required({ type: { oneOf: Object.keys(sinkCategories) } }),
    sinkName: string,
    saferAPI: required(string),
    saferPattern: required(string),
    importPackage: string,
    importName: string,
    applicability: required(oneOf("safe", "unsafe", "unfixable")),
    description: required(string),
};

const specSchema: Schema<TaintSpec> = {
    sources: required({ type: { array: { object: sourceSchema } } }),
    sinks: required({ type: { array: { object: sinkSchema } } }),
    sanitizers: required({ type: { array: { object: sanitizerSchema } } }),
    entryFunctions: strings,
    handlerEntryPoints: { type: { array: { object: handlerEntryPointSchema } } },
    fixStrategies: { type: { array: { object: fixStrategySchema } } },
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describe(type: FieldType): string {
    if (typeof type === "string") return type === "record" ? "an object" : `a ${type}`;
    if ("oneOf" in type) return `one of ${type.oneOf.map((value) => JSON.stringify(value)).join(", ")}`;
    if ("array" in type) return "an array";
    return "an object";
}

function check(value: unknown, type: FieldType, path: string, errors: string[]): void {
    if (typeof type === "string") {
        const ok =
            type === "record"
                ? isPlainObject(value)
                : type === "number"
                  ? typeof value === "number" && Number.isFinite(value)
                  : typeof value === type;
        if (!ok) errors.push(`${path}: expected ${describe(type)}`);
        return;
    }
    if ("oneOf" in type) {
        if (!type.oneOf.includes(value as string | number | boolean)) {
            errors.push(`${path}: expected ${describe(type)}, got ${JSON.stringify(value)}`);
        }
        return;
    }
    if ("array" in type) {
        if (!Array.isArray(value)) {
            errors.push(`${path}: expected an array`);
            return;
        }
        value.forEach((item, index) => check(item, type.array, `${path}[${index}]`, errors));
        return;
    }
    if (!isPlainObject(value)) {
        errors.push(`${path}: expected an object`);
        return;
    }
    for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(type.object, key)) {
            errors.push(`${path ? `${path}.` : ""}${key}: unknown field`);
        }
    }
    for (const [key, rule] of Object.entries(type.object)) {
        const field = path ? `${path}.${key}` : key;
        if (value[key] === undefined) {
            if (rule.required) errors.push(`${field}: missing required field`);
            continue;
        }
        check(value[key], rule.type, field, errors);
    }
}

/**
 * Check a parsed custom spec against the `TaintSpec` types. Returns one message
 * per problem, each prefixed with the path of the offending field.
 */
export function validateSpec(value: unknown): string[] {
    if (!isPlainObject(value)) return ["the spec must be a JSON object"];
    const errors: string[] = [];
    check(value, { object: specSchema }, "", errors);
    if (Array.isArray(value.sanitizers)) {
        value.sanitizers.forEach((sanitizer, index) => {
            if (isPlainObject(sanitizer) && sanitizer.categories === undefined && sanitizer.sinkNames === undefined) {
                errors.push(`sanitizers[${index}]: requires "categories" or "sinkNames"`);
            }
        });
    }
    return errors;
}
