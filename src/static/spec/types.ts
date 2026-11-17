/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Taint analysis specification types.
 * Defines how sources, sinks, and sanitizers are matched against code patterns.
 */

export interface TaintSpec {
    sources: SourceSpec[];
    sinks: SinkSpec[];
    sanitizers: SanitizerSpec[];
    /** Named functions that serve as entry points (e.g., "activate", "main"). */
    entryFunctions?: string[];
    /**
     * Handler methods the host calls on a registered object, analyzed as entry
     * points with clean parameters. Use this when the registration is not an
     * attacker boundary but the handler runs without the user invoking it.
     */
    handlerEntryPoints?: HandlerEntryPointSpec[];
    /** Per-sink fix strategies. Overrides default strategies from fixStrategy.ts. */
    fixStrategies?: FixStrategy[];
}

export interface HandlerEntryPointSpec {
    /** Registration call, matched by name suffix like `SourceSpec.callbackRegistration`. */
    registration: string;
    /** Registration argument holding the handler object or class instance. */
    argIndex: number;
    /** Method on the handler that the host calls. */
    method: string;
    /** Entry point label shown in output. */
    description: string;
}

export type SourceKind =
    | "callReturnValue" // e.g., vscode.window.showInputBox() return value
    | "parameter" // e.g., handleUri(uri) parameter
    | "propertyAccess"; // e.g., uri.query

export type SinkKind =
    | "callArgument" // e.g., exec(cmd) — arg 0 is dangerous
    | "assignment"; // e.g., webview.html = tainted

export type SanitizerKind =
    // Both kinds annotate returned taint; neither clears the argument's state.
    "callReturnValue" | "callWrapping";

export interface SourceSpec {
    kind: SourceKind;
    /**
     * Dot-separated API pattern to match.
     * Examples:
     *   "vscode.window.showInputBox"     (callReturnValue)
     *   "handleUri.uri"                  (parameter — method.paramName)
     *   "*.query"                        (propertyAccess — wildcard receiver)
     */
    pattern: string;
    /** Declaring type name when it differs from the public property access path. */
    resolvedPattern?: string;
    /** Human-readable description of the source. */
    description: string;
    /** If true, property reads retain taint; tracked paths can narrow known fields. */
    taintAllProperties?: boolean;
    /**
     * For "parameter" sources: the callback registration pattern.
     * e.g., "vscode.window.registerUriHandler" means the parameter
     * of the handleUri method passed to registerUriHandler is a source.
     */
    callbackRegistration?: string;
    /** Require package/type identity instead of registration-name suffix matching. */
    callbackMatch?: "api";
    /** Registration arguments that must resolve to one of the listed static strings. */
    callbackArgumentValues?: Record<number, string[]>;
    /** Require package/API identity when matching this source; no bare-name fallback. */
    requireAPIIdentity?: boolean;
    /** Only these property paths of the source parameter contain external input. */
    paramPropertyPaths?: string[][];
    /**
     * For "parameter" sources: the parameter index (0-based).
     * Defaults to 0.
     */
    paramIndex?: number;
    /**
     * For "parameter" sources with callbackRegistration: the registration's
     * argument is an OBJECT or CLASS INSTANCE, and this names the method on it
     * that is the actual handler (e.g. "handleUri" for registerUriHandler,
     * "createDebugAdapterDescriptor" for registerDebugAdapterDescriptorFactory).
     * Leave unset when the argument is a bare function.
     */
    handlerMethod?: string;
    /** Overrides the entry point label shown in output. */
    entryPointDescription?: string;
    /**
     * For "parameter" sources with callbackRegistration: taint every parameter
     * of the callback rather than just `paramIndex`. Use only when the
     * registration itself receives an arbitrary list of attacker-controlled
     * values. Leave unset when only one parameter is attacker-controlled
     * (Express passes `res` as the second argument, which is not a source).
     */
    taintAllParams?: boolean;
    /** Taint every callback parameter at or after this index; earlier parameters stay clean. */
    taintParamsFromIndex?: number;
    /**
     * For "parameter" sources with callbackRegistration: which argument
     * of the registration call contains the callback (0-based).
     * Defaults to 0. Set to 1 for patterns like app.get("/path", handler).
     */
    callbackArgIndex?: number;
    /**
     * For "parameter" sources with callbackRegistration: callback argument
     * positions to try. Use this for overloads where the callback may appear
     * in multiple positions, e.g. fs.readFile(path, cb) and
     * fs.readFile(path, options, cb).
     */
    callbackArgIndices?: number[];
    /** All callback arguments starting at this index, including arrays of handlers. */
    callbackArgStart?: number;
    /** Host API types of clean callback parameters, independent of their local names. */
    callbackParameterTypes?: Record<number, string>;
    /** Ordered callbacks share parameter instances and continue only through `next()`. */
    callbackChain?: {
        nextParamIndex: number;
        sharedParamIndices: number[];
        /** Handler arities reserved for a separate host flow, such as Express errors. */
        excludedHandlerArities?: number[];
        /** API types accepted as a sole nested router argument on a static mount. */
        mountReceiverTypes?: string[];
        role: "middleware" | "route";
        /** A static registration path; omitted means unscoped middleware. */
        pathArgIndex?: number;
        /** For a route-builder receiver, the builder call's static path argument. */
        receiverPathArgIndex?: number;
        /** Host-created nested state, such as response.locals, initially clean. */
        sharedParamProperties?: Record<number, string[][]>;
    };
    /**
     * Where callback parameter sources are analyzed.
     * - "entryPoint" (default): discovery creates an entry point from the callback.
     * - "call": the callback is analyzed at the call site, with current taint state.
     */
    callbackSource?: "entryPoint" | "call";
    /**
     * How a call-local callback source taints the target parameter.
     * - "always" (default): create a new taint from this SourceSpec.
     * - "inheritFromArg": only taint if callbackTaintFromArgIndex is tainted.
     * - "preferArgTaint": inherit existing argument taint when present, otherwise
     *   create a new taint from this SourceSpec.
     */
    callbackTaint?: "always" | "inheritFromArg" | "preferArgTaint";
    /** Argument index whose taint should flow into a callback parameter. */
    callbackTaintFromArgIndex?: number;
    /** Selection APIs return one of these argument's values, rather than new input. */
    selectionFromArgIndex?: number;
    /**
     * For command-output sources: argument positions the options object can
     * take. The call is a source only when that object sets `cwd` to a
     * workspace folder or an open document's location.
     */
    workspaceCwdOptionIndices?: number[];
    /** Reserved option; the current tracker still requires an explicit workspace cwd. */
    workspaceDefaultCwd?: true;
    promisified?: true;
    /** Match the promise-returning API variant, not a callback API's return handle. */
    callReturnKind?: "promise";
    /**
     * For `WorkspaceConfiguration.get`: descriptions by the `scope` an
     * extension manifest declares for the setting read, which decides the
     * settings files that can supply it. A scope missing here, or a setting
     * whose key or scope is unknown, keeps `description`.
     */
    settingScopeDescriptions?: Partial<Record<SettingScope, string>>;
}

/** `scope` of a setting in an extension manifest's `contributes.configuration`. */
export type SettingScope =
    | "application"
    | "machine"
    | "window"
    | "resource"
    | "language-overridable"
    | "machine-overridable";

export type SinkCategory =
    | "rce"
    | "code_injection"
    | "xss"
    | "ssrf"
    | "file_write"
    | "file_integrity"
    | "open_redirect"
    | "lfi"
    | "file_access"
    | "ssti"
    | "workspace_edit"
    | "arg_injection"
    | "prompt_injection";

export type FindingKind = "security_candidate" | "file_access" | "persistence_trace";

export interface FindingReporting {
    kind: FindingKind;
    limitation: string;
}

export interface SinkSpec {
    /** Presentation only; does not alter matching, propagation, or finding identity. */
    reportingKind?: FindingKind;
    kind: SinkKind;
    /** Short unique name for this sink (e.g., "exec", "eval", "sendText"). Used in stable finding handles. */
    name: string;
    /** Dot-separated API pattern to match. */
    pattern: string;
    /** Which argument positions are dangerous (0-based). Defaults to [0]. */
    argPositions?: number[];
    /** Override argument positions for overloads selected by argument count. */
    argPositionsByArity?: Record<number, number[]>;
    /**
     * `argPositions` are alternative positions of one argument, for overloads
     * that drop a leading string parameter: `new LanguageClient(id, name,
     * serverOptions, ...)` and `new LanguageClient(name, serverOptions, ...)`.
     * Only the first listed position whose argument is not a string is the sink.
     */
    firstNonStringArgPosition?: boolean;
    /** Every argument contains executable syntax, as with the Function constructor. */
    allArguments?: boolean;
    /** Require the standard library binding, rather than a shadowing local name. */
    globalBuiltin?: boolean;
    /** Require package/API identity rather than a bare-name sink match. */
    requireAPIIdentity?: boolean;
    /**
     * Optional AST shapes for overloaded argument positions. A known mismatch
     * is rejected; an unknown shape is accepted unless
     * `rejectUnknownArgumentShapes` is set.
     */
    argumentShapes?: Record<number, "array" | "object" | "string">;
    rejectUnknownArgumentShapes?: boolean;
    /**
     * A nonnegative literal integer fd (or immutable scalar alias) in this
     * options property overrides the path argument. Unknown, null, or
     * undefined descriptor values do not suppress the path sink.
     */
    pathOverriddenByFileDescriptor?: { argument: number; property: string };
    /**
     * Strings each listed argument must statically resolve to, by position.
     * A dispatcher that selects its operation by name, such as
     * `vscode.commands.executeCommand(id, ...args)`, is a sink only for some
     * names. An argument with no static value does not match.
     */
    argumentValues?: Record<number, string[]>;
    /** Human-readable description of the sink. */
    description: string;
    /** Severity level. */
    severity?: "critical" | "high" | "medium" | "low";
    /**
     * For sinks whose dangerous argument is a CONFIG OBJECT: only fire when the
     * taint entered through one of these property names.
     *
     * `debug.startDebugging(folder, config)` takes a whole DebugConfiguration.
     * Taint in `initCommands` is arbitrary debugger-command execution; taint in
     * `name` is a cosmetic session label. Without this the sink cannot tell
     * them apart and reports both identically.
     *
     * Filters on POSITIVE knowledge only: if the taint never passed through a
     * recognizable object-literal property (e.g. the whole config arrives from
     * elsewhere), the sink still fires, because we cannot show it is harmless.
     */
    objectProperties?: string[];
    /**
     * Known fields in the sink's config object. When present, wrapper-object
     * fields are skipped while looking for the relevant config property.
     */
    objectPropertyUniverse?: string[];
    /**
     * For an `objectProperties` entry whose value is a map, the keys under it
     * matched by this sink. For example, an env-key list can include `PATH`
     * while excluding `LOG_DIR`; excluded keys are a modeling choice, not a
     * safety guarantee. Keys match case-insensitively, with a trailing `*`
     * matching a prefix.
     *
     * Like `objectProperties`, this filters on positive knowledge only: taint
     * whose key is unknown (a spread, a computed key, or the whole map arriving
     * from elsewhere) still reports.
     */
    objectPropertyKeys?: Record<string, string[]>;
    /**
     * Report only taint known to have entered through one of
     * `objectProperties`. Set this on all but one of the sinks that read
     * different fields of the same argument, so taint whose field is unknown
     * reports once, from the sink that leaves it unset.
     */
    requireObjectProperty?: boolean;
    /**
     * For an argument-injection sink whose argv is a field of a config object:
     * the sibling field holding child-process options. A recognized `shell`
     * property not set to the literal `false` is conservatively treated as
     * enabling command interpretation.
     */
    shellOptionsProperty?: string;
    /** Sink categories, including trace-only categories; used for scoped sanitizers. */
    categories: SinkCategory[];
}

interface SanitizerSpecBase {
    kind: SanitizerKind;
    /** Dot-separated API pattern to match. */
    pattern: string;
    /** Require the standard library binding rather than a local or imported lookalike. */
    globalBuiltin?: boolean;
    /** Human-readable description. */
    description: string;
}

export type SanitizerSpec = SanitizerSpecBase & {
    /** Sink categories covered by this sanitizer. ANDed with sinkNames. */
    categories?: SinkCategory[];
    /** Sink names covered by this sanitizer. Shell quoting can downgrade rather than suppress a finding. */
    sinkNames?: string[];
    /** The sanitized value is a number, so it cannot introduce shell syntax. */
    numeric?: boolean;
    /** Require recognized shell-word context before granting argument-quoting credit. */
    requiresShellArgumentContext?: boolean;
    /**
     * Command names for which quoted values retain command-execution findings:
     * shells, interpreters, and programs with code-bearing arguments or options.
     */
    shellCommandDenylist?: string[];
} & ({ categories: SinkCategory[] } | { sinkNames: string[] });

export interface CodeLocation {
    fileName: string;
    line: number;
    column: number;
    text?: string;
}

export interface TaintFinding {
    /** Additive machine-output metadata; raw analysis does not need to populate it. */
    reporting?: FindingReporting;
    /**
     * Per-run deduplication key. Includes the sink line, so it is NOT stable
     * across runs; use `sinkSite` for cross-run identity.
     */
    handle: string;
    /** Location-free identity of the sink site; see `sinkSiteIdentity`. */
    sinkSite: string;
    /**
     * Fixed command a shell-quoted value is an argument of, when reported as
     * argument injection and the command is a known name.
     */
    quotedArgumentOf?: string;
    /** The sink function was called through a `util.promisify` wrapper. */
    promisified?: true;
    /** Which source introduced taint. */
    source: SourceSpec;
    /** Where the source was in code. */
    sourceLocation: CodeLocation;
    /** Which sink received taint. */
    sink: SinkSpec;
    /** Where the sink was in code. */
    sinkLocation: CodeLocation;
    /** The chain of assignments/calls through which taint propagated. */
    propagationChain: PropagationStep[];
    /** Generated fix suggestion, if available. */
    fix?: FixSuggestion;
}

export interface PropagationStep {
    kind:
        | "assignment"
        | "argument"
        | "return"
        | "propertyAccess"
        | "stringConcat"
        | "templateLiteral"
        | "destructuring"
        | "spread"
        | "ternary"
        | "shortCircuit"
        | "arrayIndex"
        | "mutation"
        | "closure"
        | "objectProperty"
        | "sanitizer"
        | "shellCommandComposition"
        | "nestedShellCommand";
    location: CodeLocation;
    description: string;
}

export type FixApplicability = "safe" | "unsafe" | "unfixable";

export interface FixSuggestion {
    filePath: string;
    original: string;
    replacement: string;
    line: number;
    column: number;
    applicability: FixApplicability;
    description: string;
}

export interface FixStrategy {
    category: SinkCategory;
    sinkName?: string;
    saferAPI: string;
    saferPattern: string;
    importPackage?: string;
    importName?: string;
    applicability: FixApplicability;
    description: string;
}

export interface LintMessage {
    path: string;
    line: number;
    char: number;
    category: SinkCategory | "taint" | "import";
    severity: "error" | "warning" | "advice" | "autofix" | "disabled";
    name: string;
    description: string;
    original?: string;
    replacement?: string;
    replacementIsSafe?: boolean;
}
