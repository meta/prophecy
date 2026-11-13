/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { getCallChainName, unwrapExpression } from "./functionResolver";

interface Pattern {
    lower: string;
    suffix: string;
    qualified: boolean;
    lastSegment: string;
    hasWildcard: boolean;
    wildcard?: RegExp;
}

interface Match {
    name: string;
    matched: boolean;
    accessPath: boolean;
}

/**
 * The name the spec uses for a module API. `node:fs` is `fs`, and
 * `fs/promises` (also reachable as `fs.promises`) exports the promise forms of
 * the `fs` APIs the spec names, such as `fs.readdir` and `fs.writeFile`.
 * `vscode-languageclient/node` is the Node client, which older releases export
 * from the package root.
 */
export function canonicalModuleApiName(name: string): string {
    return name
        .replace(/^node:/, "")
        .replace(/^fs-extra(?=\.)/, "fs")
        .replace(/^fs[/.]promises\./, "fs.")
        .replace(/^(?:.*\/node_modules\/@types\/)?express(?:-serve-static-core)?(?:\/index)?\./, "express.")
        .replace(/^vscode-languageclient\/node\./, "vscode-languageclient.");
}

type ReceiverIdentity = ts.Node | ts.Symbol;

interface RegistrationState {
    bindings: ReadonlyMap<ts.Symbol, ReceiverIdentity>;
    fields: ReadonlyMap<ReceiverIdentity, ReadonlyMap<string, ReceiverIdentity>>;
    writes: ReadonlyMap<ReceiverIdentity, ReadonlySet<string>>;
}

/** Declaration facts belong to a checker, independent of the current taint state. */
export class APIIdentityCache {
    private static caches = new WeakMap<ts.TypeChecker, APIIdentityCache>();
    readonly resolvedNames = new WeakMap<ts.Expression, string | undefined>();
    private importedNames = new WeakMap<ts.Expression, string | undefined>();
    private rawImportedNames = new WeakMap<ts.Expression, string | undefined>();
    private registrationNames = new WeakMap<ts.Expression, string | undefined>();
    private accessNames = new WeakMap<ts.Expression, string>();
    private externalSymbols = new WeakMap<ts.Expression, boolean>();
    private externalRoots = new WeakMap<ts.Expression, boolean>();
    private patterns = new Map<string, Pattern>();
    private matches = new WeakMap<ts.Expression, Map<string, { strict?: Match; loose?: Match }>>();
    private registrationFields = new Map<ReceiverIdentity, Map<string, ReceiverIdentity>>();
    private registrationStates = new WeakMap<ts.Statement, RegistrationState>();
    private registrationStateInProgress = new WeakSet<ts.Statement>();
    private emptyRegistrationState: RegistrationState = { bindings: new Map(), fields: new Map(), writes: new Map() };

    private constructor(private checker: ts.TypeChecker) {}

    static forChecker(checker: ts.TypeChecker): APIIdentityCache {
        let cache = this.caches.get(checker);
        if (!cache) {
            cache = new APIIdentityCache(checker);
            this.caches.set(checker, cache);
        }
        return cache;
    }

    pattern(text: string): Pattern {
        let pattern = this.patterns.get(text);
        if (!pattern) {
            const lower = text.toLowerCase();
            pattern = {
                lower,
                suffix: "." + lower,
                qualified: text.includes("."),
                lastSegment: lower.slice(lower.lastIndexOf(".") + 1),
                hasWildcard: lower.includes("*"),
            };
            this.patterns.set(text, pattern);
        }
        return pattern;
    }

    wildcard(text: string): RegExp {
        const pattern = this.pattern(text);
        return (pattern.wildcard ??= new RegExp(
            "^" + pattern.lower.replace(/\./g, "\\.").replace(/\*/g, "[^.]+") + "$",
        ));
    }

    getMatch(expr: ts.Expression, pattern: string, strict: boolean, name: string): Match | undefined {
        const variants = this.matches.get(expr)?.get(pattern);
        const match = strict ? variants?.strict : variants?.loose;
        return match?.name === name ? match : undefined;
    }

    setMatch(expr: ts.Expression, pattern: string, strict: boolean, match: Match): void {
        let patterns = this.matches.get(expr);
        if (!patterns) {
            patterns = new Map();
            this.matches.set(expr, patterns);
        }
        let variants = patterns.get(pattern);
        if (!variants) {
            variants = {};
            patterns.set(pattern, variants);
        }
        if (strict) variants.strict = match;
        else variants.loose = match;
    }

    accessName(expr: ts.Expression): string {
        const cached = this.accessNames.get(expr);
        if (cached != null) return cached;
        const value = unwrapExpression(expr);
        let name: string;
        if (ts.isPropertyAccessExpression(value)) {
            name = `${this.accessName(value.expression)}.${value.name.text}`;
        } else if (ts.isElementAccessExpression(value) && ts.isStringLiteralLike(value.argumentExpression)) {
            name = `${this.accessName(value.expression)}.${value.argumentExpression.text}`;
        } else {
            name = getCallChainName(value);
        }
        this.accessNames.set(expr, name);
        return name;
    }

    isExternalSymbol(expr: ts.Expression): boolean {
        const cached = this.externalSymbols.get(expr);
        if (cached != null) return cached;
        const value = unwrapExpression(expr);
        let symbol = ts.isPropertyAccessExpression(value)
            ? this.checker.getSymbolAtLocation(value.name)
            : ts.isElementAccessExpression(value) && ts.isStringLiteralLike(value.argumentExpression)
              ? this.checker.getTypeAtLocation(value.expression).getProperty(value.argumentExpression.text)
              : this.checker.getSymbolAtLocation(value);
        if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = this.checker.getAliasedSymbol(symbol);
        const external = symbol?.declarations?.some((decl) => decl.getSourceFile().isDeclarationFile) === true;
        this.externalSymbols.set(expr, external);
        return external;
    }

    /** Cache absent identities too; recursive alias walks have path-dependent cycle guards. */
    importedName(expr: ts.Expression): string | undefined {
        if (this.importedNames.has(expr)) return this.importedNames.get(expr);
        const resolved = this.rawImportedName(expr);
        const name = resolved == null ? undefined : canonicalModuleApiName(resolved);
        this.importedNames.set(expr, name);
        return name;
    }

    /** Preserve module spelling for API overloads such as fs/promises.readFile. */
    rawImportedName(expr: ts.Expression): string | undefined {
        if (this.rawImportedNames.has(expr)) return this.rawImportedNames.get(expr);
        const name = this.resolveImportedName(expr, new Set());
        this.rawImportedNames.set(expr, name);
        return name;
    }

    /** Identity for opt-in API rules; unknown or locally shadowed names do not match. */
    matchesAPI(expr: ts.Expression, pattern: string): boolean {
        const name = this.registrationName(expr);
        if (name == null) return false;
        const expected = canonicalModuleApiName(pattern);
        if (!expected.includes("*")) {
            if (name !== expected) return false;
        } else {
            const escaped = expected.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
            if (!new RegExp("^" + escaped.join("[^.]+") + "$").test(name)) return false;
        }
        return !this.registrationWasReplaced(expr, new Set());
    }

    registrationMatches(expr: ts.Expression, pattern: string): boolean {
        return this.matchesAPI(expr, pattern);
    }

    private registrationWasReplaced(expr: ts.Expression, seen: Set<ts.Symbol>): boolean {
        const value = unwrapExpression(expr);
        if (ts.isIdentifier(value)) {
            const symbol = this.checker.getSymbolAtLocation(value);
            if (!symbol || seen.has(symbol)) return false;
            seen.add(symbol);
            const declaration = symbol.valueDeclaration;
            return (
                declaration != null &&
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer != null &&
                ts.isVariableDeclarationList(declaration.parent) &&
                (declaration.parent.flags & ts.NodeFlags.Const) !== 0 &&
                this.registrationWasReplaced(declaration.initializer, seen)
            );
        }
        const member = this.registrationMember(value);
        if (!member) return false;
        const state = this.registrationState(value);
        const receiver = this.resolveRegistrationReceiver(member.receiver, state, new Set());
        return state.writes.get(receiver)?.has(member.name) === true;
    }

    /** Object identity at this read; const aliases capture values, not mutable field paths. */
    registrationReceiver(expr: ts.Expression): ReceiverIdentity {
        return this.resolveRegistrationReceiver(expr, this.registrationState(expr), new Set());
    }

    private registrationMember(expr: ts.Expression): { receiver: ts.Expression; name: string } | undefined {
        const value = unwrapExpression(expr);
        if (ts.isPropertyAccessExpression(value)) return { receiver: value.expression, name: value.name.text };
        if (ts.isElementAccessExpression(value) && ts.isStringLiteralLike(value.argumentExpression)) {
            return { receiver: value.expression, name: value.argumentExpression.text };
        }
        return undefined;
    }

    private resolveRegistrationReceiver(
        expr: ts.Expression,
        state: RegistrationState,
        seen: Set<ts.Symbol>,
    ): ReceiverIdentity {
        const value = unwrapExpression(expr);
        if (value.kind === ts.SyntaxKind.ThisKeyword) return ts.findAncestor(value, ts.isClassLike) ?? value;
        const member = this.registrationMember(value);
        if (member) {
            const receiver = this.resolveRegistrationReceiver(member.receiver, state, seen);
            const assigned = state.fields.get(receiver)?.get(member.name);
            if (assigned) return assigned;
            let fields = this.registrationFields.get(receiver);
            if (!fields) {
                fields = new Map();
                this.registrationFields.set(receiver, fields);
            }
            const identity = fields.get(member.name) ?? value;
            fields.set(member.name, identity);
            return identity;
        }
        if (ts.isIdentifier(value)) {
            let symbol = this.checker.getSymbolAtLocation(value);
            if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = this.checker.getAliasedSymbol(symbol);
            if (!symbol) return value;
            const assigned = state.bindings.get(symbol);
            if (assigned) return assigned;
            if (seen.has(symbol)) return symbol;
            seen.add(symbol);
            const declaration = symbol.valueDeclaration;
            if (
                declaration &&
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer &&
                ts.isVariableDeclarationList(declaration.parent) &&
                (declaration.parent.flags & ts.NodeFlags.Const) !== 0
            ) {
                const initializer = declaration.initializer;
                return this.resolveRegistrationReceiver(initializer, this.registrationState(initializer), seen);
            }
            return symbol;
        }
        if (ts.isCallExpression(value)) {
            const callee = this.registrationMember(value.expression);
            const name = this.registrationName(value.expression);
            const result = name && this.factoryResult(name, value);
            // Factory calls remain allocation sites; only known fluent APIs return the receiver.
            if (
                callee &&
                result &&
                (result === this.registrationName(callee.receiver) ||
                    name === "express.Application.route" ||
                    name === "express.Router.route")
            ) {
                return this.resolveRegistrationReceiver(callee.receiver, state, seen);
            }
        }
        return value;
    }

    /** Only preceding direct declarations and '=' writes in this statement list are modeled. */
    private registrationState(expr: ts.Expression): RegistrationState {
        let statement: ts.Node = expr;
        while (statement.parent && !ts.isBlock(statement.parent) && !ts.isSourceFile(statement.parent))
            statement = statement.parent;
        const scope = statement.parent;
        let state = this.emptyRegistrationState;
        if (!scope || (!ts.isBlock(scope) && !ts.isSourceFile(scope))) return state;
        for (const preceding of scope.statements) {
            if (preceding === statement) break;
            const cached = this.registrationStates.get(preceding);
            if (cached) {
                state = cached;
                continue;
            }
            if (this.registrationStateInProgress.has(preceding)) return state;
            this.registrationStateInProgress.add(preceding);
            try {
                if (ts.isVariableStatement(preceding) && (preceding.declarationList.flags & ts.NodeFlags.Const) !== 0) {
                    for (const declaration of preceding.declarationList.declarations) {
                        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
                        const symbol = this.checker.getSymbolAtLocation(declaration.name);
                        if (!symbol) continue;
                        const identity = this.resolveRegistrationReceiver(
                            declaration.initializer,
                            state,
                            new Set([symbol]),
                        );
                        state = { ...state, bindings: new Map(state.bindings).set(symbol, identity) };
                    }
                } else if (ts.isExpressionStatement(preceding)) {
                    const assignment = unwrapExpression(preceding.expression);
                    if (
                        ts.isBinaryExpression(assignment) &&
                        assignment.operatorToken.kind === ts.SyntaxKind.EqualsToken
                    ) {
                        const member = this.registrationMember(assignment.left);
                        if (member) {
                            const receiver = this.resolveRegistrationReceiver(member.receiver, state, new Set());
                            const identity = this.resolveRegistrationReceiver(assignment.right, state, new Set());
                            state = {
                                ...state,
                                fields: new Map(state.fields).set(
                                    receiver,
                                    new Map(state.fields.get(receiver)).set(member.name, identity),
                                ),
                                writes: new Map(state.writes).set(
                                    receiver,
                                    new Set(state.writes.get(receiver)).add(member.name),
                                ),
                            };
                        }
                    }
                }
                this.registrationStates.set(preceding, state);
            } finally {
                this.registrationStateInProgress.delete(preceding);
            }
        }
        return state;
    }

    /** Resolve imports, declared external types, and explicitly modeled factory returns. */
    registrationName(expr: ts.Expression): string | undefined {
        if (this.registrationNames.has(expr)) return this.registrationNames.get(expr);
        const resolved = this.resolveRegistrationName(expr, new Set());
        const name = resolved == null ? undefined : canonicalModuleApiName(resolved);
        this.registrationNames.set(expr, name);
        return name;
    }

    private resolveRegistrationName(expr: ts.Expression, seen: Set<ts.Symbol>): string | undefined {
        const value = unwrapExpression(expr);
        const imported = this.rawImportedName(value);
        // A local module is not an API identity. Follow its export declaration
        // below so re-exported clients retain their actual package identity.
        if (imported != null && !imported.startsWith(".") && !imported.startsWith("/")) return imported;
        if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
            const member = ts.isPropertyAccessExpression(value)
                ? value.name.text
                : ts.isStringLiteralLike(value.argumentExpression)
                  ? value.argumentExpression.text
                  : undefined;
            const receiver = this.resolveRegistrationName(value.expression, seen);
            const declared = this.declaredTypeName(value);
            // External wrapper fields can expose a modeled API instance. Method
            // signature types (for example IRouterMatcher) are not receivers.
            if (
                declared != null &&
                [
                    "express.Application",
                    "express.Router",
                    "express.Route",
                    "ws.WebSocket",
                    "ws.WebSocketServer",
                    "axios",
                    "electron.ipcMain",
                    "electron.app",
                    "electron.shell",
                ].includes(declared)
            )
                return declared;
            return receiver != null && member != null ? `${receiver}.${member}` : declared;
        }
        if (ts.isCallExpression(value) || ts.isNewExpression(value)) {
            const callee = this.resolveRegistrationName(value.expression, seen);
            const result = callee == null ? undefined : this.factoryResult(callee, value);
            return result ?? this.declaredTypeName(value);
        }
        if (ts.isIdentifier(value)) {
            let symbol = this.checker.getSymbolAtLocation(value);
            if (symbol && (symbol.flags & ts.SymbolFlags.Alias) !== 0) symbol = this.checker.getAliasedSymbol(symbol);
            if (symbol && !seen.has(symbol)) {
                seen.add(symbol);
                for (const declaration of symbol.declarations ?? []) {
                    if (ts.isExportAssignment(declaration)) {
                        const name = this.resolveRegistrationName(declaration.expression, seen);
                        if (name != null) return name;
                    }
                    if (ts.isParameter(declaration) && declaration.parent.parameters.indexOf(declaration) === 0) {
                        const registration = declaration.parent.parent;
                        if (
                            ts.isCallExpression(registration) &&
                            registration.arguments[1] === declaration.parent &&
                            ts.isStringLiteralLike(registration.arguments[0]) &&
                            registration.arguments[0].text === "connection"
                        ) {
                            const name = this.resolveRegistrationName(registration.expression, seen);
                            if (
                                name != null &&
                                [
                                    "ws.WebSocketServer.on",
                                    "ws.WebSocketServer.once",
                                    "ws.WebSocketServer.addListener",
                                ].includes(name)
                            ) {
                                return "ws.WebSocket";
                            }
                        }
                    }
                    if (
                        ts.isVariableDeclaration(declaration) &&
                        declaration.initializer &&
                        ts.isVariableDeclarationList(declaration.parent) &&
                        (declaration.parent.flags & ts.NodeFlags.Const) !== 0
                    ) {
                        const name = this.resolveRegistrationName(declaration.initializer, seen);
                        if (name != null) return name;
                    }
                }
            }
        }
        return this.declaredTypeName(value);
    }

    private factoryResult(name: string, expression: ts.CallExpression | ts.NewExpression): string | undefined {
        const api = canonicalModuleApiName(name);
        const factories: Record<string, string> = {
            express: "express.Application",
            "express.default": "express.Application",
            "express.Router": "express.Router",
            ws: "ws.WebSocket",
            "ws.WebSocket": "ws.WebSocket",
            "ws.Server": "ws.WebSocketServer",
            "ws.WebSocketServer": "ws.WebSocketServer",
            "events.EventEmitter": "events.EventEmitter",
            "stream.PassThrough": "stream.PassThrough",
            "axios.create": "axios",
        };
        if (factories[api]) return factories[api];
        if (api === "express.Application.route" || api === "express.Router.route") return "express.Route";
        const member = api.slice(api.lastIndexOf(".") + 1);
        const receiver = api.slice(0, api.lastIndexOf("."));
        const fluent = ["express.Application", "express.Router", "express.Route"];
        if (
            fluent.includes(receiver) &&
            ["use", "get", "post", "put", "delete", "patch", "head", "options", "all", "on", "route"].includes(member)
        ) {
            // Express get(name) reads a setting rather than returning the app.
            if (receiver === "express.Application" && member === "get" && (expression.arguments?.length ?? 0) < 2)
                return undefined;
            return receiver;
        }
        return undefined;
    }

    /** Only declarations with a package or ambient-module origin establish a type identity. */
    private declaredTypeName(expr: ts.Expression): string | undefined {
        const type = this.checker.getTypeAtLocation(expr);
        const symbol = type.getSymbol() ?? type.aliasSymbol;
        if (!symbol) return undefined;
        for (const declaration of symbol.declarations ?? []) {
            const file = declaration.getSourceFile();
            if (!file.isDeclarationFile) continue;
            if (file.hasNoDefaultLib) return symbol.getName();
            if (ts.isModuleDeclaration(declaration) && ts.isStringLiteral(declaration.name)) {
                return canonicalModuleApiName(declaration.name.text);
            }
            let module: string | undefined;
            for (let parent: ts.Node | undefined = declaration.parent; parent; parent = parent.parent) {
                if (ts.isModuleDeclaration(parent) && ts.isStringLiteral(parent.name)) {
                    module = parent.name.text;
                    break;
                }
            }
            if (module == null) {
                const packagePaths = [
                    ...file.fileName.replace(/\\/g, "/").matchAll(/\/node_modules\/(?:@types\/)?((?:@[^/]+\/)?[^/]+)/g),
                ];
                // A dependency's nested @types package owns its declarations,
                // not the package whose node_modules directory contains it.
                module = packagePaths[packagePaths.length - 1]?.[1];
            }
            if (!module) continue;
            const declaredName =
                symbol.getName().startsWith("__") &&
                ts.isVariableDeclaration(declaration.parent) &&
                ts.isIdentifier(declaration.parent.name)
                    ? declaration.parent.name.text
                    : symbol.getName();
            const name = canonicalModuleApiName(`${module}.${declaredName}`);
            const aliases: Record<string, string> = {
                "electron.IpcMain": "electron.ipcMain",
                "electron.App": "electron.app",
                "electron.Shell": "electron.shell",
                "express-ws.Application": "express.Application",
                "express-ws.Router": "express.Router",
                "axios.AxiosStatic": "axios",
                "axios.AxiosInstance": "axios",
                "axios.axios": "axios",
                "express.Express": "express.Application",
                "express.e": "express",
            };
            return aliases[name] ?? name;
        }
        return undefined;
    }

    /** A module namespace is available after awaiting a literal import, not on its Promise. */
    private awaitedImportName(expr: ts.Expression, seen: Set<ts.Symbol>): string | undefined {
        const value = unwrapExpression(expr);
        if (
            ts.isCallExpression(value) &&
            value.expression.kind === ts.SyntaxKind.ImportKeyword &&
            value.arguments.length === 1 &&
            ts.isStringLiteralLike(value.arguments[0])
        ) {
            return value.arguments[0].text;
        }
        if (!ts.isIdentifier(value)) return undefined;
        const symbol = this.checker.getSymbolAtLocation(value);
        if (!symbol || seen.has(symbol)) return undefined;
        seen.add(symbol);
        const declaration = symbol.valueDeclaration;
        return declaration &&
            ts.isVariableDeclaration(declaration) &&
            declaration.initializer &&
            ts.isVariableDeclarationList(declaration.parent) &&
            (declaration.parent.flags & ts.NodeFlags.Const) !== 0
            ? this.awaitedImportName(declaration.initializer, seen)
            : undefined;
    }

    /** Import and global declarations retain API identity when aliases or package types obscure it. */
    private resolveImportedName(expr: ts.Expression, seen: Set<ts.Symbol>): string | undefined {
        const value = unwrapExpression(expr);
        if (ts.isAwaitExpression(value)) return this.awaitedImportName(value.expression, seen);
        if (
            ts.isCallExpression(value) &&
            ts.isIdentifier(value.expression) &&
            value.expression.text === "require" &&
            value.arguments.length === 1 &&
            ts.isStringLiteralLike(value.arguments[0])
        ) {
            const requireSymbol = this.checker.getSymbolAtLocation(value.expression);
            if (!requireSymbol || requireSymbol.declarations?.every((decl) => decl.getSourceFile().isDeclarationFile)) {
                return value.arguments[0].text;
            }
            return undefined;
        }
        if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
            const base = this.resolveImportedName(value.expression, seen);
            const name = ts.isPropertyAccessExpression(value)
                ? value.name.text
                : ts.isStringLiteralLike(value.argumentExpression)
                  ? value.argumentExpression.text
                  : undefined;
            return base != null && name != null ? `${base}.${name}` : undefined;
        }
        if (!ts.isIdentifier(value)) return undefined;
        const symbol = this.checker.getSymbolAtLocation(value);
        if (
            value.text === "process" &&
            (!symbol || symbol.declarations?.some((decl) => decl.getSourceFile().isDeclarationFile))
        )
            return "process";
        if (symbol?.declarations?.some((decl) => decl.getSourceFile().hasNoDefaultLib)) return value.text;
        if (!symbol || seen.has(symbol)) return undefined;
        seen.add(symbol);
        for (const declaration of symbol.declarations ?? []) {
            if (
                ts.isImportEqualsDeclaration(declaration) &&
                ts.isExternalModuleReference(declaration.moduleReference) &&
                declaration.moduleReference.expression &&
                ts.isStringLiteralLike(declaration.moduleReference.expression)
            ) {
                return declaration.moduleReference.expression.text;
            }
            if (ts.isBindingElement(declaration)) {
                const properties: string[] = [];
                let binding: ts.BindingElement = declaration;
                while (!binding.dotDotDotToken) {
                    const property = binding.propertyName ?? binding.name;
                    if (!ts.isIdentifier(property) && !ts.isStringLiteralLike(property)) break;
                    properties.unshift(property.text);
                    const owner = binding.parent.parent;
                    if (
                        ts.isVariableDeclaration(owner) &&
                        owner.initializer &&
                        ts.isVariableDeclarationList(owner.parent) &&
                        (owner.parent.flags & ts.NodeFlags.Const) !== 0
                    ) {
                        const base = this.resolveImportedName(owner.initializer, seen);
                        if (base != null) return [base, ...properties].join(".");
                        break;
                    }
                    if (!ts.isBindingElement(owner)) break;
                    binding = owner;
                }
            }
            if (
                ts.isImportSpecifier(declaration) ||
                ts.isNamespaceImport(declaration) ||
                ts.isImportClause(declaration)
            ) {
                let node: ts.Node = declaration;
                while (node.parent && !ts.isImportDeclaration(node)) node = node.parent;
                if (!ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) continue;
                const module = node.moduleSpecifier.text;
                return ts.isImportSpecifier(declaration)
                    ? `${module}.${(declaration.propertyName ?? declaration.name).text}`
                    : module;
            }
            if (
                ts.isVariableDeclaration(declaration) &&
                declaration.initializer &&
                ts.isVariableDeclarationList(declaration.parent) &&
                (declaration.parent.flags & ts.NodeFlags.Const) !== 0
            ) {
                return this.resolveImportedName(declaration.initializer, seen);
            }
        }
        return undefined;
    }

    hasExternalRoot(expr: ts.Expression): boolean {
        const cached = this.externalRoots.get(expr);
        if (cached != null) return cached;
        let external = this.importedName(expr) != null;
        if (!external) {
            let root = unwrapExpression(expr);
            while (ts.isPropertyAccessExpression(root) || ts.isElementAccessExpression(root)) {
                root = unwrapExpression(root.expression);
            }
            const symbol = this.checker.getSymbolAtLocation(root);
            external = !symbol || symbol.declarations?.some((decl) => decl.getSourceFile().isDeclarationFile) === true;
        }
        this.externalRoots.set(expr, external);
        return external;
    }
}
