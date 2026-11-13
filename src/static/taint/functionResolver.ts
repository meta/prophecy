/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";

/**
 * Strip syntax-only wrappers that preserve an expression's runtime value.
 * Runtime operations such as `await` remain intact.
 */
export function unwrapExpression(expression: ts.Expression): ts.Expression {
    let value = expression;
    while (
        ts.isParenthesizedExpression(value) ||
        ts.isAsExpression(value) ||
        ts.isTypeAssertionExpression(value) ||
        ts.isNonNullExpression(value) ||
        ts.isSatisfiesExpression(value)
    ) {
        value = value.expression;
    }
    return value;
}

/**
 * Return the syntactic dotted name used for heuristic matching, such as
 * `child_process.exec`. Expressions outside identifier/property chains fall
 * back to their source text.
 */
export function getCallChainName(expression: ts.Expression): string {
    if (ts.isIdentifier(expression)) return expression.text;
    if (ts.isPropertyAccessExpression(expression)) {
        return `${getCallChainName(expression.expression)}.${expression.name.text}`;
    }
    return expression.getText();
}

/** The `extends` expression of the class whose constructor makes this `super(...)` call. */
export function superClassExpression(call: ts.CallExpression): ts.Expression | undefined {
    return ts
        .findAncestor(call, ts.isClassLike)
        ?.heritageClauses?.find((clause) => clause.token === ts.SyntaxKind.ExtendsKeyword)?.types[0]?.expression;
}

/**
 * The symbol that reads of the parameter inside the function body resolve to.
 * For a constructor parameter property, `getSymbolAtLocation(param.name)`
 * returns the class property, which only `this.name` reads resolve to.
 */
export function parameterSymbol(checker: ts.TypeChecker, param: ts.ParameterDeclaration): ts.Symbol | undefined {
    if (ts.isIdentifier(param.name) && ts.isParameterPropertyDeclaration(param, param.parent)) {
        return checker.getSymbolsOfParameterPropertyDeclaration(param, param.name.text)[0];
    }
    return checker.getSymbolAtLocation(param.name);
}

/**
 * Resolve an inline arrow/function expression, identifier or alias, method,
 * property initializer, or object-property reference to its function-like
 * declaration. Object properties resolve through spreads, casts, imports, and
 * variables that name another object or function. Dynamic forms that cannot be
 * resolved return undefined.
 */
export function resolveFunctionReference(
    checker: ts.TypeChecker,
    expr: ts.Expression,
    seen: Set<ts.Node | ts.Symbol> = new Set(),
): ts.FunctionLikeDeclaration | undefined {
    expr = unwrapExpression(expr);
    if (ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)) {
        return expr;
    }
    // A property can name a function that names the property again; stop at the cycle.
    if (seen.has(expr)) return undefined;
    seen.add(expr);

    let symbol: ts.Symbol | undefined;

    if (ts.isIdentifier(expr)) {
        symbol = checker.getSymbolAtLocation(expr);
    } else if (ts.isPropertyAccessExpression(expr)) {
        const propertyFunction = resolveObjectPropertyFunction(checker, expr, seen);
        if (propertyFunction) return propertyFunction;
        symbol = checker.getSymbolAtLocation(expr.name);
    }

    return symbol && resolveSymbolFunction(checker, symbol, seen);
}

function resolveSymbolFunction(
    checker: ts.TypeChecker,
    symbol: ts.Symbol,
    seen: Set<ts.Node | ts.Symbol>,
): ts.FunctionLikeDeclaration | undefined {
    if (symbol.flags & ts.SymbolFlags.Alias) {
        symbol = checker.getAliasedSymbol(symbol);
    }

    if (seen.has(symbol)) return undefined;
    seen.add(symbol);
    const declarations = symbol.getDeclarations();
    if (!declarations || declarations.length === 0) return undefined;

    let declarationWithoutBody: ts.FunctionLikeDeclaration | undefined;
    for (const decl of declarations) {
        if (
            ts.isFunctionDeclaration(decl) ||
            ts.isMethodDeclaration(decl) ||
            ts.isArrowFunction(decl) ||
            ts.isFunctionExpression(decl)
        ) {
            if (decl.body) return decl;
            declarationWithoutBody ??= decl;
        }

        if (ts.isVariableDeclaration(decl) && decl.initializer) {
            if (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer)) {
                return decl.initializer;
            }
            // `const run = Registry.runTool;` names a function held elsewhere.
            const aliased = resolveFunctionReference(checker, decl.initializer, seen);
            if (aliased) return aliased;
        }

        if (ts.isPropertyAssignment(decl)) {
            const initializer = decl.initializer;
            if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
                return initializer;
            }
        }

        if (ts.isPropertyDeclaration(decl) && decl.initializer) {
            const initializer = decl.initializer;
            if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
                return initializer;
            }
        }
    }

    return declarationWithoutBody;
}

/** The function an identifier or property-access initializer names, through casts. */
function resolveAliasedFunction(
    checker: ts.TypeChecker,
    initializer: ts.Expression,
    seen: Set<ts.Node | ts.Symbol>,
): ts.FunctionLikeDeclaration | undefined {
    const value = unwrapExpression(initializer);
    if (!ts.isIdentifier(value) && !ts.isPropertyAccessExpression(value)) return undefined;
    return resolveFunctionReference(checker, value, seen);
}

/**
 * The function a class or object-literal member holds: a method, or a property
 * initialized with an arrow or function expression (`handleUri = (uri) => {}`),
 * which callers invoke the same way.
 */
export function memberFunction(
    member: ts.ClassElement | ts.ObjectLiteralElementLike,
): ts.FunctionLikeDeclaration | undefined {
    if (ts.isMethodDeclaration(member)) return member;
    if ((ts.isPropertyDeclaration(member) || ts.isPropertyAssignment(member)) && member.initializer) {
        const initializer = unwrapExpression(member.initializer);
        if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
            return initializer;
        }
    }
    return undefined;
}

/**
 * Resolve a string literal through declaration initializers and imports,
 * including variable, property, parameter-default, and enum initializers.
 * This does not prove the runtime value: writes and supplied arguments are
 * not considered.
 */
export function resolveStaticString(
    checker: ts.TypeChecker,
    expression: ts.Expression,
    seen: Set<ts.Symbol> = new Set(),
): string | undefined {
    expression = unwrapExpression(expression);

    if (ts.isStringLiteralLike(expression)) return expression.text;

    let symbol = checker.getSymbolAtLocation(expression);
    if (!symbol || seen.has(symbol)) return undefined;
    if (symbol.flags & ts.SymbolFlags.Alias) {
        symbol = checker.getAliasedSymbol(symbol);
    }
    if (seen.has(symbol)) return undefined;
    seen.add(symbol);

    for (const declaration of symbol.getDeclarations() ?? []) {
        let initializer: ts.Expression | undefined;
        if (
            ts.isVariableDeclaration(declaration) ||
            ts.isPropertyDeclaration(declaration) ||
            ts.isPropertyAssignment(declaration) ||
            ts.isParameter(declaration)
        ) {
            initializer = declaration.initializer;
        } else if (ts.isEnumMember(declaration) && declaration.initializer) {
            initializer = declaration.initializer;
        }

        if (initializer) {
            const value = resolveStaticString(checker, initializer, new Set(seen));
            if (value != null) return value;
        }
    }
    return undefined;
}

function resolveObjectPropertyFunction(
    checker: ts.TypeChecker,
    expr: ts.PropertyAccessExpression,
    seen: Set<ts.Node | ts.Symbol>,
): ts.FunctionLikeDeclaration | undefined {
    const literal = objectLiteralForExpression(checker, expr.expression, new Set());
    const prop = literal && findObjectLiteralProperty(checker, literal, expr.name.text, new Set());
    if (!prop) return undefined;

    if (ts.isMethodDeclaration(prop)) return prop;
    if (ts.isPropertyAssignment(prop)) {
        const initializer = unwrapExpression(prop.initializer);
        if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
            return initializer;
        }
        return resolveAliasedFunction(checker, initializer, seen);
    }
    if (ts.isShorthandPropertyAssignment(prop)) {
        const value = checker.getShorthandAssignmentValueSymbol(prop);
        return value ? resolveSymbolFunction(checker, value, seen) : resolveFunctionReference(checker, prop.name, seen);
    }
    return undefined;
}

/**
 * The object literal an expression evaluates to: the literal itself, or the
 * initializer of the variable it names, through imports, casts, and other
 * variables (`const Registry = registryImpl as Partial<typeof registryImpl>`).
 * Writes after initialization are not considered.
 */
function objectLiteralForExpression(
    checker: ts.TypeChecker,
    expression: ts.Expression,
    seen: Set<ts.Symbol>,
): ts.ObjectLiteralExpression | undefined {
    const value = unwrapExpression(expression);
    if (ts.isObjectLiteralExpression(value)) return value;
    if (!ts.isIdentifier(value)) return undefined;

    let symbol = checker.getSymbolAtLocation(value);
    if (symbol && symbol.flags & ts.SymbolFlags.Alias) {
        symbol = checker.getAliasedSymbol(symbol);
    }
    if (!symbol || seen.has(symbol)) return undefined;
    seen.add(symbol);

    for (const decl of symbol.getDeclarations() ?? []) {
        if (!ts.isVariableDeclaration(decl) || !decl.initializer) continue;
        const literal = objectLiteralForExpression(checker, decl.initializer, seen);
        if (literal) return literal;
    }
    return undefined;
}

/**
 * The member of an object literal that defines `name`, including members of
 * spread objects (`{ ...Registry }`). Later members override earlier ones and
 * spreads. A spread that cannot be resolved is skipped, so a member it might
 * override is still returned.
 */
function findObjectLiteralProperty(
    checker: ts.TypeChecker,
    literal: ts.ObjectLiteralExpression,
    name: string,
    seen: Set<ts.Symbol>,
): ts.ObjectLiteralElementLike | undefined {
    for (let i = literal.properties.length - 1; i >= 0; i--) {
        const prop = literal.properties[i];
        if (ts.isSpreadAssignment(prop)) {
            const spreadSeen = new Set(seen);
            const spread = objectLiteralForExpression(checker, prop.expression, spreadSeen);
            const found = spread && findObjectLiteralProperty(checker, spread, name, spreadSeen);
            if (found) return found;
            continue;
        }
        if (objectPropertyName(prop.name) === name) return prop;
    }
    return undefined;
}

function objectPropertyName(name: ts.PropertyName | undefined): string | undefined {
    if (name == null) return undefined;
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) {
        return name.text;
    }
    return undefined;
}

export interface CommandRegistration {
    command: ts.Expression;
    handler: ts.Expression;
    /** Handler parameter receiving the first VS Code command argument. */
    handlerParamOffset: number;
}

interface CommandRegistrationSummary {
    commandParamIndex: number;
    handlerParamIndex: number;
    handlerParamOffset: number;
}

const commandRegistrationResolvers = new WeakMap<ts.TypeChecker, CommandRegistrationResolver>();

/**
 * Resolve direct VS Code command registrations and statically unambiguous
 * forwarding chains. Cyclic, dynamic, or ambiguous forms return undefined;
 * successful results contain expressions from the original call site.
 */
export function resolveCommandRegistration(
    checker: ts.TypeChecker,
    call: ts.CallExpression,
): CommandRegistration | undefined {
    let resolver = commandRegistrationResolvers.get(checker);
    if (!resolver) {
        resolver = new CommandRegistrationResolver(checker);
        commandRegistrationResolvers.set(checker, resolver);
    }
    return resolver.resolve(call);
}

class CommandRegistrationResolver {
    private callCache = new WeakMap<ts.CallExpression, CommandRegistration | null>();
    private directSymbolCache = new WeakMap<ts.Symbol, boolean>();
    private summaryCache = new WeakMap<ts.FunctionLikeDeclaration, CommandRegistrationSummary | null>();
    private resolving = new Set<ts.FunctionLikeDeclaration>();

    constructor(private checker: ts.TypeChecker) {}

    resolve(call: ts.CallExpression): CommandRegistration | undefined {
        const cached = this.callCache.get(call);
        if (cached !== undefined) return cached ?? undefined;

        const registration = this.resolveUncached(call);
        this.callCache.set(call, registration ?? null);
        return registration;
    }

    private resolveUncached(call: ts.CallExpression): CommandRegistration | undefined {
        if (this.isDirectVSCodeRegisterCommand(call.expression)) {
            if (call.arguments.length < 2) return undefined;
            return {
                command: call.arguments[0],
                handler: call.arguments[1],
                handlerParamOffset: 0,
            };
        }

        const target = resolveFunctionReference(this.checker, call.expression);
        if (!target?.body) return undefined;

        const summary = this.summarize(target);
        if (!summary) return undefined;
        if (call.arguments.length <= summary.commandParamIndex || call.arguments.length <= summary.handlerParamIndex) {
            return undefined;
        }
        return {
            command: call.arguments[summary.commandParamIndex],
            handler: call.arguments[summary.handlerParamIndex],
            handlerParamOffset: summary.handlerParamOffset,
        };
    }

    private summarize(fn: ts.FunctionLikeDeclaration): CommandRegistrationSummary | undefined {
        const cached = this.summaryCache.get(fn);
        if (cached !== undefined) return cached ?? undefined;
        if (!fn.body || this.resolving.has(fn)) return undefined;

        this.resolving.add(fn);
        let summary: CommandRegistrationSummary | undefined;
        let ambiguous = false;

        const stack: ts.Node[] = [fn.body];
        while (stack.length > 0 && !ambiguous) {
            const node = stack.pop()!;
            if (ts.isCallExpression(node)) {
                const registration = this.resolve(node);
                if (registration) {
                    const commandParamIndex = this.parameterIndex(fn, registration.command);
                    const handler = this.resolveForwardedHandler(
                        fn,
                        registration.handler,
                        registration.handlerParamOffset,
                    );
                    if (commandParamIndex != null && handler) {
                        const candidate = {
                            commandParamIndex,
                            ...handler,
                        };
                        if (summary && !this.sameSummary(summary, candidate)) {
                            ambiguous = true;
                        } else {
                            summary = candidate;
                        }
                    }
                }
            }
            node.forEachChild((child) => {
                stack.push(child);
            });
        }

        this.resolving.delete(fn);
        const result = ambiguous ? undefined : summary;
        this.summaryCache.set(fn, result ?? null);
        return result;
    }

    private resolveForwardedHandler(
        wrapper: ts.FunctionLikeDeclaration,
        expression: ts.Expression,
        registeredOffset: number,
    ): Pick<CommandRegistrationSummary, "handlerParamIndex" | "handlerParamOffset"> | undefined {
        const handlerParamIndex = this.parameterIndex(wrapper, expression);
        if (handlerParamIndex != null) {
            return {
                handlerParamIndex,
                handlerParamOffset: registeredOffset,
            };
        }

        const registeredHandler = resolveFunctionReference(this.checker, expression);
        if (!registeredHandler?.body) return undefined;

        const registeredParamSymbols = registeredHandler.parameters.map((param) =>
            this.checker.getSymbolAtLocation(param.name),
        );
        let forwarded: Pick<CommandRegistrationSummary, "handlerParamIndex" | "handlerParamOffset"> | undefined;
        let ambiguous = false;
        const stack: ts.Node[] = [registeredHandler.body];
        while (stack.length > 0 && !ambiguous) {
            const node = stack.pop()!;
            if (ts.isCallExpression(node)) {
                const callbackParamIndex = this.parameterIndex(wrapper, node.expression);
                if (callbackParamIndex != null) {
                    const callbackOffset = this.forwardedParameterOffset(
                        node,
                        registeredParamSymbols,
                        registeredOffset,
                    );
                    if (callbackOffset != null) {
                        const candidate = {
                            handlerParamIndex: callbackParamIndex,
                            handlerParamOffset: callbackOffset,
                        };
                        if (forwarded && !this.sameHandler(forwarded, candidate)) {
                            ambiguous = true;
                        } else {
                            forwarded = candidate;
                        }
                    }
                }
            }
            node.forEachChild((child) => {
                stack.push(child);
            });
        }
        return ambiguous ? undefined : forwarded;
    }

    private forwardedParameterOffset(
        call: ts.CallExpression,
        registeredParamSymbols: (ts.Symbol | undefined)[],
        registeredOffset: number,
    ): number | undefined {
        for (let i = 0; i < call.arguments.length; i++) {
            const argument = call.arguments[i];
            const value = ts.isSpreadElement(argument) ? argument.expression : argument;
            const symbol = this.symbolAt(value);
            if (!symbol) continue;
            const parameterIndex = registeredParamSymbols.indexOf(symbol);
            if (parameterIndex < 0 || parameterIndex > registeredOffset) continue;
            if (ts.isSpreadElement(argument)) {
                // A spread handler parameter forwards a suffix of command
                // arguments. Explicit arguments before the spread, plus the
                // inner wrapper's offset, determine where that suffix starts.
                return i + registeredOffset - parameterIndex;
            }
            if (parameterIndex === registeredOffset) return i;
        }
        return undefined;
    }

    private parameterIndex(fn: ts.FunctionLikeDeclaration, expression: ts.Expression): number | undefined {
        const symbol = this.symbolAt(expression);
        if (!symbol) return undefined;
        for (let i = 0; i < fn.parameters.length; i++) {
            const parameterSymbol = this.checker.getSymbolAtLocation(fn.parameters[i].name);
            if (parameterSymbol === symbol) return i;
        }
        return undefined;
    }

    private symbolAt(expression: ts.Expression): ts.Symbol | undefined {
        const value = unwrapExpression(expression);
        let symbol = this.checker.getSymbolAtLocation(value);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
            symbol = this.checker.getAliasedSymbol(symbol);
        }
        return symbol;
    }

    private isDirectVSCodeRegisterCommand(expression: ts.Expression, seen: Set<ts.Symbol> = new Set()): boolean {
        const value = unwrapExpression(expression);
        let symbol = this.checker.getSymbolAtLocation(ts.isPropertyAccessExpression(value) ? value.name : value);
        if (symbol?.flags && symbol.flags & ts.SymbolFlags.Alias) {
            symbol = this.checker.getAliasedSymbol(symbol);
        }
        if (symbol) {
            let direct = this.directSymbolCache.get(symbol);
            if (direct === undefined) {
                const fqn = this.checker.getFullyQualifiedName(symbol).replace(/^"([^"]+)"\./, "$1.");
                direct = fqn === "vscode.commands.registerCommand";
                this.directSymbolCache.set(symbol, direct);
            }
            if (direct) return true;

            if (!seen.has(symbol)) {
                seen.add(symbol);
                for (const declaration of symbol.getDeclarations() ?? []) {
                    if (
                        ts.isVariableDeclaration(declaration) &&
                        declaration.initializer &&
                        this.isDirectVSCodeRegisterCommand(declaration.initializer, new Set(seen))
                    ) {
                        return true;
                    }
                }
            }
        }

        return (
            ts.isPropertyAccessExpression(value) &&
            value.name.text === "registerCommand" &&
            ts.isPropertyAccessExpression(value.expression) &&
            value.expression.name.text === "commands" &&
            ts.isIdentifier(value.expression.expression) &&
            value.expression.expression.text === "vscode"
        );
    }

    private sameSummary(left: CommandRegistrationSummary, right: CommandRegistrationSummary): boolean {
        return left.commandParamIndex === right.commandParamIndex && this.sameHandler(left, right);
    }

    private sameHandler(
        left: Pick<CommandRegistrationSummary, "handlerParamIndex" | "handlerParamOffset">,
        right: Pick<CommandRegistrationSummary, "handlerParamIndex" | "handlerParamOffset">,
    ): boolean {
        return (
            left.handlerParamIndex === right.handlerParamIndex && left.handlerParamOffset === right.handlerParamOffset
        );
    }
}
