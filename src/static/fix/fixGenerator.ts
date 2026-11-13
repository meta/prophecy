/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import { TaintFinding, FixSuggestion, FixStrategy } from "../spec/types";
import { resolveFixStrategy } from "./fixStrategy";

export type FixStrategyProvider = FixStrategy[] | ((finding: TaintFinding) => FixStrategy[] | undefined);

/** Attach generated fixes to findings in place and return the number attached. */
export function generateFixes(
    findings: TaintFinding[],
    fileContents: Map<string, string>,
    specOverrides?: FixStrategyProvider,
): number {
    let fixCount = 0;
    const parsedFiles = new Map<string, ts.SourceFile>();
    for (const finding of findings) {
        const overrides = typeof specOverrides === "function" ? specOverrides(finding) : specOverrides;
        const fix = generateFixWithCache(finding, fileContents, overrides, parsedFiles);
        if (fix) {
            finding.fix = fix;
            fixCount++;
        }
    }
    return fixCount;
}

export function generateFix(
    finding: TaintFinding,
    fileContents: Map<string, string>,
    specOverrides?: FixStrategy[],
): FixSuggestion | undefined {
    return generateFixWithCache(finding, fileContents, specOverrides);
}

function generateFixWithCache(
    finding: TaintFinding,
    fileContents: Map<string, string>,
    specOverrides?: FixStrategy[],
    parsedFiles?: Map<string, ts.SourceFile>,
): FixSuggestion | undefined {
    const strategy = resolveFixStrategy(finding.sink, specOverrides);
    if (!strategy || strategy.applicability === "unfixable") return undefined;

    const content = fileContents.get(finding.sinkLocation.fileName);
    if (!content) return undefined;

    const fileName = finding.sinkLocation.fileName;
    let sourceFile = parsedFiles?.get(fileName);
    if (!sourceFile) {
        sourceFile = ts.createSourceFile(fileName, content, ts.ScriptTarget.ES2020, true);
        parsedFiles?.set(fileName, sourceFile);
    }
    const result = buildReplacement(finding, sourceFile, strategy);
    if (!result) return undefined;
    const replacementFile = ts.createSourceFile("replacement.ts", result.replacement, ts.ScriptTarget.ES2020);
    if (
        (replacementFile as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics.length > 0
    ) {
        return undefined;
    }

    return {
        filePath: finding.sinkLocation.fileName,
        original: result.original,
        replacement: result.replacement,
        line: finding.sinkLocation.line,
        column: finding.sinkLocation.column,
        applicability: strategy.applicability,
        description: strategy.description,
    };
}

interface ReplacementPair {
    original: string;
    replacement: string;
}

function buildReplacement(
    finding: TaintFinding,
    sourceFile: ts.SourceFile,
    strategy: FixStrategy,
): ReplacementPair | undefined {
    const targetPos = getPositionFromLineColumn(sourceFile, finding.sinkLocation.line, finding.sinkLocation.column);
    if (targetPos < 0) return undefined;

    const callNode = findCallOrNewExpressionAt(sourceFile, targetPos);
    if (!callNode) return undefined;

    const sinkName = finding.sink.name;
    const nsAlias = strategy.importPackage ? findNamespaceAlias(sourceFile, strategy.importPackage) : undefined;

    if (sinkName === "exec" || sinkName === "execSync") {
        // A callback-style execFile cannot stand in for an awaited promisified exec.
        if (finding.promisified) return undefined;
        return buildExecToExecFileReplacement(callNode, sourceFile, sinkName, nsAlias);
    }

    if (sinkName === "ShellExecution") {
        return buildShellToProcessExecution(callNode, sourceFile, nsAlias);
    }

    if (sinkName === "sendText" && strategy.importName) {
        return buildWrapArgReplacement(
            callNode,
            sourceFile,
            finding.sink.argPositions || [0],
            strategy.importName,
            nsAlias,
        );
    }

    if (strategy.importName) {
        return buildWrapArgReplacement(
            callNode,
            sourceFile,
            finding.sink.argPositions || [0],
            strategy.importName,
            nsAlias,
        );
    }

    return undefined;
}

function buildExecToExecFileReplacement(
    callNode: ts.CallExpression | ts.NewExpression,
    sourceFile: ts.SourceFile,
    sinkName: string,
    nsAlias?: string,
): ReplacementPair | undefined {
    if (!ts.isCallExpression(callNode)) return undefined;
    const args = callNode.arguments;
    if (args.length === 0) return undefined;

    const cmdArg = args[0];
    const cmdText = cmdArg.getText(sourceFile);
    const original = callNode.getText(sourceFile);

    const bareName = sinkName === "exec" ? "execFile" : "execFileSync";
    const replacementName = nsAlias ? `${nsAlias}.${bareName}` : bareName;
    const trailingArgs = args.slice(1).map((arg) => arg.getText(sourceFile));
    if (args[1]) {
        const options = args[1];
        const isCallback = ts.isArrowFunction(options) || ts.isFunctionExpression(options);
        if (sinkName === "exec" && args.length === 2 && !isCallback && !ts.isObjectLiteralExpression(options)) {
            // An unresolved second argument may be either options or a callback.
            return undefined;
        }
        if (sinkName === "execSync" || !isCallback) {
            trailingArgs[0] = `{ ...(${trailingArgs[0]}), shell: false }`;
        }
    }
    const restArgs = trailingArgs.length > 0 ? ", " + trailingArgs.join(", ") : "";

    if (ts.isTemplateExpression(cmdArg) || ts.isStringLiteralLike(cmdArg)) {
        const words = splitCommandWords(cmdArg);
        if (!words || words.length === 0 || words[0].some((part) => typeof part !== "string")) {
            return undefined;
        }
        const program = words[0].join("");
        if (!program) return undefined;
        const allArgs = words
            .slice(1)
            .map((word) =>
                word.length === 0
                    ? '""'
                    : word
                          .map((part) =>
                              typeof part === "string"
                                  ? JSON.stringify(part)
                                  : "`${(" + part.getText(sourceFile) + ")}`",
                          )
                          .join(" + "),
            );
        const replacement = `${replacementName}(${JSON.stringify(program)}, [${allArgs.join(", ")}]${restArgs})`;
        return { original, replacement };
    }

    // Variable/expression — can't split, suggest execFile with placeholder
    const replacement = `${replacementName}(${cmdText} /* split into program, [args] */, []${restArgs})`;
    return { original, replacement };
}

/** Quoted words and interpolation boundaries; shell expansion and operators require a manual rewrite. */
function splitCommandWords(
    command: ts.TemplateExpression | ts.StringLiteralLike,
): (string | ts.Expression)[][] | undefined {
    const words: (string | ts.Expression)[][] = [];
    let word: (string | ts.Expression)[] = [];
    let text = "";
    let active = false;
    let quote: string | undefined;
    const flushText = () => {
        if (text) word.push(text);
        text = "";
    };
    const flushWord = () => {
        flushText();
        if (active) words.push(word);
        word = [];
        active = false;
    };
    const consume = (literal: string): boolean => {
        for (const char of literal) {
            if (char === "\\" || char === "$" || char === "`") return false;
            if (quote) {
                if (char === quote) quote = undefined;
                else text += char;
            } else if (char === "'" || char === '"') {
                quote = char;
                active = true;
            } else if (char === " " || char === "\t") {
                flushWord();
            } else {
                if (/[|&;<>()*?[\]#~\r\n]/.test(char)) return false;
                text += char;
                active = true;
            }
        }
        return true;
    };
    if (ts.isTemplateExpression(command)) {
        if (!consume(command.head.text)) return undefined;
        for (const span of command.templateSpans) {
            flushText();
            word.push(span.expression);
            active = true;
            if (!consume(span.literal.text)) return undefined;
        }
    } else if (!consume(command.text)) {
        return undefined;
    }
    if (quote) return undefined;
    flushWord();
    return words;
}

function buildShellToProcessExecution(
    callNode: ts.CallExpression | ts.NewExpression,
    sourceFile: ts.SourceFile,
    nsAlias?: string,
): ReplacementPair | undefined {
    const args = callNode.arguments;
    if (!args || args.length === 0) return undefined;

    const cmdArg = args[0];
    const cmdText = cmdArg.getText(sourceFile);
    const original = callNode.getText(sourceFile);

    const name = nsAlias ? `${nsAlias}.ProcessExecution` : "ProcessExecution";
    const replacement = `new ${name}(${cmdText} /* split into program, [args] */, [])`;
    return { original, replacement };
}

function buildWrapArgReplacement(
    callNode: ts.CallExpression | ts.NewExpression,
    sourceFile: ts.SourceFile,
    argPositions: number[],
    wrapperName: string,
    nsAlias?: string,
): ReplacementPair | undefined {
    const args = callNode.arguments;
    if (!args) return undefined;

    const pos = argPositions[0] ?? 0;
    if (pos >= args.length) return undefined;

    const qualifiedWrapper = nsAlias ? `${nsAlias}.${wrapperName}` : wrapperName;
    const original = callNode.getText(sourceFile);
    const newArgs = args.map((arg, i) => {
        if (i === pos) {
            const argText = arg.getText(sourceFile);
            return qualifiedWrapper === "quote" || qualifiedWrapper.endsWith(".quote")
                ? `${qualifiedWrapper}([${argText}])`
                : `${qualifiedWrapper}(${argText})`;
        }
        return arg.getText(sourceFile);
    });

    const callee = ts.isCallExpression(callNode)
        ? callNode.expression.getText(sourceFile)
        : `new ${callNode.expression!.getText(sourceFile)}`;
    const replacement = `${callee}(${newArgs.join(", ")})`;
    return { original, replacement };
}

export function generateImportFix(
    strategy: FixStrategy,
    filePath: string,
    fileContent: string,
    importNames: readonly string[] = strategy.importName ? [strategy.importName] : [],
): FixSuggestion | undefined {
    if (!strategy.importPackage || importNames.length === 0) return undefined;
    let missingNames = [...new Set(importNames)];

    const sourceFile = ts.createSourceFile(filePath, fileContent, ts.ScriptTarget.ES2020, true);

    let target: { statement: ts.ImportDeclaration; bindings: ts.NamedImports } | undefined;
    for (const stmt of sourceFile.statements) {
        if (
            !ts.isImportDeclaration(stmt) ||
            !ts.isStringLiteral(stmt.moduleSpecifier) ||
            stmt.moduleSpecifier.text !== strategy.importPackage
        )
            continue;
        const bindings = stmt.importClause?.namedBindings;
        // Namespace imports are used as alias.name by the call replacement.
        if (bindings && ts.isNamespaceImport(bindings)) return undefined;
        if (!bindings || !ts.isNamedImports(bindings)) continue;
        const names = bindings.elements.map((element) => element.name.text);
        missingNames = missingNames.filter((name) => !names.includes(name));
        target ??= { statement: stmt, bindings };
    }
    if (missingNames.length === 0) return undefined;

    if (target) {
        const { statement, bindings } = target;
        const existingImport = statement.getText(sourceFile);
        const last = bindings.elements[bindings.elements.length - 1];
        // Insert at the AST token boundary, before trailing comments and commas.
        const offset = (last?.getEnd() ?? bindings.getStart(sourceFile) + 1) - statement.getStart(sourceFile);
        const addition = last ? `, ${missingNames.join(", ")}` : ` ${missingNames.join(", ")} `;
        return {
            filePath,
            original: existingImport,
            replacement: existingImport.slice(0, offset) + addition + existingImport.slice(offset),
            line: sourceFile.getLineAndCharacterOfPosition(statement.getStart()).line + 1,
            column: 1,
            applicability: strategy.applicability,
            description: `Add ${missingNames.join(", ")} to existing "${strategy.importPackage}" import`,
        };
    }

    const importText = `import { ${missingNames.join(", ")} } from "${strategy.importPackage}";\n`;

    let insertLine = 1;
    for (const stmt of sourceFile.statements) {
        if (ts.isImportDeclaration(stmt)) {
            const { line } = sourceFile.getLineAndCharacterOfPosition(stmt.getEnd());
            insertLine = line + 2;
        } else {
            break;
        }
    }

    return {
        filePath,
        original: "",
        replacement: importText,
        line: insertLine,
        column: 1,
        applicability: strategy.applicability,
        description: `Add import for ${missingNames.join(", ")} from "${strategy.importPackage}"`,
    };
}

function findNamespaceAlias(sourceFile: ts.SourceFile, packageName: string): string | undefined {
    for (const stmt of sourceFile.statements) {
        if (
            ts.isImportDeclaration(stmt) &&
            ts.isStringLiteral(stmt.moduleSpecifier) &&
            stmt.moduleSpecifier.text === packageName &&
            stmt.importClause?.namedBindings &&
            ts.isNamespaceImport(stmt.importClause.namedBindings)
        ) {
            return stmt.importClause.namedBindings.name.text;
        }
    }
    return undefined;
}

function getPositionFromLineColumn(sourceFile: ts.SourceFile, line: number, column: number): number {
    const starts = sourceFile.getLineStarts();
    if (line < 1 || line > starts.length || column < 1) return -1;
    const pos = starts[line - 1] + column - 1;
    const end = starts[line] ?? sourceFile.text.length;
    return pos < end ? pos : -1;
}

function findCallOrNewExpressionAt(
    sourceFile: ts.SourceFile,
    position: number,
): ts.CallExpression | ts.NewExpression | undefined {
    let result: ts.CallExpression | ts.NewExpression | undefined;

    function visit(node: ts.Node): void {
        if (node.getStart() <= position && position < node.getEnd()) {
            if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
                result = node;
            }
            ts.forEachChild(node, visit);
        }
    }

    visit(sourceFile);
    return result;
}
