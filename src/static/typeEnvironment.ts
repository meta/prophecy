/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { builtinModules } from "module";
import * as ts from "typescript";
import { ParsedProject } from "./parser";

const NODE_BUILTINS: ReadonlySet<string> = new Set(builtinModules);
const CANNOT_FIND_TYPE_DEFINITION_FILE = 2688;

export interface TypeEnvironmentGaps {
    /** Node built-in module → number of imports of it that resolve to nothing. */
    unresolvedBuiltinImports: Map<string, number>;
    /** Libraries named by the tsconfig `types` option that were not found. */
    missingTypeLibraries: string[];
}

/**
 * Declarations the project expects but the program does not have, usually
 * because its dependencies were never installed. Without them the checker has
 * no symbol for APIs such as `child_process.exec`, so sources and sinks can
 * only be matched by name and some flows are silently lost.
 */
export function findTypeEnvironmentGaps(parsed: ParsedProject): TypeEnvironmentGaps {
    const unresolvedBuiltinImports = new Map<string, number>();
    for (const sourceFile of parsed.sourceFiles) {
        for (const statement of sourceFile.statements) {
            const specifier = moduleSpecifierOf(statement);
            if (specifier == null) continue;
            const name = specifier.text.replace(/^node:/, "");
            if (!NODE_BUILTINS.has(name) || parsed.checker.getSymbolAtLocation(specifier) != null) {
                continue;
            }
            unresolvedBuiltinImports.set(name, (unresolvedBuiltinImports.get(name) ?? 0) + 1);
        }
    }

    const missingTypeLibraries: string[] = [];
    for (const diagnostic of parsed.program.getOptionsDiagnostics()) {
        if (diagnostic.code !== CANNOT_FIND_TYPE_DEFINITION_FILE) continue;
        const library = /'([^']+)'/.exec(ts.flattenDiagnosticMessageText(diagnostic.messageText, " "))?.[1];
        if (library != null) missingTypeLibraries.push(library);
    }

    return { unresolvedBuiltinImports, missingTypeLibraries };
}

/** One-paragraph description of the gaps, or undefined when there are none. */
export function describeTypeEnvironmentGaps(projectDir: string, gaps: TypeEnvironmentGaps): string | undefined {
    const parts: string[] = [];
    if (gaps.unresolvedBuiltinImports.size > 0) {
        const byCount = [...gaps.unresolvedBuiltinImports].sort((a, b) => b[1] - a[1]);
        const total = byCount.reduce((sum, [, count]) => sum + count, 0);
        const examples = byCount
            .slice(0, 5)
            .map(([name, count]) => `${name} ×${count}`)
            .join(", ");
        parts.push(`${total} import(s) of Node built-in modules have no declarations (${examples})`);
    }
    if (gaps.missingTypeLibraries.length > 0) {
        const examples = gaps.missingTypeLibraries.slice(0, 5).join(", ");
        parts.push(
            `${gaps.missingTypeLibraries.length} type library(ies) from tsconfig "types" were not found (${examples})`,
        );
    }
    if (parts.length === 0) return undefined;
    return (
        `Missing type declarations in ${projectDir}: ${parts.join("; ")}. ` +
        "Install the project's dependencies (for example `yarn install`) before scanning; " +
        "without them sources and sinks are matched by name only and some flows are not reported."
    );
}

function moduleSpecifierOf(statement: ts.Statement): ts.StringLiteral | undefined {
    if (
        (ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) &&
        statement.moduleSpecifier != null &&
        ts.isStringLiteral(statement.moduleSpecifier)
    ) {
        return statement.moduleSpecifier;
    }
    if (
        ts.isImportEqualsDeclaration(statement) &&
        ts.isExternalModuleReference(statement.moduleReference) &&
        ts.isStringLiteral(statement.moduleReference.expression)
    ) {
        return statement.moduleReference.expression;
    }
    return undefined;
}
