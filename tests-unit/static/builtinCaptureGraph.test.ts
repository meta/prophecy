/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import * as ts from "typescript";
import { parseSource } from "../../src/static/parser";
import { APIIdentityCache } from "../../src/static/taint/apiIdentity";

it("checks shared caller graphs without enumerating exponentially many activation paths", () => {
    // Only inspect the capture proof; this synthetic call tree is never executed or analyzed interprocedurally.
    const source = `const native = Number;
        function step0() { Number = ((value: string) => value) as any; }
        ${Array.from({ length: 30 }, (_, index) => `function step${index + 1}() { step${index}(); step${index}(); }`).join("\n")}
        export function main() { step30(); }`;
    const fileName = path.join(__dirname, "builtin-capture-graph.ts");
    const parsed = parseSource(source, fileName);
    expect(parsed.program.getSemanticDiagnostics().map((diagnostic) => diagnostic.code)).toEqual([]);
    const statement = parsed.program.getSourceFile(fileName)!.statements.find(ts.isVariableStatement)!;
    const capture = statement.declarationList.declarations[0].initializer!;
    expect(APIIdentityCache.forChecker(parsed.program.getTypeChecker()).builtinName(capture)).toBe("Number");
});
